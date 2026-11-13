/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registrysvc

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"
)

// recordedLog keeps every record a logger handles.
type recordedLog struct {
	mu   sync.Mutex
	recs []slog.Record
}

func (l *recordedLog) Enabled(context.Context, slog.Level) bool { return true }
func (l *recordedLog) WithAttrs([]slog.Attr) slog.Handler       { return l }
func (l *recordedLog) WithGroup(string) slog.Handler            { return l }
func (l *recordedLog) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r.Clone())
	return nil
}

// cuts returns the attributes of every Warn record naming a cut connection.
func (l *recordedLog) cuts() []map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]string
	for _, r := range l.recs {
		if r.Level != slog.LevelWarn {
			continue
		}
		attrs := map[string]string{"msg": r.Message}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		if _, ok := attrs["direction"]; ok {
			out = append(out, attrs)
		}
	}
	return out
}

// newCutLogFixture serves stallRegistry, dripping on drip, behind the relay's limiter and
// listener with stallLimits, and records what the relay logs. A POST body is
// read in full before the answer, so a body that never arrives stalls a read.
// The gate is left out: the line under test is the limiter's, not the gate's.
func newCutLogFixture(t *testing.T, drip <-chan struct{}) (*relayLimitFixture, *recordedLog) {
	t.Helper()
	rec := &recordedLog{}
	lim := stallLimits()
	reg := stallRegistry(drip)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return
			}
		}
		reg.ServeHTTP(w, r)
	})
	r := newRelay(0, 0, nil, slog.New(rec), GateAuth{}, gateCred)
	r.limits = lim
	r.limiter = newSourceLimiter(next, lim, time.Now)
	r.limiter.log = slog.New(rec)
	r.handler = r.limiter
	f := &relayLimitFixture{front: newSrcListener()}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.accept(ctx, f.front)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = f.front.Close()
	})
	return f, rec
}

// TestRelayCutIsLogged: a connection a relay deadline cuts is logged once, at
// Warn, with its direction, window and remote address, and a healthy response
// logs nothing. Every case runs in a synctest bubble over in-memory
// connections.
func TestRelayCutIsLogged(t *testing.T) {
	const peerA = "100.64.1.1"
	within := 3 * stallWindow

	t.Run("a stalled reader logs one write cut", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			drip := make(chan struct{})
			f, rec := newCutLogFixture(t, drip)
			f.stallGet(t, peerA, drip)
			// Stop reading. The slot frees only after the cut is logged.
			f.awaitSlot(t, peerA, within)
			cuts := rec.cuts()
			if len(cuts) != 1 {
				t.Fatalf("cut lines = %v, want exactly one", cuts)
			}
			got := cuts[0]
			if got["direction"] != cutWrite {
				t.Errorf("cut direction = %q, want %q", got["direction"], cutWrite)
			}
			if got["window"] != stallWindow.String() {
				t.Errorf("cut window = %q, want %q", got["window"], stallWindow)
			}
			if got["remote"] == "" || sourceOfString(got["remote"]) != peerA {
				t.Errorf("cut remote = %q, want an address of %s", got["remote"], peerA)
			}
		})
	})

	t.Run("a request body that never arrives logs one read cut", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			f, rec := newCutLogFixture(t, nil)
			c := f.dial(t, peerA)
			if _, err := fmt.Fprintf(c, "POST /v2/team/app/blobs/uploads/ HTTP/1.1\r\nHost: registry.test\r\nContent-Length: 10\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			drainPeer(c)
			// The line is awaited rather than the slot: freeing the slot is
			// the stall tests' gate, and this one is about the line alone.
			start := time.Now()
			for len(rec.cuts()) == 0 && time.Since(start) < within {
				advance(t, slotStep)
			}
			cuts := rec.cuts()
			if len(cuts) != 1 || cuts[0]["direction"] != cutRead {
				t.Fatalf("cut lines = %v, want exactly one with direction %q", cuts, cutRead)
			}
		})
	})

	t.Run("a healthy response logs no cut", func(t *testing.T) {
		relayBubble(t, func(t *testing.T) {
			drip := make(chan struct{})
			f, rec := newCutLogFixture(t, drip)
			// The drip outlasts three windows, so a deadline that wrongly
			// fired would have done so by the end.
			if n, el := f.dripGet(t, peerA, drip); n != dripLen || el < 3*stallWindow {
				t.Fatalf("slow GET body = %d bytes in %v, want %d in more than %v", n, el, dripLen, 3*stallWindow)
			}
			if cuts := rec.cuts(); len(cuts) != 0 {
				t.Errorf("cut lines = %v, want none for a healthy response", cuts)
			}
		})
	})
}

func TestRelayGateBodyWindowFollowsRelayLimits(t *testing.T) {
	r := newRelay(0, 0, nil, quietLogger(), GateAuth{}, Credential{})
	g, ok := r.limiter.next.(*gate)
	if !ok {
		t.Fatalf("limiter next is %T, want *gate", r.limiter.next)
	}
	if g.bodyProgress != r.limits.writeProgress {
		t.Errorf("gate body window = %v, want the relay's write progress %v", g.bodyProgress, r.limits.writeProgress)
	}
}
