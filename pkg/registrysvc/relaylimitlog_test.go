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
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// warnings returns the attributes of every Warn record whose message
// contains substr.
func (l *recordedLog) warnings(substr string) []map[string]string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]string
	for _, r := range l.recs {
		if r.Level != slog.LevelWarn || !strings.Contains(r.Message, substr) {
			continue
		}
		attrs := map[string]string{"msg": r.Message}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		out = append(out, attrs)
	}
	return out
}

const (
	fullMsg      = "at its connection limit"
	overShareMsg = "holds its share"
	testWarnGap  = time.Minute
	// limitPeer and limitPeerB are two client addresses on the cluster network.
	limitPeer  = "100.64.1.1"
	limitPeerB = "100.64.2.1"
)

// limitLogFixture is a limit listener over a srcListener, with a recorded log
// and an accept loop that hands out what it accepts. It is built inside a
// synctest bubble, so its warning interval runs on the bubble's clock.
type limitLogFixture struct {
	ll       *limitListener
	front    *srcListener
	rec      *recordedLog
	accepted chan net.Conn
}

func newLimitLogFixture(t *testing.T, total, perSource int) *limitLogFixture {
	t.Helper()
	f := &limitLogFixture{front: newSrcListener(), rec: &recordedLog{}, accepted: make(chan net.Conn, 8)}
	f.ll = newLimitListener(f.front, total, perSource)
	f.ll.log = slog.New(f.rec)
	f.ll.warnEvery = testWarnGap
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := f.ll.Accept()
			if err != nil {
				return
			}
			f.accepted <- c
		}
	}()
	t.Cleanup(func() {
		_ = f.ll.Close()
		<-done
		for {
			select {
			case c := <-f.accepted:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return f
}

// dial opens a connection from src and lets the accept loop act on it.
func (f *limitLogFixture) dial(t *testing.T, src string) net.Conn {
	t.Helper()
	c, err := f.front.dial(src, time.Second)
	if err != nil {
		t.Fatalf("dial from %s: %v", src, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	synctest.Wait()
	return c
}

// take returns the connection the accept loop has handed out.
func (f *limitLogFixture) take(t *testing.T) net.Conn {
	t.Helper()
	synctest.Wait()
	select {
	case c := <-f.accepted:
		return c
	default:
		t.Fatal("no connection accepted")
		return nil
	}
}

// refused dials from src and requires the listener to close the connection
// at once, as it does for a source already at its share.
func (f *limitLogFixture) refused(t *testing.T, src string) {
	t.Helper()
	c := f.dial(t, src)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("read the refused connection: %v", err)
	}
	synctest.Wait()
}

func (f *limitLogFixture) suppressed(g *warnGate) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.suppressed
}

// TestRelayLogsWhenFullOrOverShare is the gate for the relay listener's two
// warnings: the relay at its connection limit, so a further connection waits,
// and a source refused at its share. Each logs once for the first event,
// nothing for another inside the interval, and again, with the count it
// dropped, after the interval. The interval is timed on a synctest clock.
func TestRelayLogsWhenFullOrOverShare(t *testing.T) {
	t.Run("a full relay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newLimitLogFixture(t, 1, 4)
			f.dial(t, limitPeer)
			first := f.take(t)
			// The accept loop's next Accept finds the only slot held.
			got := f.rec.warnings(fullMsg)
			if len(got) != 1 {
				t.Fatalf("full warnings = %d with the only slot held, want 1", len(got))
			}
			if got[0]["addr"] != f.ll.Addr().String() || got[0]["limit"] != "1" || got[0]["suppressed"] != "0" {
				t.Errorf("full warning = %v, want addr=%s limit=1 suppressed=0", got[0], f.ll.Addr())
			}

			// A second wait inside the interval logs nothing.
			_ = first.Close()
			f.dial(t, limitPeer)
			second := f.take(t)
			if n := f.suppressed(&f.ll.full); n != 1 {
				t.Fatalf("suppressed = %d after a second wait, want 1", n)
			}
			if n := len(f.rec.warnings(fullMsg)); n != 1 {
				t.Fatalf("full warnings = %d inside the interval, want 1", n)
			}

			// After the interval the next wait logs again, with what it dropped.
			advance(t, testWarnGap)
			_ = second.Close()
			f.dial(t, limitPeer)
			third := f.take(t)
			defer third.Close()
			got = f.rec.warnings(fullMsg)
			if len(got) != 2 {
				t.Fatalf("full warnings = %d after the interval, want 2", len(got))
			}
			if got[1]["addr"] != f.ll.Addr().String() || got[1]["suppressed"] != "1" {
				t.Errorf("full warning after the interval = %v, want addr=%s suppressed=1", got[1], f.ll.Addr())
			}
			if n := len(f.rec.warnings(overShareMsg)); n != 0 {
				t.Errorf("share warnings = %d, want none", n)
			}
		})
	})

	t.Run("a source over its share", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newLimitLogFixture(t, 4, 1)
			f.dial(t, limitPeer)
			held := f.take(t)
			defer held.Close()

			f.refused(t, limitPeer)
			got := f.rec.warnings(overShareMsg)
			if len(got) != 1 {
				t.Fatalf("share warnings = %d after a refusal, want 1", len(got))
			}
			if got[0]["addr"] != f.ll.Addr().String() || got[0]["source"] != limitPeer || got[0]["share"] != "1" || got[0]["suppressed"] != "0" {
				t.Errorf("share warning = %v, want addr=%s source=%s share=1 suppressed=0", got[0], f.ll.Addr(), limitPeer)
			}

			f.refused(t, limitPeer)
			if n := f.suppressed(&f.ll.overShare); n != 1 {
				t.Fatalf("suppressed = %d after a second refusal, want 1", n)
			}
			if n := len(f.rec.warnings(overShareMsg)); n != 1 {
				t.Fatalf("share warnings = %d inside the interval, want 1", n)
			}

			advance(t, testWarnGap)
			f.refused(t, limitPeer)
			got = f.rec.warnings(overShareMsg)
			if len(got) != 2 {
				t.Fatalf("share warnings = %d after the interval, want 2", len(got))
			}
			if got[1]["addr"] != f.ll.Addr().String() || got[1]["suppressed"] != "1" {
				t.Errorf("share warning after the interval = %v, want addr=%s suppressed=1", got[1], f.ll.Addr())
			}
			if n := len(f.rec.warnings(fullMsg)); n != 0 {
				t.Errorf("full warnings = %d, want none", n)
			}
		})
	})

	t.Run("three drops inside the interval", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newLimitLogFixture(t, 4, 1)
			f.dial(t, limitPeer)
			held := f.take(t)
			defer held.Close()

			f.refused(t, limitPeer)
			for range 3 {
				f.refused(t, limitPeer)
			}
			if n := f.suppressed(&f.ll.overShare); n != 3 {
				t.Fatalf("suppressed = %d after three refusals, want 3", n)
			}
			if n := len(f.rec.warnings(overShareMsg)); n != 1 {
				t.Fatalf("share warnings = %d inside the interval, want 1", n)
			}

			// The next line after the interval carries the three it dropped.
			advance(t, testWarnGap)
			f.refused(t, limitPeer)
			got := f.rec.warnings(overShareMsg)
			if len(got) != 2 || got[1]["suppressed"] != "3" {
				t.Fatalf("share warnings after the interval = %v, want a second with suppressed=3", got)
			}

			// The one after another interval, with nothing dropped, carries 0.
			advance(t, testWarnGap)
			f.refused(t, limitPeer)
			got = f.rec.warnings(overShareMsg)
			if len(got) != 3 || got[2]["suppressed"] != "0" {
				t.Fatalf("share warnings after another interval = %v, want a third with suppressed=0", got)
			}
		})
	})

	t.Run("a share refusal inside a full warning's interval still logs", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			f := newLimitLogFixture(t, 2, 1)
			f.dial(t, limitPeer)
			heldA := f.take(t)
			defer heldA.Close()
			f.dial(t, limitPeerB)
			heldB := f.take(t)
			if n := len(f.rec.warnings(fullMsg)); n != 1 {
				t.Fatalf("full warnings = %d with both slots held, want 1", n)
			}

			// A slot frees and peer A, already at its share, dials again, with
			// the clock still inside the full warning's interval.
			_ = heldB.Close()
			f.refused(t, limitPeer)
			got := f.rec.warnings(overShareMsg)
			if len(got) != 1 || got[0]["source"] != limitPeer || got[0]["suppressed"] != "0" {
				t.Errorf("share warnings = %v, want one with source=%s suppressed=0", got, limitPeer)
			}
			if n := len(f.rec.warnings(fullMsg)); n != 1 {
				t.Errorf("full warnings = %d, want 1", n)
			}
		})
	})
}

// TestRelayLogsLimitWarningsToItsLogger is the gate for the warnings' wiring:
// a relay built by newRelay and served by its own accept hands its logger to
// the limit listener, so a full relay and a refused source reach the logger
// the relay was built with, naming the address the relay listens on.
func TestRelayLogsLimitWarningsToItsLogger(t *testing.T) {
	// serve builds a relay with a recorded logger and the given connection
	// caps, and serves it by its own accept on a srcListener.
	serve := func(t *testing.T, total, perSource int) (*recordedLog, *srcListener) {
		t.Helper()
		front := newSrcListener()
		rec := &recordedLog{}
		r := newRelay(fakeRegistryPort, fakeRegistryPort, nil, slog.New(rec), GateAuth{}, gateCred)
		r.limits.maxConns = total
		r.limits.maxConnsPerSource = perSource
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = r.accept(ctx, front)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
			_ = front.Close()
		})
		return rec, front
	}
	dial := func(t *testing.T, front *srcListener, src string) net.Conn {
		t.Helper()
		c, err := front.dial(src, time.Second)
		if err != nil {
			t.Fatalf("dial from %s: %v", src, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		synctest.Wait()
		return c
	}
	first := func(t *testing.T, rec *recordedLog, msg string) map[string]string {
		t.Helper()
		got := rec.warnings(msg)
		if len(got) == 0 {
			t.Fatalf("no %q warning reached the relay's logger", msg)
		}
		return got[0]
	}

	t.Run("a source over its share", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rec, front := serve(t, 4, 1)
			dial(t, front, limitPeer)
			c := dial(t, front, limitPeer)
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Fatalf("read the refused connection: %v", err)
			}
			synctest.Wait()
			addr := front.Addr().String()
			if got := first(t, rec, overShareMsg); got["addr"] != addr || got["source"] != limitPeer || got["share"] != "1" {
				t.Errorf("share warning = %v, want addr=%s source=%s share=1", got, addr, limitPeer)
			}
		})
	})

	t.Run("a full relay", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			rec, front := serve(t, 1, 1)
			dial(t, front, limitPeer)
			addr := front.Addr().String()
			if got := first(t, rec, fullMsg); got["addr"] != addr || got["limit"] != "1" {
				t.Errorf("full warning = %v, want addr=%s limit=1", got, addr)
			}
		})
	})
}
