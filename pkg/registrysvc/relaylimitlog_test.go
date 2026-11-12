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
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// warnClock is a clock a test moves by hand.
type warnClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *warnClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *warnClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

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
)

// TestRelayLogsWhenFullOrOverShare is the gate for the relay listener's two
// warnings: the relay at its connection limit, so a new pull waits, and a
// source refused at its share. Each logs once for the first event, nothing
// for another inside the interval, and again, with the count it dropped,
// after the interval.
func TestRelayLogsWhenFullOrOverShare(t *testing.T) {
	// listen starts a limit listener with the given caps, a recorded log and
	// a hand-moved clock, and an accept loop that hands out what it accepts.
	listen := func(t *testing.T, total, perSource int) (*limitListener, *recordedLog, *warnClock, chan net.Conn) {
		t.Helper()
		front, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		rec := &recordedLog{}
		clk := &warnClock{t: time.Unix(1_700_000_000, 0)}
		ll := newLimitListener(front, total, perSource)
		ll.log = slog.New(rec)
		ll.now = clk.now
		ll.warnEvery = testWarnGap
		t.Cleanup(func() { _ = ll.Close() })
		accepted := make(chan net.Conn, 8)
		go func() {
			for {
				c, err := ll.Accept()
				if err != nil {
					return
				}
				accepted <- c
			}
		}()
		return ll, rec, clk, accepted
	}
	dial := func(t *testing.T, ll *limitListener) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", ll.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	take := func(t *testing.T, accepted chan net.Conn) net.Conn {
		t.Helper()
		select {
		case c := <-accepted:
			return c
		case <-time.After(5 * time.Second):
			t.Fatal("no connection accepted")
			return nil
		}
	}
	// waitFor polls until cond holds.
	waitFor := func(t *testing.T, what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	suppressed := func(g *warnGate) int {
		g.mu.Lock()
		defer g.mu.Unlock()
		return g.suppressed
	}

	t.Run("a full relay", func(t *testing.T) {
		ll, rec, clk, accepted := listen(t, 1, 4)
		dial(t, ll)
		first := take(t, accepted)
		// The accept loop's next Accept finds the only slot held.
		waitFor(t, "the full warning", func() bool { return len(rec.warnings(fullMsg)) == 1 })
		got := rec.warnings(fullMsg)[0]
		if got["limit"] != "1" || got["suppressed"] != "0" {
			t.Errorf("full warning = %v, want limit=1 suppressed=0", got)
		}

		// A second wait inside the interval logs nothing.
		_ = first.Close()
		dial(t, ll)
		second := take(t, accepted)
		waitFor(t, "the second wait to be counted", func() bool { return suppressed(&ll.full) == 1 })
		if n := len(rec.warnings(fullMsg)); n != 1 {
			t.Fatalf("full warnings = %d inside the interval, want 1", n)
		}

		// After the interval the next wait logs again, with what it dropped.
		clk.advance(testWarnGap)
		_ = second.Close()
		dial(t, ll)
		third := take(t, accepted)
		defer third.Close()
		waitFor(t, "the full warning after the interval", func() bool { return len(rec.warnings(fullMsg)) == 2 })
		if got := rec.warnings(fullMsg)[1]; got["suppressed"] != "1" {
			t.Errorf("full warning after the interval = %v, want suppressed=1", got)
		}
		if n := len(rec.warnings(overShareMsg)); n != 0 {
			t.Errorf("share warnings = %d, want none", n)
		}
	})

	t.Run("a source over its share", func(t *testing.T) {
		ll, rec, clk, accepted := listen(t, 4, 1)
		dial(t, ll)
		held := take(t, accepted)
		defer held.Close()
		// refused dials once more from the same address and waits for the
		// listener to close the connection, which it does after logging.
		refused := func(t *testing.T) {
			t.Helper()
			c := dial(t, ll)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Fatalf("read the refused connection: %v", err)
			}
		}

		refused(t)
		got := rec.warnings(overShareMsg)
		if len(got) != 1 {
			t.Fatalf("share warnings = %v, want exactly 1", got)
		}
		if got[0]["source"] != "127.0.0.1" || got[0]["share"] != "1" || got[0]["suppressed"] != "0" {
			t.Errorf("share warning = %v, want source=127.0.0.1 share=1 suppressed=0", got[0])
		}

		refused(t)
		if n := len(rec.warnings(overShareMsg)); n != 1 {
			t.Fatalf("share warnings = %d inside the interval, want 1", n)
		}

		clk.advance(testWarnGap)
		refused(t)
		got = rec.warnings(overShareMsg)
		if len(got) != 2 {
			t.Fatalf("share warnings = %v after the interval, want 2", got)
		}
		if got[1]["suppressed"] != "1" {
			t.Errorf("share warning after the interval = %v, want suppressed=1", got[1])
		}
		if n := len(rec.warnings(fullMsg)); n != 0 {
			t.Errorf("full warnings = %d, want none", n)
		}
	})
}
