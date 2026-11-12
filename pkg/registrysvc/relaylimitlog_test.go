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
		if got["addr"] != ll.Addr().String() || got["limit"] != "1" || got["suppressed"] != "0" {
			t.Errorf("full warning = %v, want addr=%s limit=1 suppressed=0", got, ll.Addr())
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
		if got := rec.warnings(fullMsg)[1]; got["addr"] != ll.Addr().String() || got["suppressed"] != "1" {
			t.Errorf("full warning after the interval = %v, want addr=%s suppressed=1", got, ll.Addr())
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
		// listener to close the connection. The listener logs only after
		// closing it and releasing the slot, so callers wait for the line.
		refused := func(t *testing.T) {
			t.Helper()
			c := dial(t, ll)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Fatalf("read the refused connection: %v", err)
			}
		}

		refused(t)
		waitFor(t, "the share warning", func() bool { return len(rec.warnings(overShareMsg)) == 1 })
		got := rec.warnings(overShareMsg)
		if got[0]["addr"] != ll.Addr().String() || got[0]["source"] != "127.0.0.1" || got[0]["share"] != "1" || got[0]["suppressed"] != "0" {
			t.Errorf("share warning = %v, want addr=%s source=127.0.0.1 share=1 suppressed=0", got[0], ll.Addr())
		}

		refused(t)
		waitFor(t, "the second refusal to be counted", func() bool { return suppressed(&ll.overShare) == 1 })
		if n := len(rec.warnings(overShareMsg)); n != 1 {
			t.Fatalf("share warnings = %d inside the interval, want 1", n)
		}

		clk.advance(testWarnGap)
		refused(t)
		waitFor(t, "the share warning after the interval", func() bool { return len(rec.warnings(overShareMsg)) == 2 })
		got = rec.warnings(overShareMsg)
		if got[1]["addr"] != ll.Addr().String() || got[1]["suppressed"] != "1" {
			t.Errorf("share warning after the interval = %v, want addr=%s suppressed=1", got[1], ll.Addr())
		}
		if n := len(rec.warnings(fullMsg)); n != 0 {
			t.Errorf("full warnings = %d, want none", n)
		}
	})

	t.Run("three drops inside the interval", func(t *testing.T) {
		ll, rec, clk, accepted := listen(t, 4, 1)
		dial(t, ll)
		held := take(t, accepted)
		defer held.Close()
		refused := func(t *testing.T) {
			t.Helper()
			c := dial(t, ll)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadAll(c); err != nil {
				t.Fatalf("read the refused connection: %v", err)
			}
		}

		refused(t)
		waitFor(t, "the share warning", func() bool { return len(rec.warnings(overShareMsg)) == 1 })
		for range 3 {
			refused(t)
		}
		waitFor(t, "three refusals to be counted", func() bool { return suppressed(&ll.overShare) == 3 })
		if n := len(rec.warnings(overShareMsg)); n != 1 {
			t.Fatalf("share warnings = %d inside the interval, want 1", n)
		}

		// The next line after the interval carries the three it dropped.
		clk.advance(testWarnGap)
		refused(t)
		waitFor(t, "the share warning after the interval", func() bool { return len(rec.warnings(overShareMsg)) == 2 })
		if got := rec.warnings(overShareMsg)[1]; got["suppressed"] != "3" {
			t.Errorf("share warning after the interval = %v, want suppressed=3", got)
		}

		// The one after another interval, with nothing dropped, carries 0.
		clk.advance(testWarnGap)
		refused(t)
		waitFor(t, "the share warning after another interval", func() bool { return len(rec.warnings(overShareMsg)) == 3 })
		if got := rec.warnings(overShareMsg)[2]; got["suppressed"] != "0" {
			t.Errorf("share warning after another interval = %v, want suppressed=0", got)
		}
	})

	t.Run("a share refusal inside a full warning's interval still logs", func(t *testing.T) {
		// Two sources fill the listener, which a loopback socket cannot do,
		// so this row dials over a listener that names each source.
		front := newSrcListener()
		rec := &recordedLog{}
		clk := &warnClock{t: time.Unix(1_700_000_000, 0)}
		ll := newLimitListener(front, 2, 1)
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
		srcDial := func(t *testing.T, src string) net.Conn {
			t.Helper()
			c, err := front.dial(src, 5*time.Second)
			if err != nil {
				t.Fatalf("dial from %s: %v", src, err)
			}
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		const peerA, peerB = "100.64.1.1", "100.64.2.1"

		srcDial(t, peerA)
		heldA := take(t, accepted)
		defer heldA.Close()
		srcDial(t, peerB)
		heldB := take(t, accepted)
		waitFor(t, "the full warning", func() bool { return len(rec.warnings(fullMsg)) == 1 })

		// A slot frees and peer A, already at its share, dials again, with the
		// clock still inside the full warning's interval.
		_ = heldB.Close()
		srcDial(t, peerA)
		waitFor(t, "the share warning", func() bool { return len(rec.warnings(overShareMsg)) == 1 })
		if got := rec.warnings(overShareMsg)[0]; got["source"] != peerA || got["suppressed"] != "0" {
			t.Errorf("share warning = %v, want source=%s suppressed=0", got, peerA)
		}
		if n := len(rec.warnings(fullMsg)); n != 1 {
			t.Errorf("full warnings = %d, want 1", n)
		}
	})
}

// TestRelayLogsLimitWarningsToItsLogger is the gate for the warnings' wiring:
// a relay built by newRelay and served by its own accept hands its logger to
// the limit listener, so a full relay and a refused source reach the logger
// the relay was built with, naming the address the relay listens on.
func TestRelayLogsLimitWarningsToItsLogger(t *testing.T) {
	// serve builds a relay over the production seams with a recorded logger
	// and the given connection caps, and serves it on a loopback listener.
	serve := func(t *testing.T, total, perSource int) (*recordedLog, string) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		rec := &recordedLog{}
		r := newRelay(portOf(t, ln.Addr()), portOf(t, ln.Addr()), nil, slog.New(rec), GateAuth{}, gateCred)
		r.limits.maxConns = total
		r.limits.maxConnsPerSource = perSource
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = r.accept(ctx, ln)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
			_ = ln.Close()
		})
		return rec, ln.Addr().String()
	}
	dial := func(t *testing.T, addr string) net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	waitFor := func(t *testing.T, rec *recordedLog, msg string) map[string]string {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got := rec.warnings(msg); len(got) > 0 {
				return got[0]
			}
			if time.Now().After(deadline) {
				t.Fatalf("no %q warning reached the relay's logger", msg)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	t.Run("a source over its share", func(t *testing.T) {
		rec, addr := serve(t, 4, 1)
		dial(t, addr)
		c := dial(t, addr)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadAll(c); err != nil {
			t.Fatalf("read the refused connection: %v", err)
		}
		if got := waitFor(t, rec, overShareMsg); got["addr"] != addr || got["source"] != "127.0.0.1" || got["share"] != "1" {
			t.Errorf("share warning = %v, want addr=%s source=127.0.0.1 share=1", got, addr)
		}
	})

	t.Run("a full relay", func(t *testing.T) {
		rec, addr := serve(t, 1, 1)
		dial(t, addr)
		if got := waitFor(t, rec, fullMsg); got["addr"] != addr || got["limit"] != "1" {
			t.Errorf("full warning = %v, want addr=%s limit=1", got, addr)
		}
	})
}
