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

package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// TestSupervisorRecoversInjectedPanics checks that a panic in a start
// check, the listener source or the marker poll is recovered and fails as
// that step, and the supervisor carries on.
func TestSupervisorRecoversInjectedPanics(t *testing.T) {
	for _, tc := range []struct {
		step   string
		phase  Phase
		reason OffReason
	}{
		{"euid", PhaseOff, OffNotInstalledServer},
		{"marker", PhaseOff, OffMaintenanceUnknown},
		{"mount", PhaseOff, OffMountUnknown},
		{"install", PhaseOff, OffInstall},
		{"count", PhaseOff, OffServersUnknown},
		{"listen", PhaseBackingOff, OffListenerUnavailable},
	} {
		t.Run(tc.step, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newSupRig(t, func(c *startChecks) { c.panics = tc.step })
				st := r.wantState(t, tc.phase, tc.reason, MinBackoff)
				if !strings.Contains(st.Detail, tc.step+" panicked") {
					t.Fatalf("state detail %q, want the panic", st.Detail)
				}
				r.ck.set(func(c *startChecks) { c.panics = "" })
				advance(MinBackoff)
				r.wantState(t, PhaseServing, "", 0)
				r.dial(t, 501).admitted(t)
			})
		})
	}
	t.Run("marker poll while serving", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := newSupRig(t, nil)
			r.wantState(t, PhaseServing, "", 0)
			r.ck.set(func(c *startChecks) { c.panics = "marker" })
			advance(MaintenancePoll)
			r.wantState(t, PhaseOff, OffMaintenanceUnknown, MinBackoff)
			if r.ln.accepting() {
				t.Fatal("the listener still accepts after the marker poll panicked")
			}
			r.ck.set(func(c *startChecks) { c.panics = "" })
			advance(MinBackoff)
			r.wantState(t, PhaseServing, "", 0)
		})
	})
}

// TestServePanicStopsTheClose checks that a Serve ended by a panic leaves
// no pending close behind: cancelling its context afterwards does not
// close a socket a later run reuses.
func TestServePanicStopsTheClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ln := newFakeListener()
		creds := &panickyCreds{fakeCreds: &fakeCreds{peers: map[net.Conn]PeerCred{}}}
		creds.boom.Store(true)
		h, err := NewHandler(time.Now)
		if err != nil {
			t.Fatal(err)
		}
		l, err := NewListener(ln, creds, &fakeSandbox{}, serviceUID, bubbleClock{}, &fakeAuditor{}, h)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		panicked := make(chan any, 1)
		go func() {
			defer func() { panicked <- recover() }()
			_ = l.Serve(ctx)
		}()
		server, client := net.Pipe()
		defer func() { _ = client.Close() }()
		ln.conns <- server
		if v := <-panicked; v == nil {
			t.Fatal("Serve did not panic")
		}
		cancel()
		synctest.Wait()
		select {
		case <-ln.done:
			t.Fatal("the run's close reached the socket after its Serve panicked")
		default:
		}
	})
}

// flakyListener fails Accept with the errors queued, then hands out conns.
type flakyListener struct {
	*fakeListener
	mu   sync.Mutex
	errs []error
	at   []time.Time // when each Accept was called
}

func (f *flakyListener) Accept() (net.Conn, error) {
	f.mu.Lock()
	f.at = append(f.at, time.Now())
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		f.mu.Unlock()
		return nil, err
	}
	f.mu.Unlock()
	return f.fakeListener.Accept()
}

// tempErr is a net.Error that says it is temporary.
type tempErr struct{}

func (tempErr) Error() string   { return "fake: temporary" }
func (tempErr) Timeout() bool   { return false }
func (tempErr) Temporary() bool { return true }

// TestAcceptRetriesTransientErrors checks that transient Accept errors are
// waited out inside the accept loop, with a growing capped wait, while an
// open connection stays served; any other error ends Serve.
func TestAcceptRetriesTransientErrors(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startRig(t) // for its peer tables
		if err := r.stop(); err != nil {
			t.Fatal(err)
		}

		fl := &flakyListener{fakeListener: newFakeListener()}
		h, err := NewHandler(time.Now)
		if err != nil {
			t.Fatal(err)
		}
		l, err := NewListener(fl, r.creds, r.sandbox, serviceUID, bubbleClock{}, &fakeAuditor{}, h)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- l.Serve(ctx) }()
		r2 := &rig{ln: fl.fakeListener, creds: r.creds, sandbox: r.sandbox}
		p := r2.dial(502)
		p.admitted(t)

		transient := []error{
			fmt.Errorf("accept: %w", syscall.EMFILE), syscall.ENFILE, syscall.ECONNABORTED, syscall.EINTR, tempErr{},
		}
		for range 6 {
			transient = append(transient, syscall.EMFILE) // past the cap
		}
		fl.mu.Lock()
		fl.errs = append([]error(nil), transient...)
		start := len(fl.at)
		fl.mu.Unlock()
		// Wake the pending Accept so it reads the queued errors.
		p2 := r2.dial(503)
		p2.admitted(t)
		advance(IdleBound / 2) // the waits add up to under it; the open connection idles
		select {
		case err := <-done:
			t.Fatalf("Serve returned %v on transient errors", err)
		default:
		}
		fl.mu.Lock()
		at := append([]time.Time(nil), fl.at[start:]...)
		fl.mu.Unlock()
		if len(at) < len(transient)+1 {
			t.Fatalf("%d Accept calls after the errors were queued, want %d", len(at), len(transient)+1)
		}
		want := AcceptRetryMin
		for i := 1; i <= len(transient); i++ {
			if got := at[i].Sub(at[i-1]); got != want {
				t.Fatalf("wait before Accept %d = %v, want %v", i, got, want)
			}
			want = min(2*want, AcceptRetryMax)
		}
		// The connection admitted before the errors is still served.
		if err := WriteFrame(p.client, Frame{Type: TypeRequest, Header: []byte(`{"op":"nope"}`)}); err != nil {
			t.Fatalf("the open connection was cut: %v", err)
		}
		if f, err := ReadFrame(p.client); err != nil || f.Type != TypeError {
			t.Fatalf("reply on the open connection: %v, %v", f.Type, err)
		}

		// Any other error ends Serve.
		fatal := errors.New("fake: accept failed for good")
		fl.mu.Lock()
		fl.errs = []error{fatal}
		fl.mu.Unlock()
		r2.dial(504).close() // wakes the pending Accept; the next one fails
		synctest.Wait()
		if err := <-done; !errors.Is(err, fatal) {
			t.Fatalf("Serve = %v, want %v", err, fatal)
		}
	})
}
