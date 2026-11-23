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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// pausableListener is a listening socket with SetDeadline, as an activated
// *net.UnixListener has: an expired deadline ends Accept and keeps the
// socket open, and a cleared one lets Accept wait again.
type pausableListener struct {
	conns chan net.Conn
	done  chan struct{}

	mu     sync.Mutex // guards paused and the counts
	paused chan struct{}
	closes int
}

func newPausableListener() *pausableListener {
	return &pausableListener{conns: make(chan net.Conn), done: make(chan struct{}), paused: make(chan struct{})}
}

func (p *pausableListener) Accept() (net.Conn, error) {
	p.mu.Lock()
	paused := p.paused
	p.mu.Unlock()
	select {
	case c := <-p.conns:
		return c, nil
	case <-paused:
		return nil, os.ErrDeadlineExceeded
	case <-p.done:
		return nil, net.ErrClosed
	}
}

func (p *pausableListener) SetDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.paused:
		if t.IsZero() {
			p.paused = make(chan struct{})
		}
	default:
		if !t.IsZero() {
			close(p.paused)
		}
	}
	return nil
}

func (p *pausableListener) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closes++; p.closes == 1 {
		close(p.done)
	}
	return nil
}

func (p *pausableListener) closeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}

func (p *pausableListener) Addr() net.Addr { return &net.UnixAddr{Name: "keys.sock", Net: "unix"} }

// accepting reports whether a connection offered now is taken.
func (p *pausableListener) accepting() bool {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	select {
	case p.conns <- server:
		return true
	default:
		_ = server.Close()
		return false
	}
}

// startChecks are the supervisor's start checks, set by a test.
type startChecks struct {
	mu         sync.Mutex
	euid       int
	marked     bool
	markerErr  error
	ignores    bool
	mountErr   error
	install    error
	servers    int
	serversErr error
	listens    int
	counted    int
	ln         net.Listener // what the listener source returns
}

func (c *startChecks) set(f func(c *startChecks)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f(c)
}

func (c *startChecks) get() startChecks {
	c.mu.Lock()
	defer c.mu.Unlock()
	return startChecks{listens: c.listens, counted: c.counted}
}

// logBuf collects the supervisor's log lines.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// count returns how many lines carry every one of subs.
func (l *logBuf) count(subs ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for line := range strings.Lines(l.b.String()) {
		all := true
		for _, s := range subs {
			all = all && strings.Contains(line, s)
		}
		if all {
			n++
		}
	}
	return n
}

// panickyCreds panics on a peer while boom is set.
type panickyCreds struct {
	*fakeCreds
	boom atomic.Bool
}

func (p *panickyCreds) PeerCred(c net.Conn) (PeerCred, error) {
	if p.boom.Load() {
		panic("fake: peer-credential source panicked")
	}
	return p.fakeCreds.PeerCred(c)
}

// supRig is a Supervisor over fakes, inside a synctest bubble.
type supRig struct {
	s      *Supervisor
	ln     *pausableListener
	ck     *startChecks
	creds  *panickyCreds
	box    *fakeSandbox
	h      *Handler
	log    *logBuf
	cancel context.CancelFunc
	done   chan struct{}
}

// newSupRig builds a rig whose checks all pass; setup may change them
// before Run starts.
func newSupRig(t *testing.T, setup func(c *startChecks)) *supRig {
	t.Helper()
	r := &supRig{
		ln:    newPausableListener(),
		ck:    &startChecks{euid: serviceUID, servers: 1},
		creds: &panickyCreds{fakeCreds: &fakeCreds{peers: make(map[net.Conn]PeerCred)}},
		box:   &fakeSandbox{sandboxed: make(map[AuditToken]bool), fail: make(map[AuditToken]bool)},
		log:   &logBuf{},
		done:  make(chan struct{}),
	}
	r.ck.ln = r.ln
	if setup != nil {
		r.ck.set(setup)
	}
	h, err := NewHandler(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	s, err := NewSupervisor(r.config())
	if err != nil {
		t.Fatal(err)
	}
	r.s = s
	ctx, cancel := context.WithCancel(t.Context())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		s.Run(ctx)
	}()
	synctest.Wait()
	t.Cleanup(r.stop)
	return r
}

func (r *supRig) config() SupervisorConfig {
	ck := r.ck
	return SupervisorConfig{
		Listen: func(context.Context) (net.Listener, error) {
			ck.mu.Lock()
			defer ck.mu.Unlock()
			ck.listens++
			return ck.ln, nil
		},
		EUID:       func() int { ck.mu.Lock(); defer ck.mu.Unlock(); return ck.euid },
		ServiceUID: serviceUID,
		IgnoresOwnership: func() (bool, error) {
			ck.mu.Lock()
			defer ck.mu.Unlock()
			return ck.ignores, ck.mountErr
		},
		CheckInstall: func(context.Context) error { ck.mu.Lock(); defer ck.mu.Unlock(); return ck.install },
		ServerCount: func(context.Context) (int, error) {
			ck.mu.Lock()
			defer ck.mu.Unlock()
			ck.counted++
			return ck.servers, ck.serversErr
		},
		MaintenanceMarked: func() (bool, error) {
			ck.mu.Lock()
			defer ck.mu.Unlock()
			return ck.marked, ck.markerErr
		},
		Creds:   r.creds,
		Sandbox: r.box,
		Audit:   &fakeAuditor{},
		Handler: r.h,
		Clock:   bubbleClock{},
		Log:     slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

// stop ends Run and waits for it.
func (r *supRig) stop() {
	r.cancel()
	<-r.done
}

// dial connects an eligible peer through the listener.
func (r *supRig) dial(t *testing.T, uid uint32) peer {
	t.Helper()
	client, server := net.Pipe()
	sc := &countingConn{Conn: server}
	r.creds.mu.Lock()
	r.creds.peers[sc] = credOf(uid, 0)
	r.creds.mu.Unlock()
	r.ln.conns <- sc
	synctest.Wait()
	return peer{client: client, server: sc}
}

// wantState checks the supervisor's phase and reason, and that a retry is
// due in retry from now (when retry is not 0).
func (r *supRig) wantState(t *testing.T, phase Phase, reason OffReason, retry time.Duration) State {
	t.Helper()
	st := r.s.State()
	if st.Phase != phase || st.Reason != reason {
		t.Fatalf("state = %+v, want %s (%q)", st, phase, reason)
	}
	if retry != 0 {
		if got := st.Until.Sub(time.Now()); got != retry {
			t.Fatalf("retry due in %v, want %v", got, retry)
		}
	}
	return st
}

// cut checks that p's connection was closed by the server.
func (p peer) cut(t *testing.T) {
	t.Helper()
	if _, err := ReadFrame(p.client); err == nil {
		t.Fatal("the connection is still open")
	}
}

func TestSupervisorRequiresDependencies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, nil)
		for _, tc := range []struct {
			name   string
			mutate func(c *SupervisorConfig)
		}{
			{"listener source", func(c *SupervisorConfig) { c.Listen = nil }},
			{"euid source", func(c *SupervisorConfig) { c.EUID = nil }},
			{"service uid 0", func(c *SupervisorConfig) { c.ServiceUID = 0 }},
			{"mount-flag check", func(c *SupervisorConfig) { c.IgnoresOwnership = nil }},
			{"install check", func(c *SupervisorConfig) { c.CheckInstall = nil }},
			{"server count", func(c *SupervisorConfig) { c.ServerCount = nil }},
			{"maintenance marker check", func(c *SupervisorConfig) { c.MaintenanceMarked = nil }},
			{"peer-credential source", func(c *SupervisorConfig) { c.Creds = nil }},
			{"peer-sandbox source", func(c *SupervisorConfig) { c.Sandbox = nil }},
			{"refusal auditor", func(c *SupervisorConfig) { c.Audit = nil }},
			{"handler", func(c *SupervisorConfig) { c.Handler = nil }},
			{"clock", func(c *SupervisorConfig) { c.Clock = nil }},
			{"logger", func(c *SupervisorConfig) { c.Log = nil }},
		} {
			cfg := r.config()
			tc.mutate(&cfg)
			if s, err := NewSupervisor(cfg); err == nil || s != nil {
				t.Errorf("%s: NewSupervisor = %v, %v; want a refusal", tc.name, s, err)
			}
		}
	})
}

func TestListenerRefusesUnlessServiceUID(t *testing.T) {
	for _, euid := range []int{0, 501, serviceUID + 1, -1} {
		synctest.Test(t, func(t *testing.T) {
			r := newSupRig(t, func(c *startChecks) { c.euid = euid })
			r.wantState(t, PhaseOff, OffNotInstalledServer, MinBackoff)
			if n := r.log.count("level=WARN", "user scope needs the installed server"); n != 1 {
				t.Errorf("euid %d: %d Warn lines saying user scope needs the installed server, want 1", euid, n)
			}
			advance(MinBackoff)
			r.wantState(t, PhaseOff, OffNotInstalledServer, 2*MinBackoff)
			if got := r.ck.get(); got.listens != 0 || got.counted != 0 {
				t.Errorf("euid %d: the listener source ran %d times and the server count %d; want neither", euid, got.listens, got.counted)
			}
			r.ck.set(func(c *startChecks) { c.euid = serviceUID })
			advance(2 * MinBackoff)
			r.wantState(t, PhaseServing, "", 0)
			r.dial(t, 501).admitted(t)
		})
	}
}

func TestStartRefusesIgnoreOwnershipMount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(c *startChecks)
		reason OffReason
	}{
		{"MNT_IGNORE_OWNERSHIP set", func(c *startChecks) { c.ignores = true }, OffIgnoresOwnership},
		{"fstatfs fails", func(c *startChecks) { c.mountErr = errors.New("fake: fstatfs failed") }, OffMountUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := newSupRig(t, tc.setup)
				r.wantState(t, PhaseOff, tc.reason, MinBackoff)
				if r.ck.get().listens != 0 {
					t.Fatal("the listener source ran on a data root that ignores ownership")
				}
				r.ck.set(func(c *startChecks) { c.ignores, c.mountErr = false, nil })
				advance(MinBackoff)
				r.wantState(t, PhaseServing, "", 0)
			})
		})
	}
	t.Run("read on the data-root descriptor", func(t *testing.T) {
		dir, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = dir.Close() }()
		want := dir.Fd()
		var got uintptr
		setSeam(t, &ignoresOwnershipSeam, func(fd uintptr) (bool, error) { got = fd; return true, nil })
		if ignores, err := DataRootIgnoresOwnership(dir); !ignores || err != nil || got != want {
			t.Fatalf("DataRootIgnoresOwnership = %v, %v on fd %d; want true on the data root's fd %d", ignores, err, got, want)
		}
		setSeam(t, &ignoresOwnershipSeam, func(uintptr) (bool, error) { return false, errors.New("fake: EIO") })
		if _, err := DataRootIgnoresOwnership(dir); err == nil {
			t.Fatal("a failed fstatfs was not an error")
		}
	})
}

func TestListenerWarnsOnEveryRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, func(c *startChecks) { c.install = errors.New("fake: keystore-audit.log is not flagged") })
		warns := func() int { return r.log.count("level=WARN", "sudo k3sm install", "not flagged") }
		st := r.wantState(t, PhaseOff, OffInstall, MinBackoff)
		if !strings.Contains(st.Detail, "not flagged") {
			t.Errorf("state detail %q does not carry the check's error", st.Detail)
		}
		if n := warns(); n != 1 {
			t.Fatalf("at start: %d install Warns, want 1", n)
		}
		wait := MinBackoff
		for retry := 1; retry <= 4; retry++ {
			advance(wait)
			wait *= 2
			r.wantState(t, PhaseOff, OffInstall, wait)
			if n := warns(); n != 1+retry {
				t.Fatalf("after retry %d: %d install Warns, want %d", retry, n, 1+retry)
			}
		}
		if r.ck.get().listens != 0 {
			t.Fatal("the listener source ran while the install check failed")
		}
		r.ck.set(func(c *startChecks) { c.install = nil })
		advance(wait)
		r.wantState(t, PhaseServing, "", 0)
		advance(MaxBackoff)
		if n := warns(); n != 5 {
			t.Fatalf("after the install was fixed: %d install Warns, want 5", n)
		}
	})
}

func TestUserScopeRefusedWithTwoServers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, func(c *startChecks) { c.servers = 2 })
		st := r.wantState(t, PhaseOff, OffServers, MinBackoff)
		if st.Reason != "more than one server registered" {
			t.Errorf("reason %q is not the one doctor shows", st.Reason)
		}
		if n := r.log.count("level=WARN", "more than one server registered"); n != 1 {
			t.Errorf("%d Warn lines naming two servers, want 1", n)
		}
		if r.ck.get().listens != 0 {
			t.Fatal("the listener source ran with two servers registered")
		}
		for _, tc := range []struct {
			name   string
			set    func(c *startChecks)
			reason OffReason
		}{
			{"still two", func(c *startChecks) {}, OffServers},
			{"count fails", func(c *startChecks) { c.serversErr = errors.New("fake: apiserver unreachable") }, OffServersUnknown},
			{"none", func(c *startChecks) { c.serversErr, c.servers = nil, 0 }, OffServersUnknown},
		} {
			r.ck.set(tc.set)
			advance(r.s.State().Until.Sub(time.Now()))
			r.wantState(t, PhaseOff, tc.reason, 0)
			if r.ck.get().listens != 0 {
				t.Fatalf("%s: the listener source ran", tc.name)
			}
		}
		r.ck.set(func(c *startChecks) { c.servers = 1 })
		advance(r.s.State().Until.Sub(time.Now()))
		r.wantState(t, PhaseServing, "", 0)
	})
}

func TestMaintenanceMarkerStopsListener(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, func(c *startChecks) { c.marked = true })
		r.wantState(t, PhaseOff, OffMaintenance, MaintenancePoll)
		advance(3 * MaintenancePoll)
		r.wantState(t, PhaseOff, OffMaintenance, MaintenancePoll)
		if n := r.log.count("maintenance marker"); n != 1 {
			t.Errorf("%d lines for one standing marker, want 1", n)
		}
		if r.ck.get().listens != 0 {
			t.Fatal("the listener source ran under the marker")
		}

		r.ck.set(func(c *startChecks) { c.marked = false })
		advance(MaintenancePoll)
		r.wantState(t, PhaseServing, "", 0)
		p := r.dial(t, 501)
		p.admitted(t)

		r.ck.set(func(c *startChecks) { c.marked = true })
		advance(MaintenancePoll)
		r.wantState(t, PhaseOff, OffMaintenance, MaintenancePoll)
		p.cut(t)
		if r.ln.accepting() {
			t.Fatal("the listener accepted under the marker")
		}
		if n := r.ln.closeCount(); n != 0 {
			t.Fatalf("the listening socket was closed %d times; the marker must leave it bound", n)
		}

		r.ck.set(func(c *startChecks) { c.marked = false })
		advance(MaintenancePoll)
		r.wantState(t, PhaseServing, "", 0)
		r.dial(t, 502).admitted(t)
		if got := r.ck.get().listens; got != 2 {
			t.Fatalf("the listener source ran %d times, want 2", got)
		}

		r.ck.set(func(c *startChecks) { c.markerErr = errors.New("fake: lstat failed") })
		advance(MaintenancePoll)
		r.wantState(t, PhaseOff, OffMaintenanceUnknown, MinBackoff)
	})
}

func TestListenerRecoversPanic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, nil)
		r.wantState(t, PhaseServing, "", 0)
		open := r.dial(t, 501)
		open.admitted(t)

		// A panic in the accept loop: recovered, logged, connections cut,
		// and the listener restarted after MinBackoff on the same socket.
		r.creds.boom.Store(true)
		boom, _ := net.Pipe()
		r.ln.conns <- boom
		synctest.Wait()
		r.wantState(t, PhaseBackingOff, OffListenerFailed, MinBackoff)
		if n := r.log.count("level=ERROR", "listener panicked", "peer-credential source panicked"); n != 1 {
			t.Fatalf("%d lines logging the panic, want 1", n)
		}
		open.cut(t)
		r.creds.boom.Store(false)
		advance(MinBackoff)
		r.wantState(t, PhaseServing, "", 0)
		r.dial(t, 501).admitted(t)
		if got, closes := r.ck.get().listens, r.ln.closeCount(); got != 2 || closes != 0 {
			t.Fatalf("source ran %d times, socket closed %d times; want 2 and 0 (the same socket reused)", got, closes)
		}

		// A panic in a connection's goroutine ends that connection only.
		r.h.ops = map[string]opFunc{"boom": func(context.Context, []byte) error { panic("fake: op panicked") }}
		p := r.dial(t, 502)
		p.admitted(t)
		if err := WriteFrame(p.client, Frame{Type: TypeRequest, Header: []byte(`{"op":"boom"}`)}); err != nil {
			t.Fatal(err)
		}
		p.cut(t)
		synctest.Wait()
		r.wantState(t, PhaseServing, "", 0)
		if n := r.log.count("level=ERROR", "recovered a panic", "op panicked"); n != 1 {
			t.Fatalf("%d lines logging the connection panic, want 1", n)
		}
		r.dial(t, 503).admitted(t)

		// Back-to-back failures double the wait; a run past HealthyPeriod
		// starts it again from MinBackoff.
		r.creds.boom.Store(true)
		for _, wait := range []time.Duration{2 * MinBackoff, 4 * MinBackoff} {
			r.ln.conns <- boom
			synctest.Wait()
			r.wantState(t, PhaseBackingOff, OffListenerFailed, wait)
			advance(wait)
			r.wantState(t, PhaseServing, "", 0)
		}
		advance(HealthyPeriod)
		r.ln.conns <- boom
		synctest.Wait()
		r.wantState(t, PhaseBackingOff, OffListenerFailed, MinBackoff)
	})
}

func TestListenerSourceFailureBacksOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, func(c *startChecks) { c.ln = nil })
		st := r.wantState(t, PhaseBackingOff, OffListenerUnavailable, MinBackoff)
		if !strings.Contains(st.Detail, "no socket") {
			t.Fatalf("detail %q", st.Detail)
		}
		r.ck.set(func(c *startChecks) { c.ln = r.ln })
		advance(MinBackoff)
		r.wantState(t, PhaseServing, "", 0)
	})
}

func TestBackoffDoublesToFiveMinutes(t *testing.T) {
	d, waits := MinBackoff, []time.Duration{MinBackoff}
	for d < MaxBackoff {
		d = nextBackoff(d)
		waits = append(waits, d)
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 64, 128, 256, 300}
	if len(waits) != len(want) {
		t.Fatalf("waits %v, want %v seconds", waits, want)
	}
	for i := range want {
		if waits[i] != want[i]*time.Second {
			t.Fatalf("waits %v, want %v seconds", waits, want)
		}
	}
	if nextBackoff(MaxBackoff) != MaxBackoff {
		t.Fatal("the backoff grew past MaxBackoff")
	}
}

func TestSupervisorClosesReplacedAndLastSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newSupRig(t, nil)
		first, second := r.ln, newPausableListener()
		r.ck.set(func(c *startChecks) { c.ln, c.marked = second, true })
		advance(MaintenancePoll)
		r.ck.set(func(c *startChecks) { c.marked = false })
		advance(MaintenancePoll)
		r.wantState(t, PhaseServing, "", 0)
		if first.closeCount() != 1 {
			t.Fatal("the socket the source replaced was not closed")
		}
		r.stop()
		if second.closeCount() != 1 {
			t.Fatal("the last socket was not closed when Run returned")
		}
		if st := r.s.State(); st.Phase != PhaseStopped {
			t.Fatalf("after Run, state %+v", st)
		}
	})
}
