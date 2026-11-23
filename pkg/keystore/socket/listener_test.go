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
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// serviceUID is the service uid the tests run the listener as.
const serviceUID = 260

// fakeListener hands out the conns a test queues; Close ends Accept.
type fakeListener struct {
	conns  chan net.Conn
	done   chan struct{}
	closed sync.Once
}

func newFakeListener() *fakeListener {
	return &fakeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}

func (f *fakeListener) Close() error {
	f.closed.Do(func() { close(f.done) })
	return nil
}

func (f *fakeListener) Addr() net.Addr { return &net.UnixAddr{Name: "keys.sock", Net: "unix"} }

// countingConn counts the reads the server starts on its end.
type countingConn struct {
	net.Conn
	reads atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(b)
}

// fakeCreds answers each server conn's peer from a table; a conn missing
// from it is unreadable.
type fakeCreds struct {
	mu    sync.Mutex
	peers map[net.Conn]PeerCred
	fail  map[net.Conn]bool // answer the peer's PeerCred with an error
}

func (f *fakeCreds) PeerCred(c net.Conn) (PeerCred, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pc, ok := f.peers[c]
	if !ok {
		return PeerCred{}, errors.New("fake: no peer credentials")
	}
	if f.fail[c] {
		return pc, errors.New("fake: a read after the uid failed")
	}
	return pc, nil
}

// credOf is the PeerCred the kernel reports for a peer running as uid with
// pid: its token names both.
func credOf(uid uint32, pid int32) PeerCred {
	return PeerCred{UID: uid, UIDRead: true, PID: pid, Token: AuditToken{1: uid, 5: uint32(pid)}, TokenEUID: uid, TokenPID: pid}
}

// fakeSandbox answers from a table of sandboxed tokens and records the
// tokens it was asked about; a token in fail is an error.
type fakeSandbox struct {
	mu        sync.Mutex
	sandboxed map[AuditToken]bool
	fail      map[AuditToken]bool
	asked     []AuditToken
}

func (f *fakeSandbox) Sandboxed(tok AuditToken) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, tok)
	if f.fail[tok] {
		return false, errors.New("fake: sandbox check failed")
	}
	return f.sandboxed[tok], nil
}

// refusal is one Refused call; drop one Dropped call.
type refusal struct {
	uid    uint32
	reason string
}

type drop struct {
	uid     uint32
	dropped uint64
}

// fakeAuditor records what reaches it.
type fakeAuditor struct {
	mu      sync.Mutex
	refused []refusal
	dropped []drop
}

func (f *fakeAuditor) Refused(uid uint32, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refused = append(f.refused, refusal{uid, reason})
}

func (f *fakeAuditor) Dropped(uid uint32, n uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, drop{uid, n})
}

func (f *fakeAuditor) lines() ([]refusal, []drop) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.refused), slices.Clone(f.dropped)
}

// bubbleClock is the synctest bubble's clock.
type bubbleClock struct{}

func (bubbleClock) Now() time.Time { return time.Now() }

func (bubbleClock) After(d time.Duration) (<-chan time.Time, func() bool) {
	tm := time.NewTimer(d)
	return tm.C, tm.Stop
}

// advance lets d of the bubble's time pass and everything settle.
func advance(d time.Duration) {
	tm := time.NewTimer(d)
	<-tm.C
	synctest.Wait()
}

// rig is a Listener serving a fake listener, inside a synctest bubble.
type rig struct {
	ln      *fakeListener
	creds   *fakeCreds
	sandbox *fakeSandbox
	audit   *fakeAuditor
	cancel  context.CancelFunc
	done    chan error
	pid     int32
}

// peer is one dialled connection: the client end and the server end the
// listener accepted.
type peer struct {
	client net.Conn
	server *countingConn
}

func startRig(t *testing.T) *rig { t.Helper(); return startRigAs(t, serviceUID) }

// startRigAs starts a rig whose listener runs as service.
func startRigAs(t *testing.T, service uint32) *rig { t.Helper(); return startRigWith(t, service, nil) }

// startRigWith starts a rig whose listener runs as service and, when also
// is not nil, gives every refusal and summary to also as well as to the
// rig's recorder.
func startRigWith(t *testing.T, service uint32, also RefusalAuditor) *rig {
	t.Helper()
	r := &rig{
		ln:      newFakeListener(),
		creds:   &fakeCreds{peers: make(map[net.Conn]PeerCred), fail: make(map[net.Conn]bool)},
		sandbox: &fakeSandbox{sandboxed: make(map[AuditToken]bool), fail: make(map[AuditToken]bool)},
		audit:   &fakeAuditor{},
		done:    make(chan error, 1),
	}
	var audit RefusalAuditor = r.audit
	if also != nil {
		audit = teeAuditor{r.audit, also}
	}
	return r.serve(t, service, audit)
}

// startRigAudit starts a rig whose listener runs as service and gives
// every refusal and summary to audit alone; the rig's recorder stays empty.
func startRigAudit(t *testing.T, service uint32, audit RefusalAuditor) *rig {
	t.Helper()
	r := &rig{
		ln:      newFakeListener(),
		creds:   &fakeCreds{peers: make(map[net.Conn]PeerCred), fail: make(map[net.Conn]bool)},
		sandbox: &fakeSandbox{sandboxed: make(map[AuditToken]bool), fail: make(map[AuditToken]bool)},
		audit:   &fakeAuditor{},
		done:    make(chan error, 1),
	}
	return r.serve(t, service, audit)
}

// serve starts r's Listener as service over audit.
func (r *rig) serve(t *testing.T, service uint32, audit RefusalAuditor) *rig {
	t.Helper()
	h, err := NewHandler(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewListener(r.ln, r.creds, r.sandbox, service, bubbleClock{}, audit, h)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r.cancel = cancel
	go func() { r.done <- l.Serve(ctx) }()
	return r
}

// stop ends Serve and returns its result.
func (r *rig) stop() error {
	r.cancel()
	return <-r.done
}

// dialAs connects as uid; sandboxed marks the peer's token, and unreadable
// leaves its credentials out of the table.
func (r *rig) dialAs(uid uint32, sandboxed, sandboxFails, unreadable bool) peer {
	r.pid++
	pc := credOf(uid, r.pid)
	if unreadable {
		pc = PeerCred{}
	}
	r.sandbox.mu.Lock()
	r.sandbox.sandboxed[pc.Token] = sandboxed
	r.sandbox.fail[pc.Token] = sandboxFails
	r.sandbox.mu.Unlock()
	return r.dialCred(pc, false)
}

// dialCred connects a peer the credential source reports as pc, with an
// error when credErr is set; a zero pc is left out of the table.
func (r *rig) dialCred(pc PeerCred, credErr bool) peer {
	client, server := net.Pipe()
	sc := &countingConn{Conn: server}
	r.creds.mu.Lock()
	if pc != (PeerCred{}) {
		r.creds.peers[sc] = pc
	}
	r.creds.fail[sc] = credErr
	r.creds.mu.Unlock()
	r.ln.conns <- sc
	synctest.Wait()
	return peer{client: client, server: sc}
}

func (r *rig) dial(uid uint32) peer { return r.dialAs(uid, false, false, false) }

// admitted checks that the listener serves p: a HELLO gets its reply.
func (p peer) admitted(t *testing.T) {
	t.Helper()
	if err := WriteFrame(p.client, Frame{Type: TypeHello, Header: []byte(helloV1)}); err != nil {
		t.Fatalf("HELLO: %v", err)
	}
	f, err := ReadFrame(p.client)
	if err != nil || f.Type != TypeHello {
		t.Fatalf("HELLO reply: type %#02x, %v", byte(f.Type), err)
	}
}

// refused checks that the listener closed p without reading or writing a
// byte.
func (p peer) refused(t *testing.T) {
	t.Helper()
	if n := p.server.reads.Load(); n != 0 {
		t.Fatalf("the server read %d times from a refused peer", n)
	}
	var b [1]byte
	if n, err := p.client.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("a refused peer read %d bytes, %v; want nothing and EOF", n, err)
	}
}

func (p peer) close() { _ = p.client.Close() }

func TestListenerRequiresPeerCredSource(t *testing.T) {
	h, err := NewHandler(time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ln := newFakeListener()
	creds := &fakeCreds{}
	sandbox := &fakeSandbox{}
	audit := &fakeAuditor{}
	for _, tc := range []struct {
		name    string
		ln      net.Listener
		creds   PeerCredSource
		sandbox PeerSandboxSource
		clock   Clock
		audit   RefusalAuditor
		h       *Handler
	}{
		{"nil peer-credential source", ln, nil, sandbox, bubbleClock{}, audit, h},
		{"nil peer-sandbox source", ln, creds, nil, bubbleClock{}, audit, h},
		{"nil listening socket", nil, creds, sandbox, bubbleClock{}, audit, h},
		{"nil clock", ln, creds, sandbox, nil, audit, h},
		{"nil refusal auditor", ln, creds, sandbox, bubbleClock{}, nil, h},
		{"nil handler", ln, creds, sandbox, bubbleClock{}, audit, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if l, err := NewListener(tc.ln, tc.creds, tc.sandbox, serviceUID, tc.clock, tc.audit, tc.h); err == nil || l != nil {
				t.Fatalf("NewListener = %v, %v; want a refusal", l, err)
			}
		})
	}
	if _, err := NewListener(ln, creds, sandbox, serviceUID, bubbleClock{}, audit, h); err != nil {
		t.Fatalf("NewListener with every parameter = %v", err)
	}
}

// checkRefusals runs each case against one rig: a refused peer is closed
// with nothing read or written and leaves one refused line, an eligible one
// is served.
func checkRefusals(t *testing.T, cases []admissionCase) {
	t.Helper()
	checkRefusalsLogged(t, cases, false)
}

// checkRefusalsLogged is checkRefusals; with logged set the refusals also
// go through a StoreAuditor to a real audit log, which must then hold
// exactly the refused lines, each charged to the pre-frame budget.
func checkRefusalsLogged(t *testing.T, cases []admissionCase, logged bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		var store *storeRig
		var also RefusalAuditor
		if logged {
			store = newStoreRig(t)
			also = newStoreAuditor(t, store.logs)
		}
		r := startRigWith(t, serviceUID, also)
		var want []refusal
		for _, tc := range cases {
			p := r.dialAs(tc.uid, tc.sandboxed, tc.sandboxFails, tc.unreadable)
			if tc.reason == "" {
				p.admitted(t)
			} else {
				p.refused(t)
				want = append(want, refusal{tc.lineUID(), tc.reason})
			}
			p.close()
			synctest.Wait()
		}
		if err := r.stop(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
		got, dropped := r.audit.lines()
		if !slices.Equal(got, want) {
			t.Errorf("refused lines = %v, want %v", got, want)
		}
		if len(dropped) != 0 {
			t.Errorf("dropped summaries %v, want none", dropped)
		}
		if store != nil {
			checkLogged(t, store, want, nil)
		}
	})
}

// checkLogged checks that the rig's audit log holds exactly the refusals
// and summaries given, as pre-frame lines, and that the budget has
// charged every one of them: a refusal past the last counts what it
// holds, then lands and is charged too.
func checkLogged(t *testing.T, store *storeRig, refusals []refusal, drops []drop) {
	t.Helper()
	lines, _ := readAudit(t, store.auditPath())
	rs, ds := refusedOf(t, lines)
	if !slices.Equal(rs, refusals) || !slices.Equal(ds, drops) {
		t.Fatalf("audit log refusals %v, summaries %v; want %v and %v", rs, ds, refusals, drops)
	}
	if err := store.logs.Refused(t.Context(), 0, ReasonRoot); err != nil {
		t.Fatal(err)
	}
	if _, charged := readAudit(t, store.auditPath()); store.logs.PreFrameUsed() != charged {
		got := store.logs.PreFrameUsed()
		t.Fatalf("pre-frame budget used %d, want the log's %d", got, charged)
	}
}

type admissionCase struct {
	uid                                 uint32
	sandboxed, sandboxFails, unreadable bool
	reason                              string // "" admitted
}

func (tc admissionCase) lineUID() uint32 {
	if tc.unreadable {
		return NoUID
	}
	return tc.uid
}

func TestPeerEligibility(t *testing.T) {
	checkRefusals(t, []admissionCase{
		{uid: 0, reason: ReasonRoot},
		{uid: serviceUID, reason: ReasonServiceUID},
		{uid: 1, reason: ReasonSystemUID},
		{uid: 499, reason: ReasonSystemUID},
		{uid: 500, reason: ReasonSystemUID},
		{uid: 501},
		{uid: 502},
		{uid: 1000, unreadable: true, reason: ReasonCredUnreadable},
	})
	t.Run("service uid in the login range", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := startRigAs(t, 600)
			r.dial(600).refused(t)
			r.dial(601).admitted(t)
			if err := r.stop(); err != nil {
				t.Fatalf("Serve = %v", err)
			}
			if got, _ := r.audit.lines(); !slices.Equal(got, []refusal{{600, ReasonServiceUID}}) {
				t.Fatalf("refused lines = %v", got)
			}
		})
	})
}

// TestPeerAttribution checks whose uid a refusal names when a read after
// LOCAL_PEERCRED fails, and that the audit token must name the uid and pid
// read beside it.
func TestPeerAttribution(t *testing.T) {
	cases := []struct {
		name    string
		pc      PeerCred
		credErr bool
		uid     uint32
		reason  string // "" admitted
	}{
		{"root, later read failed", credOf(0, 7), true, 0, ReasonRoot},
		{"service uid, later read failed", credOf(serviceUID, 7), true, serviceUID, ReasonServiceUID},
		{"system uid, later read failed", PeerCred{UID: 88, UIDRead: true}, true, 88, ReasonSystemUID},
		{"high uid, later read failed", PeerCred{UID: 1 << 31, UIDRead: true}, true, 1 << 31, ReasonHighUID},
		{"login uid, later read failed", PeerCred{UID: 501, UIDRead: true}, true, 501, ReasonCredUnreadable},
		{"no uid read", PeerCred{PID: 7}, true, NoUID, ReasonCredUnreadable},
		{"success without a uid read", PeerCred{UID: 501, PID: 7, TokenEUID: 501, TokenPID: 7}, false, NoUID, ReasonCredUnreadable},
		{"token names another euid", func() PeerCred { pc := credOf(501, 7); pc.TokenEUID = 502; return pc }(), false, 501, ReasonTokenMismatch},
		{"token names root", func() PeerCred { pc := credOf(501, 7); pc.TokenEUID = 0; return pc }(), false, 501, ReasonTokenMismatch},
		{"token names another pid", func() PeerCred { pc := credOf(501, 7); pc.TokenPID = 8; return pc }(), false, 501, ReasonTokenMismatch},
		{"token names both", credOf(501, 7), false, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				r := startRig(t)
				p := r.dialCred(tc.pc, tc.credErr)
				var want []refusal
				if tc.reason == "" {
					p.admitted(t)
				} else {
					p.refused(t)
					want = []refusal{{tc.uid, tc.reason}}
				}
				p.close()
				if err := r.stop(); err != nil {
					t.Fatalf("Serve = %v", err)
				}
				if got, _ := r.audit.lines(); !slices.Equal(got, want) {
					t.Fatalf("refused lines = %v, want %v", got, want)
				}
				r.sandbox.mu.Lock()
				asked := len(r.sandbox.asked)
				r.sandbox.mu.Unlock()
				if tc.reason != "" && asked != 0 {
					t.Fatalf("the sandbox source was asked about a refused peer")
				}
			})
		})
	}
}

func TestPeerUIDRangeRefusesNobodyAndHighUIDs(t *testing.T) {
	checkRefusals(t, []admissionCase{
		{uid: 500, reason: ReasonSystemUID},
		{uid: MinPeerUID},
		{uid: MaxPeerUID},
		{uid: 2147483648, reason: ReasonHighUID},
		{uid: 3000000000, reason: ReasonHighUID},
		{uid: 4294967294, reason: ReasonHighUID}, // nobody
		{uid: 4294967295, reason: ReasonHighUID},
	})
}

func TestListenerRefusesSandboxedPeer(t *testing.T) {
	checkRefusals(t, []admissionCase{
		{uid: 501, sandboxed: true, reason: ReasonSandboxed},
		{uid: 502, sandboxFails: true, reason: ReasonSandboxUnknown},
		{uid: 503},
	})
	t.Run("checked on the peer's token, after the uid", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			r := startRig(t)
			r.dial(0).refused(t)
			p := r.dialAs(501, true, false, false)
			p.refused(t)
			if err := r.stop(); err != nil {
				t.Fatalf("Serve = %v", err)
			}
			want := []AuditToken{{1: 501, 5: 2}}
			if !slices.Equal(r.sandbox.asked, want) {
				t.Fatalf("sandbox source asked about %v, want %v", r.sandbox.asked, want)
			}
		})
	})
	t.Run("nil source refused", func(t *testing.T) {
		h, err := NewHandler(time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewListener(newFakeListener(), &fakeCreds{}, nil, serviceUID, bubbleClock{}, &fakeAuditor{}, h); err == nil {
			t.Fatal("NewListener took a nil peer-sandbox source")
		}
	})
}

func TestPreFrameRefusalsAudited(t *testing.T) {
	checkRefusalsLogged(t, []admissionCase{
		{uid: 0, reason: ReasonRoot},
		{uid: serviceUID, reason: ReasonServiceUID},
		{uid: 77, reason: ReasonSystemUID},
		{uid: 4294967294, reason: ReasonHighUID},
		{uid: 501, sandboxed: true, reason: ReasonSandboxed},
		{uid: 502, sandboxFails: true, reason: ReasonSandboxUnknown},
		{uid: 503, unreadable: true, reason: ReasonCredUnreadable},
		{uid: 504},
	}, true)
}

func TestPreFrameRefusalLinesRateLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newStoreRig(t)
		r := startRigWith(t, serviceUID, newStoreAuditor(t, store.logs))
		refuse := func(uid uint32, n int) {
			for range n {
				r.dial(uid).refused(t)
			}
		}
		count := func(uid uint32) (n int) {
			got, _ := r.audit.lines()
			for _, l := range got {
				if l.uid == uid {
					n++
				}
			}
			return n
		}
		// 0 s: uid 0 past its ten, uid 77 within, each counted apart.
		refuse(0, 15)
		refuse(77, 3)
		if count(0) != RefusalLinesPerMinute || count(77) != 3 {
			t.Fatalf("lines: uid 0 %d, uid 77 %d; want %d and 3", count(0), count(77), RefusalLinesPerMinute)
		}
		// 30 s: the minute is not over, so uid 0 is still dropped.
		advance(30 * time.Second)
		refuse(0, 2)
		if count(0) != RefusalLinesPerMinute {
			t.Fatalf("uid 0 lines within the minute = %d", count(0))
		}
		if _, d := r.audit.lines(); len(d) != 0 {
			t.Fatalf("summary before the minute: %v", d)
		}
		// 60 s: one summary, for the uid that dropped.
		advance(30 * time.Second)
		if _, d := r.audit.lines(); !slices.Equal(d, []drop{{0, 7}}) {
			t.Fatalf("summaries at one minute = %v, want uid 0 dropped 7", d)
		}
		// 61 s: the window slid past the first ten.
		advance(time.Second)
		refuse(0, 11)
		if count(0) != 2*RefusalLinesPerMinute {
			t.Fatalf("uid 0 lines after the window slid = %d, want %d", count(0), 2*RefusalLinesPerMinute)
		}
		// 120 s: the next summary, and nothing for a uid that dropped none.
		advance(59 * time.Second)
		if _, d := r.audit.lines(); !slices.Equal(d, []drop{{0, 7}, {0, 1}}) {
			t.Fatalf("summaries at two minutes = %v", d)
		}
		// The ten from 61 s fill the window until 121 s, and a drop
		// pending at stop is summarized as Serve returns.
		refuse(0, 2)
		if count(0) != 2*RefusalLinesPerMinute {
			t.Fatalf("uid 0 lines at 120 s = %d", count(0))
		}
		if err := r.stop(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
		if _, d := r.audit.lines(); !slices.Equal(d, []drop{{0, 7}, {0, 1}, {0, 2}}) {
			t.Fatalf("summaries after stop = %v", d)
		}
		// The real audit log holds what passed the limit, and the
		// summaries, each charged to the pre-frame budget.
		got, d := r.audit.lines()
		checkLogged(t, store, got, d)
	})
	t.Run("past the budget", func(t *testing.T) {
		// Pre-frame lines another writer appended have spent the budget:
		// a refusal that passes the limit is still refused at accept,
		// writes nothing and is counted, and the count reaches the log
		// with the first line written after root rotates.
		synctest.Test(t, func(t *testing.T) {
			store := newStoreRig(t)
			store.writeLog(t, store.auditPath(), fullBudget())
			r := startRigWith(t, serviceUID, newStoreAuditor(t, store.logs))
			before := size(t, store.auditPath())
			for range 3 {
				r.dial(0).refused(t)
			}
			advance(time.Minute) // no summary: nothing was rate-dropped
			if n := size(t, store.auditPath()); n != before {
				t.Fatalf("lines past the budget were written: %d -> %d bytes", before, n)
			}
			if got := store.logs.PendingDropped(0); got != 3 {
				t.Fatalf("dropped count = %d, want 3", got)
			}
			store.swap(t, keystore.AuditDirName, keystore.AuditLogName, nil)
			for range RefusalLinesPerMinute + 2 {
				r.dial(0).refused(t)
			}
			advance(time.Minute)
			if err := r.stop(); err != nil {
				t.Fatalf("Serve = %v", err)
			}
			want := slices.Repeat([]refusal{{0, ReasonRoot}}, RefusalLinesPerMinute)
			checkLogged(t, store, want, []drop{{0, 3}, {0, 2}})
		})
	})
}

func TestConnectionCapsPerUID(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startRig(t)
		a, b := r.dial(501), r.dial(501)
		a.admitted(t)
		b.admitted(t)
		r.dial(501).refused(t) // a third from one uid
		var others []peer
		for uid := uint32(502); len(others) < MaxConns-2; uid++ {
			others = append(others, r.dial(uid))
		}
		for _, p := range others {
			if p.server.reads.Load() == 0 {
				t.Fatal("a connection under the caps was not served")
			}
		}
		r.dial(9000).refused(t) // the 65th
		// A closed connection frees its slots.
		a.close()
		synctest.Wait()
		c := r.dial(501)
		c.admitted(t)
		r.dial(9001).refused(t)
		// So does one the server closes: the others never sent HELLO.
		advance(RequestBound)
		r.dial(9002).admitted(t)
		r.dial(9003).admitted(t)
		r.dial(501).refused(t) // b and c still hold uid 501's two
		if got, _ := r.audit.lines(); len(got) != 0 {
			t.Errorf("over-cap closes wrote refused lines: %v", got)
		}
		if err := r.stop(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
		// Stopping cut every connection still open.
		for _, p := range []peer{b, c} {
			if _, err := ReadFrame(p.client); !errors.Is(err, io.EOF) {
				t.Errorf("after stop, a client read %v, want EOF", err)
			}
		}
	})
}

func TestServeReturnsWhenTheListenerCloses(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := startRig(t)
		p := r.dial(501)
		p.admitted(t)
		_ = r.ln.Close()
		if err := <-r.done; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve after the listener closed = %v, want net.ErrClosed", err)
		}
		if _, err := ReadFrame(p.client); !errors.Is(err, io.EOF) {
			t.Fatalf("after Serve returned, a client read %v, want EOF", err)
		}
		r.cancel()
	})
}
