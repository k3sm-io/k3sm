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

package svclb

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
)

// peerConn is one end of a net.Pipe whose RemoteAddr is a synthetic peer, so the
// accept path can be driven with any client address and no real socket.
type peerConn struct {
	net.Conn
	peer netip.AddrPort
}

func (c peerConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.peer) }

// acceptListener hands out the conns pushed into it; Close ends Accept.
type acceptListener struct {
	addr   netip.AddrPort
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *acceptListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *acceptListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *acceptListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

// acceptBinder binds acceptListeners and remembers them by port.
type acceptBinder struct {
	mu    sync.Mutex
	lns   map[uint16]*acceptListener
	opens int
}

func (b *acceptBinder) Listen(_ context.Context, _ string, addr netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lns == nil {
		b.lns = make(map[uint16]*acceptListener)
	}
	l := &acceptListener{addr: addr, conns: make(chan net.Conn), closed: make(chan struct{})}
	b.lns[addr.Port()] = l
	b.opens++
	return l, nil
}

func (b *acceptBinder) listener(port uint16) *acceptListener {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lns[port]
}

func (b *acceptBinder) openCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.opens
}

// recordingDialer records every backend dial and answers with a live pipe, so an
// allowed connection stays open (only a denied one is closed).
type recordingDialer struct {
	mu    sync.Mutex
	dials int
	peers []net.Conn
}

func (d *recordingDialer) dial(_ context.Context, _, _ string) (net.Conn, error) {
	a, b := net.Pipe()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials++
	d.peers = append(d.peers, b)
	return a, nil
}

func (d *recordingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

func (d *recordingDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, p := range d.peers {
		_ = p.Close()
	}
}

// connect pushes a connection from peer into l and reports whether it was
// SPLICED (a backend dial happened and the client end stays open) or DENIED
// (the client end reads EOF and no dial happened).
func connect(t *testing.T, l *acceptListener, d *recordingDialer, peer string) bool {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	before := d.count()
	select {
	case l.conns <- peerConn{Conn: server, peer: netip.AddrPortFrom(netip.MustParseAddr(peer), 40000)}:
	case <-time.After(2 * time.Second):
		t.Fatalf("peer %s: the accept loop never took the connection", peer)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.count() > before {
			return true
		}
		_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		var b [1]byte
		if _, err := client.Read(b[:]); errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			if d.count() != before {
				t.Fatalf("peer %s: closed AFTER a backend dial; the check must precede splice", peer)
			}
			return false
		}
	}
	t.Fatalf("peer %s: neither spliced nor closed", peer)
	return false
}

// TestLoadBalancerSourceRangesEnforced pins B131, the k3s shape of
// spec.loadBalancerSourceRanges: enforced on LoadBalancer traffic at accept,
// before any backend dial; spec field, then the legacy annotation, then
// allow-all; entries TrimSpace'd; all-or-nothing parsing; fail-closed on first
// provisioning; last-good on an edit; and live edits applied without reopening
// the listener.
func TestLoadBalancerSourceRangesEnforced(t *testing.T) {
	ctx := context.Background()

	withRanges := func(svc *corev1.Service, spec []string, annotation string) *corev1.Service {
		svc.Spec.LoadBalancerSourceRanges = spec
		if annotation != "" {
			svc.Annotations = map[string]string{SourceRangesAnnotation: annotation}
		}
		return svc
	}

	t.Run("resolution", func(t *testing.T) {
		tests := []struct {
			name       string
			spec       []string
			annotation string
			wantErr    bool
			allowed    []string
			denied     []string
		}{
			{name: "unset is allow-all", allowed: []string{"203.0.113.9", "127.0.0.1", "2001:db8::1"}},
			{name: "spec field", spec: []string{"10.0.0.0/8"}, allowed: []string{"10.1.2.3"}, denied: []string{"198.51.100.7", "127.0.0.1"}},
			{name: "annotation honoured when the spec field is empty", annotation: "198.51.100.0/24, 172.16.0.0/12", allowed: []string{"198.51.100.4", "172.16.0.1"}, denied: []string{"10.1.2.3"}},
			{name: "spec wins over the annotation", spec: []string{"10.0.0.0/8"}, annotation: "198.51.100.0/24", allowed: []string{"10.9.9.9"}, denied: []string{"198.51.100.4"}},
			{name: "space-padded CIDR accepted", spec: []string{"  10.0.0.0/8 ", "\t203.0.113.0/24"}, allowed: []string{"10.1.1.1", "203.0.113.7"}, denied: []string{"198.51.100.200"}},
			{name: "one malformed entry fails the whole set", spec: []string{"10.0.0.0/8", "not-a-cidr", "198.51.100.0/24"}, wantErr: true},
			{name: "malformed annotation fails the whole set", annotation: "10.0.0.0/8,10.0.0.0/33", wantErr: true},
			{name: "v4-in-v6 peer matches an IPv4 range", spec: []string{"10.0.0.0/8"}, allowed: []string{"::ffff:10.1.2.3"}, denied: []string{"::ffff:198.51.100.7"}},
			{name: "IPv6 range", spec: []string{"2001:db8::/32"}, allowed: []string{"2001:db8::1"}, denied: []string{"10.1.2.3"}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc := withRanges(lbService("default", "web", "10.43.0.5", 80), tt.spec, tt.annotation)
				r, err := SourceRanges(svc)
				if (err != nil) != tt.wantErr {
					t.Fatalf("SourceRanges err = %v, wantErr %v", err, tt.wantErr)
				}
				if tt.wantErr {
					if r != nil {
						t.Errorf("a failed set must be nil (all-or-nothing), got %v", r)
					}
					return
				}
				for _, a := range tt.allowed {
					if !r.Allows(netip.MustParseAddr(a)) {
						t.Errorf("%s must be allowed by %v", a, r)
					}
				}
				for _, a := range tt.denied {
					if r.Allows(netip.MustParseAddr(a)) {
						t.Errorf("%s must be denied by %v", a, r)
					}
				}
			})
		}
	})

	t.Run("an invalid entry is truncated in the error, which reaches an Event", func(t *testing.T) {
		long := strings.Repeat("y", 300)
		_, err := SourceRanges(withRanges(lbService("default", "web", "10.43.0.5", 80), []string{"10.0.0.0/8", long}, ""))
		if !errors.Is(err, ErrInvalidSourceRange) {
			t.Fatalf("err = %v, want ErrInvalidSourceRange", err)
		}
		if strings.Contains(err.Error(), strings.Repeat("y", 49)) {
			t.Errorf("the error echoes more than 48 runes of the entry: %q", err)
		}
		if !strings.Contains(err.Error(), strings.Repeat("y", 48)) {
			t.Errorf("the error must still name the entry's first 48 runes: %q", err)
		}
	})

	type rig struct {
		c      *Controller
		cs     *fake.Clientset
		binder *acceptBinder
		dialer *recordingDialer
		rec    *record.FakeRecorder
	}
	newRig := func(t *testing.T, svc *corev1.Service) *rig {
		t.Helper()
		cs := fake.NewClientset()
		if _, err := cs.CoreV1().Services(svc.Namespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed service: %v", err)
		}
		r := &rig{cs: cs, binder: &acceptBinder{}, dialer: &recordingDialer{}, rec: record.NewFakeRecorder(16)}
		c, err := New(Config{
			Client:        cs,
			BindAddr:      testBindAddr,
			AdvertiseAddr: testAdvertiseAddr,
			PodCIDR:       testPodCIDR,
			ReservedPorts: map[int32]bool{},
			Binder:        r.binder,
			Recorder:      r.rec,
			Logger:        slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		c.dial = r.dialer.dial
		r.c = c
		t.Cleanup(func() {
			c.closeAll()
			r.dialer.close()
		})
		return r
	}
	status := func(t *testing.T, cs *fake.Clientset) []corev1.LoadBalancerIngress {
		t.Helper()
		svc, err := cs.CoreV1().Services("default").Get(ctx, "web", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return svc.Status.LoadBalancer.Ingress
	}
	events := func(rec *record.FakeRecorder) []string {
		var out []string
		for {
			select {
			case e := <-rec.Events:
				out = append(out, e)
			default:
				return out
			}
		}
	}

	t.Run("accept path", func(t *testing.T) {
		tests := []struct {
			name       string
			spec       []string
			annotation string
			peer       string
			wantSplice bool
		}{
			{name: "allowed peer spliced", spec: []string{"10.0.0.0/8"}, peer: "10.1.2.3", wantSplice: true},
			{name: "denied peer closed with zero dials", spec: []string{"10.0.0.0/8"}, peer: "198.51.100.7", wantSplice: false},
			{name: "loopback is not exempt", spec: []string{"10.0.0.0/8"}, peer: "127.0.0.1", wantSplice: false},
			{name: "unset is allow-all", peer: "203.0.113.9", wantSplice: true},
			{name: "annotation enforced when the spec field is empty", annotation: "198.51.100.0/24", peer: "10.1.2.3", wantSplice: false},
			{name: "spec wins over the annotation", spec: []string{"10.0.0.0/8"}, annotation: "198.51.100.0/24", peer: "10.1.2.3", wantSplice: true},
			{name: "space-padded CIDR enforced", spec: []string{" 10.0.0.0/8 "}, peer: "10.1.2.3", wantSplice: true},
			{name: "v4-in-v6 peer matched against an IPv4 range", spec: []string{"10.0.0.0/8"}, peer: "::ffff:10.1.2.3", wantSplice: true},
			{name: "v4-in-v6 peer outside the IPv4 range denied", spec: []string{"10.0.0.0/8"}, peer: "::ffff:198.51.100.7", wantSplice: false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				svc := withRanges(lbService("default", "web", "10.43.0.5", 8081), tt.spec, tt.annotation)
				r := newRig(t, svc)
				r.c.reconcile(ctx, []*corev1.Service{svc})
				l := r.binder.listener(8081)
				if l == nil {
					t.Fatal("the listener must be bound for a valid range set")
				}
				if got := connect(t, l, r.dialer, tt.peer); got != tt.wantSplice {
					t.Errorf("peer %s spliced = %v, want %v", tt.peer, got, tt.wantSplice)
				}
				if !tt.wantSplice && r.dialer.count() != 0 {
					t.Errorf("a denied peer must never reach the backend: %d dials", r.dialer.count())
				}
			})
		}
	})

	t.Run("unparsable set on first provisioning: no listener, pending status, event", func(t *testing.T) {
		svc := withRanges(lbService("default", "web", "10.43.0.5", 8081), []string{"10.0.0.0/8", "bogus"}, "")
		r := newRig(t, svc)
		r.c.reconcile(ctx, []*corev1.Service{svc})
		if r.binder.openCount() != 0 {
			t.Fatalf("fail closed: %d listeners opened for an unparsable set", r.binder.openCount())
		}
		if st := status(t, r.cs); len(st) != 0 {
			t.Errorf("status = %+v, want pending (empty)", st)
		}
		ev := events(r.rec)
		if len(ev) != 1 || !strings.Contains(ev[0], "Warning "+EventReasonSourceRangesInvalid) {
			t.Fatalf("events = %q, want one Warning %s", ev, EventReasonSourceRangesInvalid)
		}
		// A persistent error is recorded once, not on every resync.
		r.c.reconcile(ctx, []*corev1.Service{svc})
		if ev := events(r.rec); len(ev) != 0 {
			t.Errorf("a repeated identical error must not re-record: %q", ev)
		}
	})

	t.Run("edit-time unparsable set keeps the listener and the last-good ranges", func(t *testing.T) {
		svc := withRanges(lbService("default", "web", "10.43.0.5", 8081), []string{"10.0.0.0/8"}, "")
		r := newRig(t, svc)
		r.c.reconcile(ctx, []*corev1.Service{svc})
		l := r.binder.listener(8081)
		if l == nil {
			t.Fatal("listener must bind")
		}
		bad := svc.DeepCopy()
		bad.Spec.LoadBalancerSourceRanges = []string{"0.0.0.0/0", "300.0.0.0/8"}
		r.c.reconcile(ctx, []*corev1.Service{bad})
		if r.binder.openCount() != 1 || r.binder.listener(8081) != l {
			t.Fatal("an edit-time parse failure must not reopen or tear down the listener")
		}
		select {
		case <-l.closed:
			t.Fatal("the listener was closed on an edit-time parse failure")
		default:
		}
		if !connect(t, l, r.dialer, "10.2.2.2") {
			t.Error("the last-good set must still allow 10.2.2.2")
		}
		if connect(t, l, r.dialer, "198.51.100.7") {
			t.Error("the last-good set must still deny 198.51.100.7 (never widened to the bad set's 0.0.0.0/0)")
		}
		if st := status(t, r.cs); len(st) != 1 {
			t.Errorf("status = %+v, want still advertised while serving", st)
		}
		ev := events(r.rec)
		if len(ev) != 1 || !strings.Contains(ev[0], "Warning "+EventReasonSourceRangesInvalid) {
			t.Fatalf("events = %q, want one Warning %s", ev, EventReasonSourceRangesInvalid)
		}
	})

	t.Run("a live range edit applies to the next accept", func(t *testing.T) {
		svc := withRanges(lbService("default", "web", "10.43.0.5", 8081), []string{"10.0.0.0/8"}, "")
		r := newRig(t, svc)
		r.c.reconcile(ctx, []*corev1.Service{svc})
		l := r.binder.listener(8081)
		if connect(t, l, r.dialer, "198.51.100.7") {
			t.Fatal("198.51.100.7 must be denied before the edit")
		}
		edited := svc.DeepCopy()
		edited.Spec.LoadBalancerSourceRanges = []string{"198.51.100.0/24"}
		r.c.reconcile(ctx, []*corev1.Service{edited})
		if r.binder.openCount() != 1 {
			t.Fatalf("an edit must not reopen the listener: %d opens", r.binder.openCount())
		}
		if !connect(t, l, r.dialer, "198.51.100.7") {
			t.Error("198.51.100.7 must be allowed after the edit")
		}
		if connect(t, l, r.dialer, "10.1.2.3") {
			t.Error("10.1.2.3 must be denied after the edit")
		}
		cleared := edited.DeepCopy()
		cleared.Spec.LoadBalancerSourceRanges = nil
		r.c.reconcile(ctx, []*corev1.Service{cleared})
		if !connect(t, l, r.dialer, "10.1.2.3") {
			t.Error("clearing the ranges must restore allow-all")
		}
	})
}
