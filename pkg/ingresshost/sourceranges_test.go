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

package ingresshost

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"k3sm.io/k3sm/pkg/svclb"
)

// peerConn is a net.Pipe end with a synthetic client address.
type peerConn struct {
	net.Conn
	peer netip.AddrPort
}

func (c peerConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.peer) }

// pushListener hands out the conns pushed into it; Close ends Accept.
type pushListener struct {
	addr   netip.AddrPort
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pushListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pushListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pushListener) Addr() net.Addr { return net.TCPAddrFromAddrPort(l.addr) }

// pushBinder binds one pushListener, runs onListen at bind time (to witness
// what was enforced at that instant), and signals bound.
type pushBinder struct {
	mu       sync.Mutex
	ln       *pushListener
	onListen func()
	bound    chan struct{}
}

func newPushBinder() *pushBinder { return &pushBinder{bound: make(chan struct{})} }

func (b *pushBinder) Listen(_ context.Context, _ string, addr netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.onListen != nil {
		b.onListen()
	}
	b.ln = &pushListener{addr: addr, conns: make(chan net.Conn), closed: make(chan struct{})}
	close(b.bound)
	return b.ln, nil
}

func (b *pushBinder) listener() *pushListener {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ln
}

// canonicalService is the canonical ingress LB Service with the given ranges.
func canonicalService(ranges ...string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ServiceNamespace, Name: ServiceName,
			Labels: map[string]string{svclb.IgnoreLabel: "true"}},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, LoadBalancerSourceRanges: ranges},
	}
}

// newRangesHost builds a Host over cs with a fake recorder and the push binder.
func newRangesHost(t *testing.T, cs *fake.Clientset, binder *pushBinder, rec *record.FakeRecorder) *Host {
	t.Helper()
	h, err := New(Config{
		Client:        cs,
		NodeName:      testNodeName,
		BindAddr:      testBindAddr,
		AdvertiseAddr: testAdvertiseAddr,
		PodCIDR:       testPodCIDR,
		HTTPPort:      8080,
		Binder:        binder,
		Recorder:      rec,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

// connectPeer pushes a connection from peer into l and reports whether it was
// served (true) or closed before anything served it (false). served, when
// non-nil, receives every connection the wrapped listener handed to the
// "server"; when nil, a connection still open at the deadline counts as served.
func connectPeer(t *testing.T, l *pushListener, served chan net.Conn, peer string) bool {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	select {
	case l.conns <- peerConn{Conn: server, peer: netip.AddrPortFrom(netip.MustParseAddr(peer), 40000)}:
	case <-time.After(2 * time.Second):
		t.Fatalf("peer %s: never accepted", peer)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if served != nil {
			select {
			case c := <-served:
				_ = c.Close()
				return true
			default:
			}
		}
		_ = client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		var b [1]byte
		if _, err := client.Read(b[:]); errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			if served != nil {
				select {
				case <-served:
					t.Fatalf("peer %s: the server saw a connection that was closed", peer)
				default:
				}
			}
			return false
		}
	}
	if served == nil {
		return true // still open: something is serving it
	}
	t.Fatalf("peer %s: neither served nor closed", peer)
	return false
}

// waitEvent returns the next recorded event, failing after a bound.
func waitEvent(t *testing.T, rec *record.FakeRecorder) string {
	t.Helper()
	select {
	case e := <-rec.Events:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no event recorded")
		return ""
	}
}

// TestIngressHostEnforcesTheCanonicalSourceRanges pins B131's ingress half: the
// canonical kube-system/k3sm-ingress Service's loadBalancerSourceRanges are
// enforced by the listener the ingress host hands darwin-net's server, so a
// denied peer is closed before the server ever sees it; the listeners open only
// after the ranges are installed; a live edit applies to the next accept; a
// parse failure keeps the last valid set; and deleting the canonical Service
// never silently lifts the ranges.
func TestIngressHostEnforcesTheCanonicalSourceRanges(t *testing.T) {
	t.Run("no allow-all window at start: listeners open only after the ranges are installed", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cs := fake.NewClientset(canonicalService("10.0.0.0/8"))
		binder := newPushBinder()
		h := newRangesHost(t, cs, binder, record.NewFakeRecorder(16))
		var atBind atomic.Pointer[svclb.Ranges]
		binder.onListen = func() { atBind.Store(h.ranges.Load()) }

		done := make(chan error, 1)
		go func() { done <- h.Run(ctx) }()
		defer func() { cancel(); <-done }()
		select {
		case <-binder.bound:
		case <-time.After(10 * time.Second):
			t.Fatal("the ingress listener never bound")
		}
		if r := atBind.Load(); r == nil || len(*r) != 1 || (*r)[0].String() != "10.0.0.0/8" {
			t.Fatalf("ranges in force at bind = %v, want 10.0.0.0/8 (the listener opened before the watch synced)", r)
		}
		// The very first connection, from a denied peer, is closed.
		if connectPeer(t, binder.listener(), nil, "198.51.100.7") {
			t.Error("the first connection from a denied peer must be closed")
		}
	})

	t.Run("an unsynced watch never opens the listeners", func(t *testing.T) {
		h := newRangesHost(t, fake.NewClientset(), newPushBinder(), record.NewFakeRecorder(16))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h.serveLoop(ctx) // returns at once: rangesReady never closed
		if h.boundCount.Load() != 0 {
			t.Fatal("serveLoop bound a listener before the ranges were ready")
		}
	})

	t.Run("enforcement, live edit, parse failure, delete and recreate", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// A second LB Service in the same namespace whose ranges must NOT leak
		// into the ingress (the watch is scoped to the canonical Service by name).
		other := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: ServiceNamespace, Name: "other"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, LoadBalancerSourceRanges: []string{"172.16.0.0/12"}},
		}
		cs := fake.NewClientset(canonicalService("10.0.0.0/8"), other)
		rec := record.NewFakeRecorder(16)
		binder := newPushBinder()
		h := newRangesHost(t, cs, binder, rec)

		// Witness the ranges in force at the instant the recreate is issued.
		var atCreate atomic.Pointer[svclb.Ranges]
		created := make(chan struct{}, 1)
		cs.PrependReactor("create", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
			atCreate.Store(h.ranges.Load())
			select {
			case created <- struct{}{}:
			default:
			}
			return false, nil, nil
		})

		ln, err := (countingBinder{h: h}).Listen(ctx, "tcp", netip.AddrPortFrom(testBindAddr, 8080))
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		defer ln.Close()
		served := make(chan net.Conn, 4)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				served <- c
			}
		}()
		watchDone := make(chan struct{})
		go func() {
			defer close(watchDone)
			_ = h.watchSourceRanges(ctx)
		}()
		defer func() { cancel(); <-watchDone }()
		select {
		case <-h.rangesReady:
		case <-time.After(5 * time.Second):
			t.Fatal("the canonical Service watch never synced")
		}

		waitRanges := func(t *testing.T, want string) {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				r := h.ranges.Load()
				if r != nil && ((want == "" && len(*r) == 0) || (len(*r) == 1 && (*r)[0].String() == want)) {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Fatalf("the canonical Service's ranges never became %q", want)
		}
		connect := func(t *testing.T, peer string) bool {
			t.Helper()
			return connectPeer(t, binder.listener(), served, peer)
		}

		waitRanges(t, "10.0.0.0/8")
		if !connect(t, "10.1.2.3") {
			t.Error("an allowed peer must be served")
		}
		if connect(t, "198.51.100.7") {
			t.Error("a denied peer must be closed before the server")
		}
		if connect(t, "::ffff:198.51.100.7") {
			t.Error("a v4-in-v6 denied peer must be closed before the server")
		}

		// A live edit of the canonical Service applies to the next accept.
		edited := canonicalService("198.51.100.0/24")
		if _, err := cs.CoreV1().Services(ServiceNamespace).Update(ctx, edited, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update: %v", err)
		}
		waitRanges(t, "198.51.100.0/24")
		if !connect(t, "198.51.100.7") {
			t.Error("198.51.100.7 must be served after the edit")
		}
		if connect(t, "10.1.2.3") {
			t.Error("10.1.2.3 must be denied after the edit")
		}

		// A parse failure keeps the last valid set and records the Event, with
		// the offending entry truncated.
		long := strings.Repeat("x", 200)
		bad := canonicalService("0.0.0.0/0", long)
		if _, err := cs.CoreV1().Services(ServiceNamespace).Update(ctx, bad, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update: %v", err)
		}
		e := waitEvent(t, rec)
		if !strings.Contains(e, "Warning "+svclb.EventReasonSourceRangesInvalid) {
			t.Errorf("event = %q, want a Warning %s", e, svclb.EventReasonSourceRangesInvalid)
		}
		if strings.Contains(e, strings.Repeat("x", 49)) {
			t.Errorf("the Event echoes more than 48 runes of the offending entry: %q", e)
		}
		if connect(t, "10.1.2.3") {
			t.Error("the last-good set must still deny 10.1.2.3 (never widened to the bad set's 0.0.0.0/0)")
		}
		if !connect(t, "198.51.100.7") {
			t.Error("the last-good set must still serve 198.51.100.7")
		}
		// Restore a valid restrictive set before the delete.
		if _, err := cs.CoreV1().Services(ServiceNamespace).Update(ctx, edited, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update: %v", err)
		}
		waitRanges(t, "198.51.100.0/24")

		// Deleting the canonical Service keeps the ranges until the recreate,
		// recreates it, and records SourceRangesReset when the default spec lands.
		if err := cs.CoreV1().Services(ServiceNamespace).Delete(ctx, ServiceName, metav1.DeleteOptions{}); err != nil {
			t.Fatalf("delete: %v", err)
		}
		select {
		case <-created:
		case <-time.After(5 * time.Second):
			t.Fatal("the deleted canonical Service was not recreated")
		}
		if r := atCreate.Load(); r == nil || len(*r) != 1 || (*r)[0].String() != "198.51.100.0/24" {
			t.Errorf("ranges in force when the recreate was issued = %v, want the last valid 198.51.100.0/24", r)
		}
		if e := waitEvent(t, rec); !strings.Contains(e, "Warning "+EventReasonSourceRangesReset) {
			t.Errorf("event = %q, want a Warning %s", e, EventReasonSourceRangesReset)
		}
		if _, err := cs.CoreV1().Services(ServiceNamespace).Get(ctx, ServiceName, metav1.GetOptions{}); err != nil {
			t.Errorf("the canonical Service must exist again: %v", err)
		}
		waitRanges(t, "")
		if !connect(t, "10.1.2.3") {
			t.Error("the recreated default spec allows every peer")
		}
	})

	t.Run("a delete keeps the last ranges while the recreate has not landed (tombstone included)", func(t *testing.T) {
		ctx := context.Background()
		cs := fake.NewClientset()
		var creates atomic.Int32
		cs.PrependReactor("create", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
			creates.Add(1)
			return true, nil, errors.New("apiserver unavailable")
		})
		h := newRangesHost(t, cs, newPushBinder(), record.NewFakeRecorder(16))
		h.applySourceRanges(canonicalService("10.0.0.0/8"))

		h.onServiceDelete(ctx, cache.DeletedFinalStateUnknown{
			Key: ServiceNamespace + "/" + ServiceName, Obj: canonicalService("10.0.0.0/8")})
		if creates.Load() != 1 {
			t.Fatalf("a tombstoned delete must trigger the recreate: %d creates", creates.Load())
		}
		r := h.ranges.Load()
		if r == nil || r.Allows(netip.MustParseAddr("198.51.100.7")) || !r.Allows(netip.MustParseAddr("10.1.2.3")) {
			t.Fatalf("ranges after the delete = %v, want the last valid 10.0.0.0/8 still enforced", r)
		}
		if !h.resetPending {
			t.Error("a delete that will lift ranges must arm the SourceRangesReset Event")
		}
	})
}
