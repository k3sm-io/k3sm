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
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/k3sm/pkg/ports"
)

// fakeListener is a bind-only listener: Accept blocks until Close (no real
// sockets in unit tests — the binder seam is faked).
type fakeListener struct {
	addr   netip.AddrPort
	closed chan struct{}
	once   sync.Once
}

func newFakeListener(addr netip.AddrPort) *fakeListener {
	return &fakeListener{addr: addr, closed: make(chan struct{})}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(l.addr)
}

// fakeBinder fakes the netbind seam: configured ports fail (the conflict
// case), everything else "binds" a fakeListener and is recorded.
type fakeBinder struct {
	mu    sync.Mutex
	fail  map[uint16]error
	bound []netip.AddrPort
}

func (b *fakeBinder) Listen(_ context.Context, _ string, addr netip.AddrPort) (net.Listener, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.fail[addr.Port()]; err != nil {
		return nil, err
	}
	b.bound = append(b.bound, addr)
	return newFakeListener(addr), nil
}

func (b *fakeBinder) boundPorts() map[uint16]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[uint16]bool, len(b.bound))
	for _, ap := range b.bound {
		out[ap.Port()] = true
	}
	return out
}

// The B116 fixture addresses. BIND and ADVERTISE are deliberately DIFFERENT
// values (and the advertised one lives inside testPodCIDR) so an assertion that
// accidentally reads the wrong field cannot pass by coincidence.
var (
	testBindAddr      = netip.AddrFrom4([4]byte{}) // 0.0.0.0
	testAdvertiseAddr = netip.MustParseAddr("100.64.2.1")
	testPodCIDR       = netip.MustParsePrefix("100.64.0.0/10")
)

// lbService builds a LoadBalancer Service with the given TCP ports.
func lbService(namespace, name, clusterIP string, ports ...int32) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeLoadBalancer,
			ClusterIP: clusterIP,
		},
	}
	for _, p := range ports {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{Port: p, Protocol: corev1.ProtocolTCP})
	}
	return svc
}

// TestSvclbStatusHonesty pins the klipper-lite honesty rule (M10.3/B32):
// status.loadBalancer.ingress carries the node IP ONLY once every TCP port's
// listener is actually bound; a bind conflict leaves the status empty with a
// throttled Warn (and clears a stale IP); the ignore-labeled canonical ingress
// Service is skipped entirely; UDP-only Services get no listeners and no
// status; and a resolved conflict is advertised on the next reconcile.
func TestSvclbStatusHonesty(t *testing.T) {
	ctx := context.Background()

	newController := func(t *testing.T, binder *fakeBinder, objs ...*corev1.Service) (*Controller, *fake.Clientset, *bytes.Buffer) {
		t.Helper()
		cs := fake.NewClientset()
		for _, o := range objs {
			if _, err := cs.CoreV1().Services(o.Namespace).Create(ctx, o, metav1.CreateOptions{}); err != nil {
				t.Fatalf("seed service %s/%s: %v", o.Namespace, o.Name, err)
			}
		}
		var buf bytes.Buffer
		c, err := New(Config{
			Client:        cs,
			BindAddr:      testBindAddr,
			AdvertiseAddr: testAdvertiseAddr,
			PodCIDR:       testPodCIDR,
			ReservedPorts: ports.ReservedSet(),
			Binder:        binder,
			Logger:        slog.New(slog.NewTextHandler(&buf, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return c, cs, &buf
	}

	getStatus := func(t *testing.T, cs *fake.Clientset, namespace, name string) []corev1.LoadBalancerIngress {
		t.Helper()
		svc, err := cs.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get service %s/%s: %v", namespace, name, err)
		}
		return svc.Status.LoadBalancer.Ingress
	}

	t.Run("status written only after the listener binds", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "web", "10.43.0.5", 8081)
		c, cs, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if !binder.boundPorts()[8081] {
			t.Fatal("the listener must be bound")
		}
		st := getStatus(t, cs, "default", "web")
		if len(st) != 1 || st[0].IP != testAdvertiseAddr.String() {
			t.Errorf("status = %+v, want the ADVERTISE address once the listener is bound", st)
		}
	})

	t.Run("bind conflict: status stays empty, stale IP cleared, throttled Warn", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8082: errors.New("address already in use")}}
		svc := lbService("default", "conflicted", "10.43.0.6", 8082)
		// A stale advertisement from a previous life must be CLEARED, not kept.
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: testAdvertiseAddr.String()}}
		c, cs, buf := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if st := getStatus(t, cs, "default", "conflicted"); len(st) != 0 {
			t.Errorf("status = %+v, want empty on a bind conflict (never advertise a dead address)", st)
		}
		if !strings.Contains(buf.String(), "listener bind failed") {
			t.Error("a bind conflict must Warn")
		}
		// The Warn is throttled: an immediate re-reconcile does not double-log.
		before := strings.Count(buf.String(), "listener bind failed")
		c.reconcile(ctx, []*corev1.Service{svc})
		if after := strings.Count(buf.String(), "listener bind failed"); after != before {
			t.Errorf("bind-conflict Warn must be throttled: count went %d -> %d", before, after)
		}
	})

	t.Run("a resolved conflict is advertised on the next reconcile", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8083: errors.New("address already in use")}}
		svc := lbService("default", "later", "10.43.0.7", 8083)
		c, cs, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if st := getStatus(t, cs, "default", "later"); len(st) != 0 {
			t.Fatalf("status = %+v, want empty while the port conflicts", st)
		}
		binder.mu.Lock()
		delete(binder.fail, 8083)
		binder.mu.Unlock()
		c.reconcile(ctx, []*corev1.Service{svc})
		if st := getStatus(t, cs, "default", "later"); len(st) != 1 || st[0].IP != testAdvertiseAddr.String() {
			t.Errorf("status = %+v, want the ADVERTISE address once the conflict clears", st)
		}
	})

	t.Run("partial bind of a multi-port service is not advertised", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8085: errors.New("address already in use")}}
		svc := lbService("default", "partial", "10.43.0.8", 8084, 8085)
		c, cs, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if st := getStatus(t, cs, "default", "partial"); len(st) != 0 {
			t.Errorf("status = %+v, want empty until EVERY TCP port is bound", st)
		}
	})

	t.Run("ignore-labeled service is skipped entirely", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("kube-system", "k3sm-ingress", "10.43.0.9", 80, 443)
		svc.Labels = map[string]string{IgnoreLabel: "true"}
		c, cs, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none (the ingress server owns these listeners)", ports)
		}
		if st := getStatus(t, cs, "kube-system", "k3sm-ingress"); len(st) != 0 {
			t.Errorf("status = %+v, want untouched (ingresshost writes it, not svclb)", st)
		}
	})

	t.Run("UDP-only service: no listener, no status, deferral Warn", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "udp-lb"},
			Spec: corev1.ServiceSpec{
				Type:      corev1.ServiceTypeLoadBalancer,
				ClusterIP: "10.43.0.10",
				Ports:     []corev1.ServicePort{{Port: 9053, Protocol: corev1.ProtocolUDP}},
			},
		}
		c, cs, buf := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none (UDP LB is deferred)", ports)
		}
		if st := getStatus(t, cs, "default", "udp-lb"); len(st) != 0 {
			t.Errorf("status = %+v, want empty for a UDP-only service", st)
		}
		if !strings.Contains(buf.String(), "UDP LB deferred") {
			t.Error("the UDP deferral must Warn (the gap stays observable)")
		}
	})

	// INVERTED by B116 (was "privileged port routes through the privileged
	// binder"): the port-keyed binder selection is DELETED. Same fixture — a
	// Service declaring both a <1024 and a >=1024 port — now asserting the ONE
	// configured binder takes both. The <1024 half is the load-bearing one: it is
	// what a wrong diff that only changes the ADDRESS (leaving the privileged
	// branch live) would break, since netd refuses the wildcard.
	t.Run("the single in-process binder takes every port, privileged ones included", func(t *testing.T) {
		binder := &fakeBinder{}
		cs := fake.NewClientset()
		svc := lbService("default", "www", "10.43.0.11", 80, 8086)
		if _, err := cs.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		c, err := New(Config{
			Client:        cs,
			BindAddr:      testBindAddr,
			AdvertiseAddr: testAdvertiseAddr,
			PodCIDR:       testPodCIDR,
			ReservedPorts: ports.ReservedSet(),
			Binder:        binder,
			Logger:        slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer c.closeAll()
		c.reconcile(ctx, []*corev1.Service{svc})
		if !binder.boundPorts()[80] || !binder.boundPorts()[8086] {
			t.Errorf("bound = %v, want BOTH 80 and 8086 through the one configured binder", binder.boundPorts())
		}
		// And every one of them on the WILDCARD, not on the advertised address.
		binder.mu.Lock()
		defer binder.mu.Unlock()
		for _, ap := range binder.bound {
			if ap.Addr() != testBindAddr {
				t.Errorf("bound %s, want the BIND address %s (never the advertise address)", ap, testBindAddr)
			}
		}
	})

	// D2 — a k3sm-reserved port is REFUSED, not raced. This is the datapath half
	// of the guard (the Deny VAP is the legible half, and it is failurePolicy:
	// Ignore, so it may be absent).
	t.Run("a reserved port is refused: no listener, empty status, warn", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "greedy", "10.43.0.13", 10250)
		cs := fake.NewClientset()
		if _, err := cs.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		c, err := New(Config{
			Client:        cs,
			BindAddr:      testBindAddr,
			AdvertiseAddr: testAdvertiseAddr,
			PodCIDR:       testPodCIDR,
			ReservedPorts: map[int32]bool{10250: true, 30500: true},
			Binder:        binder,
			Logger:        slog.New(slog.NewTextHandler(&buf, nil)),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer c.closeAll()
		c.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want NONE: a reserved port must never reach the binder", ports)
		}
		svcOut, err := cs.CoreV1().Services("default").Get(ctx, "greedy", metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if st := svcOut.Status.LoadBalancer.Ingress; len(st) != 0 {
			t.Errorf("status = %+v, want empty for a refused reserved port", st)
		}
		if !strings.Contains(buf.String(), "RESERVED") {
			t.Errorf("the refusal must Warn naming the reservation; log was:\n%s", buf.String())
		}
		if !strings.Contains(buf.String(), "10250") {
			t.Error("the refusal Warn must name the port")
		}
	})

	// The stale-entry case the pre-B116 fixture could not catch: it seeded the
	// stale IP as the node IP, which the mechanical rename would have kept green
	// whether or not a retraction rule exists. This entry is NEITHER the bind
	// address NOR the advertise address — it is what a PREVIOUS podCIDR derived —
	// and it must still be dropped.
	t.Run("a stale 127.0.0.1 entry is dropped even though it is neither the bind nor the advertise address", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8088: errors.New("address already in use")}}
		svc := lbService("default", "upgraded", "10.43.0.14", 8088)
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
			{IP: "127.0.0.1"},  // the pre-B116 default an upgraded cluster carries
			{IP: "100.64.0.1"}, // a PREVIOUS enrollment's derived .1 (podCIDR moved)
			{IP: "203.0.113.9"} /* a foreign entry: never ours, never touched */}
		c, cs, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		st := getStatus(t, cs, "default", "upgraded")
		if len(st) != 1 || st[0].IP != "203.0.113.9" {
			t.Errorf("status = %+v, want ONLY the foreign entry: loopback and the previous derived .1 must both be retracted, a foreign address never", st)
		}
	})

	t.Run("removed service drains its forwarders", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "gone", "10.43.0.12", 8087)
		c, _, _ := newController(t, binder, svc)
		defer c.closeAll()

		c.reconcile(ctx, []*corev1.Service{svc})
		if len(c.forwarders) != 1 {
			t.Fatalf("forwarders = %d, want 1", len(c.forwarders))
		}
		c.reconcile(ctx, nil)
		if len(c.forwarders) != 0 {
			t.Errorf("forwarders = %d, want 0 after the service is removed", len(c.forwarders))
		}
	})
}

// TestSvclbNewValidationAsymmetry pins the B116 construction contract, which had
// NO test before: BindAddr must be valid but MAY be the wildcard (the production
// choice — rejecting IsUnspecified here would refuse the shipped configuration),
// while AdvertiseAddr may be the ZERO Addr, which is the honest "derivation
// failed" signal rather than an error.
func TestSvclbNewValidationAsymmetry(t *testing.T) {
	tests := []struct {
		name      string
		bind      netip.Addr
		advertise netip.Addr
		wantErr   bool
	}{
		{"wildcard bind accepted", netip.AddrFrom4([4]byte{}), testAdvertiseAddr, false},
		{"specific bind accepted", netip.MustParseAddr("192.168.7.20"), testAdvertiseAddr, false},
		{"zero bind rejected", netip.Addr{}, testAdvertiseAddr, true},
		{"zero advertise accepted (bind, never advertise)", netip.AddrFrom4([4]byte{}), netip.Addr{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{
				Client:        fake.NewClientset(),
				BindAddr:      tt.bind,
				AdvertiseAddr: tt.advertise,
				ReservedPorts: ports.ReservedSet(),
				Logger:        slog.New(slog.DiscardHandler),
			})
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("New err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
	if _, err := New(Config{BindAddr: netip.AddrFrom4([4]byte{}), ReservedPorts: ports.ReservedSet()}); err == nil {
		t.Error("New must still reject a nil client")
	}

	// FAIL CLOSED on the zero value of a guard. The reserved-port refusal is the
	// last of three layers that all fail OPEN (the VAP is failurePolicy: Ignore
	// and is provisioned log-and-continue), so a nil set must be a construction
	// ERROR, not a silent "reserve nothing". An explicit empty map is the visible
	// opt-out.
	if _, err := New(Config{
		Client:   fake.NewClientset(),
		BindAddr: netip.AddrFrom4([4]byte{}),
		Logger:   slog.New(slog.DiscardHandler),
	}); err == nil {
		t.Error("New must REJECT a nil ReservedPorts: the zero value of a guard must not disable it")
	}
	if _, err := New(Config{
		Client:        fake.NewClientset(),
		BindAddr:      netip.AddrFrom4([4]byte{}),
		ReservedPorts: map[int32]bool{},
		Logger:        slog.New(slog.DiscardHandler),
	}); err != nil {
		t.Errorf("an EXPLICIT empty ReservedPorts is the sanctioned opt-out, got %v", err)
	}
}

// TestSvclbDerivationFailureBindsButNeverAdvertises is gate assert (c) for the
// svclb half: when the node's advertisable address could NOT be derived, the
// listeners still bind (the Service is <pending>, not disabled) and the status
// length is exactly ZERO.
//
// It asserts len == 0, deliberately NOT "!= 127.0.0.1": the zero netip.Addr
// stringifies to "invalid IP", so a controller that published it would satisfy
// the negative check while advertising an EXTERNAL-IP worse than loopback.
//
// The Service is seeded with a STALE entry, not an empty status. An empty seed
// cannot distinguish "retracted" from "never written", which is exactly how the
// original version of this code shipped a gap: a fully-bound Service with an
// underivable advertise address was routed to ensureStatus, which returned early
// — so clearStatus (and therefore Retractable) never ran and a pre-existing
// loopback or previous-/24 entry survived forever.
func TestSvclbDerivationFailureBindsButNeverAdvertises(t *testing.T) {
	ctx := context.Background()
	binder := &fakeBinder{}
	svc := lbService("default", "pending", "10.43.0.15", 8090)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{IP: "127.0.0.1"},   // a pre-B116 entry an upgraded cluster carries
		{IP: "100.64.0.1"},  // a previous enrollment's derived .1
		{IP: "203.0.113.9"}, // foreign: outside the pod space and not loopback
	}
	cs := fake.NewClientset()
	if _, err := cs.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		Client:        cs,
		BindAddr:      testBindAddr,
		AdvertiseAddr: netip.Addr{}, // the derivation failed
		PodCIDR:       testPodCIDR,
		ReservedPorts: ports.ReservedSet(),
		Binder:        binder,
		Logger:        slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.closeAll()

	c.reconcile(ctx, []*corev1.Service{svc})
	if !binder.boundPorts()[8090] {
		t.Error("listeners must STILL bind when the advertise address is undecidable (the Service is <pending>, not disabled)")
	}
	out, err := cs.CoreV1().Services("default").Get(ctx, "pending", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, lbi := range out.Status.LoadBalancer.Ingress {
		if lbi.IP == "invalid IP" || lbi.IP == "" {
			t.Errorf("status carries %q — the zero netip.Addr must never be published", lbi.IP)
		}
	}
	// The retraction MUST have run: a fully-bound Service with no advertisable
	// address settles into the same state as an unbound one.
	if len(out.Status.LoadBalancer.Ingress) != 1 || out.Status.LoadBalancer.Ingress[0].IP != "203.0.113.9" {
		t.Errorf("status = %+v, want ONLY the foreign entry: the stale loopback and previous-/24 entries must be RETRACTED, not merely left unwritten", out.Status.LoadBalancer.Ingress)
	}
}

// TestRetractable pins the ONE retraction rule both svclb and ingresshost apply.
// A single-value comparison against the current advertise address strands both a
// pre-B116 loopback entry and a previous enrollment's derived .1.
func TestRetractable(t *testing.T) {
	podCIDR := netip.MustParsePrefix("100.64.0.0/10")
	advertise := netip.MustParseAddr("100.64.2.1")
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"the current advertise address", "100.64.2.1", true},
		{"a previous enrollment's derived .1", "100.64.0.1", true},
		{"the pre-B116 loopback default", "127.0.0.1", true},
		{"another loopback address", "127.0.0.53", true},
		{"a foreign public address", "203.0.113.9", false},
		{"a LAN address", "192.168.7.20", false},
		{"not an address at all", "some-hostname", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Retractable(podCIDR, advertise, tt.ip); got != tt.want {
				t.Errorf("Retractable(%s, %s, %q) = %v, want %v", podCIDR, advertise, tt.ip, got, tt.want)
			}
		})
	}
	// With no podCIDR configured the pod-space arm is simply off; the other two
	// arms still hold (never a panic, never a widened rule).
	if Retractable(netip.Prefix{}, advertise, "100.64.0.1") {
		t.Error("with a zero PodCIDR the pod-space arm must be disabled")
	}
	if !Retractable(netip.Prefix{}, advertise, "127.0.0.1") {
		t.Error("the loopback arm must hold with a zero PodCIDR")
	}
}
