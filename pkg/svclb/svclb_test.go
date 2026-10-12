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
	"strconv"
	"strings"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"k3sm.io/darwin-net/pkg/netbind"

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

// The hoster fixture. testNode is the node under test; lbService stamps every
// Service onto it so the hoster binds, and a test that needs another stamp (or
// none) edits the annotation.
const testNode = "node-a"

var testBindAddr = netip.AddrFrom4([4]byte{}) // 0.0.0.0

// lbService builds a LoadBalancer Service with the given TCP ports, stamped
// onto testNode.
func lbService(namespace, name, clusterIP string, ports ...int32) *corev1.Service {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespace,
			Name:        name,
			UID:         types.UID("uid-" + name),
			Annotations: map[string]string{HostsAnnotation: testNode},
		},
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

// testNodeObject is a Ready Node named name.
func testNodeObject(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{
			{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
		}},
	}
}

// newTestHoster builds a Hoster for node on cs (which must hold the Node) and
// lands its start-of-life reset, the precondition for binding anything.
func newTestHoster(t *testing.T, cs *fake.Clientset, node string, binder netbind.Binder, reserved map[int32]bool, log *slog.Logger) *Hoster {
	t.Helper()
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h, err := NewHoster(HosterConfig{
		Client:        cs,
		NodeName:      node,
		BindAddr:      testBindAddr,
		ReservedPorts: reserved,
		Binder:        binder,
		Logger:        log,
	})
	if err != nil {
		t.Fatalf("NewHoster: %v", err)
	}
	n := 0
	h.newIncarnation = func() string { n++; return node + "-inc-" + strconv.Itoa(n) }
	h.incarnation = h.newIncarnation()
	if err := h.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	t.Cleanup(h.closeAll)
	return h
}

// reportOf reads node's bound report from cs.
func reportOf(t *testing.T, cs kubernetes.Interface, node string) boundReport {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", node, err)
	}
	r, ok := parseBound(n.Annotations[BoundAnnotation])
	if !ok {
		t.Fatalf("node %s carries no parsable %s: %q", node, BoundAnnotation, n.Annotations[BoundAnnotation])
	}
	return r
}

// TestSvclbBindHonesty pins the klipper-lite honesty rule on the hoster side: a
// node reports a Service bound ONLY once every TCP port's listener is actually
// bound (the decider advertises nothing else); a bind conflict leaves it
// unreported with a throttled Warn; the ignore-labeled canonical ingress
// Service is skipped entirely; UDP-only Services get no listeners and no
// report; and a resolved conflict is reported on the next reconcile.
func TestSvclbBindHonesty(t *testing.T) {
	ctx := context.Background()

	newHoster := func(t *testing.T, binder *fakeBinder, objs ...*corev1.Service) (*Hoster, *fake.Clientset, *bytes.Buffer) {
		t.Helper()
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		for _, o := range objs {
			if _, err := cs.CoreV1().Services(o.Namespace).Create(ctx, o, metav1.CreateOptions{}); err != nil {
				t.Fatalf("seed service %s/%s: %v", o.Namespace, o.Name, err)
			}
		}
		var buf bytes.Buffer
		h := newTestHoster(t, cs, testNode, binder, ports.ReservedSet(), slog.New(slog.NewTextHandler(&buf, nil)))
		return h, cs, &buf
	}
	reported := func(t *testing.T, cs *fake.Clientset, svc *corev1.Service) bool {
		t.Helper()
		return reportOf(t, cs, testNode).entries[reportEntry(svc)]
	}

	t.Run("reported only after the listener binds", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "web", "10.43.0.5", 8081)
		h, cs, _ := newHoster(t, binder, svc)
		if reported(t, cs, svc) {
			t.Fatal("the reset report must list nothing")
		}
		h.reconcile(ctx, []*corev1.Service{svc})
		if !binder.boundPorts()[8081] {
			t.Fatal("the listener must be bound")
		}
		if !reported(t, cs, svc) {
			t.Error("the service must be reported once its listener is bound")
		}
	})

	t.Run("bind conflict: not reported, a previous report withdrawn, throttled Warn", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "conflicted", "10.43.0.6", 8082)
		h, cs, buf := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if !reported(t, cs, svc) {
			t.Fatal("precondition: reported while bound")
		}
		// The listener is lost (a VIP change forces a rebind) and the port is now
		// taken: the report must be WITHDRAWN, not kept.
		moved := svc.DeepCopy()
		moved.Spec.ClusterIP = "10.43.0.66"
		binder.mu.Lock()
		binder.fail = map[uint16]error{8082: errors.New("address already in use")}
		binder.mu.Unlock()
		h.reconcile(ctx, []*corev1.Service{moved})
		if reported(t, cs, moved) {
			t.Error("a bind conflict must leave the service unreported (never vouch for a dead listener)")
		}
		if !strings.Contains(buf.String(), "listener bind failed") {
			t.Error("a bind conflict must Warn")
		}
		before := strings.Count(buf.String(), "listener bind failed")
		h.reconcile(ctx, []*corev1.Service{moved})
		if after := strings.Count(buf.String(), "listener bind failed"); after != before {
			t.Errorf("bind-conflict Warn must be throttled: count went %d -> %d", before, after)
		}
	})

	t.Run("a resolved conflict is reported on the next reconcile", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8083: errors.New("address already in use")}}
		svc := lbService("default", "later", "10.43.0.7", 8083)
		h, cs, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if reported(t, cs, svc) {
			t.Fatal("must not be reported while the port conflicts")
		}
		binder.mu.Lock()
		delete(binder.fail, 8083)
		binder.mu.Unlock()
		h.reconcile(ctx, []*corev1.Service{svc})
		if !reported(t, cs, svc) {
			t.Error("must be reported once the conflict clears")
		}
	})

	t.Run("partial bind of a multi-port service is not reported", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8085: errors.New("address already in use")}}
		svc := lbService("default", "partial", "10.43.0.8", 8084, 8085)
		h, cs, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if reported(t, cs, svc) {
			t.Error("must not be reported until EVERY TCP port is bound")
		}
	})

	t.Run("ignore-labeled service is skipped entirely", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("kube-system", "k3sm-ingress", "10.43.0.9", 80, 443)
		svc.Labels = map[string]string{IgnoreLabel: "true"}
		h, cs, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none (the ingress server owns these listeners)", ports)
		}
		if reported(t, cs, svc) {
			t.Error("an ignore-labelled service must never be reported")
		}
	})

	t.Run("UDP-only service: no listener, no report, deferral Warn", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "udp-lb", "10.43.0.10")
		svc.Spec.Ports = []corev1.ServicePort{{Port: 9053, Protocol: corev1.ProtocolUDP}}
		h, cs, buf := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none (UDP LB is deferred)", ports)
		}
		if reported(t, cs, svc) {
			t.Error("a UDP-only service must not be reported")
		}
		if !strings.Contains(buf.String(), "UDP LB deferred") {
			t.Error("the UDP deferral must Warn (the gap stays observable)")
		}
	})

	// INVERTED by B116 (was "privileged port routes through the privileged
	// binder"): the port-keyed binder selection is DELETED. A Service declaring
	// both a <1024 and a >=1024 port goes through the ONE configured binder, on
	// the WILDCARD.
	t.Run("the single in-process binder takes every port, privileged ones included", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "www", "10.43.0.11", 80, 8086)
		h, _, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if !binder.boundPorts()[80] || !binder.boundPorts()[8086] {
			t.Errorf("bound = %v, want BOTH 80 and 8086 through the one configured binder", binder.boundPorts())
		}
		binder.mu.Lock()
		defer binder.mu.Unlock()
		for _, ap := range binder.bound {
			if ap.Addr() != testBindAddr {
				t.Errorf("bound %s, want the BIND address %s", ap, testBindAddr)
			}
		}
	})

	// A k3sm-reserved port is REFUSED, not raced: the datapath half of the guard.
	t.Run("a reserved port is refused: no listener, not reported, warn", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "greedy", "10.43.0.13", 10250)
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		var buf bytes.Buffer
		h := newTestHoster(t, cs, testNode, binder, map[int32]bool{10250: true, 30500: true}, slog.New(slog.NewTextHandler(&buf, nil)))
		h.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want NONE: a reserved port must never reach the binder", ports)
		}
		if reportOf(t, cs, testNode).entries[reportEntry(svc)] {
			t.Error("a refused reserved port must not be reported")
		}
		if !strings.Contains(buf.String(), "RESERVED") || !strings.Contains(buf.String(), "10250") {
			t.Errorf("the refusal must Warn naming the reservation and the port; log was:\n%s", buf.String())
		}
	})

	t.Run("an absent stamp (an older server) binds nothing", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "unstamped", "10.43.0.15", 8090)
		delete(svc.Annotations, HostsAnnotation)
		h, cs, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none without a stamp", ports)
		}
		if reported(t, cs, svc) {
			t.Error("an unstamped service must not be reported")
		}
	})

	t.Run("a stamp naming another node binds nothing here", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "elsewhere", "10.43.0.16", 8091)
		svc.Annotations[HostsAnnotation] = "node-b"
		h, _, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Errorf("bound ports = %v, want none for a service stamped onto node-b", ports)
		}
	})

	t.Run("removed service drains its forwarders and leaves the report", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "gone", "10.43.0.12", 8087)
		h, cs, _ := newHoster(t, binder, svc)
		h.reconcile(ctx, []*corev1.Service{svc})
		if len(h.forwarders) != 1 {
			t.Fatalf("forwarders = %d, want 1", len(h.forwarders))
		}
		h.reconcile(ctx, nil)
		if len(h.forwarders) != 0 {
			t.Errorf("forwarders = %d, want 0 after the service is removed", len(h.forwarders))
		}
		if reported(t, cs, svc) {
			t.Error("a removed service must leave the report")
		}
	})

	t.Run("nothing binds before the start-of-life reset lands", func(t *testing.T) {
		binder := &fakeBinder{}
		svc := lbService("default", "early", "10.43.0.17", 8092)
		// The Node is not registered yet: the reset cannot land.
		cs := fake.NewClientset()
		h, err := NewHoster(HosterConfig{Client: cs, NodeName: testNode, BindAddr: testBindAddr, ReservedPorts: map[int32]bool{}, Binder: binder, Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		defer h.closeAll()
		h.step(ctx, []*corev1.Service{svc}, nil)
		if ports := binder.boundPorts(); len(ports) != 0 {
			t.Fatalf("bound ports = %v before the reset landed, want none", ports)
		}
		if _, err := cs.CoreV1().Nodes().Create(ctx, testNodeObject(testNode, nil), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		h.step(ctx, []*corev1.Service{svc}, nil)
		if !binder.boundPorts()[8092] {
			t.Error("once the reset lands the stamped service binds")
		}
	})
}

// TestSvclbNewHosterValidation pins the hoster construction contract: BindAddr
// must be valid but MAY be the wildcard (the production choice), a client and a
// node name are required, and a nil ReservedPorts is an error (the zero value
// of a guard must not disable it) while an explicit empty map is the opt-out.
func TestSvclbNewHosterValidation(t *testing.T) {
	base := func() HosterConfig {
		return HosterConfig{
			Client:        fake.NewClientset(),
			NodeName:      testNode,
			BindAddr:      netip.AddrFrom4([4]byte{}),
			ReservedPorts: ports.ReservedSet(),
			Logger:        slog.New(slog.DiscardHandler),
		}
	}
	tests := []struct {
		name    string
		mutate  func(*HosterConfig)
		wantErr bool
	}{
		{"wildcard bind accepted", func(*HosterConfig) {}, false},
		{"specific bind accepted", func(c *HosterConfig) { c.BindAddr = netip.MustParseAddr("192.0.2.20") }, false},
		{"zero bind rejected", func(c *HosterConfig) { c.BindAddr = netip.Addr{} }, true},
		{"nil client rejected", func(c *HosterConfig) { c.Client = nil }, true},
		{"empty node name rejected", func(c *HosterConfig) { c.NodeName = "" }, true},
		{"nil ReservedPorts rejected", func(c *HosterConfig) { c.ReservedPorts = nil }, true},
		{"explicit empty ReservedPorts accepted", func(c *HosterConfig) { c.ReservedPorts = map[int32]bool{} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(&cfg)
			_, err := NewHoster(cfg)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("NewHoster err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestRetractable pins the retraction rule the ingress host applies (svclb's
// decider replaces the whole slice instead). A single-value comparison against the current advertise address strands both a
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
