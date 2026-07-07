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
	nodeIP := netip.MustParseAddr("192.168.7.20")

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
			Client:           cs,
			NodeIP:           nodeIP,
			Binder:           binder,
			PrivilegedBinder: binder,
			Logger:           slog.New(slog.NewTextHandler(&buf, nil)),
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
		if len(st) != 1 || st[0].IP != nodeIP.String() {
			t.Errorf("status = %+v, want the node IP once the listener is bound", st)
		}
	})

	t.Run("bind conflict: status stays empty, stale IP cleared, throttled Warn", func(t *testing.T) {
		binder := &fakeBinder{fail: map[uint16]error{8082: errors.New("address already in use")}}
		svc := lbService("default", "conflicted", "10.43.0.6", 8082)
		// A stale advertisement from a previous life must be CLEARED, not kept.
		svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: nodeIP.String()}}
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
		if st := getStatus(t, cs, "default", "later"); len(st) != 1 || st[0].IP != nodeIP.String() {
			t.Errorf("status = %+v, want the node IP once the conflict clears", st)
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

	t.Run("privileged port routes through the privileged binder", func(t *testing.T) {
		priv := &fakeBinder{}
		direct := &fakeBinder{}
		cs := fake.NewClientset()
		svc := lbService("default", "www", "10.43.0.11", 80, 8086)
		if _, err := cs.CoreV1().Services("default").Create(ctx, svc, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		c, err := New(Config{
			Client:           cs,
			NodeIP:           nodeIP,
			Binder:           direct,
			PrivilegedBinder: priv,
			Logger:           slog.New(slog.DiscardHandler),
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer c.closeAll()
		c.reconcile(ctx, []*corev1.Service{svc})
		if !priv.boundPorts()[80] || priv.boundPorts()[8086] {
			t.Errorf("priv bound = %v, want exactly {80} (<1024 through the netd seam)", priv.boundPorts())
		}
		if !direct.boundPorts()[8086] || direct.boundPorts()[80] {
			t.Errorf("direct bound = %v, want exactly {8086} (>=1024 in-process)", direct.boundPorts())
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
