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
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

// netdRefusal is what a LoadBalancer listener bind returns when the root netd
// helper refuses it by policy, spelled the way the wire client and
// netbind.Netd wrap the daemon's error (no named reason, so a plain string).
func netdRefusal(ap netip.AddrPort) error {
	return fmt.Errorf("netd bind tcp %s: netd BindPort rejected: netd: request denied by policy: privileged port %d not authorized: port %d on %s is not in the allowed LoadBalancer port list (80, 443)", ap, ap.Port(), ap.Port(), ap.Addr())
}

// listedPorts is the operator's --lb-privileged-ports in these tests.
var listedPorts = []uint16{80, 443}

// netdRoute is the node daemon's svclb binder shape (cmd/k3sm hosterBinder):
// every bind of a listed port, the wildcard included, goes to netd and nothing
// else; every other bind is in-process, where a specific address below 1024 is
// refused with EACCES as macOS refuses an unprivileged process. The netd leg
// maps the family-pinned network svclb asks for ("tcp4") to the wire name, as
// cmd/k3sm's netdBinder adapter does, and the fake daemon refuses any other
// protocol as netd does, so a binder that forwarded "tcp4" would fail here. It
// records every netd request and which binder each opened listener came from.
type netdRoute struct {
	netd   *setBinder
	direct *setBinder

	mu       sync.Mutex
	networks []string
	asked    []netip.AddrPort
	viaNetd  []netip.AddrPort
	inProc   []netip.AddrPort
}

func (r *netdRoute) Listen(ctx context.Context, network string, ap netip.AddrPort) (net.Listener, error) {
	if ap.Port() <= privilegedPortMax && slices.Contains(listedPorts, ap.Port()) {
		r.mu.Lock()
		r.asked = append(r.asked, ap)
		r.networks = append(r.networks, network)
		r.mu.Unlock()
		proto := network
		switch network {
		case "tcp4", "tcp6":
			proto = "tcp"
		case "udp4", "udp6":
			proto = "udp"
		}
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("netd bind %s %s: netd BindPort rejected: bindPort: unsupported protocol %q", network, ap, proto)
		}
		ln, err := r.netd.Listen(ctx, proto, ap)
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.viaNetd = append(r.viaNetd, ap)
		r.mu.Unlock()
		return ln, nil
	}
	if ap.Port() <= privilegedPortMax && !ap.Addr().IsUnspecified() {
		return nil, fmt.Errorf("listen tcp %s: %w", ap, syscall.EACCES)
	}
	ln, err := r.direct.Listen(ctx, network, ap)
	if err == nil {
		r.mu.Lock()
		r.inProc = append(r.inProc, ap)
		r.mu.Unlock()
	}
	return ln, err
}

// netdAsks counts the netd requests for port.
func (r *netdRoute) netdAsks(port uint16) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ap := range r.asked {
		if ap.Port() == port {
			n++
		}
	}
	return n
}

// portOwners splits the listeners route opened on port by the binder they
// came from.
func portOwners(r *netdRoute, port uint16) (netd, inProc []netip.AddrPort) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ap := range r.viaNetd {
		if ap.Port() == port {
			netd = append(netd, ap)
		}
	}
	for _, ap := range r.inProc {
		if ap.Port() == port {
			inProc = append(inProc, ap)
		}
	}
	return netd, inProc
}

// echoDialer is a backend that echoes every byte it receives.
func echoDialer(_ context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() { defer server.Close(); _, _ = io.Copy(server, server) }()
	return client, nil
}

// TestPrivilegedPortServedOnSpecificSetViaNetd is the gate for serving a
// listed LoadBalancer port below 1024 through the root netd helper: on the
// node's own address and 127.0.0.1 with LAN access off and on the wildcard with
// it on, every listener of the port from the helper so a swap in either
// direction binds before it closes without ever meeting Darwin's cross-owner
// EADDRINUSE, an accepted connection surviving each swap; an unlisted port
// never asking the helper (in-process on the wildcard, unserved on a specific
// set, as before the list); a helper refusal of a listed port leaving only
// that Service unserved until a later reconcile is granted; and an ingress
// host port refused as reserved in both LAN states, on a worker too.
func TestPrivilegedPortServedOnSpecificSetViaNetd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	node := netip.MustParseAddr("100.64.0.1")
	node80 := netip.AddrPortFrom(node, 80)
	loop80 := netip.MustParseAddrPort("127.0.0.1:80")
	wild80 := netip.MustParseAddrPort("0.0.0.0:80")

	prepare := func(h *Hoster, addrs []netip.Addr) (*Rebind, error) {
		req := rebindRequest{addrs: addrs, reply: make(chan rebindReply, 1)}
		go h.handleRebind(ctx, req)
		r := <-req.reply
		return r.rb, r.err
	}
	newRouted := func(t *testing.T, netdDeny map[netip.AddrPort]error, addrs []netip.Addr, reserved map[int32]bool, log *slog.Logger) (*Hoster, *fake.Clientset, *netdRoute) {
		t.Helper()
		route := &netdRoute{netd: &setBinder{deny: netdDeny}, direct: &setBinder{}}
		cs := fake.NewClientset(testNodeObject(testNode, nil))
		if reserved == nil {
			reserved = map[int32]bool{}
		}
		h := newTestHoster(t, cs, testNode, route, reserved, log)
		h.cfg.PrivilegedPorts = slices.Clone(listedPorts)
		h.addrs = slices.Clone(addrs)
		h.dial = echoDialer
		return h, cs, route
	}
	sorted := func(aps ...netip.AddrPort) []netip.AddrPort {
		slices.SortFunc(aps, func(a, b netip.AddrPort) int { return a.Compare(b) })
		return aps
	}
	assertOwners := func(t *testing.T, route *netdRoute, wantNetd ...netip.AddrPort) {
		t.Helper()
		viaNetd, inProc := portOwners(route, 80)
		if len(inProc) != 0 {
			t.Errorf("port 80 was bound in-process on %v; every listener of a listed port must come from netd", inProc)
		}
		if got := sorted(viaNetd...); !slices.Equal(got, sorted(wantNetd...)) {
			t.Errorf("netd opened port 80 on %v, want %v", got, sorted(wantNetd...))
		}
	}
	refuse := func(aps ...string) map[netip.AddrPort]error {
		deny := map[netip.AddrPort]error{}
		for _, ap := range aps {
			deny[netip.MustParseAddrPort(ap)] = netdRefusal(netip.MustParseAddrPort(ap))
		}
		return deny
	}

	t.Run("with LAN access off a listed port is served on the node address and loopback via netd", func(t *testing.T) {
		t.Parallel()
		h, cs, route := newRouted(t, nil, local, nil, nil)
		www := lbService("default", "www", "10.43.0.6", 80, 8080)
		h.reconcile(ctx, []*corev1.Service{www})
		if !reportOf(t, cs, testNode).entries[reportEntry(www)] {
			t.Fatal("the service is not reported; a port of 80 the helper granted must be served")
		}
		assertOwners(t, route, loop80, node80)
		route.mu.Lock()
		networks := slices.Clone(route.networks)
		route.mu.Unlock()
		if !slices.Equal(networks, []string{"tcp4", "tcp4"}) {
			t.Errorf("svclb asked the netd leg for %v, want tcp4 for both IPv4 addresses (the wire name is the adapter's job)", networks)
		}
		route.direct.get(t, "127.0.0.1:8080")
		route.direct.get(t, "100.64.0.1:8080")
		for _, ap := range []netip.AddrPort{node80, loop80} {
			c := route.netd.get(t, ap.String()).connect(t)
			if err := echoTwice(c, "served"); err != nil {
				t.Errorf("a connection to %s was not spliced: %v", ap, err)
			}
			_ = c.Close()
		}
	})

	t.Run("LAN access swaps both ways keep one owner and an accepted connection", func(t *testing.T) {
		t.Parallel()
		h, cs, route := newRouted(t, nil, wildcard, nil, nil)
		www := lbService("default", "www", "10.43.0.6", 80)
		h.reconcile(ctx, []*corev1.Service{www})
		assertOwners(t, route, wild80)
		wild := route.netd.get(t, wild80.String())
		client := wild.connect(t)
		defer client.Close()
		if err := echoTwice(client, "before"); err != nil {
			t.Fatal(err)
		}

		rb, err := prepare(h, local)
		if err != nil {
			t.Fatalf("prepare LAN off: %v", err)
		}
		if len(rb.Unserved) != 0 {
			t.Fatalf("Unserved = %v, want none: the helper grants port 80", rb.Unserved)
		}
		if wild.isClosed() {
			t.Fatal("prepare closed the wildcard before the commit")
		}
		if err := rb.Commit(); err != nil {
			t.Fatalf("commit LAN off: %v", err)
		}
		if !wild.isClosed() {
			t.Error("the wildcard listener is still open after the LAN-off commit")
		}
		if err := echoTwice(client, "after-off"); err != nil {
			t.Fatalf("the connection accepted on the wildcard did not survive the LAN-off swap: %v", err)
		}
		assertOwners(t, route, wild80, node80, loop80)
		onNode := route.netd.get(t, node80.String())
		nodeClient := onNode.connect(t)
		defer nodeClient.Close()
		if err := echoTwice(nodeClient, "new"); err != nil {
			t.Fatalf("a new connection on %s was not spliced: %v", node80, err)
		}
		h.reconcile(ctx, []*corev1.Service{www})
		if !reportOf(t, cs, testNode).entries[reportEntry(www)] {
			t.Error("the moved service is not reported after the LAN-off swap")
		}

		rb, err = prepare(h, wildcard)
		if err != nil {
			t.Fatalf("prepare LAN on: %v", err)
		}
		if onNode.isClosed() {
			t.Fatal("prepare closed the node-address listener before the commit")
		}
		if err := rb.Commit(); err != nil {
			t.Fatalf("commit LAN on: %v", err)
		}
		if !onNode.isClosed() || !route.netd.get(t, loop80.String()).isClosed() {
			t.Error("a specific-address listener is still open after the LAN-on commit")
		}
		if err := echoTwice(nodeClient, "after-on"); err != nil {
			t.Fatalf("the connection accepted on the node address did not survive the LAN-on swap: %v", err)
		}
		assertOwners(t, route, wild80, node80, loop80, wild80)
		c := route.netd.get(t, wild80.String()).connect(t)
		defer c.Close()
		if err := echoTwice(c, "wild-again"); err != nil {
			t.Fatalf("a new connection on the wildcard was not spliced: %v", err)
		}
	})

	t.Run("an unlisted port never asks netd: in-process on the wildcard, unserved on a specific set", func(t *testing.T) {
		t.Parallel()
		h, cs, route := newRouted(t, nil, wildcard, nil, nil)
		odd := lbService("default", "odd", "10.43.0.7", 81)
		www := lbService("default", "www", "10.43.0.6", 80)
		svcs := []*corev1.Service{odd, www}
		h.reconcile(ctx, svcs)
		oddWild := route.direct.get(t, "0.0.0.0:81")
		if !reportOf(t, cs, testNode).entries[reportEntry(odd)] {
			t.Fatal("an unlisted port below 1024 is not served on the wildcard with LAN access on")
		}
		rb, err := prepare(h, local)
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		if !slices.Equal(rb.Unserved, []string{"default/odd"}) {
			t.Fatalf("Unserved = %v, want default/odd only", rb.Unserved)
		}
		if err := rb.Commit(); err != nil {
			t.Fatal(err)
		}
		if !oddWild.isClosed() {
			t.Error("the unserved service still listens on the wildcard")
		}
		h.reconcile(ctx, svcs)
		r := reportOf(t, cs, testNode)
		if r.entries[reportEntry(odd)] || !r.entries[reportEntry(www)] {
			t.Fatalf("report with LAN access off = %v, want www, not odd", r.entries)
		}
		if n := route.netdAsks(81); n != 0 {
			t.Errorf("netd was asked for the unlisted port 81 %d times, want never", n)
		}
	})

	t.Run("a refusal of a listed port is unserved and the next reconcile asks again", func(t *testing.T) {
		t.Parallel()
		// Not yet in netd's view (an unsynced or lagging Service set).
		h, cs, route := newRouted(t, refuse("100.64.0.1:443", "127.0.0.1:443", "0.0.0.0:443"), local, nil, nil)
		tls := lbService("default", "tls", "10.43.0.8", 443)
		web := lbService("default", "web", "10.43.0.5", 8080)
		svcs := []*corev1.Service{tls, web}
		h.reconcile(ctx, svcs)
		r := reportOf(t, cs, testNode)
		if r.entries[reportEntry(tls)] || !r.entries[reportEntry(web)] {
			t.Fatalf("report with 443 refused = %v, want web only", r.entries)
		}
		if _, inProc := portOwners(route, 443); len(inProc) != 0 {
			t.Fatalf("a refused listed port was bound in-process on %v", inProc)
		}
		asked := route.netdAsks(443)
		route.netd.mu.Lock()
		route.netd.deny = nil
		route.netd.mu.Unlock()
		h.reconcile(ctx, svcs)
		if route.netdAsks(443) <= asked {
			t.Fatal("the next reconcile did not ask netd again")
		}
		if !reportOf(t, cs, testNode).entries[reportEntry(tls)] {
			t.Fatal("the service is not served once netd grants the port")
		}

		// LAN on with the wildcard refused: that Service comes off the node,
		// the swap itself succeeds, and nothing is bound in-process for 443.
		route.netd.mu.Lock()
		route.netd.deny = refuse("0.0.0.0:443")
		route.netd.mu.Unlock()
		rb, err := prepare(h, wildcard)
		if err != nil {
			t.Fatalf("prepare LAN on: %v (a policy refusal must not fail the swap)", err)
		}
		if !slices.Equal(rb.Unserved, []string{"default/tls"}) {
			t.Fatalf("Unserved = %v, want default/tls only", rb.Unserved)
		}
		if err := rb.Commit(); err != nil {
			t.Fatal(err)
		}
		if route.direct.get(t, "0.0.0.0:8080").isClosed() {
			t.Error("the unprivileged service was rolled back with the refused one")
		}
		if _, inProc := portOwners(route, 443); len(inProc) != 0 {
			t.Errorf("a refused listed port was bound in-process on %v", inProc)
		}
	})

	t.Run("a refusal on first provisioning is unserved with the throttled warning", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		log := slog.New(slog.NewTextHandler(&buf, nil))
		h, cs, _ := newRouted(t, refuse("100.64.0.1:443", "127.0.0.1:443"), local, nil, log)
		tls := lbService("default", "tls", "10.43.0.8", 443)
		h.reconcile(ctx, []*corev1.Service{tls})
		if reportOf(t, cs, testNode).entries[reportEntry(tls)] {
			t.Fatal("a service whose port the helper refused is reported")
		}
		if !strings.Contains(buf.String(), "--lb-privileged-ports") {
			t.Errorf("the warning does not name the allowed-port list: %s", buf.String())
		}
	})

	t.Run("an ingress host port is reserved with LAN access on and off", func(t *testing.T) {
		t.Parallel()
		for _, addrs := range [][]netip.Addr{wildcard, local} {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			h, cs, route := newRouted(t, nil, addrs, map[int32]bool{80: true}, log)
			www := lbService("default", "www", "10.43.0.6", 80)
			h.reconcile(ctx, []*corev1.Service{www})
			if reportOf(t, cs, testNode).entries[reportEntry(www)] {
				t.Errorf("bind %v: a tenant service on the ingress host's port is reported", addrs)
			}
			if n := route.netdAsks(80); n != 0 {
				t.Errorf("bind %v: netd was asked %d times for a reserved port", addrs, n)
			}
			if !strings.Contains(buf.String(), "RESERVED") {
				t.Errorf("bind %v: no reserved-port warning: %s", addrs, buf.String())
			}
		}
	})

	t.Run("on a worker the canonical ingress Service's ports are reserved, LAN access on or off", func(t *testing.T) {
		t.Parallel()
		ingress := lbService("kube-system", "k3sm-ingress", "10.43.0.2", 80, 443)
		ingress.Labels = map[string]string{IgnoreLabel: "true"}
		for _, addrs := range [][]netip.Addr{wildcard, local} {
			var buf bytes.Buffer
			log := slog.New(slog.NewTextHandler(&buf, nil))
			// A worker: no ingress host here, so nothing flag-derived is reserved.
			h, cs, route := newRouted(t, nil, addrs, nil, log)
			h.cfg.IngressService = types.NamespacedName{Namespace: "kube-system", Name: "k3sm-ingress"}
			www := lbService("default", "www", "10.43.0.6", 80)
			web := lbService("default", "web", "10.43.0.5", 8080)

			// Before the informer has the ingress Service the tenant is served;
			// once it appears the tenant's listener is torn down.
			h.reconcile(ctx, []*corev1.Service{www, web})
			if !reportOf(t, cs, testNode).entries[reportEntry(www)] {
				t.Fatalf("bind %v: precondition: the tenant is served while no ingress Service exists", addrs)
			}
			h.reconcile(ctx, []*corev1.Service{ingress, www, web})
			r := reportOf(t, cs, testNode)
			if r.entries[reportEntry(www)] || !r.entries[reportEntry(web)] {
				t.Errorf("bind %v: report = %v, want web only: the ingress Service declares 80", addrs, r.entries)
			}
			if !strings.Contains(buf.String(), "RESERVED") || !strings.Contains(buf.String(), "k3sm-ingress") {
				t.Errorf("bind %v: no reserved-port warning naming the ingress host: %s", addrs, buf.String())
			}
			asked := route.netdAsks(80)
			h.reconcile(ctx, []*corev1.Service{ingress, www, web})
			if route.netdAsks(80) != asked {
				t.Errorf("bind %v: netd was asked again for a reserved port", addrs)
			}
			for _, ap := range []string{"0.0.0.0:80", "100.64.0.1:80", "127.0.0.1:80"} {
				route.netd.mu.Lock()
				l := route.netd.open[netip.MustParseAddrPort(ap)]
				route.netd.mu.Unlock()
				if l != nil && !l.isClosed() {
					t.Errorf("bind %v: the tenant still listens on %s", addrs, ap)
				}
			}
		}
	})

	t.Run("any other netd failure still refuses the whole swap", func(t *testing.T) {
		t.Parallel()
		down := errors.New("netd bind tcp 100.64.0.1:80: dial unix /var/run/k3sm-netd.sock: connect: connection refused")
		h, _, route := newRouted(t, map[netip.AddrPort]error{node80: down}, wildcard, nil, nil)
		www := lbService("default", "www", "10.43.0.6", 80)
		web := lbService("default", "web", "10.43.0.5", 8080)
		h.reconcile(ctx, []*corev1.Service{www, web})
		if _, err := prepare(h, local); err == nil {
			t.Fatal("prepare succeeded although the helper could not be reached")
		}
		if route.netd.get(t, wild80.String()).isClosed() || route.direct.get(t, "0.0.0.0:8080").isClosed() {
			t.Error("a refused swap closed an old listener")
		}
		if !route.direct.get(t, "100.64.0.1:8080").isClosed() {
			t.Error("a refused swap left a new listener open")
		}
		if !IsWildcard(h.BindAddrs()) {
			t.Errorf("BindAddrs after a refused swap = %v, want the wildcard", h.BindAddrs())
		}
	})
}
