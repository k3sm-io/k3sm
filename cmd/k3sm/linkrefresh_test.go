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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/linkwatch"
	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// fakeLinkMesh records ConfigureLink calls and can refuse them.
type fakeLinkMesh struct {
	mu        sync.Mutex
	calls     []mesh.LinkConfig
	err       error
	statuses  []netv1alpha1.DirectLinkStatus
	unsupport bool
}

func (m *fakeLinkMesh) ConfigureLink(_ context.Context, cfg mesh.LinkConfig) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, cfg)
	if m.unsupport {
		return netip.Addr{}, mesh.ErrLinksUnsupported
	}
	if m.err != nil {
		return netip.Addr{}, m.err
	}
	return cfg.LinkIP, nil
}

func (m *fakeLinkMesh) RemoveLink(context.Context, string) error { return nil }

func (m *fakeLinkMesh) SetDirectLinkStatus(st netv1alpha1.DirectLinkStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, st)
}

func (m *fakeLinkMesh) configured() []mesh.LinkConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mesh.LinkConfig(nil), m.calls...)
}

// linkFixture is a runtime over fakes: two Thunderbolt ports, en2 cabled.
type linkFixture struct {
	rt        *directLinkRuntime
	m         *fakeLinkMesh
	clock     *time.Time
	ports     []linkenum.Port
	published []netv1alpha1.DirectLinkSpec
	pubErr    error
}

func newLinkFixture(t *testing.T, podCIDR string, first netip.Addr) *linkFixture {
	t.Helper()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	f := &linkFixture{m: &fakeLinkMesh{}, clock: &now}
	f.ports = []linkenum.Port{
		{Iface: "en2", PortOrdinal: 0, DomainUUID: "uuid-a", PeerDomainUUID: "uuid-peer", SpeedGbps: 40},
		{Iface: "en3", PortOrdinal: 1, DomainUUID: "uuid-b", SpeedGbps: 40},
	}
	f.rt = newDirectLinkRuntime(directLinkConfig{
		node:      "worker-1",
		podCIDR:   netip.MustParsePrefix(podCIDR),
		meshPort:  51820,
		enumerate: func(context.Context) ([]linkenum.Port, error) { return append([]linkenum.Port(nil), f.ports...), nil },
		ifaceUp:   func(iface string) bool { return iface == "en2" },
		publish: func(_ context.Context, spec netv1alpha1.DirectLinkSpec) error {
			if f.pubErr != nil {
				return f.pubErr
			}
			f.published = append(f.published, spec)
			return nil
		},
		firstContact: first,
		now:          func() time.Time { return *f.clock },
		log:          quietLogger(),
	})
	return f
}

func (f *linkFixture) advance(d time.Duration) { *f.clock = f.clock.Add(d) }

// TestDirectLinkRefresherWritesOnlyOnChange is the write-on-change gate: an idle
// loop writes the DirectLink spec once and then never again, and each real change
// (a link event, a lost peer, a re-confirmed port) is exactly one write.
func TestDirectLinkRefresherWritesOnlyOnChange(t *testing.T) {
	ctx := context.Background()
	f := newLinkFixture(t, "100.64.1.0/24", netip.Addr{})
	f.rt.attach(ctx, f.m)
	for range 5 {
		f.rt.tickOnce(ctx)
		f.advance(linkTickInterval)
	}
	if len(f.published) != 1 {
		t.Fatalf("an idle loop published %d times over five ticks, want once (no kine churn)", len(f.published))
	}
	spec := f.published[0]
	if spec.NodeName != "worker-1" || spec.Medium != netv1alpha1.MediumThunderbolt || len(spec.Ports) != 2 {
		t.Fatalf("published spec = %+v", spec)
	}
	en2, en3 := spec.Ports[0], spec.Ports[1]
	// Index 1, port 0 and port 1: 169.254.0.9 and .10.
	if en2.LinkIP != "169.254.0.9" || en3.LinkIP != "169.254.0.10" {
		t.Errorf("link IPs = %s, %s; want the derived 169.254.0.9 and 169.254.0.10", en2.LinkIP, en3.LinkIP)
	}
	if !en2.LinkUp || !en2.RouteReady || en3.LinkUp || en3.RouteReady {
		t.Errorf("en2 up/ready = %v/%v (want true/true: cabled and configured); en3 = %v/%v (want false/false: nothing cabled)", en2.LinkUp, en2.RouteReady, en3.LinkUp, en3.RouteReady)
	}
	if err := spec.ValidateWithIndex(1); err != nil {
		t.Errorf("the published spec does not validate against its own index: %v", err)
	}
	if got := f.m.configured(); len(got) != 1 || got[0].Iface != "en2" || got[0].PortOrdinal != 0 || got[0].LinkIP != netip.MustParseAddr("169.254.0.9") {
		t.Errorf("ConfigureLink calls = %+v, want one for the cabled en2 only", got)
	}

	// A link event is a change: one more write.
	f.rt.onLinkEvent(linkwatch.Event{Iface: "en2", Up: false})
	f.rt.tickOnce(ctx)
	if len(f.published) != 2 || f.published[1].Ports[0].LinkUp {
		t.Fatalf("after en2 went down: %d writes (want 2) with en2 linkUp %v", len(f.published), f.published[len(f.published)-1].Ports[0].LinkUp)
	}
	f.rt.tickOnce(ctx)
	if len(f.published) != 2 {
		t.Fatalf("the same state after the event wrote again (%d writes)", len(f.published))
	}

	// A peer that stops answering clears routeReady: one write; the holdoff then
	// keeps it cleared (no flapping writes); after it the port is re-confirmed.
	f.rt.onLinkEvent(linkwatch.Event{Iface: "en2", Up: true})
	f.rt.tickOnce(ctx)
	writes := len(f.published)
	f.rt.onLiveness("en2", netip.MustParseAddr("169.254.0.1"), false)
	f.rt.tickOnce(ctx)
	if len(f.published) != writes+1 || f.published[len(f.published)-1].Ports[0].RouteReady {
		t.Fatalf("a dead peer did not republish routeReady=false (writes %d -> %d)", writes, len(f.published))
	}
	before := len(f.m.configured())
	f.advance(routeReadyHoldoff / 2)
	f.rt.tickOnce(ctx)
	if len(f.m.configured()) != before || len(f.published) != writes+1 {
		t.Fatalf("the port was re-confirmed inside its holdoff")
	}
	f.advance(routeReadyHoldoff)
	f.rt.tickOnce(ctx)
	if len(f.m.configured()) != before+1 || !f.published[len(f.published)-1].Ports[0].RouteReady {
		t.Fatalf("after the holdoff the port was not re-confirmed and republished ready")
	}
}

// TestDirectLinkRefresherRetriesAFailedPublishOnTheSlowCadence pins the backoff:
// an unreachable or old control plane is asked again only after
// linkPublishRetry, and ErrServerTooOld is not an error loop.
func TestDirectLinkRefresherRetriesAFailedPublishOnTheSlowCadence(t *testing.T) {
	ctx := context.Background()
	f := newLinkFixture(t, "100.64.1.0/24", netip.Addr{})
	f.rt.attach(ctx, f.m)
	attempts := 0
	f.rt.publish = func(context.Context, netv1alpha1.DirectLinkSpec) error {
		attempts++
		return fmt.Errorf("%w: test", bootstrap.ErrServerTooOld)
	}
	f.rt.tickOnce(ctx)
	f.advance(linkTickInterval)
	f.rt.tickOnce(ctx)
	if attempts != 1 {
		t.Fatalf("attempts within the retry window = %d, want 1", attempts)
	}
	f.advance(linkPublishRetry)
	f.rt.tickOnce(ctx)
	if attempts != 2 {
		t.Fatalf("attempts after the retry window = %d, want 2", attempts)
	}
}

// TestDirectLinkFirstContactRoute pins the cable-only cold start: the first
// cabled port's ConfigureLink carries the server's link address, once.
func TestDirectLinkFirstContactRoute(t *testing.T) {
	ctx := context.Background()
	server := netip.MustParseAddr("169.254.0.1")
	f := newLinkFixture(t, "100.64.1.0/24", server)
	f.rt.attach(ctx, f.m)
	got := f.m.configured()
	if len(got) != 1 || got[0].PeerLinkIP != server {
		t.Fatalf("first ConfigureLink = %+v, want the first-contact PeerLinkIP %s", got, server)
	}
	if c := f.rt.directCandidates(); len(c) != 1 || c[0].Address != "169.254.0.9:51820" || c[0].Link != netv1.EndpointLinkDirect {
		t.Fatalf("direct candidates = %+v", c)
	}
}

// TestDirectLinkOldHelperRunsTunnelOnly pins the degrade: a helper that predates
// direct links is asked once and never again, and no port is reported ready.
func TestDirectLinkOldHelperRunsTunnelOnly(t *testing.T) {
	ctx := context.Background()
	f := newLinkFixture(t, "100.64.1.0/24", netip.Addr{})
	f.m.unsupport = true
	f.rt.attach(ctx, f.m)
	f.rt.tickOnce(ctx)
	f.rt.tickOnce(ctx)
	if n := len(f.m.configured()); n != 1 {
		t.Fatalf("ConfigureLink calls against an old helper = %d, want 1", n)
	}
	if len(f.published) != 1 || f.published[0].Ports[0].RouteReady {
		t.Fatalf("an old helper's node reported a ready route: %+v", f.published)
	}
}

// TestDirectLinkTunnelOnlyOverride pins the kill switch: the node-local file wins
// over the object's own spec, and the object's value applies when the file is
// silent.
func TestDirectLinkTunnelOnlyOverride(t *testing.T) {
	ctx := context.Background()
	f := newLinkFixture(t, "100.64.1.0/24", netip.Addr{})
	f.rt.attach(ctx, f.m)
	obj := &netv1alpha1.DirectLink{Spec: netv1alpha1.DirectLinkSpec{Ports: []netv1alpha1.DirectLinkPort{{Iface: "en2", TunnelOnly: true}}}}
	f.rt.setObject(obj)
	f.rt.tickOnce(ctx)
	if !f.published[len(f.published)-1].Ports[0].TunnelOnly {
		t.Fatal("an administrator's tunnelOnly on the object was not carried into the node's spec")
	}
	off := false
	f.rt.tunnelOnly = func() (tunnelOnlyOverrides, error) {
		return tunnelOnlyOverrides{Ifaces: map[string]bool{"en2": off}}, nil
	}
	f.rt.tickOnce(ctx)
	if f.published[len(f.published)-1].Ports[0].TunnelOnly {
		t.Fatal("an explicit node-local override did not win over the object")
	}
	if got := applyTunnelOnly(tunnelOnlyOverrides{Ifaces: map[string]bool{"en2": true}}, true, nil, false); got.All == nil || *got.All || len(got.Ifaces) != 0 {
		t.Fatalf("--all --off = %+v, want one All=false and no per-port entries", got)
	}
}

func TestCandidatesFor(t *testing.T) {
	direct := []netv1.EndpointCandidate{{Address: "169.254.0.9:51820", Link: netv1.EndpointLinkDirect}}
	got := candidatesFor("192.0.2.10:51820", direct)
	if len(got) != 2 || got[0].Link != netv1.EndpointLinkUnderlay || got[1].Link != netv1.EndpointLinkDirect {
		t.Fatalf("candidates = %+v", got)
	}
	// A cable-only node's endpoint is its direct address: it never rides as an
	// underlay candidate (apis refuses a reserved-half underlay address).
	got = candidatesFor("169.254.0.9:51820", direct)
	if len(got) != 1 || got[0].Link != netv1.EndpointLinkDirect {
		t.Fatalf("cable-only candidates = %+v", got)
	}
	spec := netv1.MeshPeerSpec{NodeName: "n", PublicKey: "k", Endpoint: "169.254.0.9:51820", Endpoints: got, PodCIDR: "100.64.1.0/24", AllowedIPs: []string{"100.64.1.0/24"}}.WithDefaults()
	if err := spec.Validate(); err != nil {
		t.Fatalf("a cable-only MeshPeer does not validate: %v", err)
	}
}

func TestPostJoinBootstrapHost(t *testing.T) {
	rows := []struct{ server, join, link, want string }{
		{"192.0.2.1", "192.0.2.1:9345", "169.254.0.1", "192.0.2.1:9345"},
		{"fe80::1%bridge0", "[fe80::1%bridge0]:9345", "169.254.0.1", "169.254.0.1:9345"},
		{"", "169.254.0.1:9345", "169.254.0.1", "169.254.0.1:9345"},
		{"fe80::1%bridge0", "[fe80::1%bridge0]:9345", "", "[fe80::1%bridge0]:9345"},
	}
	for _, r := range rows {
		if got := postJoinBootstrapHost(r.server, r.join, r.link); got != r.want {
			t.Errorf("postJoinBootstrapHost(%q, %q, %q) = %q, want %q", r.server, r.join, r.link, got, r.want)
		}
	}
	if got := bootstrap.HTTPSURL("[fe80::1%en2]:9345"); got != "https://[fe80::1%25en2]:9345" {
		t.Errorf("HTTPSURL zoned = %q", got)
	}
}

// TestHARefusesDirectLinkAddress is the R9 gate: an HA server flag naming a
// zoned link-local literal or a reserved-half address is refused with the named
// error, and an ordinary LAN address is not.
func TestHARefusesDirectLinkAddress(t *testing.T) {
	rows := []struct {
		name string
		opts serverOptions
		want bool
	}{
		{"cluster-init with a reserved-half node IP", serverOptions{clusterInit: true, nodeIP: "169.254.0.1"}, true},
		{"cluster-init with a zoned node IP", serverOptions{clusterInit: true, nodeIP: "fe80::1%en2"}, true},
		{"server-join with a zoned server", serverOptions{serverJoin: true, nodeIP: "192.0.2.20", joinServer: "fe80::1%en2"}, true},
		{"server-join with a reserved-half server", serverOptions{serverJoin: true, nodeIP: "192.0.2.20", joinServer: "169.254.255.9"}, true},
		{"a LAN address is accepted", serverOptions{serverJoin: true, nodeIP: "192.0.2.20", joinServer: "192.0.2.21"}, false},
		{"a self-assigned 169.254 address is not this refusal", serverOptions{clusterInit: true, nodeIP: "169.254.17.3"}, false},
	}
	for _, r := range rows {
		err := r.opts.validateEtcdFlags()
		if got := errors.Is(err, errHADirectLinkAddress); got != r.want {
			t.Errorf("%s: validateEtcdFlags = %v, refusal %v want %v", r.name, err, got, r.want)
		}
	}
}

// TestDirectLinkRoutesToTheResolvedPeer pins the host route toward the peer the
// resolver names: it is installed from the status alone (the probe and the
// handshake ride it), and every later re-confirmation of the port re-sends it,
// because a ConfigureLink naming no peer would withdraw it.
func TestDirectLinkRoutesToTheResolvedPeer(t *testing.T) {
	ctx := context.Background()
	f := newLinkFixture(t, "100.64.0.0/24", netip.Addr{})
	f.rt.attach(ctx, f.m)
	peer := netip.MustParseAddr("169.254.0.9")
	f.rt.setObject(&netv1alpha1.DirectLink{Status: netv1alpha1.DirectLinkStatus{Ports: []netv1alpha1.DirectLinkPortStatus{
		{Iface: "en2", PeerNodeName: "worker-1", PeerLinkIP: peer.String(), State: netv1alpha1.DirectLinkStateDown},
	}}})
	calls := f.m.configured()
	if last := calls[len(calls)-1]; last.Iface != "en2" || last.PeerLinkIP != peer {
		t.Fatalf("last ConfigureLink = %+v, want the host route to %s", last, peer)
	}
	if len(f.m.statuses) != 1 {
		t.Fatalf("the status reached the mesh %d times, want once", len(f.m.statuses))
	}
	f.rt.onLiveness("en2", peer, false)
	f.advance(routeReadyHoldoff + time.Second)
	f.rt.tickOnce(ctx)
	calls = f.m.configured()
	if last := calls[len(calls)-1]; last.PeerLinkIP != peer {
		t.Fatalf("the re-confirmation dropped the peer (%+v): the helper would withdraw the host route", last)
	}
}
