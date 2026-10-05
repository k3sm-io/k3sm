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
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/linkenum"
	"k3sm.io/darwin-net/pkg/linkwatch"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
)

const (
	// linkTickInterval is how often the direct-link loop re-reads its status and
	// re-derives its spec. The loop is an in-memory heartbeat: a tick that finds
	// the spec unchanged writes nothing, so kine sees no idle churn.
	linkTickInterval = 5 * time.Second
	// linkEnumerateBackstop bounds how long the port enumeration (system_profiler,
	// the expensive half) goes un-refreshed when no link event asks for it.
	linkEnumerateBackstop = 5 * time.Minute
	// linkPublishRetry is the least time between two failed publishes, so an
	// unreachable or old control plane is asked on the mesh refresh cadence, not
	// every tick.
	linkPublishRetry = meshRefreshInterval
	// routeReadyHoldoff is how long a port whose peer stopped answering the probe
	// stays routeReady=false before the loop re-confirms its routes. Without it a
	// sleeping peer would flap the port up and down on every probe round: the
	// re-confirm succeeds locally, the resolver says up, the probe misses again.
	routeReadyHoldoff = time.Minute
)

// linkMesh is the consumer-side view of darwin-net's mesh the direct-link loop
// drives. *mesh.Mesh satisfies it.
type linkMesh interface {
	ConfigureLink(ctx context.Context, cfg mesh.LinkConfig) (netip.Addr, error)
	RemoveLink(ctx context.Context, iface string) error
	SetDirectLinkStatus(status netv1alpha1.DirectLinkStatus)
}

// directLinkConfig is the fixed configuration of one node's direct-link loop:
// its identity, its seams to the system and the control plane, and its clock.
type directLinkConfig struct {
	node     string
	podCIDR  netip.Prefix
	meshPort int
	// enumerate lists the node's Thunderbolt ports (linkenum.Exec{}.Ports).
	enumerate func(ctx context.Context) ([]linkenum.Port, error)
	// ifaceUp reports an interface's link state before any link event arrives.
	ifaceUp func(iface string) bool
	// publish writes the spec (the node-certificate verb on a worker, the
	// enroller in-process on the server).
	publish func(ctx context.Context, spec netv1alpha1.DirectLinkSpec) error
	// fetch reads the node's own DirectLink (spec and resolved status) on every
	// tick: a worker's node identity holds no read verb on DirectLink, so it asks
	// the server over its certificate. Nil when watch feeds setObject instead.
	fetch func(ctx context.Context) (*netv1alpha1.DirectLink, bool, error)
	// watch, when set, runs until ctx ends and calls sink on every change of the
	// node's own DirectLink (the server's informer over its admin client).
	watch func(ctx context.Context, sink func(*netv1alpha1.DirectLink)) error
	// statusDir is where the last resolved object is recorded for `k3sm doctor`
	// and `k3sm status` (directLinkStatusFile). Empty records nothing.
	statusDir string
	// tunnelOnly reads the node-local per-port override file (`k3sm link
	// tunnel-only`); explicit entries win over the object's own spec.
	tunnelOnly func() (tunnelOnlyOverrides, error)
	// firstContact is the server's link address a cable-only worker routes to
	// before any link state exists; the zero Addr on every other node.
	firstContact netip.Addr
	// rdmaEnabled reports whether RDMA is enabled on this Mac (rdma_ctl status).
	rdmaEnabled func() bool
	// onFacts receives every enumeration's label facts (the node's advisory
	// labels).
	onFacts func(directLinkFacts)
	log     *slog.Logger
	now     func() time.Time
}

// directLinkRuntime is one node's direct-link loop: it enumerates the node's
// cable ports, configures the cabled ones through the mesh (which removes them
// from the bridge and gives them their derived address), tracks link and route
// state, and publishes the node's DirectLink spec ONLY when it changed. It also
// carries the resolved status back into the mesh, which is what installs or
// withdraws the direct routes.
//
// Locking discipline: mu guards every field below it. No mesh call, publish or
// status read runs with mu held; the loop copies what it needs, releases, calls,
// and re-locks to record the result.
type directLinkRuntime struct {
	directLinkConfig

	kick chan struct{}

	mu            sync.Mutex
	m             linkMesh
	ports         []linkenum.Port
	enumerated    time.Time
	enumerateDue  bool
	configured    map[string]bool
	routeReady    map[string]bool
	holdoffUntil  map[string]time.Time
	linkUp        map[string]bool
	object        *netv1alpha1.DirectLink
	published     *netv1alpha1.DirectLinkSpec
	lastFailure   time.Time
	tooOldLogged  bool
	unsupported   bool
	firstContactd bool
	// peerOf is the peer link address each configured port's host route points
	// at (the first contact, then whatever the resolver names).
	peerOf map[string]netip.Addr
}

// newDirectLinkRuntime returns a runtime with its maps made.
func newDirectLinkRuntime(cfg directLinkConfig) *directLinkRuntime {
	r := &directLinkRuntime{directLinkConfig: cfg}
	r.kick = make(chan struct{}, 1)
	r.configured = map[string]bool{}
	r.routeReady = map[string]bool{}
	r.holdoffUntil = map[string]time.Time{}
	r.linkUp = map[string]bool{}
	r.peerOf = map[string]netip.Addr{}
	r.enumerateDue = true
	if r.now == nil {
		r.now = time.Now
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	return r
}

// trigger asks the loop for an immediate tick without blocking.
func (r *directLinkRuntime) trigger() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// nodeIndex is this node's index, from its pod /24.
func (r *directLinkRuntime) nodeIndex() (int, bool) {
	idx, err := podnet.NodeIndex(podnet.ClusterPodCIDR, r.podCIDR)
	return idx, err == nil
}

// linkIP is the derived address of port p, or the zero Addr when this node's
// index has none (a named NoLinkAddress, never an improvised address).
func (r *directLinkRuntime) linkIP(p linkenum.Port) netip.Addr {
	idx, ok := r.nodeIndex()
	if !ok {
		return netip.Addr{}
	}
	a, err := netv1alpha1.LinkIP(idx, p.PortOrdinal)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// observe wraps the link-event stream the mesh watcher consumes so this loop sees
// every event too: it records the link state and asks for an immediate tick (and
// a re-enumeration, since a plug or unplug is exactly when the cable changed).
func (r *directLinkRuntime) observe(src linkwatch.LinkEvents) linkwatch.LinkEvents {
	return observedLinks{src: src, on: r.onLinkEvent}
}

func (r *directLinkRuntime) onLinkEvent(ev linkwatch.Event) {
	r.mu.Lock()
	if ev.Gone {
		delete(r.linkUp, ev.Iface)
	} else {
		r.linkUp[ev.Iface] = ev.Up
	}
	r.enumerateDue = true
	r.mu.Unlock()
	r.trigger()
}

// onLiveness is the mesh's liveness callback: a peer that stopped answering the
// probe clears the port's routeReady (and the next tick republishes the spec, so
// the resolver demotes the port on both ends). The route comes back only after
// the holdoff, a re-confirmed ConfigureLink, the resolver's up and an answered
// probe.
func (r *directLinkRuntime) onLiveness(iface string, peer netip.Addr, alive bool) {
	if alive {
		return
	}
	r.mu.Lock()
	r.routeReady[iface] = false
	r.holdoffUntil[iface] = r.now().Add(routeReadyHoldoff)
	r.mu.Unlock()
	r.log.Warn("direct link peer stopped answering; its routes are withdrawn and the port is reported not ready", "iface", iface, "peer", peer.String())
	r.trigger()
}

// setObject records the node's own DirectLink as the server last resolved it and
// hands its status to the mesh when it changed.
func (r *directLinkRuntime) setObject(dl *netv1alpha1.DirectLink) {
	r.mu.Lock()
	changed := r.object == nil || !reflect.DeepEqual(r.object.Status, dl.Status)
	r.object = dl.DeepCopy()
	m := r.m
	r.mu.Unlock()
	if !changed {
		return
	}
	if m != nil {
		m.SetDirectLinkStatus(dl.Status)
		r.routeToKnownPeers(context.Background(), m, dl.Status)
	}
	if r.statusDir != "" {
		if err := writeDirectLinkStatus(r.statusDir, dl); err != nil {
			r.log.Debug("the resolved direct-link status was not recorded for doctor and status", "err", err)
		}
	}
}

// routeToKnownPeers keeps each configured port's on-link host route pointed at the
// peer the resolver names for it. The host route carries no Pod traffic (the /25
// routes do, and those stay gated on the resolver's up AND the liveness probe); it
// is what lets the probe, the wireguard handshake and the bootstrap verbs reach a
// peer that is only reachable over the cable, including after this node restarts
// and before the probe has heard anything. Without it a cable-only pair could not
// re-establish the very probe its direct routes wait on.
func (r *directLinkRuntime) routeToKnownPeers(ctx context.Context, m linkMesh, st netv1alpha1.DirectLinkStatus) {
	type job struct{ cfg mesh.LinkConfig }
	var jobs []job
	r.mu.Lock()
	for _, ps := range st.Ports {
		if ps.PeerNodeName == "" || ps.PeerLinkIP == "" || !r.configured[ps.Iface] || r.unsupported {
			continue
		}
		peer, err := netip.ParseAddr(ps.PeerLinkIP)
		if err != nil || !netv1alpha1.IsLinkAddress(peer) || r.peerOf[ps.Iface] == peer {
			continue
		}
		for _, p := range r.ports {
			if p.Iface != ps.Iface {
				continue
			}
			if ip := r.linkIP(p); ip.IsValid() {
				jobs = append(jobs, job{mesh.LinkConfig{Iface: p.Iface, PortOrdinal: p.PortOrdinal, LinkIP: ip, PeerLinkIP: peer}})
			}
		}
	}
	r.mu.Unlock()
	for _, j := range jobs {
		if _, err := m.ConfigureLink(ctx, j.cfg); err != nil {
			r.log.Warn("the host route to a cabled peer was not installed", "iface", j.cfg.Iface, "peer", j.cfg.PeerLinkIP.String(), "err", err)
			continue
		}
		r.mu.Lock()
		r.peerOf[j.cfg.Iface] = j.cfg.PeerLinkIP
		r.mu.Unlock()
	}
}

// attach hands the runtime its mesh and configures every cabled port at once,
// synchronously, so a cable-only worker's first-contact route to the server
// exists before anything dials the server. It must run after the mesh device is
// up (the helper refuses ConfigureLink until the node identity is confirmed).
func (r *directLinkRuntime) attach(ctx context.Context, m linkMesh) {
	r.mu.Lock()
	r.m = m
	r.mu.Unlock()
	r.enumerateIfDue(ctx)
	r.configurePorts(ctx)
}

// run is the loop: one tick per linkTickInterval and per trigger, until ctx ends.
func (r *directLinkRuntime) run(ctx context.Context) {
	if r.watch != nil {
		go func() {
			if err := r.watch(ctx, r.setObject); err != nil && ctx.Err() == nil {
				r.log.Warn("the node's DirectLink watch stopped; direct routes follow the last status it saw", "err", err)
			}
		}()
	}
	t := time.NewTicker(linkTickInterval)
	defer t.Stop()
	for {
		r.tickOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.kick:
		}
	}
}

// tickOnce is one pass: refresh the object (worker), re-enumerate when due,
// configure newly cabled ports and re-confirm held-off ones, then publish the
// spec if and only if it changed.
func (r *directLinkRuntime) tickOnce(ctx context.Context) {
	if r.fetch != nil {
		if dl, ok, err := r.fetch(ctx); err == nil && ok {
			r.setObject(dl)
		} else if err != nil && !errors.Is(err, bootstrap.ErrServerTooOld) {
			r.log.Debug("direct link status not read; keeping the last one", "err", err)
		}
	}
	r.enumerateIfDue(ctx)
	r.configurePorts(ctx)
	r.publishIfChanged(ctx)
}

// enumerateIfDue re-reads the ports when a link event asked for it or the
// backstop expired.
func (r *directLinkRuntime) enumerateIfDue(ctx context.Context) {
	r.mu.Lock()
	due := r.enumerateDue || r.now().Sub(r.enumerated) >= linkEnumerateBackstop
	r.mu.Unlock()
	if !due {
		return
	}
	ports, err := r.enumerate(ctx)
	if err != nil {
		if errors.Is(err, linkenum.ErrNoThunderboltService) {
			r.log.Debug("no Thunderbolt hardware port is listed; this node has no direct links", "err", err)
		} else {
			r.log.Warn("direct-link ports not enumerated; keeping the last enumeration", "err", err)
			return
		}
		ports = nil
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].PortOrdinal < ports[j].PortOrdinal })
	r.mu.Lock()
	r.ports = ports
	r.enumerated = r.now()
	r.enumerateDue = false
	for _, p := range ports {
		if _, ok := r.linkUp[p.Iface]; !ok && r.ifaceUp != nil {
			r.linkUp[p.Iface] = r.ifaceUp(p.Iface)
		}
	}
	r.mu.Unlock()
	if r.onFacts != nil {
		rdma := r.rdmaEnabled != nil && r.rdmaEnabled()
		r.onFacts(factsFromPorts(ports, rdma))
	}
}

// configurePorts runs ConfigureLink for every cabled port not yet configured, and
// for every held-off port whose holdoff ended. The first cabled port of a
// cable-only worker carries the first-contact route to the server.
func (r *directLinkRuntime) configurePorts(ctx context.Context) {
	type job struct {
		cfg mesh.LinkConfig
	}
	r.mu.Lock()
	m := r.m
	if m == nil || r.unsupported {
		r.mu.Unlock()
		return
	}
	now := r.now()
	var jobs []job
	for _, p := range r.ports {
		if p.PeerDomainUUID == "" && !r.configured[p.Iface] {
			continue // nothing cabled here; the bridge keeps it
		}
		held, isHeld := r.holdoffUntil[p.Iface]
		if isHeld && now.Before(held) {
			continue // held off: a dead peer, or a configure that just failed
		}
		if r.configured[p.Iface] && !isHeld {
			continue
		}
		ip := r.linkIP(p)
		if !ip.IsValid() {
			continue
		}
		// The peer the port's host route already points at is always re-sent: the
		// helper treats a ConfigureLink naming no peer as a re-point and would
		// withdraw that route.
		cfg := mesh.LinkConfig{Iface: p.Iface, PortOrdinal: p.PortOrdinal, LinkIP: ip, PeerLinkIP: r.peerOf[p.Iface]}
		if r.firstContact.IsValid() && !r.firstContactd && p.PeerDomainUUID != "" {
			cfg.PeerLinkIP = r.firstContact
		}
		jobs = append(jobs, job{cfg: cfg})
	}
	r.mu.Unlock()

	for _, j := range jobs {
		_, err := m.ConfigureLink(ctx, j.cfg)
		r.mu.Lock()
		switch {
		case errors.Is(err, mesh.ErrLinksUnsupported):
			r.unsupported = true
			r.mu.Unlock()
			r.log.Info("the network helper predates direct links; this node runs over the tunnel only")
			return
		case err != nil:
			r.routeReady[j.cfg.Iface] = false
			r.holdoffUntil[j.cfg.Iface] = r.now().Add(linkPublishRetry)
			r.log.Warn("direct-link port not configured; it is reported not ready and retried", "iface", j.cfg.Iface, "retryIn", linkPublishRetry, "err", err)
		default:
			wasReady := r.routeReady[j.cfg.Iface]
			r.configured[j.cfg.Iface] = true
			r.routeReady[j.cfg.Iface] = true
			delete(r.holdoffUntil, j.cfg.Iface)
			if j.cfg.PeerLinkIP.IsValid() {
				r.firstContactd = true
				r.peerOf[j.cfg.Iface] = j.cfg.PeerLinkIP
			}
			if !wasReady {
				r.log.Info("direct-link port configured: out of the bridge, address and routes read back", "iface", j.cfg.Iface, "linkIP", j.cfg.LinkIP.String(), "firstContact", j.cfg.PeerLinkIP.String())
			}
		}
		r.mu.Unlock()
	}
}

// contact installs the first-contact host route toward a node that just joined
// over the cable on iface: the server's half of the cold start (the joiner routes
// to the server from its join response). The port is configured now if it was
// not, with peer as the cable's other end.
func (r *directLinkRuntime) contact(ctx context.Context, iface string, peer netip.Addr) {
	r.mu.Lock()
	m := r.m
	var port *linkenum.Port
	for i := range r.ports {
		if r.ports[i].Iface == iface {
			port = &r.ports[i]
		}
	}
	r.mu.Unlock()
	if m == nil || port == nil {
		return
	}
	ip := r.linkIP(*port)
	if !ip.IsValid() {
		return
	}
	if _, err := m.ConfigureLink(ctx, mesh.LinkConfig{Iface: iface, PortOrdinal: port.PortOrdinal, LinkIP: ip, PeerLinkIP: peer}); err != nil {
		r.log.Warn("the first-contact route to a node that joined over the cable was not installed", "iface", iface, "peer", peer.String(), "err", err)
		return
	}
	r.mu.Lock()
	r.configured[iface] = true
	r.routeReady[iface] = true
	r.peerOf[iface] = peer
	r.mu.Unlock()
	r.log.Info("first-contact route to a node that joined over the cable", "iface", iface, "peer", peer.String())
	r.trigger()
}

// buildSpec derives the node's DirectLink spec from the current state. It is the
// whole change detector's input: two equal specs are one write.
func (r *directLinkRuntime) buildSpec() netv1alpha1.DirectLinkSpec {
	var overrides tunnelOnlyOverrides
	if r.tunnelOnly != nil {
		if o, err := r.tunnelOnly(); err == nil {
			overrides = o
		} else {
			r.log.Warn("the tunnel-only override file could not be read; ignoring it", "err", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	objTunnel := map[string]bool{}
	if r.object != nil {
		for _, p := range r.object.Spec.Ports {
			objTunnel[p.Iface] = p.TunnelOnly
		}
	}
	spec := netv1alpha1.DirectLinkSpec{
		SchemaVersion: netv1alpha1.DirectLinkSchemaVersion,
		NodeName:      r.node,
		Medium:        netv1alpha1.MediumThunderbolt,
	}
	for _, p := range r.ports {
		port := netv1alpha1.DirectLinkPort{
			Iface:          p.Iface,
			PortOrdinal:    int32(p.PortOrdinal),
			DomainUUID:     p.DomainUUID,
			PeerDomainUUID: p.PeerDomainUUID,
			SpeedGbps:      int32(p.SpeedGbps),
			RDMADevice:     p.RDMADevice,
			LinkUp:         r.linkUp[p.Iface],
			RouteReady:     r.routeReady[p.Iface] && r.configured[p.Iface],
			TunnelOnly:     overrides.resolve(p.Iface, objTunnel[p.Iface]),
		}
		if ip := r.linkIP(p); ip.IsValid() {
			port.LinkIP = ip.String()
		}
		spec.Ports = append(spec.Ports, port)
	}
	return spec
}

// publishIfChanged writes the spec when it differs from the last one written,
// and not sooner than linkPublishRetry after a failure.
func (r *directLinkRuntime) publishIfChanged(ctx context.Context) {
	spec := r.buildSpec()
	r.mu.Lock()
	same := r.published != nil && reflect.DeepEqual(*r.published, spec)
	backoff := !r.lastFailure.IsZero() && r.now().Sub(r.lastFailure) < linkPublishRetry
	r.mu.Unlock()
	if same || backoff {
		return
	}
	err := r.publish(ctx, spec)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.lastFailure = r.now()
		if errors.Is(err, bootstrap.ErrServerTooOld) {
			if !r.tooOldLogged {
				r.tooOldLogged = true
				r.log.Info("the control plane is older than direct links; this node runs over the tunnel only until it is upgraded", "err", err)
			}
			return
		}
		r.log.Warn("direct link spec not published; retrying", "err", err)
		return
	}
	r.lastFailure = time.Time{}
	r.published = &spec
}

// directCandidates are this node's direct endpoint candidates: one per
// configured port with an address, at the mesh port, lowest ordinal first.
func (r *directLinkRuntime) directCandidates() []netv1.EndpointCandidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []netv1.EndpointCandidate
	for _, p := range r.ports {
		if !r.configured[p.Iface] {
			continue
		}
		ip := r.linkIP(p)
		if !ip.IsValid() {
			continue
		}
		out = append(out, netv1.EndpointCandidate{Address: net.JoinHostPort(ip.String(), strconv.Itoa(r.meshPort)), Link: netv1.EndpointLinkDirect})
	}
	return out
}

// configuredPorts returns the interfaces this node configured (out of the bridge,
// addressed), in ordinal order: where the server sends beacons and opens its
// link-local join listeners.
func (r *directLinkRuntime) configuredPorts() []linkenum.Port {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []linkenum.Port
	for _, p := range r.ports {
		if r.configured[p.Iface] {
			out = append(out, p)
		}
	}
	return out
}

// observedLinks is a LinkEvents that reports every event to on before passing it
// to its consumer.
type observedLinks struct {
	src linkwatch.LinkEvents
	on  func(linkwatch.Event)
}

func (o observedLinks) Events(ctx context.Context) <-chan linkwatch.Event {
	in := o.src.Events(ctx)
	out := make(chan linkwatch.Event, 64)
	go func() {
		defer close(out)
		for ev := range in {
			o.on(ev)
			select {
			case out <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// candidatesFor is the endpoint candidate list a node publishes: its underlay
// endpoint (unless the endpoint is itself a direct-link address, which an underlay
// candidate may never carry) followed by its direct candidates.
func candidatesFor(endpoint string, direct []netv1.EndpointCandidate) []netv1.EndpointCandidate {
	var out []netv1.EndpointCandidate
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		if a, err := netip.ParseAddr(host); err != nil || !netv1alpha1.IsLinkAddress(a) {
			out = append(out, netv1.EndpointCandidate{Address: endpoint, Link: netv1.EndpointLinkUnderlay})
		}
	}
	return append(out, direct...)
}
