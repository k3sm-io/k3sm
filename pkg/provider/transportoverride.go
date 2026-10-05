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

package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/darwin-net/pkg/proxy"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TransportOverrideSink is the Service-proxy seam a vm pod's LIVE TRANSPORT
// address is published through: darwin-net's *proxy.RoutingTable satisfies it
// (RoutingTable.SetTransportOverrides). It is declared HERE, at the consumer, per
// the standards — the provider is the only component that holds both halves of a
// vm pod's two-address identity, so it is the only one that can feed the map.
//
// The map is PUBLISHED address -> the pod's transport (its LIVE address and its
// declared TCP container ports), and it is REPLACED WHOLESALE on every call: the
// table drops the previous generation entire, which is what makes the feeder's
// liveness obligation cheap to discharge (see transportFeed). The same call is
// what installs and removes the node's published-address relay for the pod
// (darwin-net pkg/proxy podrelay.go): a generation that drops a pod closes its
// relay listeners and connections before it returns.
type TransportOverrideSink interface {
	SetTransportOverrides(overrides map[netip.Addr]proxy.VMPodTransport)
}

// transportLease is one vm pod's two addresses and the ports its published
// address is relayed on. published is the /32 the node's IPAM carved for the pod
// — its cluster identity, which EndpointSlices, DNS and status.podIP carry, and
// which the node aliases on lo0 for the pod's lifetime so the proxy's relay can
// answer on it. live is the address the guest's DHCP client leased on the node's
// NAT segment, as the guest agent reported it through runtimed's PodStatus. They
// are never interchangeable and are never reconciled into one address. ports is
// the pod's declared TCP container ports, sorted and de-duplicated (see
// DeclaredTCPPorts), so an unchanged spec compares equal and never republishes.
type transportLease struct {
	published netip.Addr
	live      netip.Addr
	ports     []uint16
}

// equal reports whether l and o describe the same transport. The port lists are
// canonical (DeclaredTCPPorts), so element-wise equality is set equality.
func (l transportLease) equal(o transportLease) bool {
	return l.published == o.published && l.live == o.live && slices.Equal(l.ports, o.ports)
}

// DeclaredTCPPorts returns the TCP ports pod declares, sorted ascending and
// de-duplicated, with zero and out-of-range values dropped. It reads the regular
// containers and the restartable (native sidecar) init containers, the ones that
// run beside them for the pod's life; a plain init container has exited before
// the pod serves, so a port it declares is never relayed. A port whose protocol
// is unset counts as TCP, as the API defaults it.
//
// The result is deterministic so the feed's change test is exact and the relay
// sees one canonical list. The node's relay refuses a pod whose port set (this
// list together with the Service-targeted ports) is over its per-pod cap, 32
// ports, rather than relaying a truncated subset; that ceiling is the relay's to
// enforce and is documented in docs/user/limitations.md, so the list is never
// trimmed here.
//
// It is exported for the one other reader that must agree with the feed: the
// root k3sm-netd's privileged-port authorizer, which admits a <1024 relay bind
// on a vm pod's published address only on a port this function (or a Service)
// lists for that pod.
func DeclaredTCPPorts(pod *corev1.Pod) []uint16 {
	if pod == nil {
		return nil
	}
	var out []uint16
	add := func(cs []corev1.Container, sidecarsOnly bool) {
		for i := range cs {
			c := &cs[i]
			if sidecarsOnly && (c.RestartPolicy == nil || *c.RestartPolicy != corev1.ContainerRestartPolicyAlways) {
				continue
			}
			for _, p := range c.Ports {
				if p.Protocol != "" && p.Protocol != corev1.ProtocolTCP {
					continue
				}
				if p.ContainerPort < 1 || p.ContainerPort > 65535 {
					continue
				}
				out = append(out, uint16(p.ContainerPort))
			}
		}
	}
	add(pod.Spec.Containers, false)
	add(pod.Spec.InitContainers, true)
	slices.Sort(out)
	return slices.Compact(out)
}

// transportFeed is the provider's half of the two-address model: it holds the
// per-pod lease state and pushes the derived published->live map into the Service
// proxy. A nil *transportFeed is the inert feed (no sink configured — the
// --network none / no-datapath posture), and every method tolerates it, so no
// caller needs a nil check.
//
// THE LIVENESS OBLIGATION IS OURS, not the table's (see
// proxy.RoutingTable.SetTransportOverrides): a DHCP lease is not an identity, so
// a stale override dials an address that now belongs to a DIFFERENT guest — a
// cross-pod misdelivery, not a failed dial. The feed therefore REPLACES an entry
// the moment a pod's reported lease changes and DROPS it the moment the pod dies
// or reports no lease.
//
// Locking discipline: mu guards leases AND serializes the sink push, which is
// deliberately made UNDER the lock. The sink is a leaf (an atomic map swap that
// never calls back into the provider), so there is no re-entrancy hazard; and
// holding the lock across the push is what makes generation inversion impossible
// — two concurrent observations can never land their maps out of order, which
// would leave the table holding a superseded generation forever. Ordering here is
// a correctness property, not a performance one.
//
// The map is DERIVED WHOLE from the tracked lease state on every change, never
// mutated incrementally: the shared map the sink took ownership of is never
// touched again, and a lost delete cannot survive as a stale override.
type transportFeed struct {
	sink TransportOverrideSink
	log  *slog.Logger

	mu     sync.Mutex
	leases map[string]transportLease // pod id -> its two addresses
}

// newTransportFeed returns the feed publishing into sink, or nil when no sink is
// configured (the inert feed — see the type comment).
func newTransportFeed(sink TransportOverrideSink, log *slog.Logger) *transportFeed {
	if sink == nil {
		return nil
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &transportFeed{sink: sink, log: log, leases: map[string]transportLease{}}
}

// observe records podID's published/live pair and its declared TCP ports (in the
// canonical form DeclaredTCPPorts returns) and republishes when any of them
// changed. An unchanged report is a no-op: a vm pod's status is re-observed on
// every stream event and every resync tick, and re-pushing an identical map would
// churn the table's override generation, and the relay's, for nothing.
func (f *transportFeed) observe(podID string, published, live netip.Addr, ports []uint16) {
	if f == nil {
		return
	}
	next := transportLease{published: published, live: live, ports: slices.Clone(ports)}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.leases[podID]; ok && cur.equal(next) {
		return
	}
	f.leases[podID] = next
	f.log.Info("vm pod transport override installed",
		"pod", podID, "published", published.String(), "live", live.String(), "ports", ports)
	f.republishLocked()
}

// drop removes podID's override and republishes, if it had one. It is the
// death/lease-loss half of the liveness obligation and is idempotent, so every
// path that can end a pod may call it unconditionally. When it returns, the sink
// has taken the generation without the pod, which closes the pod's relay
// listeners and every connection they were relaying; that is what lets a caller
// remove the published alias right after it (releasePodNetwork).
func (f *transportFeed) drop(podID string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.leases[podID]; !ok {
		return
	}
	delete(f.leases, podID)
	f.log.Info("vm pod transport override dropped", "pod", podID)
	f.republishLocked()
}

// has reports whether podID currently holds an override — the exact predicate
// observeTransport maintains, read back under the same lock, so the readiness
// gate and the Service proxy can never disagree about whether a pod is dialable.
//
// A nil (inert) feed holds no leases and answers false. The readiness gate's
// no-sink case is decided at its own call site (transportGateFor) rather than
// here, because "this node runs no Service proxy" and "this pod has no lease"
// are different facts and only the latter belongs in the lease map.
func (f *transportFeed) has(podID string) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.leases[podID]
	return ok
}

// live returns podID's LIVE transport address — the lease the guest reported and
// the value the Service proxy's override map carries for it — and whether one is
// held at all. It reads the SAME map has and republishLocked read, under the same
// lock, so the probe dial (probeDialFor), the readiness gate and the proxy can
// never disagree about where a pod is dialable.
//
// A nil (inert) feed holds no leases and answers false; its callers decide what
// that means for them, exactly as has documents.
func (f *transportFeed) live(podID string) (netip.Addr, bool) {
	if f == nil {
		return netip.Addr{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.leases[podID]
	if !ok {
		return netip.Addr{}, false
	}
	return l.live, true
}

// republishLocked derives the FULL current map from the tracked lease state and
// hands it to the sink in one call, so the proxy's dial override and its relay
// port sets always change together. Each value carries its own copy of the port
// list: the sink takes ownership of the map, and the tracked state must never
// share a backing array with it. Callers hold mu.
func (f *transportFeed) republishLocked() {
	next := make(map[netip.Addr]proxy.VMPodTransport, len(f.leases))
	for _, l := range f.leases {
		next[l.published] = proxy.VMPodTransport{Live: l.live, Ports: slices.Clone(l.ports)}
	}
	f.sink.SetTransportOverrides(next)
}

// guestAddressSource is the optional slice of the pod-network seam the transport
// feed reads a vm pod's PUBLISHED /32 back from — *PodNetAdapter's record of what
// SetupGuest allocated. It is an optional interface rather than a PodNetwork
// method because it is a READ of state the seam already keeps for runtimed's
// GuestNetworker, and a no-datapath deployment has no such state at all.
type guestAddressSource interface {
	GuestNetwork(podID string) (sandbox.GuestNetworkConfig, bool)
}

// guestNetwork returns the guest config the pod-network seam recorded for podID,
// comma-ok. false means "not a vm pod on this node" — either the seam records no
// guest for it (a host-process pod), the pod's network was already torn down, or
// the deployment runs no adapter at all.
func (r *runtimedRuntime) guestNetwork(podID string) (sandbox.GuestNetworkConfig, bool) {
	src, ok := r.network.(guestAddressSource)
	if !ok {
		return sandbox.GuestNetworkConfig{}, false
	}
	return src.GuestNetwork(podID)
}

// observeTransport feeds the Service proxy one vm pod's live transport address
// from a runtimed PodStatus, together with the TCP ports pod declares (the ports
// the node relays the pod's published address on). It runs from buildStatus, the convergence point
// every status observation passes through (the watch stream, the resync
// backstop, a direct GetPodStatus), so a lease change reaches the proxy by
// whichever path delivered it first and the backstop repairs a stream event the
// broker dropped.
//
// IT IS VM-GATED ON THE NODE'S OWN RECORD, not on the reported field. The
// published key is the /32 the node's IPAM carved for the guest — read back from
// the pod-network seam — so a status that carries a transport address for a pod
// this node never provisioned a guest for installs NOTHING. That is what keeps a
// host-process pod (whose published address IS live on lo0, and whose backend
// dial must stay byte-identical) unreachable by a malformed or malicious report:
// there is no key to override it under.
//
// It NEVER publishes the live address anywhere else. status.podIP, the
// EndpointSlice and DNS carry the published identity only — the two-address model
// forbids advertising a node-local NAT lease as cluster-routable, and a lease
// churns on every guest restart while an identity must not.
//
// Last writer wins: PodStatus carries no generation, so two observations of one
// pod that cross in flight settle in arrival order. The exposure is bounded and
// self-healing in the SAFE direction — a stale EMPTY report can only drop a live
// override (the next status reinstalls it), never resurrect a dead one, because
// the reinstall path requires a currently-recorded guest and a currently-reported
// lease.
func (r *runtimedRuntime) observeTransport(pod *corev1.Pod, rs *runtimev1.PodStatus) {
	if r.transport == nil || pod == nil {
		return
	}
	podID := string(pod.UID)
	gn, ok := r.guestNetwork(podID)
	if !ok || !gn.PodIP.IsValid() {
		r.transport.drop(podID)
		return
	}
	reported := rs.GetGuestTransportAddress()
	if reported == "" {
		// No lease yet, or the guest lost the one it had: the pod is UNDIALABLE
		// rather than dialed at some substitute address (the table's no-fallback
		// contract), so the override must go.
		r.transport.drop(podID)
		return
	}
	live, err := netip.ParseAddr(reported)
	if err != nil || !live.IsValid() {
		r.log.Warn("vm pod reported an unparsable guest transport address; dropping its override",
			"pod", podID, "reported", reported, "err", err)
		r.transport.drop(podID)
		return
	}
	live = live.Unmap()
	if live == gn.PodIP.Unmap() {
		// An override onto the published address itself is a no-op that would only
		// disguise the missing lease as a working one.
		r.transport.drop(podID)
		return
	}
	r.transport.observe(podID, gn.PodIP.Unmap(), live, DeclaredTCPPorts(pod))
}

// transportGateFor computes the pod-level readiness precondition for pod: whether
// the Service proxy can dial it at the published address its EndpointSlice will
// carry. It is the SAME predicate observeTransport maintains — one lease map,
// read back — so the window it closes cannot reopen through a second notion of
// "installed".
//
// It answers transportReady for everything that is not a vm pod waiting on a
// lease, in three cases that are each a different fact:
//   - no sink is configured (the --network none / no-datapath posture): there is
//     no dial path to withhold readiness for, and gating on a feed nothing will
//     ever fill would strand every vm pod NotReady forever;
//   - the pod is not vm-backed: its published /32 is live on lo0 and is dialed
//     directly, with no override in the picture at any point in its life;
//   - its RuntimeClass does not resolve: CreatePod already refused such a pod, so
//     there is no running workload to gate — fail toward the pre-existing
//     behaviour rather than inventing a NotReady for a pod that cannot exist. That
//     upstream refusal is pinned by TestToPodBoxUnknownRuntimeClassFailsClosed
//     (translate_test.go); a change to toPodBox's error path re-opens this branch
//     and must re-audit it.
func (r *runtimedRuntime) transportGateFor(pod *corev1.Pod) transportGate {
	if pod == nil || r.transport == nil {
		return transportReady
	}
	backend, err := podSandboxBackend(pod)
	if err != nil || backend != runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return transportReady
	}
	if r.transport.has(string(pod.UID)) {
		return transportReady
	}
	return transportPending
}

// probeDialFor returns the dial one pod's probes use — the third consumer of the
// two-address model, after the Service proxy's override map and the readiness
// gate, and the one that dials on this node's own behalf.
//
// WHY A PROBE CANNOT USE THE PUBLISHED ADDRESS. Every probe target is resolved
// once, at CreatePod (buildCheck), and defaults to the pod's published /32. For a
// vm pod that /32 is the pod's cluster identity, not the guest: the node answers
// on it only through the proxy's relay, only on the relayed ports, and only once
// the lease the relay forwards to has arrived (through the status stream; it
// changes on every guest restart). A probe on an undeclared port, or before the
// lease, would never answer: readiness would stay false and liveness would
// restart a healthy guest. Dialing the lease directly also keeps the probe off
// the relay, which applies NetworkPolicy and re-originates the connection. The
// resolution is made PER ATTEMPT rather than at build time for the same reason
// the override map is rebuilt per observation — a lease is not an identity.
//
// A native pod gets r.dial verbatim, so its probes are byte-identical to what they
// were before this seam existed. So does a vm pod on a node with no feed (the
// --network none / no-datapath posture): there is no lease map to resolve
// through, and withholding every probe on a feed nothing will ever fill would
// strand the pod — the same carve-out, for the same reason, as transportGateFor's
// no-sink case.
//
// The PENDING window is reported, never dialed and never guessed: while the pod
// holds no lease the returned dial answers errProbeTargetPending, which the probe
// runner treats as NOT EVALUATED (no success, no failureThreshold progress — see
// runCheck). Dialing the published address "just to see" would count a certain
// failure against a window this node owns, and substituting the node IP would
// probe the wrong process entirely.
//
// Only the pod's OWN address is rewritten: a probe carrying an explicit
// tcpSocket.Host / httpGet.Host names some other target and is dialed verbatim.
// The comparison is against the node's own guest record — the same authority
// observeTransport keys the override on — so the probe and the proxy translate
// one identity to one lease.
func (r *runtimedRuntime) probeDialFor(podID string, vmBacked bool) dialFunc {
	if !vmBacked || r.transport == nil {
		return r.dial
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		live, ok := r.transport.live(podID)
		if !ok {
			return nil, fmt.Errorf("pod %s: the guest has not reported its transport address yet, "+
				"so %s is not dialable: %w", podID, address, errProbeTargetPending)
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			// Not a host:port target (no probe handler builds one), so there is
			// nothing to translate — dial it exactly as asked.
			return r.dial(ctx, network, address)
		}
		// SINGLE-ADDRESS ASSUMPTION, stated because it is load-bearing and silent
		// if it ever stops holding: a pod has exactly ONE published address here —
		// the single /32 SetupGuest allocated (sandbox.GuestNetworkConfig.PodIP) —
		// and exactly one lease, so "the pod's own address" is an equality test.
		// The day a pod carries several (a second family for dual-stack, or a
		// multi-homed guest), status.podIPs and the lease both become lists, and
		// this comparison must be revisited into a per-family match rather than
		// quietly matching only whichever address happens to be first. It fails
		// toward today's behaviour — an unmatched host is dialed verbatim — so the
		// symptom would be an unresolved probe, not a misdirected one.
		if gn, recorded := r.guestNetwork(podID); recorded && gn.PodIP.IsValid() {
			if h, perr := netip.ParseAddr(host); perr == nil && h.Unmap() == gn.PodIP.Unmap() {
				address = net.JoinHostPort(live.String(), port)
			}
		}
		return r.dial(ctx, network, address)
	}
}
