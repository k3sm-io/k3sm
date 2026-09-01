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
	"log/slog"
	"net/netip"
	"sync"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// TransportOverrideSink is the Service-proxy seam a vm pod's LIVE TRANSPORT
// address is published through: darwin-net's *proxy.RoutingTable satisfies it
// (RoutingTable.SetTransportOverrides). It is declared HERE, at the consumer, per
// the standards — the provider is the only component that holds both halves of a
// vm pod's two-address identity, so it is the only one that can feed the map.
//
// The map is PUBLISHED address -> LIVE address, and it is REPLACED WHOLESALE on
// every call: the table drops the previous generation entire, which is what makes
// the feeder's liveness obligation cheap to discharge (see transportFeed).
type TransportOverrideSink interface {
	SetTransportOverrides(overrides map[netip.Addr]netip.Addr)
}

// transportLease is one vm pod's two addresses. published is the /32 the node's
// IPAM carved for the pod — its cluster identity, which EndpointSlices, DNS and
// status.podIP carry and which is live on NO interface for a guest. live is the
// address the guest's DHCP client leased on the node's NAT segment, as the guest
// agent reported it through runtimed's PodStatus. They are never interchangeable
// and are never reconciled into one address.
type transportLease struct {
	published netip.Addr
	live      netip.Addr
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

// observe records podID's published/live pair and republishes when it changed. An
// unchanged report is a no-op: a vm pod's status is re-observed on every stream
// event and every resync tick, and re-pushing an identical map would churn the
// table's override generation for nothing.
func (f *transportFeed) observe(podID string, published, live netip.Addr) {
	if f == nil {
		return
	}
	next := transportLease{published: published, live: live}
	f.mu.Lock()
	defer f.mu.Unlock()
	if cur, ok := f.leases[podID]; ok && cur == next {
		return
	}
	f.leases[podID] = next
	f.log.Info("vm pod transport override installed",
		"pod", podID, "published", published.String(), "live", live.String())
	f.republishLocked()
}

// drop removes podID's override and republishes, if it had one. It is the
// death/lease-loss half of the liveness obligation and is idempotent, so every
// path that can end a pod may call it unconditionally.
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

// republishLocked derives the FULL current map from the tracked lease state and
// hands it to the sink. Callers hold mu.
func (f *transportFeed) republishLocked() {
	next := make(map[netip.Addr]netip.Addr, len(f.leases))
	for _, l := range f.leases {
		next[l.published] = l.live
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
// from a runtimed PodStatus. It runs from buildStatus, the convergence point
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
func (r *runtimedRuntime) observeTransport(podID string, rs *runtimev1.PodStatus) {
	if r.transport == nil {
		return
	}
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
	r.transport.observe(podID, gn.PodIP.Unmap(), live)
}
