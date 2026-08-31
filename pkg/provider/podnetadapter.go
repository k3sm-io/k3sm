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
	"net/netip"
	"sync"
	"time"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/podnet"
	"k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/sandbox"
	"k3sm.io/runtimed/pkg/supervisor"
)

// PodNetwork is the provider-side pod-IP seam (M10.1): the ONE per-node
// allocation authority the runtimed provider resolves a pod's IP from BEFORE
// translation (so box.PodIp, the downward-API status.podIP env, and the SBPL
// bind discipline all carry the same /32) and the embedded runtimed daemon
// re-reads through its supervisor.PodNetwork seam (idempotent Setup returns the
// SAME address — no second allocator). Defined here at the consumer per the
// standards; *PodNetAdapter is the production implementation.
type PodNetwork interface {
	// Setup provisions networking for podID and returns the pod's IP: the
	// allocated /32 for a normal pod, the node IP for a MarkHostNetwork-ed pod.
	// Idempotent per podID. Errors preserve the podnet sentinels with %w, so
	// errors.Is(err, podnet.ErrPoolExhausted) is detectable through it.
	Setup(ctx context.Context, podID string) (ip string, err error)
	// Teardown releases podID's networking (idempotent, unknown podID is a
	// no-op success). Callers log-and-continue; it never blocks pod deletion.
	Teardown(podID string) error
	// MarkHostNetwork records podID as a spec.hostNetwork pod: it shares the
	// node's addresses, so Setup returns the node IP and allocates nothing.
	MarkHostNetwork(podID string)
	// SetupGuest provisions the GUEST network of a vm-RuntimeClass pod (M11.4-d4)
	// and RECORDS the resulting config for the runtimed-side read: darwin-net
	// allocates the pod IP + NAT parameters and derives the guest resolv.conf from
	// dnsCfg, and the implementation folds both into runtimed's plain-data
	// sandbox.GuestNetworkConfig. Idempotent per podID; released by Teardown.
	// Errors preserve the podnet sentinels with %w, exactly as Setup does.
	SetupGuest(ctx context.Context, podID string, dnsCfg netv1.DNSConfig) (sandbox.GuestNetworkConfig, error)
}

// PodIPAM is the consumer-side slice of darwin-net's *podnet.Network the
// adapter drives: idempotent per-pod /32 allocation + lo0 alias plumbing,
// leak-free teardown, and the startup stale-alias sweep. *podnet.Network
// satisfies it; tests inject a fake over a real podnet.Allocator.
type PodIPAM interface {
	// Setup allocates an IP for podID, plumbs its lo0 alias, and returns the
	// bindable address (idempotent per podID).
	Setup(ctx context.Context, podID string) (netip.Addr, error)
	// SetupGuest allocates an IP for podID and returns the vm-backend (guest) NAT
	// config, plumbing NO lo0 alias (idempotent per podID). A guest owns its own
	// address inside its netstack and is reached over its NAT attachment; a host
	// alias for that address would make the host answer for the guest.
	SetupGuest(ctx context.Context, podID string) (podnet.GuestNetwork, error)
	// Teardown removes podID's lo0 alias and releases its IP (idempotent;
	// unknown podID is a no-op success). It releases a guest allocation too — a
	// vm pod draws from the SAME node pool.
	Teardown(ctx context.Context, podID string) error
	// SweepStale removes every k3sm-owned lo0 alias in the node podCIDR not in
	// the known podID->IP set (the crash-recovery orphan sweep).
	SweepStale(ctx context.Context, known map[string]netip.Addr) error
	// EnsureNodeAlias plumbs the lo0 /32 alias for the node's OWN advertised
	// address (the mesh-egress .1) so the apiserver node-proxy can dial
	// NodeInternalIP:10250 on the same host (kubectl top node). It is outside the
	// pod range the sweep touches, and idempotent.
	EnsureNodeAlias(ctx context.Context, ip netip.Addr) error
}

// podnetTeardownTimeout bounds the ctx-less Teardown leg (the
// supervisor.PodNetwork contract carries no context): one lo0 alias removal via
// netd/ifconfig is fast; a wedged helper must not hang pod deletion forever.
const podnetTeardownTimeout = 15 * time.Second

// PodNetAdapter bridges darwin-net's podnet IPAM (netip.Addr, ctx-ful) to
// runtimed's supervisor.PodNetwork (string IPs, ctx-less Teardown) and its
// optional runtime.NetworkReconciler startup-reconcile seam. ONE adapter is
// constructed per node at assembly, seeded from the node's enrolled podCIDR,
// and injected into BOTH the provider (allocate-before-translate) and the
// embedded runtimed daemon (runtimed.Deps.Network) — darwin-net stays the sole
// allocator.
//
// Locking discipline: mu guards BOTH per-pod maps — hostNet, the set of podIDs
// the provider marked spec.hostNetwork, and guest, the per-pod guest network
// config SetupGuest recorded for the runtimed-side GuestNetwork read. hostNet's
// pods share the node's addresses, so Setup must return the node IP without
// allocating even when the runtimed-side seam calls it unconditionally on the
// host-process spine (the PodBox contract carries no hostNetwork bit). One mutex
// covers both because both are per-pod entries with the SAME lifetime — created
// on the provider's create path, deleted by the one Teardown — so a second lock
// would only add an ordering rule with nothing to buy. The wrapped IPAM has its
// own locks.
type PodNetAdapter struct {
	ipam   PodIPAM
	nodeIP string
	log    *slog.Logger

	mu      sync.Mutex
	hostNet map[string]struct{}
	guest   map[string]sandbox.GuestNetworkConfig
}

// Compile-time checks: the adapter satisfies the provider seam, runtimed's
// supervisor.PodNetwork, the optional runtime.NetworkReconciler (so runtimed's
// once-before-Serve startup reconcile fires — fail-closed), and the optional
// runtime.GuestNetworker (so the vm route reads back the config SetupGuest
// recorded — this adapter is the SOLE production source of VMSpec.Network).
var (
	_ PodNetwork                = (*PodNetAdapter)(nil)
	_ supervisor.PodNetwork     = (*PodNetAdapter)(nil)
	_ runtime.NetworkReconciler = (*PodNetAdapter)(nil)
	_ runtime.GuestNetworker    = (*PodNetAdapter)(nil)
)

// NewPodNetAdapter builds the adapter over the node's podnet IPAM. nodeIP is
// the address handed to MarkHostNetwork-ed pods; a nil log discards.
func NewPodNetAdapter(ipam PodIPAM, nodeIP string, log *slog.Logger) *PodNetAdapter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PodNetAdapter{
		ipam:    ipam,
		nodeIP:  nodeIP,
		log:     log,
		hostNet: map[string]struct{}{},
		guest:   map[string]sandbox.GuestNetworkConfig{},
	}
}

// Setup returns podID's IP: the node IP for a marked hostNetwork pod (no
// allocation), else the idempotent podnet /32 (allocated + lo0-aliased). The
// podnet sentinels (ErrPoolExhausted, ...) survive the wrap for errors.Is.
func (a *PodNetAdapter) Setup(ctx context.Context, podID string) (string, error) {
	a.mu.Lock()
	_, host := a.hostNet[podID]
	a.mu.Unlock()
	if host {
		return a.nodeIP, nil
	}
	ip, err := a.ipam.Setup(ctx, podID)
	if err != nil {
		return "", fmt.Errorf("podnet setup %s: %w", podID, err)
	}
	return ip.String(), nil
}

// Teardown releases podID's networking: a marked hostNetwork pod is only
// unmarked (nothing was allocated); otherwise the podnet teardown removes the
// lo0 alias and frees the /32 (idempotent, unknown podID is a no-op success). It
// also drops any guest config SetupGuest recorded for the pod, so the guest
// carrier has NO lifecycle of its own to leak from — one teardown, one release.
// The seam is ctx-less (the supervisor.PodNetwork contract), so the podnet leg
// runs under a bounded background context — documented, not a deep
// context.Background: there is no caller context to thread.
func (a *PodNetAdapter) Teardown(podID string) error {
	a.mu.Lock()
	_, host := a.hostNet[podID]
	delete(a.hostNet, podID)
	// Drop the recorded guest config on the SAME teardown that frees the address
	// it describes — deliberately NOT a second lifecycle. It is deleted before the
	// hostNetwork early return so no path can leave an entry behind, and it is
	// unconditional: an unknown podID is a no-op, matching the idempotent contract.
	delete(a.guest, podID)
	a.mu.Unlock()
	if host {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), podnetTeardownTimeout)
	defer cancel()
	if err := a.ipam.Teardown(ctx, podID); err != nil {
		return fmt.Errorf("podnet teardown %s: %w", podID, err)
	}
	return nil
}

// SetupGuest provisions the GUEST network of a vm-RuntimeClass pod and records
// the config runtimed reads back through GuestNetwork. It is the ONE MAPPER on
// this seam: darwin-net's podnet allocates the pod's cluster IP and composes the
// NAT parameters, darwin-net's pkg/dns derives the guest resolv.conf from dnsCfg
// — structured (nameservers/search/options) AND rendered — and this adapter folds
// both into runtimed's plain-data sandbox.GuestNetworkConfig, which runtimed
// cannot build itself (darwin-net and runtimed are co-equal leaves of the
// cross-repo DAG; neither imports the other).
//
// The DNS pair is derived from ONE dnsCfg through ONE normalization pass:
// GuestResolvConf renders exactly the GuestResolvConfFields result, so the
// structured fields the guest renders from and the host-rendered text carried
// beside them describe the same configuration by construction.
//
// It DRAWS FROM THE SHARED node pool — the same 253 addresses host-process pods
// allocate from — so the podnet sentinels are preserved with %w and
// errors.Is(err, podnet.ErrPoolExhausted) is detectable through the wrap, which
// is what lets the provider name the exhaustion the same way it does for a
// host-process pod.
//
// A DNS-derivation failure after a successful allocation does NOT release the
// address here: the pod's eventual DeletePod -> releasePodNetwork -> Teardown
// reclaims it. That is the same no-auto-release posture the provider's
// allocate-before-translate ordering takes, and it keeps a retry idempotent
// rather than ripping an address away mid-create.
func (a *PodNetAdapter) SetupGuest(ctx context.Context, podID string, dnsCfg netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	gn, err := a.ipam.SetupGuest(ctx, podID)
	if err != nil {
		return sandbox.GuestNetworkConfig{}, fmt.Errorf("podnet setup guest %s: %w", podID, err)
	}
	fields, err := dns.GuestResolvConfFields(dnsCfg)
	if err != nil {
		return sandbox.GuestNetworkConfig{}, fmt.Errorf("guest resolv.conf fields for %s: %w", podID, err)
	}
	rendered, err := dns.GuestResolvConf(dnsCfg)
	if err != nil {
		return sandbox.GuestNetworkConfig{}, fmt.Errorf("render guest resolv.conf for %s: %w", podID, err)
	}
	cfg := sandbox.GuestNetworkConfig{
		Nameservers: fields.Nameservers,
		Searches:    fields.Search,
		Options:     fields.Options,
		ResolvConf:  rendered,
		PodIP:       gn.PodIP,
		Gateway:     gn.Gateway,
		NATSubnet:   gn.NATSubnet,
		DNSVIP:      gn.DNSVIP,
	}
	a.mu.Lock()
	a.guest[podID] = cfg
	a.mu.Unlock()
	a.log.Info("guest network provisioned for vm pod",
		"pod", podID, "pod_ip", gn.PodIP.String(), "dns_vip", gn.DNSVIP.String())
	return cfg, nil
}

// GuestNetwork implements runtimed's optional runtime.GuestNetworker seam: it
// returns the config SetupGuest recorded for podID, comma-ok. false means this
// adapter has no config for the pod — not an error: the pod is networked by
// something else (a host process binds an lo0 /32 and reads no guest config), or
// the provider has not run its create path for it yet. runtimed logs that miss on
// the vm route and boots the guest with the inert zero value.
//
// The returned slices are the ones stored at SetupGuest and are never mutated
// afterwards, so callers must treat them as READ-ONLY.
func (a *PodNetAdapter) GuestNetwork(podID string) (sandbox.GuestNetworkConfig, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, ok := a.guest[podID]
	return cfg, ok
}

// MarkHostNetwork records podID as a spec.hostNetwork pod so BOTH Setup callers
// (the provider's allocate-before-translate and runtimed's host-process spine)
// resolve it to the node IP — one authority, zero allocation. Teardown unmarks.
func (a *PodNetAdapter) MarkHostNetwork(podID string) {
	a.mu.Lock()
	a.hostNet[podID] = struct{}{}
	a.mu.Unlock()
}

// ReconcileStartup implements runtimed's optional runtime.NetworkReconciler: it
// runs once, before the runtime serves any CreatePod, and sweeps EVERY
// k3sm-owned lo0 alias in the node podCIDR. The known set is empty by design:
// at assembly the fresh adapter/provider tracks no pods (runtimed pods are
// in-process children with no durable podID->IP manifest to ReattachPod from,
// so nothing survives a daemon restart) — every alias a crashed previous daemon
// left behind is stale. A failed sweep fails the runtime closed (runtimed's
// sticky once), never serving allocations over an inconsistent alias table.
func (a *PodNetAdapter) ReconcileStartup(ctx context.Context) error {
	if err := a.ipam.SweepStale(ctx, nil); err != nil {
		return fmt.Errorf("podnet startup stale-alias sweep: %w", err)
	}
	// Plumb the node's OWN lo0 alias so the apiserver node-proxy can dial the
	// advertised NodeInternalIP:10250 on the same host — a globally-unicast
	// mesh-egress .1 loops back to the local :10250 listener only once aliased.
	// This unblocks `kubectl top node` (the apiserver's isProxyableHostname rejects
	// a loopback InternalIP with HTTP 400). A loopback nodeIP needs no alias
	// (already on lo0) and is skipped. Fail closed on error, consistent with the
	// sweep above: an advertised address the host cannot answer for is an
	// inconsistency (top-node AND hostNetwork-pod binds would both break).
	if ip, err := netip.ParseAddr(a.nodeIP); err == nil && !ip.IsLoopback() {
		if err := a.ipam.EnsureNodeAlias(ctx, ip); err != nil {
			return fmt.Errorf("podnet ensure node lo0 alias %s: %w", ip, err)
		}
		a.log.Info("node lo0 alias ensured for apiserver node-proxy reachability", "node_ip", a.nodeIP)
	}
	a.log.Info("pod network startup reconcile complete (full stale-alias sweep)")
	return nil
}
