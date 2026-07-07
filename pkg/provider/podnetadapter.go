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

	"k3sm.io/runtimed/pkg/runtime"
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
}

// PodIPAM is the consumer-side slice of darwin-net's *podnet.Network the
// adapter drives: idempotent per-pod /32 allocation + lo0 alias plumbing,
// leak-free teardown, and the startup stale-alias sweep. *podnet.Network
// satisfies it; tests inject a fake over a real podnet.Allocator.
type PodIPAM interface {
	// Setup allocates an IP for podID, plumbs its lo0 alias, and returns the
	// bindable address (idempotent per podID).
	Setup(ctx context.Context, podID string) (netip.Addr, error)
	// Teardown removes podID's lo0 alias and releases its IP (idempotent;
	// unknown podID is a no-op success).
	Teardown(ctx context.Context, podID string) error
	// SweepStale removes every k3sm-owned lo0 alias in the node podCIDR not in
	// the known podID->IP set (the crash-recovery orphan sweep).
	SweepStale(ctx context.Context, known map[string]netip.Addr) error
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
// Locking discipline: mu guards hostNet, the set of podIDs the provider marked
// spec.hostNetwork. Those pods share the node's addresses, so Setup must return
// the node IP without allocating even when the runtimed-side seam calls it
// unconditionally on the host-process spine (the PodBox contract carries no
// hostNetwork bit). The wrapped IPAM has its own locks.
type PodNetAdapter struct {
	ipam   PodIPAM
	nodeIP string
	log    *slog.Logger

	mu      sync.Mutex
	hostNet map[string]struct{}
}

// Compile-time checks: the adapter satisfies the provider seam, runtimed's
// supervisor.PodNetwork, and the optional runtime.NetworkReconciler (so
// runtimed's once-before-Serve startup reconcile fires — fail-closed).
var (
	_ PodNetwork                = (*PodNetAdapter)(nil)
	_ supervisor.PodNetwork     = (*PodNetAdapter)(nil)
	_ runtime.NetworkReconciler = (*PodNetAdapter)(nil)
)

// NewPodNetAdapter builds the adapter over the node's podnet IPAM. nodeIP is
// the address handed to MarkHostNetwork-ed pods; a nil log discards.
func NewPodNetAdapter(ipam PodIPAM, nodeIP string, log *slog.Logger) *PodNetAdapter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PodNetAdapter{ipam: ipam, nodeIP: nodeIP, log: log, hostNet: map[string]struct{}{}}
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
// lo0 alias and frees the /32 (idempotent, unknown podID is a no-op success).
// The seam is ctx-less (the supervisor.PodNetwork contract), so the podnet leg
// runs under a bounded background context — documented, not a deep
// context.Background: there is no caller context to thread.
func (a *PodNetAdapter) Teardown(podID string) error {
	a.mu.Lock()
	_, host := a.hostNet[podID]
	delete(a.hostNet, podID)
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
	a.log.Info("pod network startup reconcile complete (full stale-alias sweep)")
	return nil
}
