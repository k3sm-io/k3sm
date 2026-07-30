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

// Package runtimeclass provisions, idempotently at server start, the upstream
// node.k8s.io/v1 RuntimeClass named "vm" that opts a pod into k3sm's
// Virtualization.framework micro-VM isolation backend (M5.1), and owns the k3sm
// NODE-CAPABILITY label keys — both the one that RuntimeClass's nodeSelector pins to
// (LabelVirtualization) and the capability keys that have NO RuntimeClass attached
// and are selected directly by a pod (LabelRosetta, LabelRosettaLinux — B103). The
// keys live here, next to the selector that consumes one of them, so the label a
// node stamps and the selector a pod is admitted against can never drift.
//
// # The two halves of the vm RuntimeClass
//
//   - The handler→backend MAPPING lives in apis (runtimev1.DefaultHandlerConfig:
//     handler "vm" → SANDBOX_BACKEND_VM); the provider resolves it in toPodBox after
//     scheduling. k3sm CONSUMES the upstream RuntimeClass API — it does not fork it.
//   - The operator-facing / SCHEDULING half is this RuntimeClass object: handler
//     "vm" plus a scheduling.nodeSelector requiring LabelVirtualization on the node.
//     The kube RuntimeClass admission plugin merges that nodeSelector into every pod
//     that sets spec.runtimeClassName: vm, so the scheduler places it ONLY on a
//     VZ-capable node.
//
// # Fail-closed node-capability gate
//
// A node advertises the VZ backend by carrying LabelVirtualization=LabelTrue, set
// from the node's ACTUAL Virtualization.framework availability (cmd/k3sm's
// applyVirtualizationLabel). runtimed's GetRuntimeInfo RPC reports that availability
// as an additive VMBackendAvailable RuntimeCondition (the B1 extension — the SAFE
// isSupported + entitlement probe that never boots a VM), which the provider reads
// ONCE at node bring-up via provider.Capabilities. When no node carries the label, a
// vm pod has no node to land on and stays Pending/Unschedulable. That is the correct
// posture for a non-VZ cluster, and it complements runtimed's runtime-refusal
// backstop: even if a vm pod reached a node, runtimed's SelectBackend fails closed
// (sandbox.ErrBackendUnavailable) rather than downgrade to a weaker rung.
// Provisioning the RuntimeClass itself is also fail-closed by absence: a vm pod
// naming an unprovisioned RuntimeClass is rejected at admission.
//
// The Rosetta capability keys (LabelRosetta, LabelRosettaLinux — B103) are read from
// the SAME single GetRuntimeInfo probe and stamped by the same fail-closed rule: a
// probe error, an absent condition (an older runtimed), or any non-TRUE status
// leaves the key ABSENT, so a node never advertises a translation capability it
// cannot honor. They gate SCHEDULING ONLY through a pod's own nodeSelector — there
// is no RuntimeClass and no admission plugin merging them in.
//
// # Two-guard defense-in-depth (what B49's reconcile self-heals)
//
// The vm confinement is defended at TWO independent layers; B49's reconcile
// (Provision → reconcileManagedShape) self-heals the FIRST:
//
//   - Guard #1 — SCHEDULING: the vm RuntimeClass's scheduling.nodeSelector VZ pin
//     (LabelVirtualization=LabelTrue). The kube RuntimeClass admission plugin merges it
//     into every spec.runtimeClassName: vm pod, confining the pod to VZ-capable nodes.
//     This is a k3sm-owned, MUTABLE shape, so Provision reconciles it in place: a class
//     hand-edited or laid down by an older k3sm that lost the pin is repaired via a
//     per-key floor-merge that PRESERVES operator-added keys (a wholesale clobber would
//     strip an operator key and WIDEN placement, relaxing confinement).
//   - Guard #2 — RUNTIME: runtimed's sandbox.SelectBackend, keyed on the POD's own
//     runtimeClassName (through the compile-time apis handler→backend table, NOT the
//     RuntimeClass object), REFUSES a vm-stamped pod on a non-VZ node with
//     sandbox.ErrBackendUnavailable rather than downgrade to a weaker rung.
//
// Honest severity framing: because guard #2 is keyed on the pod, a MALFORMED guard #1
// (a "vm" class that lost its nodeSelector) can at worst let a vm pod SCHEDULE onto a
// non-VZ node, where runtimed then REFUSES it — an AVAILABILITY failure, NOT an isolation
// escape (the pod never runs unconfined). B49 is defense-in-depth robustness of guard #1,
// with guard #2 as the fail-closed backstop. (Today all vm pods are Unschedulable — no
// node is VZ-labelled yet — so B49 protects the FUTURE VZ mechanism.) The class's handler
// half is IMMUTABLE at the apiserver, so Provision compares and WARNS on a wrong handler
// but never Update-repairs it (an Update carrying a handler change is rejected Invalid and
// would block the nodeSelector repair); a wrong handler is itself fail-closed via guard
// #2's runtimev1.ErrUnknownHandler.
//
// # Provisioning lifecycle (mirrors pkg/policy / pkg/rbac)
//
// Provision runs in cmd/k3sm/server.go's provisioning slot after the apiserver is
// healthy. It is Create-tolerate-AlreadyExists (idempotent, safe on every restart)
// and never LISTs to decide what to provision — a watch-cache LIST under the pinned
// kine, where ConsistentListFromCache is GA-locked true, can read stale. It authors
// ONLY the k3sm-named "vm" object, never an upstream/system default. Unlike pkg/rbac
// (fail-closed: a half-applied authz graph locks workers out), a missing vm
// RuntimeClass cannot lock anything out — it only makes vm pods unschedulable — so
// the caller treats a provisioning error as log-and-continue, matching the advisory
// admission policies.
//
// # Lab-gated remainder (NOT built here — needs a VZ Mac + the entitlement)
//
// The verifiable foundation (provider dispatch + this RuntimeClass + the node-label
// gate) is unit-proven. The LIVE vm leg is the M5.1 lab remainder:
//
//   - VM dispatch end-to-end: provider → darwin-net podnet.Network.SetupGuest for
//     the guest network → thread the GuestNetwork (guest IP / gateway / NAT subnet /
//     DNS VIP) to runtimed's VZ backend → boot the Linux guest. darwin-net flagged
//     there is NO transport for GuestNetwork to runtimed yet; the clean fix is a
//     runtimed consumer-side supervisor.GuestNetwork seam (no apis change) — the
//     M5.1-d2 lab leg.
//   - Foreign runAsUser/fsGroup admission: M4.1's foreign-user VAP rejects them
//     because the host-process path cannot honor a foreign uid, but a vm pod's guest
//     CAN. The VAP should therefore EXEMPT runtimeClassName: vm. It is deferred (not
//     implemented here) on purpose: it is observable only once the VM boots (a vm
//     pod is Unschedulable until a VZ node exists), and keeping the admission surface
//     minimal until the capability is real is the fail-closed default.
//   - The guest resolv.conf injection (pinned static/immutable per darwin-net's
//     caveat) and the separate-binary virtualization-entitlement signing (M4.0
//     packaging) are lab/packaging remainders.
//   - Rosetta: B103 lands the ADVERTISEMENT half only (the probes + LabelRosetta /
//     LabelRosettaLinux). Actually EXECUTING a translated darwin/amd64 Mach-O under
//     Seatbelt, and a live Rosetta-for-Linux guest, remain lab remainders — so a node
//     may truthfully carry the capability label before the translated exec path is
//     end-to-end proven.
package runtimeclass
