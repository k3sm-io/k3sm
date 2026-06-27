// Package runtimeclass provisions, idempotently at server start, the upstream
// node.k8s.io/v1 RuntimeClass named "vm" that opts a pod into k3sm's
// Virtualization.framework micro-VM isolation backend (M5.1), and defines the node
// label that RuntimeClass's nodeSelector pins to.
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
// applyVirtualizationLabel). When no node carries it — the default today, because
// runtimed's GetRuntimeInfo RPC reports only the selected host-process backend's
// health and NOT per-backend (VZ) availability (a runtimed extension is needed; see
// cmd/k3sm/node.go nodeVMCapable) — a vm pod has no node to land on and stays
// Pending/Unschedulable. That is the correct posture for a non-VZ cluster, and it
// complements runtimed's runtime-refusal backstop: even if a vm pod reached a node,
// runtimed's SelectBackend fails closed (sandbox.ErrBackendUnavailable) rather than
// downgrade to a weaker rung. Provisioning the RuntimeClass itself is also
// fail-closed by absence: a vm pod naming an unprovisioned RuntimeClass is rejected
// at admission.
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
//     caveat), Rosetta-for-amd64, and the separate-binary virtualization-entitlement
//     signing (M4.0 packaging) are lab/packaging remainders.
package runtimeclass
