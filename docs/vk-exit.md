# The Virtual Kubelet exit seam (`vkadapter`)

k3sm's node runs today on the
[`virtual-kubelet/virtual-kubelet`](https://github.com/virtual-kubelet/virtual-kubelet)
node/provider machinery. k3sm confines every reference to that module to ONE
package — `k3sm.io/k3sm/pkg/provider/vkadapter` — so the coupling is visible,
auditable, and edited in one place. The module-wide gate
`provider.TestVKImportsConfinedToAdapter` fails the `go test` / `hack/ci.sh` gate
(not `go build` — a stray direct import still compiles) if any other file imports
Virtual Kubelet directly.

This document is honest about what that buys and what it does not.

## What the confinement achieves: one edit site, not decoupling

The vkadapter re-exports are deliberately **type aliases** (`type Provider =
nodeutil.Provider`, `type AttachIO = api.AttachIO`, …), not fresh wrapper
interfaces. An alias preserves the VK type's **identity**: `vkadapter.AttachIO`
IS `api.AttachIO`, the same type. That is required for correctness — the
provider's streaming verbs hand these values straight to VK's own
`PodHandler`/`PodController` over the kubelet HTTP API, so a structurally
identical but *distinct* wrapper type would not satisfy the contract, and the
bidirectional exec/attach `Resize()` stream would not typecheck against VK's
handler.

The consequence: vkadapter is the single **edit site**, not a decoupling layer.
The rest of the repo names `vkadapter.X` in its signatures, but those signatures
are still the VK types by identity. A true swap of the VK machinery must either
(a) supply replacement types that are structurally identical to
`AttachIO`/`ContainerLogOpts`/`PodLifecycleHandler`/`Provider` and re-point every
alias, or (b) change every alias consumer's signature. Either way, vkadapter
localizes the change; it does not eliminate it.

The `errdefs` pass-throughs (`NotFound`, `NotFoundf`, `IsNotFound`) are a sharper
case: they MUST delegate to VK's own `errdefs` and return VK's own concrete
not-found error. VK's `PodController` reconcile keys "pod is gone" detection on
`errdefs.IsNotFound`, which inspects the error's `NotFound() bool` interface. A
k3sm-local sentinel or a bare `fmt.Errorf` substitute would satisfy neither, and
would **silently** break gone-pod detection (the controller would keep trying to
reconcile a pod the runtime has forgotten). So these are thin delegators, not
re-implementations.

## What a client-go replacement would have to re-implement

Confinement makes the surface small, but the surface is load-bearing: Virtual
Kubelet is not just a type package, it is a running control loop. Replacing it
with hand-written client-go plumbing means re-implementing FOUR things it
provides today:

1. **The PodController reconcile loop.** VK runs a Pod informer against the
   apiserver and drives it into the provider's `PodLifecycleHandler`
   (create/update/delete/get), diffing desired vs. actual and retrying with
   rate-limited workqueues. A replacement is a full informer + workqueue +
   reconcile implementation, including the `errdefs.IsNotFound` gone-pod edge
   the pass-throughs above exist to preserve.

2. **Node status + the Lease heartbeat.** With a nil `NodeProvider`, VK installs
   its `NewNaiveNodeProvider`, which pushes node status and renews the
   `coordination.k8s.io` **Lease** object on a cadence so the control plane sees
   the node as `Ready` and does not evict its pods. A replacement must write node
   status and drive the Lease renewal loop itself (miss it and the node goes
   `NotReady`).

3. **The kubelet HTTP API server.** VK's `nodeutil` wires the HTTPS server that
   serves the kubelet verbs the apiserver proxies to — `/containerLogs`
   (`kubectl logs`), and exec/attach/port-forward — behind an auth handler,
   TLS config, and request instrumentation
   (`AttachProviderRoutes` + `InstrumentHandler`). `vkadapter.NewNode`
   encapsulates exactly this wiring. A replacement must stand up that HTTPS
   server, route the streaming verbs, and reproduce the auth/TLS posture — which
   for k3sm means mutual TLS anchored on the cluster's client-identity CA plus the
   accepted-identity predicate in `provider.KubeletEndpointAuth`, not `nodeutil`'s
   own auth helpers.

4. **Node registration + lifecycle.** VK registers the Node object at bring-up
   (letting the provider stamp labels/capacity/taints via the bootstrap
   callback — k3sm's `configureNode`), runs the controllers to `Ready`, and tears
   down cleanly on context cancellation. A replacement owns node
   create/patch/deregister and the run/ready/stop lifecycle.

None of these are stubbed by the vkadapter. They remain VK's job; the confinement
only guarantees that the day k3sm chooses to re-implement them, there is exactly
one package to edit and one gate to flip.

## The vkadapter surface (for maintainers)

- **Type aliases** re-exporting VK's provider/node/streaming types by identity:
  `Provider`, `ProviderConfig`, `Node`, `PodLifecycleHandler`, `PodNotifier`,
  `NodeProvider`, `AttachIO`, `ContainerLogOpts`, `TermSize`.
- **`errdefs` pass-throughs** (`NotFound`, `NotFoundf`, `IsNotFound`) delegating
  to VK's own not-found error so VK's reconcile agrees on "gone".
- **`NewNode(nodeName, NodeConfig)`** encapsulating the `nodeutil` node-builder
  dance (config options, `NewNode`, the nil-`NodeProvider` → `NaiveNodeProvider`
  path, and the TLS-gated provider-route/HTTP-handler wiring).

Everything else in the repo imports `vkadapter`, never Virtual Kubelet.
