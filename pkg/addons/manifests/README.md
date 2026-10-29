# Embedded add-on manifests

Every `*.yaml` / `*.yml` file in this directory is **compiled into the `k3sm` binary**
(`//go:embed manifests` in `../addons.go`) and server-side-applied onto the cluster on every
server start by `addons.Reconciler.Converge`.

It holds one add-on today: **`metrics-server.yaml`**, upstream metrics-server v0.9.0. Its RBAC,
Service and APIService are upstream's bytes; its header comment lists the only Deployment lines
changed to run k3sm's native darwin/arm64 build (`hack/images/metrics-server/`) as a native pod
on a server node. `TestMetricsServerAddonManifest` pins the exact object set and the RBAC;
`TestMetricsServerAddonRunsNative` pins the scheduling fields, the args and the upstream bytes;
`TestMetricsServerImageLockstep` binds the image line to `hack/images/metrics-server/image.yaml`,
its one digest record. Any change to this file is a deliberate change to those tests too. It is
applied once the server's node has minted its kubelet serving certificate, on every server
topology; before that, or when the cluster CA does not issue the kubelet serving certificates, it
is skipped (and withdrawn only on positive evidence). It is never applied over an operator's own metrics.k8s.io APIService. See
`TestMetricsServerAddonGate`.

## Why the manifests live in the binary and not on disk

An on-disk manifest directory under the server work dir would be owned by the same `_k3sm`
uid every pod runs as, so ownership is no barrier. Only runtimed's Seatbelt profile keeps a
confined pod out of `<work dir>/server`, and that is a profile rule keyed to the work dir it
was generated for, not a permission. The reconciler would apply the directory's contents with
the `system:masters` admin kubeconfig. That widens the set of principals that can reach
cluster-admin from "whoever holds the 0600 admin kubeconfig" to "any process running as the
service user".
Compiling the manifests in removes the ingress entirely: there is no path an unprivileged
process can write, and manifest integrity is inherited from the signed binary.

Do not add a filesystem, ConfigMap, URL, or flag ingress to this reconciler. A directory-drop
mechanism is a separate design with its own applying identity (a bounded ServiceAccount, never
`system:masters`), a root-owned location, and symlink/size/GVK guards.

## Authoring contract for a manifest added here

- **Name everything.** Server-side apply requires `metadata.name`; `generateName` is rejected.
- **Namespaced objects must declare `metadata.namespace`**; cluster-scoped objects must not.
  The reconciler refuses either mistake rather than guessing `default`.
- **Nothing per-boot-varying.** The reconciler re-applies the identical bytes on every start;
  a timestamp, nonce, or generated suffix turns a no-op reconcile into a write per boot, and
  the datastore is append-only.
- **Darwin scheduling is not automatic.** A stock upstream add-on manifest carries no
  `kubernetes.io/os: darwin` nodeSelector and no toleration for the `k3sm.io/provider`
  NoSchedule taint, so its Deployment applies cleanly while its pods are rejected at admission
  or left Unschedulable two controllers away. Adapt the pod template before adding it here.
- **Removing a file does not delete anything from the cluster.** The reconciler never prunes
  (see `../doc.go`); its one delete is the withdrawal of a gated add-on. An object dropped from
  this directory is left in place for an operator to remove.
