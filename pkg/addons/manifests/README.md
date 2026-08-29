# Embedded add-on manifests

Every `*.yaml` / `*.yml` file in this directory is **compiled into the `k3sm` binary**
(`//go:embed manifests` in `../addons.go`) and server-side-applied onto the cluster on every
server start by `addons.Reconciler.Converge`.

**This directory deliberately ships with no product manifest yet.** The reconciler is the
substrate; the first real add-on (metrics-server) lands separately. An empty set converges to
zero API calls, which is the intended posture until then.

## Why the manifests live in the binary and not on disk

An on-disk manifest directory under the server work dir would be readable *and writable* by
every pod on the node — all pods run as the same `_k3sm` uid and the work dir is not in
runtimed's sandbox-protected prefix set — while the reconciler applies its contents with the
`system:masters` admin kubeconfig. That widens the set of principals that can reach
cluster-admin from "whoever holds the 0600 admin kubeconfig" to "every pod on the node".
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
- **Removing a file does not delete anything from the cluster.** The reconciler never issues a
  delete verb (see `../doc.go`); an object dropped from this directory is left in place for an
  operator to remove.
