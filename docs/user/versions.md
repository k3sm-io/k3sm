# Versions

Which Kubernetes version k3sm tracks, and how to read the **live** pin so this page cannot silently
drift.

## Read the Live Pin

The authoritative version is what the binary reports and what the conformance register records; a
number written into prose can go stale. Always read the live values:

```sh
k3sm version    # prints the k3sm build version + the embedded Kubernetes control-plane pin
```

The **machine-authoritative** Kubernetes pin is the shipped control-plane pin
(`executor.DefaultKubeVersion`), which release tooling compares against the version the project has
triaged its conformance notes against. When a pin bump lands, that tooling
updates the register. Treat that pin, and `k3sm version`, as the source of truth over this page.

## Current Skew (Point-in-Time)

On `main` at the time of writing (the v0.1.7 release pins v1.36.5 and v0.36.5):

- **Control plane** (embedded kube-apiserver / KCM / scheduler): `DefaultKubeVersion` **v1.37.1**.
- **Client libraries** (`k8s.io/api`, `k8s.io/client-go`): **v0.37.1**.

The client libraries match the control-plane minor. If the numbers here disagree with `k3sm version`,
**the live output wins**. A future pin bump moves the register and the
binary before this prose catches up.

## Compatibility

Standard `kubectl` and client-go clients within a minor of the control-plane pin work normally, since the
API surface is a **real upstream apiserver** (see [Concepts](concepts.md)). The divergences are on the
node side, not the API version.

## Next

- [Upgrade](upgrade.md) covers moving to a new k3sm release.
- [kubectl access](kubectl-access.md) covers client setup.
