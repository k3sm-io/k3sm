# Versions

Which Kubernetes version k3sm tracks, and how to read the **live** pin so this page cannot silently
drift.

## Read the Live Pin — Don't Trust a Literal

The authoritative version is what the binary reports and what the conformance register records; a
number written into prose can go stale. Always read the live values:

```sh
k3sm version    # prints the k3sm build version + the embedded Kubernetes control-plane pin
```

The **machine-authoritative** Kubernetes pin is the shipped control-plane pin
(`executor.DefaultKubeVersion`), which release tooling compares against the version the project has
triaged its conformance notes against. When a pin bump lands, that tooling
updates the register; treat it — and `k3sm version` — as the source of truth over this page.

## Current Skew (Point-in-Time)

At the time of writing:

- **Control plane** (embedded kube-apiserver / KCM / scheduler): `DefaultKubeVersion` **v1.36.2**.
- **Client libraries** (`k8s.io/api`, `k8s.io/client-go`): **v0.35.0**.

The one-minor skew between the control-plane pin and the client-go line is expected. If the numbers here
disagree with `k3sm version`, **the live output wins** — a future pin bump will move the register and the
binary before this prose catches up.

## Compatibility

Standard `kubectl` and client-go clients within a minor of the control-plane pin work normally, since the
API surface is a **real upstream apiserver** (see [Concepts](concepts.md)). The divergences are on the
node side, not the API version.

## Next

- [Upgrade](upgrade.md) — moving to a new k3sm release.
- [kubectl access](kubectl-access.md) — client setup.
