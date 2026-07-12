# Concepts

How k3sm maps Kubernetes onto macOS. The full design is in [`../DESIGN.md`](../DESIGN.md); this is the
user-facing mental model.

## Pods are native Darwin processes

k3sm has **no Linux, no containers, no cgroups, no CNI, no network namespaces**. A Pod's containers are
launched as native macOS processes (`posix_spawn`), Seatbelt-confined, with an APFS-cloned root. This is
the fundamental difference from every Linux Kubernetes distribution and the reason several behaviors
diverge — see [limitations.md](limitations.md).

## The control plane

k3sm embeds a **real upstream kube-apiserver, controller-manager, and scheduler**, supervised in one
process, backed by **kine over SQLite** (WAL). The API surface is genuine Kubernetes: RBAC, admission,
CRDs, workload controllers, and the scheduler all work. What differs is the **node** underneath.

## The node — a Virtual Kubelet

The node is a **Virtual Kubelet** Darwin provider. It reconstructs the kubelet surface (Pod phases,
conditions, probes, graceful stop, the `/stats/summary` observability surface) on top of native
processes rather than a container runtime.

## The trust domain — one `_k3sm` user

All Pods on a node run as the **same unprivileged `_k3sm` user**. There is **no per-pod uid isolation**;
same-node Pods share one OS trust domain. For untrusted or multi-tenant workloads, use the **`vm`
RuntimeClass** for a real isolation boundary — see [vm-runtimeclass.md](vm-runtimeclass.md). The
rationale lives in `docs/privilege-model.md`. This is the same framing you will see in
[limitations.md](limitations.md).

## Images

k3sm workloads are **native Darwin executables**, not OCI Linux images: today you reference a
binary directly in the Pod spec (`image: native` plus an absolute `command`, or `image: /abs/path`).
An OCI-based image path — registry pull, `k3sm image load`, a `k3sm build` command — is on the
roadmap. See [images.md](images.md).

## Networking

Pods share the node's `lo0`-based network today; Services are handled by a userspace Service proxy, and
cluster DNS runs on `:53`. Per-pod IP identity, headless DNS, and general UDP Services are limited or
planned — see [limitations.md](limitations.md).

## Storage

Persistent volumes use a **local-path** provisioner with **node affinity** — a PV is pinned to the node
that holds its data. See [storage.md](storage.md).

## Next

- [limitations.md](limitations.md) — what diverges and why.
- [multi-node.md](multi-node.md) — more than one Mac.
- [versions.md](versions.md) — which Kubernetes version this tracks.
