# Concepts

How k3sm maps Kubernetes onto macOS. The full design is in [the design document](../DESIGN.md); this is the
user-facing mental model.

## Pods Are Native Darwin Processes

On the default path, k3sm has **no Linux, no containers, no cgroups, no CNI, no network
namespaces**. A Pod's containers are launched as native macOS processes (`posix_spawn`),
Seatbelt-confined, with an APFS-cloned root. This is the fundamental difference from every Linux
Kubernetes distribution, and the reason several behaviors diverge (see
[Limitations](limitations.md)). The `vm` RuntimeClass opts a Pod into a Linux
guest instead; see [`vm` RuntimeClass](vm-runtimeclass.md).

## Control Plane

k3sm embeds **the upstream kube-apiserver, controller-manager, and scheduler**, supervised in one
process, backed by **kine over SQLite** (WAL). The API surface is Kubernetes. RBAC, admission,
CRDs, workload controllers, and the scheduler all work. What differs is the **node** underneath.

## Virtual Kubelet Node

The node is a **Virtual Kubelet** Darwin provider. It reconstructs the kubelet surface (Pod phases,
conditions, probes, graceful stop, the `/stats/summary` observability surface) on top of native
processes rather than a container runtime.

## Trust Domain

All Pods on a node run as the **same unprivileged `_k3sm` user**. There is **no per-pod uid isolation**;
same-node Pods share one OS trust domain. For untrusted or multi-tenant workloads the **`vm`
RuntimeClass** is the intended isolation boundary, and it boots a Pod into its own micro-VM.
See [`vm` RuntimeClass](vm-runtimeclass.md). The rationale lives in
[the privilege model](../privilege-model.md), and [Limitations](limitations.md) frames it the same way.

## Images

k3sm workloads are OCI images whose payload is a **native Darwin executable**. Registry pull,
tags, digests, pull policy and pull secrets work as in any Kubernetes. `k3sm build` builds any
Dockerfile into an image, natively for a copy-only recipe and on the cluster's build engine when it
has `RUN` steps, and `k3sm image load` ingests a tarball without a registry. For development, a
Pod can name a binary directly (`image: native` plus an absolute `command`). A `linux/arm64` image
runs under the `vm` RuntimeClass. See
[Images](images.md) and [Linux images](vm-runtimeclass.md).

## Networking

Each Pod gets its own `lo0` address; Services are handled by a userspace Service proxy, and each node
serves cluster DNS on `:53` for Service A records, headless Services, StatefulSet per-Pod names, SRV
and PTR. What a Pod resolves depends on its runtime path, and general UDP Services are still deferred
(see [Limitations](limitations.md)).

## Storage

Persistent volumes use a **local-path** provisioner with **node affinity**, so a PV is pinned to the
node that holds its data. See [Storage](storage.md).

## Next

- [Limitations](limitations.md) covers what diverges and why.
- [Multi-node](multi-node.md) covers running more than one Mac.
- [Versions](versions.md) names which Kubernetes version this tracks.
