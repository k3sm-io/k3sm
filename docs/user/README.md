# k3sm user documentation

**k3sm** is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
k3s. Pods run as **native Darwin processes** (no Linux, no containers, no VM by default). This
directory is the front door to the user-facing docs; read them roughly in the journey order below.

> These pages describe user-visible behavior. The authoritative product design lives in
> [`../DESIGN.md`](../DESIGN.md); the milestone ledger in [`../PHASES.md`](../PHASES.md).

## Read in order

1. [Quickstart](quickstart.md) — one node, first Pod, in a few minutes.
2. [Install](install.md) — what `k3sm install` does, the one-time admin step, the `_k3sm` posture.
3. [Concepts](concepts.md) — how k3sm maps Kubernetes onto native Darwin processes.
4. [kubectl access](kubectl-access.md) — getting a kubeconfig and talking to the cluster.
5. [Images](images.md) — the native image model (`k3sm build`), how it differs from OCI.
6. [Storage](storage.md) — local-path PVs, node affinity, what is and isn't supported.
7. [Versions](versions.md) — the Kubernetes version k3sm tracks and how to read the live pin.
8. [Upgrade](upgrade.md) — upgrading a node or cluster, the launchd restart model.
9. [Backup & restore](backup-restore.md) — the kine/SQLite datastore, snapshot and restore.
10. [Multi-node](multi-node.md) — joining agents, the mesh, EXPERIMENTAL status.
11. [High availability](ha.md) — HA control plane, EXPERIMENTAL status.
12. [The `vm` RuntimeClass](vm-runtimeclass.md) — isolation for untrusted workloads, EXPERIMENTAL.
13. [Limitations](limitations.md) — **the honest gaps** — read this before you rely on k3sm.
14. [Troubleshooting](troubleshooting.md) — logs, common failures, recovery.
15. [FAQ](faq.md) — short answers to the common questions.

## Before you build anything real

k3sm is **not** a drop-in replacement for a Linux Kubernetes cluster. Workloads must be adapted, and
several standard behaviors diverge by design. Read [Limitations](limitations.md) first — it cites the
canonical conformance registers so nothing there is rosier than the truth.

MLX / Apple-GPU workloads are a **separate track** (the `MLXModel` CRD and the
`mlx.k3sm.io/gpu` extended resource), documented on their own once that track ships. They are not
covered by these pages.
