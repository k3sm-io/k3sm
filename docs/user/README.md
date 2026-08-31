# k3sm user documentation

**k3sm** is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
k3s. Pods run as **native Darwin processes** (no Linux, no containers, no VM by default). This
directory is the front door to the user-facing docs; read them roughly in the journey order below.

> These pages describe user-visible behavior. The authoritative product design lives in
> [`../DESIGN.md`](../DESIGN.md).

## Read in order

1. [Quickstart](quickstart.md) — one node, first Pod, in a few minutes.
2. [Install](install.md) — what `k3sm install` does, the one-time admin step, the `_k3sm` posture.
3. [Concepts](concepts.md) — how k3sm maps Kubernetes onto native Darwin processes.
4. [kubectl access](kubectl-access.md) — getting a kubeconfig and talking to the cluster.
5. [Images](images.md) — how native workloads are referenced today, and the OCI image/build path on the roadmap.
6. [Storage](storage.md) — local-path PVs, node affinity, what is and isn't supported.
7. [Versions](versions.md) — the Kubernetes version k3sm tracks and how to read the live pin.
8. [Upgrade](upgrade.md) — upgrading a node or cluster, the launchd restart model.
9. [Certificates](certificates.md) — the two CAs, `k3sm certificate rotate`, and what it does not do.
10. [Backup & restore](backup-restore.md) — the kine/SQLite datastore: `k3sm snapshot save`/`restore`,
    the automatic pre-migration copy, and the restore drill.
11. [Multi-node](multi-node.md) — joining agents, the mesh, EXPERIMENTAL status.
12. [High availability](ha.md) — HA control plane, EXPERIMENTAL status.
13. [The `vm` RuntimeClass](vm-runtimeclass.md) — the intended isolation boundary for untrusted
    workloads. EXPERIMENTAL, and it does not run a Pod yet.
14. [MLX quickstart](mlx-quickstart.md) — serving a model on the Mac's GPU through an OpenAI-compatible endpoint.
15. [Limitations](limitations.md) — **the real gaps** — read this before you rely on k3sm.
16. [Troubleshooting](troubleshooting.md) — logs, common failures, recovery.
17. [FAQ](faq.md) — short answers to the common questions.

## Before you build anything real

k3sm is **not** a drop-in replacement for a Linux Kubernetes cluster. Workloads must be adapted, and
several standard behaviors diverge by design. Read [Limitations](limitations.md) first — it cites the
canonical conformance registers so nothing there is rosier than the truth.

MLX / Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page — see [MLX quickstart](mlx-quickstart.md), item 14 above. The rest of these pages
describe the general workload path.
