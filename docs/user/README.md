# k3sm user documentation

**k3sm** is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
k3s. Pods run as **native Darwin processes** (no Linux, no containers, no VM by default). This
directory is the front door to the user-facing docs; read them roughly in the journey order below.

> These pages describe user-visible behavior. The authoritative product design lives in
> [the design document](../DESIGN.md).

## Read in Order

1. [Quickstart](quickstart.md) — one node, first Pod, in a few minutes.
2. [Installation](install.md) — what `k3sm install` does, the one-time admin step, the `_k3sm` posture.
3. [Concepts](concepts.md) — how k3sm maps Kubernetes onto native Darwin processes.
4. [Cluster access](kubectl-access.md) — getting a kubeconfig and talking to the cluster.
5. [Supported workloads](what-runs.md) — the OCI images k3sm runs, what it refuses, and the path from a
   Dockerfile to a running Pod.
6. [Images](images.md) — the reference: both workload conventions, `k3sm build`, `image
   load`/`import`/`push`, and every deliberate difference from the Docker tool of the same name.
7. [Storage](storage.md) — local-path PVs, node affinity, what is and isn't supported.
8. [Version support](versions.md) — the Kubernetes version k3sm tracks and how to read the live pin.
9. [Upgrades](upgrade.md) — upgrading a node or cluster, the launchd restart model.
10. [Certificates](certificates.md) — the two CAs, `k3sm certificate rotate`, and what it does not do.
11. [Backup and restore](backup-restore.md) — the kine/SQLite datastore: `k3sm snapshot save`/`restore`,
    the automatic pre-migration copy, and the restore drill.
12. [Multi-node clusters](multi-node.md) — joining agents, the mesh, EXPERIMENTAL status.
13. [High availability](ha.md) — HA control plane, EXPERIMENTAL status.
14. [Linux images](vm-runtimeclass.md) — the intended isolation boundary for untrusted
    workloads: it boots `linux/arm64` images per Pod today.
15. [MLX serving](mlx-quickstart.md) — serving a model on the Mac's GPU through an OpenAI-compatible endpoint.
16. [Limitations](limitations.md) — **the real gaps**.
17. [Troubleshooting](troubleshooting.md) — logs, common failures, recovery.
18. [FAQ](faq.md) — short answers to the common questions.

## Before You Build Anything Real

k3sm is **not** a drop-in replacement for a Linux Kubernetes cluster. Workloads must be adapted, and
several standard behaviors diverge by design. Read [Limitations](limitations.md) first — it cites the
canonical conformance registers so nothing there is rosier than the truth.

MLX / Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page — see [MLX quickstart](mlx-quickstart.md), item 14 above. The rest of these pages
describe the general workload path.
