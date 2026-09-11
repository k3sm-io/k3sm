# k3sm user documentation

**k3sm** is a macOS-native Kubernetes distribution for Apple Silicon, the macOS/arm64 analog of
k3s. Pods run as **native Darwin processes** (no Linux, no containers, no VM by default). This
directory is the front door to the user-facing docs; read them roughly in the journey order below.

> These pages describe user-visible behavior. The authoritative product design lives in
> [the design document](../DESIGN.md).

## Read in Order

1. [Quickstart](quickstart.md) brings up one node and runs your first Pod in a few minutes.
2. [Installation](install.md) covers what `k3sm install` does, the one-time admin step, and the
   `_k3sm` posture.
3. [Concepts](concepts.md) explains how k3sm maps Kubernetes onto native Darwin processes.
4. [Cluster access](kubectl-access.md) walks through getting a kubeconfig and talking to the cluster.
5. [Supported workloads](what-runs.md) lists the OCI images k3sm runs, what it refuses, and the path
   from a Dockerfile to a running Pod.
6. [Images](images.md) is the reference for both workload conventions, `k3sm build`, `image
   load`/`import`/`push`, and every deliberate difference from the `docker` verb of the same name.
7. [Node-local registry](registry.md) covers the loopback OCI registry, where you push a locally
   built image and pull it back through the ordinary Kubernetes image path.
8. [Storage](storage.md) covers local-path PVs, node affinity, and what is and isn't supported.
9. [Version support](versions.md) names the Kubernetes version k3sm tracks and shows how to read the
   live pin.
10. [Upgrades](upgrade.md) walks through upgrading a node or cluster and the launchd restart model.
11. [Certificates](certificates.md) covers the two CAs, `k3sm certificate rotate`, and what it does
    not do.
12. [Backup and restore](backup-restore.md) covers the kine/SQLite datastore, with
    `k3sm snapshot save`/`restore`, the automatic pre-migration copy, and the restore drill.
13. [Multi-node clusters](multi-node.md) covers joining agents, the mesh, and its EXPERIMENTAL status.
14. [High availability](ha.md) covers the HA control plane and its EXPERIMENTAL status.
15. [Linux images](vm-runtimeclass.md) describes the intended isolation boundary for untrusted
    workloads; it boots `linux/arm64` images per Pod today.
16. [MLX serving](mlx-quickstart.md) walks through serving a model on the Mac's GPU through an
    OpenAI-compatible endpoint.
17. [Limitations](limitations.md) lists the gaps.
18. [Troubleshooting](troubleshooting.md) covers logs, common failures, and recovery.
19. [FAQ](faq.md) gives short answers to the common questions.

## Before You Build Anything Real

k3sm is **not** a drop-in replacement for a Linux Kubernetes cluster. Workloads must be adapted, and
several standard behaviors diverge by design. Read [Limitations](limitations.md) first; it cites the
canonical conformance registers, so nothing there is rosier than the truth.

MLX / Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page; see [MLX quickstart](mlx-quickstart.md), item 16 above. The rest of these pages
describe the general workload path.
