# k3sm user documentation

**k3sm** is a macOS-native Kubernetes distribution for Apple Silicon, the macOS/arm64 analog of
k3s. Pods run as **native Darwin processes** (no Linux, no containers, no VM by default). This
directory is the front door to the user-facing docs; read them roughly in the journey order below.

> These pages describe user-visible behavior. The authoritative product design lives in
> [the design document](../DESIGN.md).

## Experimental and Alpha
<a id="what-experimental-means"></a>

Pages and features labeled **experimental** share one meaning. There is no upgrade-compatibility
promise between releases, so a release may change or drop the feature and its data. Keep datastore
backups (see [Backup and restore](backup-restore.md)) and do not use it for production. **Alpha**
marks an API version (`v1alpha1`) with the same terms. Where a page also says an alpha is not yet
run on hardware, that is an added caveat: nobody has exercised it on real Macs yet.

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
7. [The cluster registry](registry.md) covers the cluster's one image store, `registry-k3sm:6450`,
   where you push a locally built image and pull it back through the ordinary Kubernetes image path.
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
    `/v1/chat/completions` endpoint.
17. [A Linux server under the vm RuntimeClass](temporal-example.md) runs a durable-execution
    server's `linux/arm64` images in per-Pod micro-VMs and talks to it from a native client.
18. [Interconnects](interconnects.md) covers a Thunderbolt cable between Macs as an opt-in network
    for Pods that ask for it, the MLX ranks of a sharded model above all.
19. [Limitations](limitations.md) lists the gaps.
20. [Conformance profile](../conformance-profile.md) is the self-assessment of what k3sm targets and why it
    is not a CNCF `[Conformance]` pass.
21. [Troubleshooting](troubleshooting.md) covers the node's own daemon logs, common failures, and
    recovery.
22. [Status JSON](status-json.md) is the contract for `k3sm status -o json` and the cheap
    `k3sm status daemons -o json` probe: fields, enums, versioning and exit codes.
23. [Container logs](logs.md) covers where a Pod's output is written, `kubectl logs` and its
    options, rotation, and how to ship logs off a node.
24. [Stopping and starting](stop-start.md) covers `k3sm stop`, `start` and `restart`, what a stop does
    to pods and the cluster, and how a stop survives a reboot.
25. [Building images](builder.md) covers `k3sm build` and the in-cluster build engine.
26. [Helm charts](helm.md) covers installing releases with the `HelmChart` object.
27. [FAQ](faq.md) gives short answers to the common questions.

## Before You Build Anything Real

k3sm is **not** a drop-in replacement for a Linux Kubernetes cluster. Workloads must be adapted, and
several standard behaviors diverge by design. Read [Limitations](limitations.md) first; it cites the
canonical conformance registers, so nothing there is rosier than the truth.

MLX / Apple-GPU workloads (the `MLXModel` CRD and the `mlx.k3sm.io/gpu` extended resource) have
their own page; see [MLX quickstart](mlx-quickstart.md), item 16 above. The rest of these pages
describe the general workload path.
