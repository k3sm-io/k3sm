# k3sm synthetic-conformance profile

> ## ⚠️ This is NOT a CNCF Certified-Kubernetes badge
>
> **k3sm has not run the upstream `[Conformance]` suite, and by design cannot pass it.** That
> suite ([CNCF Certified Kubernetes](https://www.cncf.io/training/certification/software-conformance/))
> assumes **Linux containers, cgroups, CNI, and network namespaces**; k3sm runs Pods as **native Darwin
> processes** on Apple Silicon with none of those substrates, so it does not pass
> `[Conformance]`, and this document does **not** claim it does.
>
> This document maps k3sm's **targeted feature classes** to a **synthetic-conformance criterion**
> (a k3sm-authored test, **NOT** the CNCF suite) **or** a documented ceiling. A criterion here means
> "k3sm's own test asserts this behavior," not "upstream's e2e passed."

## Why k3sm Cannot Pass `[Conformance]`

This profile is k3sm's whole public statement of which upstream areas it cannot conform to and why.
User-facing tradeoff guidance (what an operator should do about each ceiling) is owned by
**[Limitations](user/limitations.md)**.

## Terms

- **criterion**: a k3sm-authored Go test that asserts the behavior. It is either a unit test, run by
  `go test ./...`, or an end-to-end test in `e2e/` (build tag `e2e`) that k3sm's acceptance scripts
  run against a live server.
- **live criterion owed**: the behavior ships and its unit tests pass, but the end-to-end test
  against a live cluster is not written yet.
- **ceiling**: a behavior the macOS substrate forbids, or one that routes to the `vm` RuntimeClass
  for correctness. It is documented rather than chased.
- **🟡 planned**: the behavior does not ship yet.

## Feature classes → criterion or ceiling

| feature class | k3sm posture | criterion or ceiling |
|---|---|---|
| **API machinery** (apiserver, RBAC, VAP admission, APF, CRD/aggregated-API, SSA, webhook delivery) | embedded real kube-apiserver | **criterion** (`Node,RBAC`; admission and conversion webhook delivery through the Service proxy) |
| **Admission config** (audit logging, PSA cluster default, default LimitRange) | argv + config written at provision | **criterion** (audit-log level, PSA warn default and its enforce cutover, memory-only default LimitRange) |
| **Pod lifecycle** (phase/conditions, probes, graceful stop, OOMKill, restartPolicy, native sidecars, hooks) | provider reconstructs the kubelet surface | **criterion**; live criterion owed for native sidecars and CrashLoopBackOff |
| **Workload controllers** (Deployment/RS/StatefulSet/DaemonSet/Job/CronJob, GC/finalizers, preemption) | embedded real KCM + scheduler | **criterion** (the controllers are upstream's), with DaemonSet toleration injection and Job completion and backoff accounting unit-tested; live criterion owed for Job completion |
| **Services** (ClusterIP/NodePort TCP, EndpointSlices, sessionAffinity, `internalTrafficPolicy: Local`) | userspace Service proxy | **criterion**; `externalTrafficPolicy: Local` is a **ceiling** (admitted, behaves as `Cluster`) |
| **DNS** (search/ndots/A, ExternalName, in-pod wiring, headless, SRV, PTR, pod A) | in-process resolver + getaddrinfo shim | **criterion** (headless, SRV, PTR and per-pod A answers unit-tested in the resolver) |
| **Per-pod network identity** (per-pod IP, headless, StatefulSet identity) | a distinct `/32` per Pod on the node's range | **criterion** (distinct pod IP per Pod, unit-tested); live criterion owed. Addressing only, never isolation |
| **Ingress / IngressClass / LoadBalancer** | own userspace L7 proxy; LoadBalancer Services hosted on every node by node pool | **criterion** (unit-tested ingress hosting, IngressClass status and LoadBalancer bind reporting); live criterion owed |
| **NetworkPolicy** | Service-VIP-mediated ingress allow/deny at the proxy | policy hint on the server node; **ceiling** as tenant isolation → `vm` |
| **Scheduling** (nodeSelector/affinity/taints, topology labels) | real upstream scheduler | **criterion** |
| **Resource model** (QoS, memory→OOMKill) | `proc_pid_rusage` sampler | **criterion** memory / **ceiling** CPU CFS-millicore limits |
| **Observability** (`/stats/summary`, `/metrics/resource`, lifecycle Events) | runtimed usage samples; provider EventRecorder | **criterion** (summary, `/metrics/resource` joint CPU and memory emission, Pulled/Created/Started/Killing Events) |
| **Config & storage** (ConfigMap/Secret, emptyDir/projected, PVC/PV local-path) | apiserver-served + runtimed materialization | **criterion** + **🟡 planned** resize/snapshot/generic ephemeral volumes |
| **Auth & supply chain** (bootstrap triad, apiserver↔node TLS, code-signing) | k3s-style join token pinned to the cluster CA; release binaries are Developer ID signed and notarized | **criterion** |
| **Datastore** (kine→SQLite WAL, KCM scoping) | bundled kine (child process); embedded etcd on an experimental two-server control plane | **criterion** |

## Hard ceilings (documented, never chased)

- No Linux containers / cgroups / CNI / netns / device-plugins / hugepages.
- No per-pod uid isolation, because same-node pods share one `_k3sm` trust domain. Untrusted tenancy
  is destined for `vm` (`linux/arm64`, single-node).
- Absolute-path volume mounts resolve for **native workloads** (a `DYLD_INSERT` path-rebase shim; no
  chroot), **not** SIP platform binaries. A `/bin/sh` script can't read a mounted file at its
  absolute path, because macOS strips `DYLD_INSERT_LIBRARIES` from platform binaries.
- `externalTrafficPolicy: Local`, CFS millicore CPU *limits*, HPA-on-CPU-limit, `hostPath` /
  `terminationMessagePath` bind mounts, node-pressure eviction as a hard guarantee, NetworkPolicy as a
  tenant boundary.

## Scope of these claims

- Criteria are **k3sm's own tests**. A criterion row is "asserted by a k3sm test," never a
  `[Conformance]` pass. Re-derive any row against current `main`.
- A `🟡 planned` row names behavior that does not ship yet, and a "live criterion owed" row names an
  end-to-end test still to be written.
- A live `[Conformance]` run against the *adapted* subset remains a future goal, out of scope for
  this profile.
