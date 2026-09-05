# k3sm synthetic-conformance profile

> ## ⚠️ This is NOT a CNCF Certified-Kubernetes badge
>
> **k3sm has not run — and by design cannot pass — the upstream Sonobuoy `[Conformance]` suite.** That
> suite ([CNCF Certified Kubernetes](https://www.cncf.io/training/certification/software-conformance/))
> assumes **Linux containers, cgroups, CNI, and network namespaces**; k3sm runs Pods as **native Darwin
> processes** on Apple Silicon with none of those substrates, so it does not pass
> `[Conformance]`, and this document does **not** claim it does.
>
> What this document *is*: a map from k3sm's **targeted feature classes** to a **green synthetic-
> conformance criterion** (a k3sm-authored test in `hack/lib/conformance.sh`, static, run in
> `hack/ci.sh` — **NOT** the CNCF suite) **or** a documented ceiling. A green criterion here means
> "k3sm's own test asserts this behavior," not "upstream's e2e passed."

## Canonical "why we can't pass"

The authoritative, single-source explanation of **which upstream areas k3sm cannot conform to and why**
lives in k3sm's internal full-surface conformance register (one row per feature × verdict, with a
canonical §By-design non-conformance summary). This profile summarizes that assessment; it does not
restate the full register. User-facing tradeoff guidance (what an operator should do about each ceiling)
is owned by **[Limitations](user/limitations.md)**.

## Terms

- **synthetic-conformance criterion** — a k3sm-authored Go test in a `hack/lib/conformance.sh`
  criterion slice, static and hermetic-or-integration-tiered, run by `hack/ci.sh`. Promoted into a
  criterion set **only in the PR that lands it green** (never regress a green gate).
- **ceiling** — a behavior the macOS substrate forbids (`honest-limitation` in the register) or that
  routes to the `vm` RuntimeClass for correctness. Documented, not chased.
- **🟡 planned** — achievable-as-wiring and scheduled (tracked internally against the
  conformance-hardening work); green criterion owed, not yet landed.

## Feature classes → criterion or ceiling

| feature class | k3sm posture | criterion or ceiling | register §home |
|---|---|---|---|
| **API machinery** (apiserver, RBAC, VAP admission, APF, CRD/aggregated-API, SSA, webhook delivery) | embedded real kube-apiserver | **criterion** (`Node,RBAC`; webhook-delivery e2e owed) | §1 |
| **Admission config** (audit logging, PSA cluster default, default LimitRange) | argv + config additions | **🟡 planned** audit-log level / PSA cluster default / memory-only LimitRange criteria (integration-tiered) | §1 |
| **Pod lifecycle** (phase/conditions, probes, graceful stop, OOMKill, restartPolicy, hooks) | provider reconstructs the kubelet surface | **criterion** + **🟡 planned** native sidecars, subPath | §2 |
| **Workload controllers** (Deployment/RS/StatefulSet/DaemonSet/Job/CronJob, GC/finalizers, preemption) | embedded real KCM + scheduler | **criterion** (free-because-embedded) + **🟡 planned** Job/CronJob fidelity, DaemonSet toleration, rolling-update readiness | §10 |
| **Services** (ClusterIP/NodePort TCP, EndpointSlices, sessionAffinity, iTP:Local) | userspace Service proxy | **criterion** | §3 |
| **DNS** (search/ndots/A, ExternalName, in-pod wiring) | in-process resolver + getaddrinfo shim | **criterion** + **🟡 planned** headless/SRV/PTR/pod-A | §3/§4 |
| **Per-pod network identity** (headless, SRV, PTR, StatefulSet identity) | `/32` allocator + SBPL bind-discipline exist, **unwired today** | **🟡 planned** (achievable-as-wiring, **not** a ceiling) | §3 |
| **Ingress / IngressClass / LoadBalancer** | own userspace L7 proxy (`pkg/ingress`) | **🟡 planned** (`hack/acceptance/m10-ingress.sh`) | §12 |
| **NetworkPolicy** | userspace-proxy dst-VIP allow/deny | **🟡 planned** L4 *hint* / **ceiling** as tenant isolation → `vm` | §12 |
| **Scheduling** (nodeSelector/affinity/taints, topology labels) | real upstream scheduler | **criterion** | §6 |
| **Resource model** (QoS, memory→OOMKill) | `proc_pid_rusage` sampler | **criterion** memory / **ceiling** CPU CFS-millicore limits | §7 |
| **Observability** (`/stats/summary`, `/metrics/resource`, lifecycle Events) | runtimed working-set surface | **criterion** summary + **🟡 planned** `/metrics/resource`, node Events | §5/§7 |
| **Config & storage** (ConfigMap/Secret, emptyDir/projected, PVC/PV local-path) | apiserver-served + runtimed materialization | **criterion** + **🟡 planned** resize/snapshot/ephemeral | §11 |
| **Auth & supply chain** (bootstrap triad, apiserver↔node TLS, code-signing) | k3s-style join + notarized binary | **criterion** | §8 |
| **Datastore** (kine→SQLite WAL, KCM scoping) | bundled kine (child process) | **criterion** | §9 |

## Hard ceilings (documented, never chased)

Per the internal §By-design summary — summarized, not restated:

- No Linux containers / cgroups / CNI / netns / device-plugins / hugepages (`not-applicable`).
- No per-pod uid isolation — same-node pods share one `_k3sm` trust domain; untrusted tenancy is
  destined for `vm`, which runs today (`linux/arm64`, single-node, validated on real hardware).
- Absolute-path volume mounts resolve for **native workloads** (a `DYLD_INSERT` path-rebase shim; no
  chroot), **not** SIP platform binaries — a `/bin/sh` script can't read a mounted file at its
  absolute path (macOS strips `DYLD_INSERT_LIBRARIES` from platform binaries).
- `externalTrafficPolicy: Local`, CFS millicore CPU *limits*, HPA-on-CPU-limit, `hostPath` /
  `terminationMessagePath` bind mounts, node-pressure eviction as a hard guarantee, NetworkPolicy as a
  tenant boundary.

## Scope of these claims

- Criteria are **k3sm's own tests**, static — a green row is "asserted by a k3sm test," never a
  `[Conformance]` pass. Re-derive any row against current `main`.
- A `🟡 planned` row's criterion is **owed**, not present; it names the behaviour still to be
  asserted.
- A live `[Conformance]`/Sonobuoy run against the *adapted* subset remains an explicit future lab goal
  (DESIGN §9), out of scope for this static profile.
