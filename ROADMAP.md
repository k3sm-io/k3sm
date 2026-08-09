# k3sm roadmap

> **Hand-written public roadmap narrative.** The per-repo `docs/PHASES.md` are the engineering
> source of truth. **Edit by hand.**

k3sm is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
[k3s](https://github.com/k3s-io/k3s). Pods run as **native Darwin processes: zero Linux, no VM in
the default path**, isolated with macOS's own primitives (Seatbelt, `lo0`/vmnet, wireguard-go,
launchd, APFS) instead of Linux's (cgroups, namespaces, iptables, systemd, OverlayFS).

This is a k3s-style three-horizon roadmap. Honesty is a feature: where a capability is
code-complete but not yet proven on real hardware, this page says so. The forthcoming
`docs/user/limitations.md` (landing in M7) is the canonical honest-tradeoffs page.

## Shipped

The engine. Milestones **M0–M6** are code-complete and workspace-integration-green (`hack/ci.sh`);
M0/M1 are validated end-to-end by their acceptance gates, and the remaining live-hardware and
two-Mac gates are burned down in M7. What works:

- **Native Darwin-process pods, zero Linux.** OCI images ship an arm64 Mach-O payload (never
  `/System`); the runtime `posix_spawn`s them **in place at host paths** — no chroot, SIP-compatible.
  *(validated on macOS 26.5.1)*
- **Seatbelt isolation.** A generated **default-deny SBPL profile** per pod (read `/System`+the pod
  dir, write only the pod's APFS data volume, network scoped to the pod IP). *(validated)*
- **One `k3sm server`.** A single binary embeds the upstream apiserver / scheduler /
  controller-manager (built from source for darwin/arm64) over **kine → SQLite**, plus the Virtual
  Kubelet Darwin node, a userspace Service proxy, and DNS.
- **Pod networking.** IP-per-pod on `lo0` aliases (XNU preserves the bound source IP — no NAT),
  a userspace ClusterIP/NodePort Service proxy, and a per-node DNS resolver.
- **Multi-node mesh.** A **wireguard-go** userspace mesh over root utun; peers join with one token;
  public keys distributed via a `MeshPeer` CRD. *(code-complete; the two-Mac e2e is a lab gate)*
- **Local-path storage.** A local-path provisioner with node-affinity PVs + StatefulSet identity.
- **RBAC + admission.** `Node,RBAC` authorization with `NodeRestriction`, and admission guardrails
  (workloads must select `kubernetes.io/os=darwin`). *(code-complete; the live RBAC flip is a
  dev-mac gate)*
- **`vm` RuntimeClass (EXPERIMENTAL).** A fail-closed dispatch to a Virtualization.framework Linux
  micro-VM for Linux-only images (e.g. Postgres). *(foundation code-complete; the live VM boot needs
  a VZ Mac + entitlement — ships EXPERIMENTAL)*
- **HA control plane (EXPERIMENTAL).** kine→Postgres multi-writer + leader-election + server-join
  with an identical-CA bundle. *(code-complete; the live 2-Mac+Postgres failover is a lab gate)*

## Next — v0.1.0 (the public release, with MLX)

The first public release. Two tracks, both launch-blocking:

- **Ship it.** Install arrives in three generations, in shipping order: *(1)*
  `curl -fsSL https://k3sm.io/install.sh | sh` — a checksum-verified release tarball handed to
  `sudo k3sm install` (works from the first tagged release; a curl download carries no quarantine
  xattr); *(2)* `brew install k3sm-io/tap/k3sm`; *(3)* a signed, notarized `.pkg`. Underneath:
  goreleaser, GitHub Actions CI across all repos, user docs (`docs/user/`, including
  `limitations.md`), and the website.
- **MLX — the differentiator.** Native Apple-Silicon ML serving: schedule and serve ML models on
  Apple GPUs / unified memory with first-class Kubernetes semantics. An **`MLXModel` CRD**
  (`mlx.k3sm.io/v1alpha1`) + an `mlx.k3sm.io/gpu` **extended resource** + an in-binary operator that
  reconciles a model to a StatefulSet + Service serving an OpenAI-compatible API. This is the
  **NVIDIA-GPU-Operator analog for Mac** — running LLMs on a Mac mini as a k3sm pod is the launch
  story.
- **Bring your images (targeted).** `k3sm image load` / `k3sm image import` ingest docker-save
  tarballs and OCI layouts (the `docker buildx -o type=oci` output) into k3sm's image store, and a
  first `k3sm build` packages native darwin/arm64 binaries from a COPY-only Dockerfile subset
  (`RUN` arrives with the vm-backed builder, below). *(targeted at v0.1.0; included in the release
  announcement only if merged and green by the pre-flight)*
- **Run your Linux images (targeted, EXPERIMENTAL).** Standard **linux/arm64 AND linux/amd64
  images** run as `vm`-RuntimeClass pods — one lightweight micro-VM per pod (amd64 via
  Rosetta-for-Linux, the Docker-Desktop-class path; no qemu) — with `kubectl exec/logs/top`,
  PVC-backed persistence, Service/DNS reachability in both directions, readiness probes, and
  private-registry pulls. A whole multi-part app's containers, unmodified images with a
  three-line manifest adaptation (`kubernetes.io/os: darwin` + `runtimeClassName: vm`).
  *(targeted at v0.1.0 as EXPERIMENTAL — launch-gated by a live lab proof against the release
  artifact; included in the announcement only if that gate is green; the de-EXPERIMENTAL
  graduation with published performance figures is the v0.2 milestone below)*

Launch (the public flip, the `v0.1.0` tag, the announcement) is its own runbook.

## Future — post-v0.1.0

- **Kubernetes conformance hardening (M10)** — get as close to standard k8s as the Darwin substrate
  honestly allows. k3sm already embeds the real apiserver/scheduler/controller-manager, so the whole
  control-plane API surface is genuine; M10 closes the achievable gaps at the node/network/storage
  edge: per-pod IPs (unblocking headless/SRV/StatefulSet DNS), an in-process Ingress controller +
  LoadBalancer, native sidecar containers, Job/CronJob fidelity, Pod Security Admission + audit
  logging, node lifecycle Events. The honest "where we are vs upstream k8s" register lives at
  `docs/UPSTREAM-ALIGNMENT.md`; the self-assessment (k3sm cannot pass Sonobuoy `[Conformance]` — it
  has no Linux containers — but targets a documented subset) at `docs/conformance-profile.md`.
- **De-EXPERIMENTAL the Linux `vm` path (the graduation)** — the Linux-image capability ships at
  v0.1 (EXPERIMENTAL, above); the v0.2 milestone is its **graduation**: the full lab ledger green
  with **published performance figures** (VM boot latency = restart cost, the Rosetta non-TSO
  ratio, virtiofs I/O vs native APFS), the branding removed, and the remaining ceilings either
  closed or documented (per-pod network segmentation between micro-VMs, host-path sharing).
  Plus darwin/amd64 pod payloads under host Rosetta on the native path. Engineering plan:
  `docs/m11-plan.md` (workspace).
- **A built-in image build engine** — `k3sm build` grows full Dockerfile support (`RUN` included)
  by managing a BuildKit builder inside a `vm`-RuntimeClass micro-VM (linux/arm64 natively,
  linux/amd64 via Rosetta) behind a bundled buildx front-end — install only k3sm, build and run
  containers with no Docker Desktop. Lands **shortly after v0.1** (the builder needs the vm path
  live plus the signed vmhost and kernel artifacts that ship with it, then its own lab
  validation). Kubelet-faithful registry semantics on the native path (imagePullPolicy,
  pull-failure backoff, multi-arch selection, offline warm-cache starts) land alongside.
  Engineering plan: `docs/m12-plan.md` (workspace).
- **De-EXPERIMENTAL HA** — the v0.3 headline, once lab-validated (two Macs + Postgres).
- **ANE** — Apple Neural Engine serving, pending a stable public API (CoreML-only today).
- **DRA** — Dynamic Resource Allocation for GPUs, once extended resources have shipped.
- **JACCL / distributed inference** — multi-Mac model sharding (the reserved `MLXModel.Distributed`
  seam + the already-rendered headless governing Service).
- **Autoscaling** — scale-to-zero / activator-fronted model serving.

### Non-goals (deliberate)

- **Not a Linux-container runtime.** k3sm runs native Darwin processes. Linux images route to the
  EXPERIMENTAL `vm` RuntimeClass (a separate micro-VM stack), never the default path.
- **A single node is one trust domain.** Same-node pods share `lo0` and a uid — Seatbelt bounds
  filesystem/network *reach*, but there are no per-pod network namespaces or uid isolation.
  Untrusted multi-tenancy is out of scope for the native path; use the `vm` RuntimeClass.
