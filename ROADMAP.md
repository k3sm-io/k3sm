# k3sm roadmap

> **Hand-written public roadmap narrative.** The engineering ledger each repo keeps is the
> source of truth for delivery state. **Edit by hand.**

k3sm is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
[k3s](https://github.com/k3s-io/k3s). Pods run as **native Darwin processes: zero Linux, no VM in
the default path**, isolated with macOS's own primitives (Seatbelt, `lo0`/vmnet, wireguard-go,
launchd, APFS) instead of Linux's (cgroups, namespaces, iptables, systemd, OverlayFS).

This is a k3s-style three-horizon roadmap. Honesty is a feature: where a capability is
code-complete but not yet proven on real hardware, this page says so. The canonical
honest-tradeoffs page is [**docs/user/limitations.md**](docs/user/limitations.md), which ships with
the docs today.

## Shipped

The engine. Milestones **M0–M6 and M10** are code-complete and workspace-integration-green
(`hack/ci.sh`). **M0, M1 and M2 are validated end to end on Apple-Silicon hardware** — M2's gate is
the strongest evidence so far: run against a real root install on macOS 26.5, all **13 required
conformance criteria passed**, together with the full install/uninstall lifecycle checks. That is
the first live-hardware proof of the packaged single-node path. The remaining live-hardware and
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
- **Conformance hardening (M10).** As close to standard k8s as the Darwin substrate honestly
  allows: per-pod IPs (headless/SRV/StatefulSet DNS), an in-process Ingress controller +
  LoadBalancer, native sidecar containers, Job/CronJob fidelity, Pod Security Admission + audit
  logging, node lifecycle Events. Proven by k3sm's own synthetic-conformance criteria — **not** a
  CNCF `[Conformance]` pass (k3sm has no Linux containers). The honest self-assessment —
  targeted feature classes mapped to a green criterion or a documented ceiling — is
  [`docs/conformance-profile.md`](docs/conformance-profile.md).
- **MLX — native Apple-Silicon ML serving (the NVIDIA-GPU-Operator analog for Mac).** Schedule
  and serve ML models on Apple GPUs / unified memory with first-class Kubernetes semantics: an
  **`MLXModel` CRD** (`mlx.k3sm.io/v1alpha1`), an `mlx.k3sm.io/gpu` **extended resource**, and an
  in-binary operator that reconciles a model to a StatefulSet + Service serving an
  OpenAI-compatible API. *(validated end to end on Apple-GPU hardware — the
  `hack/acceptance/m8.sh` gate: 22/22 checks green, including a real Hugging Face weight
  download under a default-deny Seatbelt profile and a GC-clean deletion)*

## Next — v0.1.0 (the public release)

The first public release. One track is launch-blocking:

- **Ship it.** Install arrives in three generations, in shipping order: *(1)*
  `curl -fsSL https://k3sm.io/install.sh | sh` — a checksum-verified release tarball handed to
  `sudo k3sm install` (works from the first tagged release; a curl download carries no quarantine
  xattr); *(2)* `brew install k3sm-io/tap/k3sm`; *(3)* a signed, notarized `.pkg`. Underneath:
  goreleaser, GitHub Actions CI across all repos, [user docs](docs/user/) (which ship today —
  they are not gated on the release), and the website.
- **Bring your images (targeted).** `k3sm image load` / `k3sm image import` ingest docker-save
  tarballs and OCI layouts (the `docker buildx -o type=oci` output) into k3sm's image store, and a
  first `k3sm build` packages native darwin/arm64 binaries from a COPY-only Dockerfile subset
  (`RUN` arrives with the vm-backed builder, below). *(targeted at v0.1.0; included in the release
  announcement only if merged and green by the pre-flight)*
- **Run your Linux images (targeted, EXPERIMENTAL).** Standard **linux/arm64 images** run as
  `vm`-RuntimeClass pods — one lightweight micro-VM per pod — with `kubectl exec/logs/top`,
  PVC-backed persistence, Service/DNS reachability, readiness probes, and private-registry
  pulls. A whole multi-part app's containers, unmodified images with a three-line manifest
  adaptation (`kubernetes.io/os: darwin` + `runtimeClassName: vm`).
  *(targeted at v0.1.0 as EXPERIMENTAL — launch-gated by a live lab proof against the release
  artifact; included in the announcement only if that gate is green; the de-EXPERIMENTAL
  graduation with published performance figures is the v0.2 milestone below)*
- **linux/amd64 images are NOT in v0.1.0.** Running them needs Rosetta-for-Linux translation
  inside the guest, and it is deliberately cut from the first release so the arm64 path can be
  proven on hardware on its own. There is no emulation fallback — no qemu exists for a Darwin
  host — so until translation lands, an amd64-only image is refused at pull with a
  no-matching-platform error rather than started and left to crash, and a node that cannot
  translate does not advertise that it can. *(scheduled for a v0.1.x follow-up)*

Launch (the public flip, the `v0.1.0` tag, the announcement) is its own runbook.

## Future — post-v0.1.0

- **De-EXPERIMENTAL the Linux `vm` path (the graduation)** — the Linux-image capability ships at
  v0.1 (EXPERIMENTAL, above); the v0.2 milestone is its **graduation**: the full lab ledger green
  with **published performance figures** (VM boot latency = restart cost, the Rosetta non-TSO
  ratio, virtiofs I/O vs native APFS), the branding removed, and the remaining ceilings either
  closed or documented (per-pod network segmentation between micro-VMs, host-path sharing).
  Plus darwin/amd64 pod payloads under host Rosetta on the native path.
- **A built-in image build engine** — `k3sm build` grows full Dockerfile support (`RUN` included)
  by managing a BuildKit builder inside a `vm`-RuntimeClass micro-VM (linux/arm64 natively,
  linux/amd64 via Rosetta) behind a bundled buildx front-end — install only k3sm, build and run
  containers with no Docker Desktop. Lands **shortly after v0.1** (the builder needs the vm path
  live plus the signed vmhost and kernel artifacts that ship with it, then its own lab
  validation). Kubelet-faithful registry semantics on the native path (imagePullPolicy,
  pull-failure backoff, multi-arch selection, offline warm-cache starts) land alongside.
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
