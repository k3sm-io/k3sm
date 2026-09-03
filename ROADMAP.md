# k3sm roadmap

> **Hand-written public roadmap narrative.** The engineering ledger each repo keeps is the
> source of truth for delivery state. **Edit by hand.**

k3sm is a macOS-native Kubernetes distribution for Apple Silicon — the macOS/arm64 analog of
[k3s](https://github.com/k3s-io/k3s). Pods run as **native Darwin processes: zero Linux, no VM in
the default path**, isolated with macOS's own primitives (Seatbelt, `lo0`/vmnet, wireguard-go,
launchd, APFS) instead of Linux's (cgroups, namespaces, iptables, systemd, OverlayFS). A
`vm` RuntimeClass adds an opt-in path that boots `linux/arm64` OCI images in a
per-pod micro-VM — see Shipped, below.

This is a k3s-style three-horizon roadmap. Where a capability is implemented but not yet
validated on real hardware, this page says so. The trade-offs page is [**docs/user/limitations.md**](docs/user/limitations.md), which ships with
the docs today.

## Shipped

The engine. Milestones **M0–M6 and M10** are implemented and workspace-integration-green
(`hack/ci.sh`). **M0, M1 and M2 are validated end to end on Apple-Silicon hardware** — M2's gate is
the strongest evidence so far: run against a real root install on macOS 26.5, all **13 required
conformance criteria passed**, together with the full install/uninstall lifecycle checks. That is
the first live-hardware validation of the packaged single-node path. The remaining live-hardware and
two-Mac gates are burned down in M7. What works:

- **Native Darwin-process pods, zero Linux on the default path.** OCI images ship an arm64
  Mach-O payload (never `/System`); the runtime `posix_spawn`s them **in place at host paths** —
  no chroot, SIP-compatible. *(validated on macOS 26.5.1)* Linux images run too, opt-in, under the
  `vm` RuntimeClass below.
- **Seatbelt isolation.** A generated **default-deny SBPL profile** per pod (read `/System`+the pod
  dir, write only the pod's APFS data volume, network scoped to the pod IP). *(validated)*
- **One `k3sm server`.** A single binary embeds the upstream apiserver / scheduler /
  controller-manager (built from source for darwin/arm64) over **kine → SQLite**, plus the Virtual
  Kubelet Darwin node, a userspace Service proxy, and DNS.
- **Pod networking.** IP-per-pod on `lo0` aliases (XNU preserves the bound source IP — no NAT),
  a userspace ClusterIP/NodePort Service proxy, and a per-node DNS resolver.
- **Multi-node mesh.** A **wireguard-go** userspace mesh over root utun; peers join with one token;
  public keys distributed via a `MeshPeer` CRD. *(partly built: the join flow and the worker side
  work, but a server does not yet bring up its own mesh device, so cross-node pod traffic does not
  reach its destination. Measured on a two-Mac rig 2026-08-31.)*
- **Local-path storage.** A local-path provisioner with node-affinity PVs + StatefulSet identity.
- **RBAC + admission.** `Node,RBAC` authorization with `NodeRestriction`, and admission guardrails
  (workloads must select `kubernetes.io/os=darwin`). *(implemented; the live RBAC flip is a
  dev-mac gate)*
- **`vm` RuntimeClass.** A fail-closed dispatch to a
  Virtualization.framework Linux micro-VM for `linux/arm64` images (e.g. Postgres): the RuntimeClass,
  the fail-closed backend selection, the capability labels, the scheduler overhead accounting, and
  PVC-backed storage. Validated end to end on the reference hardware (see
  [docs/user/limitations.md](docs/user/limitations.md)): boot and restart, `kubectl logs`/`exec` with
  exit-code propagation, PersistentVolumeClaims that survive a hard hypervisor kill, in-guest cluster
  DNS, per-container CPU and memory, and a Service routing to a `vm` pod through its ClusterIP.
  Shipped at v0.1.0 (tagged 2026-09-01), `linux/arm64` only — an `amd64` image is refused at pull
  rather than started and left to crash, on either the native or the `vm` path. See Next.
- **A built-in image build engine.** `k3sm builder up|down|delete` manages a guest-root buildkitd
  engine inside a `vm`-RuntimeClass micro-VM with a PVC-backed cache; `k3sm build` auto-routes any
  Dockerfile with `RUN` (or another engine-only verb) through it while a COPY-only Dockerfile keeps
  the native fast path, and `k3sm builder buildx` exposes the bundled, pinned buildx directly —
  install only k3sm, build and run containers with no Docker Desktop. Validated live end to end,
  2026-09-02/03: a RUN build → OCI export → `k3sm image push` → a Pod running the result.
  `linux/arm64` only — `linux/amd64` under guest Rosetta is not wired (see Future, below). The
  buildkitd image currently defaults to the pinned upstream digest rather than the (still-private)
  k3sm GHCR mirror, and buildx ships as a verified prebuilt asset rather than source-built; both are
  the remaining packaging work.
- **HA control plane (EXPERIMENTAL).** kine→Postgres multi-writer + leader-election + server-join
  with an identical-CA bundle. *(implemented; the live 2-Mac+Postgres failover is a lab gate)*
- **Conformance hardening (M10).** As close to standard k8s as the Darwin substrate honestly
  allows: per-pod IPs (headless/SRV/StatefulSet DNS), an in-process Ingress controller +
  LoadBalancer, native sidecar containers, Job/CronJob fidelity, Pod Security Admission + audit
  logging, node lifecycle Events. Validated by k3sm's own synthetic-conformance criteria — **not** a
  CNCF `[Conformance]` pass (the default path, which the suite targets, runs no Linux containers).
  The self-assessment —
  targeted feature classes mapped to a green criterion or a documented ceiling — is
  [`docs/conformance-profile.md`](docs/conformance-profile.md).
- **MLX — native Apple-Silicon ML serving (the NVIDIA-GPU-Operator analog for Mac).** Schedule
  and serve ML models on Apple GPUs / unified memory with first-class Kubernetes semantics: an
  **`MLXModel` CRD** (`mlx.k3sm.io/v1alpha1`), an `mlx.k3sm.io/gpu` **extended resource**, and an
  in-binary operator that reconciles a model to a StatefulSet + Service serving an
  OpenAI-compatible API. *(validated end to end on Apple-GPU hardware — the
  `hack/acceptance/m8.sh` gate: 22/22 checks green, including a real Hugging Face weight
  download under a default-deny Seatbelt profile and a GC-clean deletion)*

## v0.1.0 — the public release (shipped 2026-09-01)

- **Ship it.** Install arrives in three generations, in shipping order: *(1)*
  `curl -fsSL https://k3sm.io/install.sh | sh` — a checksum-verified release tarball handed to
  `sudo k3sm install` (a curl download carries no quarantine xattr); *(2)*
  `brew install k3sm-io/tap/k3sm`; *(3)* a signed, notarized `.pkg`. Underneath: goreleaser,
  [user docs](docs/user/), and the website.
- **Bring your images.** `k3sm image load` / `k3sm image import` ingest docker-save
  tarballs and OCI layouts (the `docker buildx -o type=oci` output) into k3sm's image store, and
  `k3sm build` packages native darwin/arm64 binaries from a COPY-only Dockerfile subset
  (`RUN` arrives with the vm-backed builder — see Shipped, above).
- **Run your Linux images (validated on hardware).** Standard **linux/arm64 images**
  run as `vm`-RuntimeClass pods — one lightweight micro-VM per pod — with `kubectl exec/logs/top`,
  PVC-backed persistence, Service/DNS reachability, readiness probes, and private-registry
  pulls. A whole multi-part app's containers, unmodified images with a three-line manifest
  adaptation (`kubernetes.io/os: darwin` + `runtimeClassName: vm`).
  *(the live lab run against the released artifact is green — see Shipped, above;
  published performance figures and the remaining ceilings are the v0.2 milestone below)*
- **linux/amd64 images are not supported on any path yet.** Running them needs Rosetta-for-Linux
  translation inside the guest, deliberately cut from the first release so the arm64 path could be
  validated on hardware on its own. There is no emulation fallback — no qemu exists for a Darwin
  host — so an amd64-only image is refused at pull with a no-matching-platform error rather than
  started and left to crash, and a node that cannot translate does not advertise that it can.
  *(scheduled for a v0.1.x follow-up)*

v0.1.1 followed on 2026-09-02 — see [CHANGELOG.md](CHANGELOG.md) for what it adds.

## Future — post-v0.1.0

- **The Linux `vm` path, v0.2** — the Linux-image capability ships at v0.1 (above); v0.2 adds
  the full lab ledger green with **published performance figures** (VM boot latency = restart
  cost, the Rosetta non-TSO ratio, virtiofs I/O vs native APFS), and the remaining ceilings
  either closed or documented (per-pod network segmentation between micro-VMs, host-path
  sharing). Plus darwin/amd64 pod payloads under host Rosetta on the native path.
- **`linux/amd64` in the build engine, via guest Rosetta** — the managed buildkitd builder (see
  Shipped, above) builds `linux/arm64` only today; targeting `linux/amd64` needs the same
  in-guest Rosetta translation the `vm` RuntimeClass itself doesn't have yet (see Limitations).
- **Kubelet-faithful registry semantics on the native path** — the pull-failure backoff taxonomy
  (`ErrImagePull`/`ImagePullBackOff` alternation, `ErrImageNeverPull`), Rosetta-consuming
  multi-arch selection, and a warm-cache offline start under `imagePullPolicy: IfNotPresent` /
  `Never` are still open.
- **De-EXPERIMENTAL HA** — the v0.3 headline, once lab-validated (two Macs + Postgres).
- **ANE** — Apple Neural Engine serving, pending a stable public API (CoreML-only today).
- **DRA** — Dynamic Resource Allocation for GPUs, once extended resources have shipped.
- **JACCL / distributed inference** — multi-Mac model sharding (the reserved `MLXModel.Distributed`
  seam + the already-rendered headless governing Service).
- **Autoscaling** — scale-to-zero / activator-fronted model serving.

### Non-goals (deliberate)

- **Not a Linux-container runtime.** k3sm runs native Darwin processes. Linux images run only
  under the `vm` RuntimeClass (a separate micro-VM stack, `linux/arm64` only), never
  the default path.
- **A single node is one trust domain.** Same-node pods share `lo0` and a uid — Seatbelt bounds
  filesystem/network *reach*, but there are no per-pod network namespaces or uid isolation.
  Untrusted multi-tenancy is out of scope for the native path; the `vm` RuntimeClass is the
  intended boundary.
