# k3sm — a macOS-native Kubernetes distribution for Apple Silicon

> **`k3sm`** (k3s-for-macOS) — GitHub org `k3sm-io`, domain `k3sm.io`. The macOS/arm64 analog of [k3s](https://github.com/k3s-io/k3s): reuse Kubernetes' portable control plane, replace every Linux-bound node component with a Darwin-native one, ship one signed binary, and run **truly native Darwin workloads — zero Linux, no VM in the default path** — across one or more Macs.
>
> **Status: v2 (2026-06-24), red-teamed.** A 4-persona adversarial pressure-test against a macOS 26.5.1 machine + primary sources reshaped the runtime and networking designs (see §3). This is the living design doc; the four repos live under `/Users/miko/Code/k3sm-io/`.

## 1. Context

Kubernetes' control plane is portable Go; its node layer is deeply Linux-specific. Every existing "k8s on Mac" (Colima, Lima, Rancher Desktop, k3d, Docker Desktop) runs k3s/k8s **inside a Linux VM** — nobody runs the distro itself natively on Darwin. k3sm closes that gap: a Kubernetes-conformant orchestrator whose Pods are **native arm64 Mach-O processes** isolated with macOS's own primitives.

**Decisions locked:** (1) Pods run **truly native Darwin workloads, zero Linux**. (2) **Multi-node from the start** (no single-node-only shortcuts baked in). (3) Goals: **local dev + Mac CI/build-farm + Kubernetes/Darwin research**. (4) Org `k3sm-io`, domain `k3sm.io` (owned), vanity module paths `k3sm.io/<repo>`.

**Target & outcome.** macOS 26+ (Tahoe), Apple Silicon arm64. `k3sm server` brings up a conformant control plane + node; `kubectl run` a native-macOS image and it executes on the Mac with native isolation/networking; a second Mac joins with one token. The whole distribution installs via `brew install k3sm-io/tap/k3sm`.

## 2. The core constraint

Darwin (XNU/BSD) has **none** of the Linux container primitives, so the upstream **kubelet can't even build for `darwin/arm64`** (cAdvisor + cgroups are Linux-only). Replacements (✅ verified present/working on a macOS 26.5.1 box; ⚠️ works but constrained):

| Linux primitive | Used by | Darwin-native replacement |
|---|---|---|
| pid/mount namespaces | container isolation | ✅ default-deny **Seatbelt/SBPL** profile per process (NO chroot — see §3) |
| net namespaces, veth | pod networking | ⚠️ **`lo0` alias IP/pod** (loopback preserves bound src IP); micro-VM for true isolation |
| cgroups | resource mgmt | ⚠️ **userspace enforcement**: poll `proc_pid_rusage` → SIGKILL on mem breach; QoS/`taskpolicy` for CPU (best-effort) |
| cAdvisor | metrics | ✅ `proc_pid_rusage(RUSAGE_INFO_V6)` (`ri_phys_footprint`) → Summary API |
| OverlayFS | image layering | ✅ **APFS `clonefile`** CoW pod data dirs |
| iptables/ipvs | kube-proxy | ⚠️ **userspace Service proxy** (VIP-owning sockets) |
| VXLAN/flannel | cross-node net | ✅ **wireguard-go** userspace mesh (root-gated utun; Tailscale-proven on 26.2) |
| systemd/OpenRC | supervision | ✅ **launchd** LaunchDaemons (in an app-bundle wrapper) |
| etcd | datastore | ✅ **kine** → SQLite **via cgo** (`mattn/go-sqlite3`; kine needs CGO — see §5c) |

## 3. Red-team verdict & the pivots it forced

Four hostile personas attacked the v1 design on a macOS 26.5.1 machine (SIP **on**, sealed read-only system volume, Gatekeeper **on**). Verdicts: Runtime = **FATAL-as-designed → redesigned**; Control-plane, Networking, Security = **SURVIVES-WITH-CHANGES**. Project-killer? **None today** — closest is Apple denying a Network Extension capability (a policy risk we avoid by using raw root utun/pf).

**EXCISED (verified fictional/impossible on macOS 26):**
- ❌ **chroot + bind-mounting host `/System`/frameworks/dyld cache into a pod root.** SIP forbids `chroot` of framework-linked binaries (darwin-jail README: *"SIP doesn't allow to chroot"*); no `mount_nullfs`/bindfs on stock macOS; the dyld cache is a ~6.5 GB cryptex at `/System/Volumes/Preboot/Cryptexes/OS/…`. The only working impl copies 7.37 GB/image with SIP off. **→ Pivot: drop chroot entirely.** Pods run as native processes **at real host paths**, so they see the real `/System` and link normally; a **default-deny Seatbelt profile** confines them (read `/System`,`/usr/lib`,dyld cryptex + the pod dir; write only the pod's APFS data volume; deny `/Users`, other pods, host loopback). Simpler *and* SIP-compatible.
- ❌ **Reliable `OOMKilled` via jetsam/`memorystatus_control`.** Private SPI; Mac jetsam is pressure/priority-driven and kills the *largest* process, not your target. **→ Pivot: enforce memory in userspace** — sample `proc_pid_rusage(ri_phys_footprint)` ~1 Hz, SIGKILL on breach, emit `OOMKilled`; memorystatus HWM as best-effort assist.
- ❌ **`pf nat … user <uid> -> POD_IP` source-pinning.** `user`/`group` is filter-only on macOS pf — the rule **doesn't even parse** (verified via `pfctl -n`) — and it's moot because loopback already stamps the bound source IP. **→ Pivot: source identity = `bind()` discipline** (the runtime binds each pod's process to its lo0 IP) + optional pf *filter* verification. Honest consequence: same-node pods are **one OS-level trust domain** (Seatbelt limits filesystem/network *reach*, but there are no separate net namespaces); **untrusted multi-tenant → the `vm` RuntimeClass** (micro-VM, separate stack).
- ❌ **DNS via a per-pod `/etc/resolv.conf`.** macOS `getaddrinfo` goes through mDNSResponder/configd and never reads the file. **→ Pivot: inject a userspace resolver** — a `DYLD_INSERT_LIBRARIES` shim that routes `getaddrinfo`/`res_*` to CoreDNS, or a machine-wide DNS proxy. CoreDNS stays the cluster resolver.

**CONFIRMED SOUND (sometimes sounder than v1's rationale):**
- ✅ apiserver + scheduler + controller-manager genuinely **run** on darwin/arm64 — **KWOK runs the real upstream binaries on Macs daily** (only its kubelet stand-in is fake). Linux runtime assumptions live in kubelet/kube-proxy, which we don't ship.
- ✅ **lo0 alias /32 pod IPs**: XNU preserves the bound source IP over loopback, so pod-to-pod works with no NAT.
- ✅ **wireguard-go over utun**: gated by root (`CTL_FLAG_PRIVILEGED`), **not** the NE entitlement; SIP/notarization don't touch it.
- ✅ **Running downloaded arm64 binaries**: `codesign -s - -f` (ad-hoc) on pull satisfies AMFI; Gatekeeper/notarization **never fire** because a root daemon writing to `/var/lib/k3sm` sets no `com.apple.quarantine` xattr. (Keep a "notarized-images-only" mode ready in case Apple ever closes that gap.)
- ⚠️ **Seatbelt** is the real isolation mechanism (`libsandbox` `sandbox_compile/apply`, survives `execve`) but is **private/deprecated SPI** → abstract it behind a per-OS shim with a CI symbol-canary and a `vm` fallback.

## 4. Architecture

Two load-bearing reuses make this feasible: **Virtual Kubelet** (CNCF) reimplements the kubelet's API-facing half in portable Go and delegates execution to a provider (prior art: **agoda/macOS-vz-kubelet** runs native-macOS workloads on K8s this way); and the **control plane builds from source for darwin/arm64** with **kine** providing the SQLite datastore. (✅ M0-spike finding: kine's SQLite **requires CGO** — `mattn/go-sqlite3`; the no-cgo build *disables* SQLite. So k3sm builds **`CGO_ENABLED=1`** on darwin — fine, since macOS has no fully-static binaries anyway and cgo+sqlite notarizes normally. See `docs/M0-spike.md`.)

```
k3sm server (control-plane Mac; also a worker)            ── one app-bundle-wrapped binary (CGO=1: kine sqlite)
  ├─ kine (goroutine) → unix socket (SQLite ≥0.15, WAL)   ConsistentListFromCache=false until soak-validated
  ├─ kube-apiserver / kube-scheduler / kube-controller-manager (goroutines via New*Command, KCM --controllers scoped)
  ├─ supervisor HTTP (/v1-k3sm/*: token + node-password + HTTP-CSR + mesh-enroll)
  ├─ CoreDNS · userspace Service proxy · wireguard-go (goroutines)
  ├─ ValidatingAdmissionPolicy: workloads must nodeSelector kubernetes.io/os=darwin (os.name:darwin doesn't exist)
  └─ Virtual Kubelet → Darwin provider → registers the Mac as a Node (provider taint; provider OWNS logs/exec/top)
                            │ gRPC (unix socket)
                            ▼
                   k3sm-runtimed (root): default-deny Seatbelt @ host paths · APFS data vol · userspace mem-kill
k3sm agent (worker Mac) = join client + VK provider + Service proxy + wireguard-go   (no kubelet, no kube-proxy)
```

### Component mapping (k3s → k3sm)
| k3s (Linux) | k3sm (macOS-native) | Strategy |
|---|---|---|
| apiserver / scheduler / controller-manager | same, built from source (track `k3s-io/kubernetes`) | **REUSE** |
| etcd | **kine → SQLite** (pin ≥0.15) | **REUSE** |
| kubelet | **Virtual Kubelet + Darwin provider** (logs/exec/top are provider-built) | **BUILD** |
| containerd + runc | **`k3sm-runtimed`**: Seatbelt @ host paths + APFS + posix_spawn + userspace limits | **BUILD** |
| Flannel | `lo0`-alias pod IPs + **wireguard-go** mesh | **BUILD** |
| kube-proxy | **userspace Service proxy** | **BUILD** |
| CoreDNS | same + `getaddrinfo` shim in pods | **REUSE+BUILD** |
| systemd/OpenRC | **launchd** (app-bundle-wrapped daemon) | **BUILD** |

## 5. Subsystem designs (post-red-team)

### 5a. Node runtime & isolation (`runtimed`, `apis`)
- **Pod model (no namespaces, no chroot):** a **PodBox** = a per-pod dir `/var/lib/k3sm/pods/<id>/rootfs` (image payload materialized via `clonefile`) + one default-deny **Seatbelt profile** + one process group (`setpgid`/`setsid`) + a dedicated uid/gid + a lo0 pod IP. Containers = `posix_spawn`'d arm64 processes **running in place at host paths** (they see the real `/System`, so frameworks/dyld resolve with zero plumbing); Seatbelt confines them. Init containers sequential; restart policy via `kqueue(EVFILT_PROC)`.
- **Isolation = generated default-deny SBPL** per pod: `allow file-read*` `/System`,`/usr/lib`,dyld cryptex, pod dir; `allow file-write*` only the pod's APFS data volume; `deny file*` `/Users`,`/private/var/db`,other pods; network scoped to the pod IP. Backend is **swappable + OS-version-gated** (`seatbelt-exec` → `seatbelt-inproc` via `libsandbox` → `uidjail` → **`vm`** Virtualization.framework for untrusted tenancy), behind a CI symbol-canary that re-verifies `libsandbox`/`memorystatus` exports each macOS build. ✅ **Validated on macOS 26.5.1** (`runtimed/prototypes/seatbelt-hostpath`): a Foundation-linked arm64 binary runs at host paths under default-deny, `/Users` denied, pod dir writable — confirming the no-chroot model. The generated profile **must** `(import "system.sb")` (dyld/mach baseline) or processes SIGABRT during linker init.
- **Resources (userspace, honest):** memory limit = sample `proc_pid_rusage(ri_phys_footprint)` ~1 Hz → SIGKILL + `OOMKilled` (memorystatus HWM assist); CPU = QoS via `taskpolicy`/`setpriority` + `RLIMIT_CPU_USAGE_MONITOR` (%-over-interval, **not** CFS millicores — documented best-effort); `RLIMIT_NOFILE/NPROC` hard. Metrics via `proc_pid_rusage` → Summary API (`kubectl top`).
- **Image/rootfs:** image = **OCI artifact**, app payload only (never `/System`); pull → content-addressed cache → `clonefile` into the pod dir; run in place. **`codesign -s - -f`** (ad-hoc) any unsigned binary on pull to satisfy AMFI; enforce signature policy (`require-notarized`/`require-signed`/`adhoc-ok`) before exec.

### 5b. Networking (`darwin-net`, `apis`)
- **Pod IP (intra-node):** `ifconfig lo0 alias <ip>/32` from `100.64.0.0/10` (per-node /24 from `node.spec.podCIDR`); pod-to-pod same-node = loopback (src IP preserved by XNU). Runtime **binds each pod's process to its IP** (`IP_BOUND_IF`/explicit `bind`); Seatbelt scopes ports. **No pf-NAT source-pin** (excised). Honest isolation: same-node pods share a trust domain; untrusted → `vm` RuntimeClass.
- **Services:** **userspace Service proxy** owning each ClusterIP:port (lo0 alias), watching Services/EndpointSlices; L4 LB to local lo0 IPs or remote pods over the mesh; **NodePort binds a direct wildcard `*:nodePort` (≥1024) in-process** — its contract is all-interfaces reachability (incl. `127.0.0.1`), which the `k3sm-netd` helper rejects (the helper binds only specific addresses), so the unprivileged `_k3sm` proxy binds it itself (`net.Listen`); the apiserver's pinned `--service-node-port-range` (30000–32767) keeps every NodePort ≥1024, and a `<1024` NodePort is unsupported. (The helper's specific-address `<1024` bind is for lo0 VIP/alias ports — ClusterIP and infra VIPs — **not** NodePort.) externalTrafficPolicy: Local is not honored (the userspace splice does not preserve client source IP — only Cluster) and there is no UDP datapath yet; both surfaced as `Warn` admission policies. Cap/batch lo0 aliases (watch the `getifaddrs`/configd O(N) cost at scale). kube-proxy never built.
- **Multi-node:** **wireguard-go** mesh over root-created utun; `AllowedIPs` per peer = its podCIDR (symmetric); unique per-node /24 ⇒ routed not NAT'd; MTU 1380 + `pf scrub max-mss`; `PersistentKeepalive 25`. Node **public** keys + endpoints distributed via join + a `MeshPeer` CRD in kine (private keys never leave the node).
- **DNS:** a per-node resolver on the cluster DNS VIP; pods resolve via a **`DYLD_INSERT_LIBRARIES` `getaddrinfo` shim** → that VIP (NOT resolv.conf; macOS uses mDNSResponder/configd). **M3 ships an in-process A-record + upstream-forward resolver** (IPv4-only; no SRV/PTR/headless), **not** CoreDNS-the-binary — darwin-net exposes no embeddable DNS server and CoreDNS cannot inherit the netd-helper-passed `<1024` socket fd under launchd. Full CoreDNS parity (SRV/headless for StatefulSet peer discovery) is a follow-up, tied to the per-pod-IP gap. The VIP's `<1024` bind + lo0 alias go through `k3sm-netd`; the proxy steps aside for the DNS VIP (infra-VIP exemption) so the resolver owns it.
- **Privilege (user-space by default):** one root **`k3sm-netd`** owns lo0 aliases, the `pf` `k3sm` sub-anchor, utun, wireguard; needs **only root** (no restricted NE entitlement). It is the **sole** root component — **everything else** (control plane, VK node, `runtimed`, the Service proxy, pods) runs as the unprivileged **`_k3sm`** user, reaching the helper over a **uid-authenticated unix socket** (`/var/lib/k3sm/run/netd.sock`) carrying a **closed, typed-scalar, re-validated RPC** (the helper renders every `ifconfig`/`route`/`pfctl`/UAPI artifact itself — never client text — and validates each param against pinned policy). Selected per the `--network` backend (`auto`: root→direct, unprivileged→helper+probe; `none`: control-plane-only). No per-command `sudo`. See `../docs/privilege-model.md`.

### 5c. Control plane, bootstrap, packaging (`k3sm`)
- **Single binary, in-process goroutines** (k3s `pkg/executor/embed` pattern), **`CGO_ENABLED=1` `GOOS=darwin GOARCH=arm64`** (✅ M0-spike: kine's SQLite needs cgo via `mattn/go-sqlite3`; the no-cgo build disables SQLite. "Fully static" isn't a macOS concept anyway — cgo links libSystem + compiled sqlite3 and notarizes fine. Future: a pure-Go `modernc.org/sqlite` kine driver would regain CGO_ENABLED=0). **Scope KCM `--controllers=…`** to disable node-side controllers (attach/detach, cloud-node-lifecycle) that assume real kubelets — KCM is the riskiest binary.
- **Datastore:** kine + SQLite (WAL, busy-timeout) at `/var/lib/k3sm/server/db/state.db`; **pin kine ≥0.15** (≥0.14.9 floor) and run with **`--feature-gates=ConsistentListFromCache=false`** until a multi-day watch-staleness soak passes (kine#577); HA via kine→Postgres (pure-Go pgx) for >2 servers.
- **Persistent storage (M3.2):** an in-process **local-path provisioner** (`pkg/provisioner`, a pure API-object controller — *not* a KCM controller) registers a `local-path` StorageClass (**`reclaimPolicy: Retain`** — k3sm has no volume-delete path, so a `Delete` class would strand `Released` PVs and leak dirs onto the APFS volume kine's SQLite shares; **`volumeBindingMode: WaitForFirstConsumer`** so the scheduler picks the node first) and, on a scheduled PVC (the `volume.kubernetes.io/selected-node` annotation), creates a PV named `pvc-<uid>` (idempotent under kine watch-staleness) with `Retain`, the requested capacity, an **advisory** `local.path` from the **resolved** runtime root (`<runtime-root>/storage`, the same root runtimed derives against — *not* the root-only `/var/lib/k3sm/storage`), and **`nodeAffinity` pinned to the selected node**. The provisioner does **no filesystem I/O**: runtimed empty-creates the per-`(namespace, claim)` dir on the *consuming* node; correctness rests on the node-affinity pin + that derivation, not the advisory path. Restart-idempotent (re-lists on start) and drained before the control plane stops. **StatefulSet:** stable **storage + name** identity work; stable **network** identity is an **explicit excluded subset** — on the hostprocess runtime every pod reports `podIP = nodeIP`, so headless-Service per-pod DNS does not resolve distinct addresses (needs the runtimed per-pod lo0-alias path). **Honest gaps (dev/CI scope):** PV storage shares the APFS volume with `state.db` (an unbounded PV can ENOSPC the datastore — prod mitigation: a separate volume); `capacity.storage` is best-effort (over-commit → write-time `ENOSPC`, like best-effort CPU); a recreated same-named PVC under `Retain` inherits prior bytes (intended for stable storage, bounded by the single `_k3sm` trust domain).
- **Node verbs:** `kubectl logs/exec/top/port-forward` are **implemented in the Darwin provider** (not inherited). Define the apiserver→node serving-cert trust: kubelet-serving CSR + `--kubelet-certificate-authority` (prod) or `--kubelet-insecure-tls` (dev).
- **Admission guardrail:** since `Pod.spec.os.name: darwin` is invalid in k8s, ship a **ValidatingAdmissionPolicy** requiring `nodeSelector: kubernetes.io/os=darwin` on workloads + keep the VK provider taint, so stray Linux pods can't land on Macs.
- **Multi-node bootstrap (reuse k3s):** token `K10<sha256(server-CA)>::<user>:<secret>` (CA-pinning), node-password (anti-impersonation), HTTP-CSR cert issuance, AES-256-GCM bootstrap bundle so HA servers reconstruct identical CAs. Mesh-enroll (wg pubkey + podCIDR) rides this join.
- **Packaging/signing:** ship as an **app-bundle-wrapped root LaunchDaemon**. Two launchd identities from the **one** signed binary (DESIGN §6): **`io.k3sm.netd`** (root) and **`io.k3sm.server`** (`UserName=_k3sm`, `RunAtLoad`/`KeepAlive`, boot-surviving — *not* a session LaunchAgent, so a headless Mac's cluster survives reboot). Entitlement split: the code-running entitlements (`allow-jit`, `allow-unsigned-executable-memory`, `disable-library-validation`) are for the **pod-running** path (it execs foreign images); the root **`k3sm-netd`** helper ships **hardened-runtime with minimal entitlements** (NONE of that trio — a root process must not load foreign code). **Stay on raw root utun/pf — no restricted NE/System-Extension capability** (avoids Apple approval risk). `sudo k3sm install/uninstall` via `launchctl bootstrap/bootout/kickstart` (**not** SMAppService — it needs a GUI `.app`/cask + System-Settings approval + can't be re-registered by `brew upgrade`, disqualifying for a headless CLI/server); the helper binary lives in a **root-owned `/Library/k3sm`** path (never an `admin`-writable Homebrew/`/Applications` prefix), DR-pinned (`identifier "io.k3sm.netd" and anchor apple generic and <TeamID>` — no downgrade). Admin kubeconfig → the invoking user's `~/.kube/config`. User-folder access (if ever needed) requires pre-granted FDA via MDM PPPC.
- **Distribution = Homebrew (first-class):** users run `brew install k3sm-io/tap/k3sm`, which lays down the notarized binary + app-bundle; a `caveats` note (and a `brew services`/`sudo k3sm install server` path) bootstraps the root LaunchDaemon. **goreleaser's `brews:` block auto-updates `Formula/k3sm.rb`** in the `k3sm-io/homebrew-tap` repo on every tagged release, so the tap always tracks the latest signed build. Formula installs the prebuilt notarized bottle (fast); a `--build-from-source` path (`depends_on "go" => :build`) ad-hoc-signs locally for contributors.

## 6. Repositories (cloned at `/Users/miko/Code/k3sm-io/`)

Org `k3sm-io` + domain `k3sm.io`; **vanity module paths `k3sm.io/<repo>`** (code hosted at `github.com/k3sm-io/<repo>`). Four repos tied by one `go.work`. **Repos are code-org boundaries; the shipped artifact is ONE signed `k3sm` binary** importing the others. Reverse-DNS IDs (`io.k3sm.*`) and CRD groups (`net.k3sm.io`, `runtime.k3sm.io`) are domain-backed.

| Repo (github.com/k3sm-io/…) | Module | Role (k3s analog) | Key contents |
|---|---|---|---|
| **`apis`** | `k3sm.io/apis` | shared contracts | runtimed/netd gRPC `.proto`+gen, shared types (PodBox, image manifest), CRDs (MeshPeer/NodeNetwork) |
| **`runtimed`** | `k3sm.io/runtimed` | native runtime (`containerd`) | gRPC svc; `pkg/sandbox` (seatbelt/uidjail/vm, SBPL gen, OS-version shim+CI canary); supervisor (posix_spawn/kqueue/userspace-mem-kill/QoS); cgo (clonefile, rusage, codesign-on-pull); OCI→APFS |
| **`darwin-net`** | `k3sm.io/darwin-net` | networking (`flannel`+`kube-proxy`+CNI) | `netd` (lo0 IPAM, pf anchor, utun); Service proxy; wireguard mesh; `getaddrinfo` DNS shim; PodNetwork seam |
| **`k3sm`** | `k3sm.io/k3sm` | distribution (`k3s`) | `cmd/k3sm`; `pkg/executor/embed`; kine; bootstrap/cert; VK Darwin provider (+logs/exec/top); admission policy; launchd + app-bundle; `pkg/image` (oras); `docs/DESIGN.md` |

```
dep graph:   apis ← runtimed ─┐
             apis ← darwin-net ┤←─ k3sm  (builds the single binary)
```

**Workspace wire-up:**
```sh
cd /Users/miko/Code/k3sm-io
for r in apis runtimed darwin-net k3sm; do ( cd $r && go mod init k3sm.io/$r ); done
go work init ./apis ./runtimed ./darwin-net ./k3sm
```

**`k3sm-io/homebrew-tap`** (Homebrew tap, `Formula/k3sm.rb`): created at M4, **auto-updated by goreleaser**, **public** so `brew install k3sm-io/tap/k3sm` works. **Deferred:** `kubernetes` fork (only if darwin patches needed; until then `replace` → `k3s-io/kubernetes`). Visibility: four core repos private now → public at M4; the tap is public from creation.

### 6a. Vanity import paths via GitHub Pages
Local dev does **not** need this (the `go.work` resolves all four modules from local dirs, so M0–M2 are unblocked while DNS propagates). Vanity only matters for external `go get`/CI without the workspace. Recipe (static per-module `index.html`; Go's parent-path validation makes subpackages resolve):

1. Create the org Pages site repo (public): `gh repo create k3sm-io/k3sm-io.github.io --public --clone`.
2. Add a `CNAME` file containing one line: `k3sm.io`.
3. For each module add `<repo>/index.html` (4 files):
   ```html
   <!DOCTYPE html><html><head>
   <meta name="go-import" content="k3sm.io/REPO git https://github.com/k3sm-io/REPO">
   <meta name="go-source" content="k3sm.io/REPO https://github.com/k3sm-io/REPO https://github.com/k3sm-io/REPO/tree/main{/dir} https://github.com/k3sm-io/REPO/blob/main{/dir}/{file}#L{line}">
   <meta http-equiv="refresh" content="0; url=https://github.com/k3sm-io/REPO">
   </head><body>go get k3sm.io/REPO</body></html>
   ```
4. Enable Pages: Settings → Pages → Source `main`/root → custom domain `k3sm.io` → Enforce HTTPS once the cert provisions.
5. DNS at the `k3sm.io` registrar: apex `A` → `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153` (+ `AAAA` `2606:50c0:8000::153`…`8003::153`); add the org domain-verification `TXT` (`_github-pages-challenge-k3sm-io`).
6. Verify: `curl -fsSL "https://k3sm.io/runtimed?go-get=1" | grep go-import`. Private repos: consumers set `GOPRIVATE=k3sm.io/*` + `git config --global url."git@github.com:".insteadOf https://github.com/`.
7. CI before public: check out the workspace (use `go.work`) so vanity isn't on the path; flip to vanity+`GOPRIVATE`+deploy-keys when repos go public (M4).

## 7. Build roadmap (vertical slices)

- **M0 — Walking skeleton.** ✅ **Exit achieved 2026-06-24** — a native pod runs via a real Virtual Kubelet node (`docs/M0-spike.md` + `docs/M0-node.md`); the spike used prebuilt CP binaries, so the *from-source in-process* embedding below rolls into M1. Build apiserver+scheduler+CM+kine from source as goroutines → `kubectl get nodes` Ready (VK node). Runtime in **HostProcess mode** (no isolation): provider `posix_spawn`s one native arm64 binary at host path; logs/exec/status/top via the provider. **Exit:** `kubectl run` a native workload → it executes; zero Linux end-to-end. *Prototype-first (highest risk): a native Foundation-linked binary runs under a default-deny Seatbelt profile, seeing `/System`, confined to its pod dir — no chroot.*
- **M1 — `k3sm server` + images + Services + DNS (single node).** ✅ **Landed 2026-06-25.** Single binary, **child-process `Supervised` executor** (KCM scoped, admission policy, kine pinned; the from-source *in-process* embedding is deferred — a stub returns `ErrEmbeddedNotImplemented`, the k/k monorepo import being infeasible today); OCI pull → `clonefile` pod dir → ad-hoc-sign → Seatbelt confine; userspace Service proxy + CoreDNS + **`getaddrinfo` DNS shim**. **Exit (met):** pull a native image, run it, `kubectl expose` ClusterIP, DNS resolves.
- **M2 — Isolation, resources & pod-spec fidelity.** SBPL generation (exec→inproc + CI symbol-canary); split `k3sm-runtimed` (root, gRPC); userspace memory kill (`OOMKilled`) + QoS + Summary API; IP-per-pod (lo0 alias + bind discipline). **Plus the runtime-independent pod surface a real workload needs** (driven by `../../docs/stockkitty-readiness.md`): volume mounts (configMap/secret/emptyDir/downwardAPI/projected-SA-token), downward-API env + `envFrom`, probes, `securityContext`, `terminationGracePeriodSeconds`, in-pod API access (`kubernetes.default.svc` + bound SA token + CA), and **`k3sm kubectl`/`k3sm kubeconfig`** ergonomics. **Exit:** pods confined (no `/Users`), memory breach → `OOMKilled`, `kubectl top` real, same-node pod-to-pod, the M2 conformance slice green.
- **M3 — Multi-node, mesh, NodePort & persistent storage.** `k3sm token create`; `k3sm agent --server --token` (node-password + HTTP-CSR); wireguard-go mesh + `MeshPeer` CRD; cross-node pod-to-pod + ClusterIP. **Plus NodePort** (`*:port`) and **PV/PVC + an APFS local-path provisioner + StatefulSet** (the persistent storage stockkitty needs); per-node CoreDNS so infra VIPs aren't steered over the mesh. *Prototype: two real Macs, wg utun, `iperf3` both directions, bounce a node → reconverge.* **Exit:** two Macs, one cluster, A↔B works, a NodePort Service, a persistent StatefulSet survives restart.
- **M4 — Install/launchd, packaging, Homebrew, hardening.** App-bundle-wrapped root LaunchDaemon + `k3sm install/uninstall`; codesign+notarize (code-running entitlements; raw utun/pf, no NE); `.pkg`; **goreleaser release pipeline publishing the `k3sm-io/homebrew-tap` Formula**; `uidjail` backend; **RBAC enforcement** (`AlwaysAllow → Node,RBAC`, with the system roles + VK-node `system:node` identity + NodeRestriction bootstrap provisioned *before* the flip); LoadBalancer; CI on macOS arm64; the **synthetic conformance gate** green in CI + Darwin-subset node conformance. **Single-server** datastore (kine→SQLite) — multi-server HA is **M6**. **Exit:** `brew install k3sm-io/tap/k3sm` → `sudo k3sm install server` → running cluster; survives reboot; core repos public.
- **M5 (committed) — `vm` RuntimeClass** (Virtualization.framework Linux micro-VM), behind the existing swappable `sandbox.Backend` seam. Two purposes: strong isolation for untrusted tenants **and** running **Linux** images with no native arm64 build — the HYBRID path for stockkitty's Postgres/pgvector (see `../../docs/stockkitty-readiness.md`). `runtimeClassName: vm` maps to the existing `SANDBOX_BACKEND_VM` (the upstream `node.k8s.io/RuntimeClass` is consumed, not forked); guest images are digest-pinned (codesign/notarization is meaningless inside the VM); networking is vmnet/bridged with a guest-side resolver. **Exit:** a Linux image runs under `runtimeClassName: vm`, Service/DNS-reachable, beside native pods.
- **M6 (last phase) — HA: multi-server control plane.** Moved here from M4 so HA is the final, most complex ops capability (single-server suffices through M5). **kine→Postgres** (pure-Go pgx) for a shared multi-writer datastore (SQLite is single-host single-writer; two servers each on their own SQLite = split-brain) — the named **kine/SQLite datastore-migration** exception. **HA server-join**: the M3 worker-join extended to a second control-plane server + the **AES-256-GCM identical-CA bundle** (§5c) so joining servers reconstruct identical cluster+signing CAs (server-bootstrap-identity-only, strong-KDF'd). **Exit:** two servers on shared Postgres; kill one → the cluster keeps serving.

## 8. Top risks (verified) + mitigations
1. **Isolation depends on private/deprecated `sandbox-exec`/`libsandbox` SPI** (no removal date, but unsupported). → Swappable backend + `libsandbox` in-proc path + `uidjail` + `vm`; CI symbol-canary on every macOS build; abstract so the engine is replaceable.
2. **kine `ConsistentListFromCache` staleness (k3s 1.31–1.33 band).** → Pin kine ≥0.15, gate `ConsistentListFromCache=false`, multi-day watch-staleness soak in CI before trusting it.
3. **Node verbs + apiserver→node trust are unbuilt provider work; KCM assumes real kubelets.** → Provider implements logs/exec/top; define kubelet-serving CSR/CA story; scope KCM `--controllers`.
4. **Same-node pods are one OS trust domain (no net/pid namespaces); a pod can bind another's IP.** → Document trust model; `vm` RuntimeClass for untrusted tenancy; bind-discipline + pf filter verification for honest pods.
5. **Shipping: restricted NE capability + bare-daemon-can't-hold-a-profile; quarantine-gap could close.** → App-bundle-wrapped daemon on **raw root utun/pf (no NE)**; ad-hoc-sign-on-pull; keep a notarized-images-only mode; instrument every macOS beta for AMFI/Gatekeeper/NE changes. *(Maintenance reality: k3sm runs a darwin/cgo-free k8s config that k3s doesn't ship → we own 100% of regression testing; ~30+ staging `replace`s kept in lockstep per k8s bump.)*

## 9. Verification
On real hardware (one Mac = M0–M2; **a second Apple-Silicon Mac on macOS 26 is a prerequisite for M3**):
- M0: `kubectl get nodes` Ready; `kubectl run` a native arm64 binary → Running; `logs`/`exec`/`top` work (provider-served).
- M1: pull a native image → Running; `kubectl expose` → ClusterIP reachable; CoreDNS resolves a Service via the `getaddrinfo` shim.
- M2: pod denied reading `/Users`; memory breach → `OOMKilled`; `kubectl top pod` shows real footprint; same-node pod-to-pod over pod IPs.
- M3: two Macs, one cluster; cross-node pod-to-pod + ClusterIP.
- M4: `brew install` → `sudo k3sm install` → cluster; reboot → auto-starts (launchd); `.pkg` install/uninstall clean; HA with 2 servers on Postgres; watch-staleness soak green; RBAC enforcement (restricted SA denied, control-plane SAs allowed).
- M5: a **Linux** image runs under `runtimeClassName: vm`, reachable via a ClusterIP Service + cluster DNS, alongside native arm64 pods.
- A **synthetic conformance set** (`hack/acceptance/conformance/`, build-tagged Go tests per criterion, sliced M2–M5) exercises every k8s feature class the `~/stockkitty` reference workload needs — proving feature-class coverage, not image-level compat (see `../../docs/stockkitty-readiness.md`). It complements a documented **subset of upstream conformance**; full Sonobuoy is a stretch goal.

## 10. Prerequisites & decisions
- **Prereqs:** Go toolchain; 1–2 Apple-Silicon Macs on macOS 26+ (second for M3); a registry (GHCR) for M1; an Apple Developer ID for M4 notarization.
- **Defaults chosen:** name **`k3sm`** (org/domain owned); **Seatbelt isolation at host paths by default**, **`vm` RuntimeClass** for untrusted tenancy; **multi-node designed-in** but built node-by-node (two-Mac join is M3). Open choice: **private→public timing** (default: private now → public at M4).

---
*This is the canonical, living design doc for k3sm. The original planning artifact lives at `~/.claude/plans/i-would-like-to-soft-conway.md`.*
