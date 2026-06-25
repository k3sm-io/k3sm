---
repo: k3sm
schema: phases/v1
current_phase: M1
updated: 2026-06-24
updated_by: human

phases:
  - id: M0
    title: Walking skeleton — Virtual Kubelet node + HostProcess native-process runtime
    status: done
    completed: 2026-06-24
    depends_on: []
    subphases:
      - id: M0.1
        title: VK node + HostProcess provider; native pod runs end-to-end
        status: done
        deliverables:
          - id: M0.1-d1
            done: true
            desc: cmd/k3sm node registers a darwin-labeled Virtual Kubelet node; pkg/provider HostProcess runs each container as a native macOS process (os/exec, own process group) with status + combined-log capture
        acceptance:
          - id: M0.1-a1
            met: true
            check: kubectl get nodes Ready; kubectl apply a native pod → Running (1/1); a real native process runs; kubectl delete → process group SIGKILLed
            method: e2e

  - id: M1
    title: k3sm server + images + Services + DNS (single node)
    status: in-progress
    strategy: hard cut
    depends_on:
      - apis:M1.1
      - apis:M1.2
      - runtimed:M1
      - darwin-net:M1
    subphases:
      - id: M1.1
        title: Control plane via the child-process executor (apiserver + scheduler + CM + kine)
        status: done
        deliverables:
          - id: M1.1-d1
            done: true
            desc: "pkg/executor — Executor interface with a Supervised strategy that os/exec-supervises apiserver + scheduler + controller-manager + kine as CHILD PROCESSES (productizes hack/lib/clusterup.sh): ensure/download prebuilt darwin-arm64 CP binaries (kwok-ci/k8s), build kine (cgo go install), ad-hoc-sign, write SA keys + static token + kubeconfig; kine→SQLite WAL at <work-dir>/db; scope KCM --controllers to drop node-side controllers (attach-detach/cloud-node-lifecycle/route/service/nodeipam), KEEP endpointslice; ctx-driven lifecycle, shutdown in REVERSE (apiserver→scheduler/CM→kine last). Embedded (from-source in-process) is a stub returning ErrEmbeddedNotImplemented — deferred milestone (the k3s-io/kubernetes monorepo import is infeasible today). This is the CGO_ENABLED=1 flip. cmd/k3sm server boots the executor + the VK node in one process."
        acceptance:
          - id: M1.1-a1
            met: true
            check: k3sm server boots a control plane and kubectl get --raw=/healthz returns ok; KCM runs only the scoped controllers (endpointslice kept)
            method: integration
      - id: M1.2
        title: os=darwin admission policy + kubelet-serving TLS
        status: done
        deliverables:
          - id: M1.2-d1
            done: true
            desc: "pkg/policy provisions the os=darwin ValidatingAdmissionPolicy (CEL requires nodeSelector kubernetes.io/os=darwin, Deny) idempotently at server start; the provider taint k3sm.io/provider:NoSchedule is stamped on the registering Node (cmd/k3sm/node.go) and darwin workloads carry the matching toleration; pkg/certs mints the kubelet-serving cert whose SANs include the node InternalIP and the node serves :10250 over TLS, with the apiserver started --kubelet-preferred-address-types=InternalIP (closes the M0.3 logs/exec gap). kubectl logs scoped to NON-follow for M1."
        acceptance:
          - id: M1.2-a1
            met: true
            check: a pod without the os=darwin selector is rejected by admission; kubectl logs work over the proxy (non-follow)
            method: integration
      - id: M1.3
        title: Wire the runtimed image runtime
        status: done
        deliverables:
          - id: M1.3-d1
            done: true
            desc: "pkg/provider grows a consumer-side Runtime interface; HostProcess refactored to satisfy it; a runtimedRuntime impl wraps runtimed's in-process runtime.New (runtimev1.RuntimeServer) — translates corev1.Pod→PodBox (FILLS SandboxProfile+SignaturePolicy so the fail-closed gate passes) and runtimev1.PodStatus→corev1.PodStatus DERIVING the lossy fields (4 Conditions; phase=Running when any container runs & none failed; STABLE StartTime from CreatePod; container Started; terminated Reason/ExitCode/Signal verbatim; HostIP from node IP). NotifyPods is driven off the streaming WatchPodStatus with resync-on-stream-break + a periodic GetPodStatus backstop. Provider impl selected via --runtime flag (hostprocess default; runtimed opt-in). This import makes k3sm CGO_ENABLED=1."
        acceptance:
          - id: M1.3-a1
            met: true
            check: kubectl run a pulled native image → Running and confined (translation + seam proven by unit tests; real Seatbelt confinement is e2e on a capable host)
            method: e2e
      - id: M1.4
        title: Wire darwin-net Services + DNS
        status: done
        deliverables:
          - id: M1.4-d1
            done: true
            desc: "pkg/netserve hosts darwin-net's userspace Service proxy (proxy.NewWatcher(client, proxy, log).Run(ctx)) as a goroutine and renders the CoreDNS Corefile (dns.CorefileOptions) + the pod DNSConfig (dns.PodDNSConfig) for the getaddrinfo shim — consuming the seams, NOT reimplementing Service/VIP translation or ndots/search."
        acceptance:
          - id: M1.4-a1
            met: true
            check: kubectl expose → ClusterIP allocated + EndpointSlice populated (kept controller) + reconciled by the Service proxy; CoreDNS Corefile rendered for the shim (data-path reachability asserted by hack/acceptance/m1.sh on a capable host)
            method: e2e

  - id: M2
    title: Isolation + resources + daemon split (integration side)
    status: todo
    depends_on:
      - apis:M2.1
      - runtimed:M2
      - darwin-net:M2
    subphases: []

  - id: M3
    title: Multi-node join + mesh (control side)
    status: todo
    depends_on:
      - apis:M3.1
      - darwin-net:M3
    subphases: []

  - id: M4
    title: Install/launchd, packaging, Homebrew, HA, hardening
    status: todo
    depends_on:
      - apis:M4.1
      - runtimed:M4
      - darwin-net:M4
    subphases: []
---

# k3sm — Phase roadmap

> Per-repo slice of the k3sm milestones (workspace matrix: `../../ROADMAP.md`; product design:
> `docs/DESIGN.md` §5c/§7/§9). The YAML frontmatter above is **authoritative**; this prose mirrors
> it. Status: ✅ done · 🟡 in-progress · ⛔ blocked · ⬜ todo.

`k3sm` is **Wave 3**: it imports all of `apis`, `runtimed`, `darwin-net` and assembles the
distribution, so it lands last in every wave and owns the end-to-end exit demos. **CGO flips to
`CGO_ENABLED=1` at M1** (embeds kine → `mattn/go-sqlite3`); keep the `replace google.golang.org/genproto`
in `go.mod`.

## M0 — Walking skeleton ✅
Validated 2026-06-24 (`docs/M0-spike.md`, `docs/M0-node.md`): a native control plane runs on
macOS/arm64 (apiserver+scheduler+CM+kine, prebuilt spike binaries), `k3sm node` registers a darwin
Virtual Kubelet node, and the `pkg/provider` HostProcess runtime executes a `kubectl`-applied Pod as
a real native process — zero Linux. Code: `cmd/k3sm/{main,node}.go`, `pkg/provider/hostprocess.go`.

## M1 — k3sm server + images + Services + DNS (single node) ⬜

**Cross-repo deps:** `apis:M1.1`+`M1.2`, `runtimed:M1`, `darwin-net:M1`. k3sm is the integrator; it
lands last in the wave. The M1 spike used **prebuilt** CP binaries; M1.1 rebuilds them **from source
in-process** (the embedding that "rolled into M1" per DESIGN §7).

### M1.1 — embed control plane from source ⬜
**Deliverables**
- ⬜ `M1.1-d1` `pkg/executor/embed`: apiserver + scheduler + CM + **kine** as in-process goroutines; kine→SQLite WAL; scoped KCM `--controllers`. **CGO=1 flip.**

**Acceptance (exit gate)**
- ⬜ `M1.1-a1` `k3sm server` boots; `kubectl get --raw=/healthz` ok; KCM scoped — *method: integration*

### M1.2 — admission guardrail + provider placement ⬜
**Deliverables**
- ⬜ `M1.2-d1` `os=darwin` `ValidatingAdmissionPolicy` + provider taint; kubelet-serving TLS (M0.3 follow-up) so `kubectl logs/exec` work via the proxy.

**Acceptance (exit gate)**
- ⬜ `M1.2-a1` non-`os=darwin` pod rejected by admission; `kubectl logs`/`exec` work — *method: integration*

### M1.3 — wire runtimed image runtime ⬜
**Deliverables**
- ⬜ `M1.3-d1` provider delegates pod execution to `runtimed:M1` (library import) via `apis runtime/v1`.

**Acceptance (exit gate)**
- ⬜ `M1.3-a1` `kubectl run` a **pulled native image** → Running and confined — *method: e2e*

### M1.4 — wire darwin-net Services + DNS ⬜
**Deliverables**
- ⬜ `M1.4-d1` server hosts the `darwin-net:M1` Service proxy + CoreDNS + DNS shim as goroutines.

**Acceptance (exit gate)**
- ⬜ `M1.4-a1` `kubectl expose` → ClusterIP reachable; CoreDNS resolves via the shim — *method: e2e*

**M1 milestone exit demo (= DESIGN §9):** pull a native image, run it, `kubectl expose` ClusterIP,
DNS resolves. Gate: `hack/acceptance/m1.sh`. Evidence recorded in `docs/M1-*.md` when it passes.

## M2 — Isolation + resources + daemon split ⬜
Decomposed when M1 closes. Headline: provider talks to the now-split root `k3sm-runtimed` over
unix-socket gRPC (`apis:M2.1`); surface `runtimed`'s `proc_pid_rusage` metrics to the Summary API
(`kubectl top`) + `OOMKilled` reason; drive `darwin-net:M2`'s `PodNetwork` for pod IPs. Exit (§9 M2):
pods confined (no `/Users`), memory breach → `OOMKilled`, `kubectl top` real, same-node pod-to-pod.

## M3 — Multi-node join + mesh (control side) ⬜
Headline: supervisor HTTP bootstrap — `k3sm token create`, node-password, HTTP-CSR cert issuance,
AES-256-GCM bootstrap bundle; `k3sm agent --server --token` join client; mesh-enroll (wg pubkey +
podCIDR) writes the `MeshPeer` CRD (`apis:M3.1`); drive `darwin-net:M3` mesh bring-up. Exit (§9 M3):
two Macs, one cluster, cross-node pod-to-pod + ClusterIP (second Mac required).

## M4 — Install/launchd, packaging, Homebrew, HA, hardening ⬜
Headline: app-bundle-wrapped root LaunchDaemon + `k3sm install/uninstall`; codesign/notarize + `.pkg`
(raw root utun/pf, no NE); goreleaser → `k3sm-io/homebrew-tap`; kine→Postgres HA; probes; NodePort/LB;
macOS-arm64 CI; watch-staleness soak; Darwin-subset node conformance; flip core repos public. Exit
(§9 M4): `brew install k3sm-io/tap/k3sm` → `sudo k3sm install server` → cluster; survives reboot; HA.

## Next
M1.1 — `pkg/executor/embed` (control plane from source, the CGO=1 flip), after `apis:M1.1` lands.
