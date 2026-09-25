---
repo: k3sm
schema: phases/v1
current_phase: M6
updated: 2026-09-24
updated_by: B375 write-back (retroactive record of the shipped datavol feature)

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
    status: done
    completed: 2026-06-25
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
            check: a pod without the os=darwin selector is rejected by admission; kubectl logs work over the proxy (non-follow) — B282 write-back 2026-09-13: the M1 non-follow scoping is retired; the node now serves kubectl logs (tail, since, timestamps, limit-bytes, follow, previous) from the on-disk CRI log files at ContainerStatus.log_path with the kubelet's own reader, rotates them (containerLogMaxSize/Files) and garbage-collects them, behind a kubelet-shaped /containerLogs handler (pkg/provider/podlogs); docs/user/logs.md
            method: integration
      - id: M1.3
        title: Wire the runtimed image runtime
        status: done
        deliverables:
          - id: M1.3-d1
            done: true
            desc: "pkg/provider grows a consumer-side Runtime interface; HostProcess refactored to satisfy it; a runtimedRuntime impl wraps runtimed's in-process runtime.New (runtimev1.RuntimeServer) — translates corev1.Pod→PodBox (FILLS SandboxProfile+SignaturePolicy so the fail-closed gate passes) and runtimev1.PodStatus→corev1.PodStatus DERIVING the lossy fields. Provider impl selected via --runtime flag (hostprocess default; runtimed opt-in). This import makes k3sm CGO_ENABLED=1."
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
            desc: "pkg/netserve hosts darwin-net's userspace Service proxy (proxy.NewWatcher) as a goroutine and renders the CoreDNS Corefile + the pod DNSConfig for the getaddrinfo shim — consuming the seams, NOT reimplementing Service/VIP translation or ndots/search."
        acceptance:
          - id: M1.4-a1
            met: true
            check: kubectl expose → ClusterIP allocated + EndpointSlice populated + reconciled by the Service proxy; CoreDNS Corefile rendered for the shim (data-path reachability asserted by hack/acceptance/m1.sh on a capable host)
            method: e2e

  - id: M2
    title: Isolation, resources & pod-spec fidelity (integration side)
    status: done
    completed: 2026-07-11
    note: "All k3sm sub-phases M2.0–M2.6 done (named unit tests at the seam, -race clean), and the workspace-root e2e gate hack/acceptance/m2.sh run GREEN on Apple-Silicon hardware (macOS 26.5, root install lifecycle): all 13 required conformance criteria PASS plus the install/uninstall cleanliness checks — the first live-hardware proof of the packaged single-node path."
    strategy: hard cut
    depends_on:
      - apis:M2.1
      - runtimed:M2
      - darwin-net:M2
    subphases:
      - id: M2.0
        title: kubectl ergonomics — k3sm kubectl + k3sm kubeconfig
        status: done
        deliverables:
          - id: M2.0-d1
            done: true
            desc: "cmd/k3sm/kubectl.go — `k3sm kubectl <args>` execs the bundled kubectl (or one on PATH) with KUBECONFIG preset to the executor's admin kubeconfig and forwards the child exit code (mirrors `k3s kubectl`); work dir honors K3SM_WORK_DIR. cmd/k3sm/kubeconfig.go — `k3sm kubeconfig` prints the admin kubeconfig, or --write MERGES the k3sm cluster/user/context into ~/.kube/config (atomic write + .bak backup, --context-name to avoid collisions); --server retargets the endpoint and REFUSES to persist an insecure (skip-TLS-verify) context off loopback unless --certificate-authority embeds a CA. Exported executor.KubeconfigPath/KubectlPath single-source the layout."
        acceptance:
          - id: M2.0-a1
            met: true
            check: mergeKubeconfig (into empty / preserves existing / custom-name) + retarget (refuses insecure off-loopback, keeps loopback) + isLoopbackServer unit tests pass; `go test ./cmd/...` green under CGO_ENABLED=1
            method: unit
      - id: M2.1
        title: Provider pod-spec fidelity — volumes, env, securityContext, grace
        status: done
        deliverables:
          - id: M2.1-d1
            done: true
            desc: "pkg/provider translates the apis:M2.1 corev1 surface → runtime PodBox: volumes + volume_mounts (configMap/secret/emptyDir/downwardAPI/projected incl. serviceAccountToken), downward-API env (spec.nodeName/status.podIP/metadata.name) + envFrom (configMapRef/secretRef), securityContext (runAsUser/runAsGroup/fsGroup), terminationGracePeriodSeconds; derives the PAIRED ContainerStatus fields so kubectl Pod state stays a lossless mirror."
        acceptance:
          - id: M2.1-a1
            met: true
            check: a pod with configMap+secret+emptyDir+downwardAPI mounts + downward-API env runs; kubectl describe shows the mounts/resources (status round-trip)
            method: e2e
      - id: M2.2
        title: Provider-served probes
        status: done
        deliverables:
          - id: M2.2-d1
            done: true
            desc: "the provider executes httpGet/tcp/exec liveness/readiness/startup probes and maps results to the Ready/ContainersReady conditions (endpoint membership) and to container restart on liveness failure — kubelet-inherited behavior the VK provider must reproduce. pkg/provider/probe.go runs one goroutine per (container,probe) bounded by the pod ctx (started at CreatePod, stopped at DeletePod via stopProber; status callbacks run OUTSIDE locks), applying k8s success/failureThreshold counting, startup-gates-liveness, and committed-readiness→Ready overlay (applyProbeOverlay in toPodStatus, so a NotReady container drops from the EndpointSlice). Handlers (probe_handlers.go): httpGet (2xx-3xx=ok, injectable RoundTripper), tcpSocket (injectable dialer), exec (in-process bidi adapter over the runtime Exec RPC); named probe ports resolve via the Container.ports table; dial host = bound pod IP. Liveness failure owns the restart DECISION + restart_count + gate reset; the literal per-container process re-exec awaits a runtime RestartContainer RPC (apis follow-up) wired via the restartFunc seam."
        acceptance:
          - id: M2.2-a1
            met: true
            check: a readiness-probe failure removes the pod from its Service EndpointSlice; a liveness-probe failure increments restart_count (transition cases, not just eventually-Ready). Proven by named unit tests TestM2_ReadinessGatesEndpoints / TestM2_LivenessRestarts / TestM2_StartupGatesLiveness / TestM2_ProbeHandlers / TestM2_ProbeThresholds (fakes for targets + clock; -race clean)
            method: e2e
      - id: M2.3
        title: Resources → Summary API (kubectl top) + OOMKilled
        status: done
        deliverables:
          - id: M2.3-d1
            done: true
            desc: "surface runtimed:M2's proc_pid_rusage(ri_phys_footprint) metering to the kubelet Summary API so kubectl top reports a real footprint, and translate a userspace memory-limit kill to the OOMKilled reason. CPU limits are documented best-effort QoS (taskpolicy/setpriority), NOT CFS millicores."
        acceptance:
          - id: M2.3-a1
            met: true
            check: kubectl top pod shows a non-zero footprint; a memory-limit breach yields phase=Failed reason=OOMKilled
            method: e2e
      - id: M2.4
        title: In-cluster API access — kubernetes.default.svc reachable + SA-token projection
        status: done
        deliverables:
          - id: M2.4-d1
            done: true
            desc: "project the POD'S-OWN-SA BOUND token (not the namespace default): the shared kubeResolver mints the TokenRequest token (audience + expirationSeconds, rotated) for spec.serviceAccountName, bound per-CreatePod via the request context the provider threads to mount.Materialize in-process — NO runtimed/apis seam change (the M2 daemon split will carry the SA in the materialization RPC). The apiserver SERVING CA (kube-root-ca.crt ConfigMap, published by the kept root-ca-cert-publisher controller) + the namespace materialize at the canonical in-pod path /var/run/secrets/kubernetes.io/serviceaccount so a stock client-go in-cluster config validates. kubernetes.default.svc reachability: --advertise-address=NodeIP defaults to loopback (127.0.0.1) single-node, so the auto-created endpoint resolves to the address the apiserver binds and the in-process Service proxy reaches it (M3.3 rewrites it per-node for a routable NodeIP). In-pod DNS requires the exec-shim backend (sandbox-exec strips DYLD_*). Authorization is exercised under RBAC at M4 (M2 runs AlwaysAllow)."
        acceptance:
          - id: M2.4-a1
            met: true
            check: "a pod with serviceAccountName foo gets a token minted for foo (not default), an unset pod gets default, and the CA + namespace materialize at the canonical paths with an internally-consistent in-pod config triple. Proven by TestM2_InPodKubectl (fake apiserver client + fake TokenRequest reactor; -race clean). The live kubernetes.default.svc round-trip is the m2.sh e2e leg (single-node root)."
            method: e2e
      - id: M2.5
        title: Implement Exec/Attach/PortForward provider verbs
        status: done
        deliverables:
          - id: M2.5-d1
            done: true
            desc: "wire the provider's RunInContainer/AttachToContainer/PortForward (NotFound in M1) to the already-existing runtime/v1 Exec/Attach/PortForward bidi RPCs via the StreamingRuntime capability (the runtimedRuntime serves it; HostProcess does not). pkg/provider/runtimed_exec.go bridges the VK api.AttachIO (stdin/stdout/stderr + resize) and the port-forward byte stream to an in-process grpc.BidiStreamingServer adapter (streamPipe, mirroring watchStream/logSink), mapping a non-zero exec exit to a utilexec.CodeExitError. A provider-implementation gap against a frozen apis contract, not an apis change. NOTE: runtimed's server Exec/Attach/PortForward still return Unimplemented (runtimed:M2); the provider surfaces that as an error (no panic) and the live verbs light up when runtimed lands them."
        acceptance:
          - id: M2.5-a1
            met: true
            check: "RunInContainer streams stdin/stdout to/from the runtime Exec RPC and returns its exit status; PortForward proxies bytes both ways; AttachToContainer attaches; exec/port-forward error + not-found paths surface (no panic). Proven by TestM2_Exec / TestM2_Attach / TestM2_PortForward (+ error/not-found cases) with a fake runtime stream; -race clean. Live kubectl exec/port-forward against a confined pod is the m2.sh e2e leg."
            method: e2e
      - id: M2.6
        title: Consume the apis:M2.2 typed contract (the k3sm half of the swap)
        status: done
        deliverables:
          - id: M2.6-d1
            done: true
            desc: "pkg/provider consumes apis:M2.2's typed resource/metrics surface in place of the M2.2/M2.3 interim seams. (1) translate.go sets the TYPED PodBox.memory_limit_bytes (from resources.limits.memory) + qos_class (computePodQOS reproduces the kubelet Guaranteed/Burstable/BestEffort classification over init+regular containers, mapped to the apis QOSClass enum) — the k3sm.io/memory-limit-bytes annotation stays as a transitional belt-and-suspenders fallback runtimed bridges. (2) the probe runner's restartFunc seam (nil pre-swap, bookkeeping-only) is wired to runtimedRuntime.restartContainer → the runtime RestartContainer RPC, so a committed liveness failure re-execs the container in place, not just increments restart_count. (3) GetStatsSummary/StatsSummary consumes the typed ListPodStats RPC (per-container PodStats/ContainerStats/MemoryStats; footprint→working-set) in place of the in-proc PodMetrics path — the podMetricsSource seam is retired for the wire contract. A provider-side consume of a frozen apis contract, no apis/runtimed change."
        acceptance:
          - id: M2.6-a1
            met: true
            check: "a pod with resources.limits.memory sets PodBox.memory_limit_bytes + the right qos_class; a liveness failure (failureThreshold reached) calls the runtime RestartContainer RPC and increments restart_count; GetStatsSummary builds the kubelet Summary from a ListPodStats response (footprint→working-set). Proven by TestTypedMemoryLimitWritten / TestProbeRestartInvokesRPC / TestStatsSummaryFromListPodStats (fake runtime + apiserver client, no root; -race clean)."
            method: unit

  - id: M3
    title: Multi-node, mesh, NodePort & persistent storage (control side)
    status: done  # 2026-09-01 — the sole remaining acceptance (the live two-Mac K3SM_LAB e2e) ran full green; see M3.3-a1
    completed: 2026-09-01
    note: "M3.0 (multi-node bootstrap + trust core) done. M3.1/M3.2/M3.3 are now CODE-COMPLETE + unit-proven + workspace-integration-green (hack/ci.sh), under the user-space netd-helper posture: M3.1 NodePort (direct wildcard *:nodePort >=1024 in-process — NOT via the helper; +honest-gap Warn admission for externalTrafficPolicy:Local & UDP) ; M3.2 local-path provisioner (pure API-object controller, Retain SC, UID-named PV + nodeAffinity) + StatefulSet (storage+name identity; network identity gapped — needs per-pod IPs) ; M3.3 worker netserve bringup + per-node DNS resolver on the DNS VIP + infra-VIP exemption + mesh-egress source + Seatbelt egress VIPs threaded. DIVERGENCE (open, documented): the per-node resolver is an IN-PROCESS A-record+forward server, NOT CoreDNS-the-binary — CoreDNS-the-binary creates its own sockets (no systemd socket-activation/LISTEN_FDS) so it can't adopt the netd-helper-passed <1024 fd in the unprivileged _k3sm posture, whereas the in-process resolver can (net.FileListener/FilePacketConn); no SRV/PTR/headless, IPv4-only. FOLLOW-UP (faithful k3s realization): run the REAL CoreDNS as a NATIVE darwin/arm64 binary (CoreDNS is pure Go — build+ad-hoc-sign like kine via the executor) supervised on the kube-dns VIP, restoring the infra-VIP exemption so it owns 10.43.0.10:53. Deferred behind that unprivileged-posture fd-bind blocker (root mode could bind directly, but production is unprivileged and a root-only resolver would be a second DNS path); the missing SRV/PTR/headless are MOOT on the native hostprocess path (every pod reports podIP==nodeIP, no per-pod/headless addresses) and material only on the per-pod-IP vm path. NOTE: a LINUX CoreDNS image (Deployment) is NOT the answer — it cannot run on the native hostprocess path and would regress native DNS. The SOLE remaining acceptance is the live two-Mac K3SM_LAB e2e (hack/lab/m3.sh: NodePort reachable, StatefulSet persistence, in-pod kubectl+DNS on the joined node) — never auto-greened. Open production-trust gate: the kine bump-vs-soak decision before PV/PVC under load."
    strategy: hard cut
    depends_on:
      - apis:M3.1
      - runtimed:M3
      - darwin-net:M3
    subphases:
      - id: M3.0
        title: Multi-node bootstrap (token / node-password / HTTP-CSR / join)
        status: done
        deliverables:
          - id: M3.0-d1
            done: true
            desc: "WORKER-join bootstrap + trust, the security Wave-0 core. pkg/certs grows a real two-CA PKI: a CLUSTER CA (the pinned serving anchor + issuer of kubelet-serving certs) and a SIGNING CA (issues system:node client certs); VerifyPinnedChain implements CA-hash-pinned join WITHOUT insecure-skip-tls-verify (the live dialer disables only default verification, then re-imposes pinned verification against the token anchor). pkg/bootstrap: K10<sha256(cluster-CA)>::<user>:<secret> tokens minted by `k3sm token create` (TTL-bounded, hashed/bcrypt, identity system:k3sm-bootstrap — NEVER system:masters); node-password anti-impersonation (bcrypt-hashed, constant-time compare, first-write-wins name binding, local copy 0600); HTTP-CSR approver minting CN=system:node:<name>, O=system:nodes bound to the authenticated node + InternalIP (rejects a cross-node SAN); kubelet-serving certs from the cluster CA; the MeshPeer write-guard (a node writes only its own MeshPeer; enroll is controller-mediated); the supervisor-side Server + the agent-side Join client over a pinned-CA TLS exchange. `k3sm agent --server --token` runs the join → writes a system:node kubeconfig (0600, cluster-CA-verified — NOT the admin token) → mesh-enrolls (writes THIS node's MeshPeer; apis net/v1) → drives darwin-net mesh.New/NewWatcher. pkg/executor binds the apiserver to the wireguard mesh interface ONLY + --anonymous-auth=false + --client-ca-file (so M4's Node,RBAC flip is a pure authorizer switch) + --kubelet-certificate-authority + a cluster-CA-signed serving cert (gated on `k3sm server --mesh-ip`; single-node loopback/self-signed path unchanged). The AES-256-GCM identical-CA bundle (HA-server CA reconstruction) is M6, not here."
        acceptance:
          - id: M3.0-a1
            met: true
            check: "the trust core is proven by named unit tests (fakes/in-proc, -race clean): TestCAHierarchyAndPinnedJoin (token embeds sha256(cluster-CA); a join client verifies a chain rooted in it and REJECTS a different root, no insecure-skip), TestNodePasswordHashedConstantTime (hashed + constant-time + first-write-wins), TestCSRIssuesSystemNodeIdentity (CN=system:node:<name>,O=system:nodes; cross-node SAN rejected), TestJoinTokenTTLAndNotAdmin (TTL-bounded, not system:masters), TestMeshPeerWriteGuardOwnNodeOnly, TestApiserverFlagsMeshBindAnonOff (mesh bind not 0.0.0.0 + anon-off + client-ca + kubelet-ca). The live two-Mac join — cross-node pod-to-pod + ClusterIP, the MeshPeer CRD install, the mesh utun bring-up, the apiserver secure-cutover boot — is the K3SM_LAB e2e leg."
            method: e2e
      - id: M3.1
        title: Wire NodePort Services
        status: done
        deliverables:
          - id: M3.1-d1
            done: true
            desc: "surface darwin-net:M3's NodePort listener (*:nodePort, TCP) through the server so a NodePort Service is reachable on the host port — no apis change (ServicePort.NodePort already exists). Bound as a DIRECT wildcard *:nodePort in-process (>=1024; NOT via the netd helper, which rejects wildcards); apiserver pins --service-node-port-range 30000-32767 so the unprivileged _k3sm proxy binds it; <1024 NodePort unsupported. Honest-gap Warn VAPs added: externalTrafficPolicy:Local (userspace splice doesn't preserve client src IP) and UDP Service ports (no UDP datapath yet); foreign-user Deny VAP extended to runAsGroup/supplementalGroups/ephemeralContainers. UDP NodePort deferred with darwin-net's UDP relay. CODE-COMPLETE + unit-proven; live reachability is the lab e2e."
        acceptance:
          - id: M3.1-a1
            met: true
            check: a Deployment behind a NodePort Service is reachable on *:nodePort
            method: e2e
            evidence: "PROVEN 2026-08-27 on the lab host by TestM3_NodePort under hack/acceptance/m3.sh (single-node integration gate): `M3 (integration): 2 passed, 0 failed`, exit 0. Single-node-testable, so it is NOT owed to the two-Mac lab."
      - id: M3.2
        title: APFS local-path provisioner + StatefulSet
        status: done
        deliverables:
          - id: M3.2-d1
            done: true
            desc: "a local-path provisioner controller watches PVCs and provisions a PV via runtimed:M3 (stable per-PVC dir on the same APFS volume as /var/lib/k3sm, empty-create, lifecycle decoupled from the pod dir, honors ReclaimPolicy); StatefulSet support — stable STORAGE + NAME identity on the hostprocess runtime; stable NETWORK identity requires per-pod IPs (runtimed M2 path)."
        acceptance:
          - id: M3.2-a1
            met: true
            check: a StatefulSet + PVC writes data, the pod restarts, and the SAME data is present (persistence across restart)
            method: e2e
            evidence: "PROVEN 2026-08-27 on the lab host by TestM3_PVCPersistsAcrossRestart under hack/acceptance/m3.sh, exit 0. Reaching green required a PRODUCT fix, not just a harness one: pkg/provider toVolume had no PersistentVolumeClaim case, so the volume was silently dropped and every StatefulSet with a volumeClaimTemplate was rejected as `volume_mount \"data\" references undefined volume`."
      - id: M3.3
        title: Per-node CoreDNS + node-local kubernetes endpoint (infra-VIP mesh exemption)
        status: done  # 2026-09-01 — a1 green on the two-Mac lab rig
        completed: 2026-09-01
        deliverables:
          - id: M3.3-d1
            done: true
            desc: "per-node DNS resolver bound to the DNS VIP + node-local kubernetes endpoint (with darwin-net:M3.3) so infra VIPs (10.43.0.1/10.43.0.10) are never steered over the wireguard mesh where no peer's AllowedIPs covers them. Implemented: worker netserve bringup (runAgent now builds the proxy+resolver post-enroll so the mesh-egress source is known); the proxy steps aside for the DNS VIP via WithInfraVIPExemptions while OWNING the API VIP 10.43.0.1:443 (L4-forward to the apiserver endpoint over the mesh with WithMeshEgressSource — pod keeps dialing 10.43.0.1 so the serving-cert SAN holds; default/kubernetes is NOT mutated — the lease reconciler owns it); the <1024 DNS/API VIP binds go through the netd helper BindPort (specific address); per-pod Seatbelt egress scoped to the real DNS VIP (10.43.0.10) + API VIP (10.43.0.1:443) via runtimed Posture. DIVERGENCE: the resolver is IN-PROCESS (A-record + upstream forward, IPv4-only, no SRV/PTR/headless), NOT CoreDNS-the-binary — CoreDNS-the-binary creates its own sockets (no socket activation) so it can't adopt the netd-helper-passed <1024 fd in the unprivileged _k3sm posture, while the in-process resolver can; documented in pkg/netserve. FOLLOW-UP (faithful k3s, deferred): the REAL CoreDNS as a NATIVE darwin/arm64 binary (pure Go — build+ad-hoc-sign like kine) supervised on the VIP; blocked by that unprivileged-posture fd bind. A LINUX CoreDNS image (Deployment) is explicitly NOT the path — it can't run on the native hostprocess backend and would REGRESS native DNS (k3s server must keep a resolver on the VIP). The SRV/PTR/headless gap is moot on the native hostprocess path (no per-pod IPs) and material only on the per-pod-IP vm path. CODE-COMPLETE + unit-proven; the cross-node in-pod kubectl+DNS is the lab e2e."
        acceptance:
          - id: M3.3-a1
            met: true  # 2026-09-01: hack/lab/m3.sh FULL GREEN on the two-Mac rig (server + worker, both on main @eee0fb3 with the kubelet serving-cert fix): TestM3_InPodKubectlAndDNSOnWorker PASS — a pod on the joined worker resolves kubernetes.default.svc through the in-pod DNS shim and completes an authenticated apiserver call; TestM3_NodePort and TestM3_PVCPersistsAcrossRestart PASS in the same run (M3: 3 passed, 0 failed). Log: hack/lab/runs/m3-lab-twomac-2026-09-01.log. STANDS ON (recorded 2026-09-09): the operator's decision that this 2026-09-01 two-Mac run counts for this flag, taken while reconciling the public multi-node sentence against the ledger. RE-GREENED 2026-09-17: the same gate ran exit 0 again on the current build on the two-Mac rig (run 17, the maintainers' run log). 2026-09-17: M14.4 is now fully discharged — the tutorial was also executed exactly as written and recorded (run 19, the maintainers' run log) — so this flag rests on the completed M14.4 write-through (M14.4-d1 done, M14.4-a1 met).
            check: on a 2-node cluster, in-pod kubectl and cluster DNS work from a pod on the joined (non-control-plane) node
            method: e2e

  - id: M4
    title: Install/launchd, packaging, Homebrew, hardening
    status: in-progress
    note: "M4.1 (RBAC enforcement) is CODE-COMPLETE + unit-proven: the apiserver default is now --authorization-mode=Node,RBAC + NodeRestriction (pkg/executor), and pkg/rbac.Provision lays down the node-datapath ClusterRole (system:nodes ⇒ read services/endpointslices/meshpeers) + the in-pod reader RoleBinding, FAIL-CLOSED before the node/join-supervisor start. The LIVE authz flip (a system:node cert denied a cross-node write + a non-granted verb but authorized for the datapath reads; a restricted SA denied a verb) is the integration tier — authored as the build-tagged e2e/TestM4_RBACEnforced, NOT run in unit CI (M4.1-a1 met:false, integration-pending). M4.0 (packaging/launchd) remains todo; M4.2 (synthetic conformance gate) is in-progress — the per-criterion TestM2_*/TestM3_* suite in e2e/ + the m2.sh/m3.sh/m4.sh gates + the non-vacuous guard (hack/lib/conformance.sh) are authored + compile-verified + gate-wired, the live integration green owed (M4.2-a1 met:false, integration-pending)."
    depends_on:
      - apis:M4.1
      - runtimed:M4
      - darwin-net:M4
    subphases:
      - id: M4.0
        title: Packaging + launchd + install (single-server) — DESCOPED → k3sm:M7.1
        status: descoped
        note: "TOMBSTONE (2026-07): M4.0 is absorbed into M7.1 (release-engineering pipeline). No M4-scope work remains here; the deliverable + acceptance transferred verbatim to M7.1, which carries phases_ref: k3sm M4.0. M4.0-a1 stays met:false and flips ONLY via the M7.1 phases_ref write-through when hack/lab/m7.sh greens in the M7 tail — NOT on any M4-local completion — so M4 does not falsely flip done. Records the transfer per the NodeNetwork no-op convention (apis:M3.2-d3)."
        deliverables:
          - id: M4.0-d1
            done: false
            desc: "DESCOPED 2026-07 → k3sm:M7.1; deliverable + acceptance transferred verbatim; no M4-scope work remains. The single-server packaging/launchd/install (launchctl bootstrap/kickstart) + codesign/notarize/.pkg + goreleaser → k3sm-io/homebrew-tap + admin-kubeconfig-to-~/.kube/config work now lives in M7.1 (which carries phases_ref: k3sm M4.0). The retired 'app-bundle-wrapped' SHAPE is deliberately NOT transferred (retired by the DESIGN §5c/§8 app-bundle-retirement amendment — M7.1 is authoritative for the shape: raw-utun/pf posture, no app bundle, two signed artifacts k3sm + k3sm-netd). Only the scope + acceptance transfer."
        acceptance:
          - id: M4.0-a1
            met: false
            check: "brew install → sudo k3sm install server → cluster; survives reboot (launchd). TRANSFERRED verbatim to k3sm:M7.1 — flips met:true ONLY via the M7.1 phases_ref write-through when hack/lab/m7.sh greens in the M7 tail, NOT on any M4-local completion."
            method: e2e
      - id: M4.1
        title: RBAC enforcement (AlwaysAllow → Node,RBAC)
        status: in-progress
        strategy: hard cut
        deliverables:
          - id: M4.1-d1
            done: true
            desc: "the apiserver default authorizer flips AlwaysAllow → Node,RBAC + the additive NodeRestriction admission plugin (pkg/executor Config.AuthorizationMode default Node,RBAC; --enable-admission-plugins=NodeRestriction; --anonymous-auth=false retained). The flip is a PURE authorizer switch: the in-process VK node / provisioners / enroller keep the static admin token (system:masters, RBAC-exempt). M4.1 shipped with the scheduler + KCM on that token too (the documented component-identity divergence); #14 (f855a0a) RETIRED that half — they now authenticate with their OWN per-component client certs (CN=system:kube-scheduler / system:kube-controller-manager) which the apiserver's auto-created bootstrap RBAC binds, so the switch stays pure. pkg/rbac.Provision (NEW package; Create-tolerate-AlreadyExists, never a watch-cache LIST-to-decide under kine v1.14.2 ConsistentListFromCache=true) provisions ONLY k3sm-named objects — it NEVER creates/mutates the apiserver's auto-reconciled system:* defaults: (1) a node-datapath ClusterRole + ClusterRoleBinding to the system:nodes group granting get/list/watch on services (core) + endpointslices (discovery.k8s.io) + meshpeers (net.k3sm.io) — THE fix that keeps a joined worker's Service proxy + DNS resolver + mesh watcher (system:node:<name>) alive after the flip, since the Node authorizer/stock system:node role grant none of these; (2) the minimal in-pod reader Role+RoleBinding for the in-pod-kubectl reference SA (default/snapshot-manager, exported constants) so the M2 in-pod-kubectl path stays green under default-deny. FAIL-CLOSED: runs in cmd/k3sm/server.go's step-3 slot (apiserver healthy, BEFORE startNode + the bootstrap-join server so worker bindings pre-exist) with a bounded retry; a provisioning failure halts bring-up, NOT the log-and-continue admission pattern. The MeshPeer write-guard (bootstrap.AuthorizeMeshPeerWrite) stays load-bearing + PERMANENT (NodeRestriction is core-resource-only, never covers the net.k3sm.io/MeshPeer CRD). On multi-node the kickstart rolls node-by-node, control-plane Mac last, bindings pre-existing so no node is denied mid-roll (no binary-version skew → not the rolling-restart exception). Proven by TestRBACNodeDatapathClusterRole / TestRBACInPodReaderBinding / TestRBACProvisionIdempotent / TestRBACProvisionFailClosed (pkg/rbac) + TestApiserverArgsNodeRBAC (pkg/executor), -race clean."
        acceptance:
          - id: M4.1-a1
            met: true
            evidence: "PROVEN 2026-08-27 on the lab host: hack/acceptance/m4.sh green, `M4 (integration): 2 passed, 0 failed`, exit 0 — TestM4_RBACEnforced passes both subtests live. Two gate defects had to be fixed first: the leg defaulted to the INSTALLED work dir (/var/lib/k3sm/server) rather than the cluster under test, so it either skipped or signed a node cert with a stale CA (surfacing as `Unauthorized`, indistinguishable from an RBAC denial); and the cross-node assertion targeted a NONEXISTENT node, which 404s inside the registry BEFORE NodeRestriction admission runs — vacuous, since it behaved identically with NodeRestriction disabled. The foreign Node is now created by the admin client first, so the write actually reaches admission and the denial proves the control."
            check: "INTEGRATION-TIER (needs a running apiserver on a dev Mac — does NOT run in unit CI; RUN GREEN 2026-08-27, see evidence). The unit tests prove the RBAC GRAPH (the ClusterRole/RoleBinding objects + read verbs + system:nodes subject) + the apiserver args (Node,RBAC default + NodeRestriction). The live flip is the build-tagged e2e/TestM4_RBACEnforced: a self-issued CN=system:node:<name>,O=system:nodes cert is DENIED a cross-node Node write + a non-granted verb but AUTHORIZED for the services/endpointslices/meshpeers datapath reads; a restricted SA (the conformance in-pod reader SA) is allowed its granted verb and denied secrets. The admin client remains authorized across the flip (system:masters); the scheduler/KCM are NOT — they are authorized by their own per-component identities under the apiserver's bootstrap RBAC (#14)."
            method: integration
      - id: M4.2
        title: Synthetic conformance gate in CI
        status: in-progress
        note: "M4.2-d1 is AUTHORED + compile-verified (CGO_ENABLED=1 go vet -tags e2e ./e2e/...) + gate-wired; the LIVE green is integration-tier (dev Mac + root), so M4.2-a1 stays met:false (integration-pending) — NOT faked. Per-criterion TestM2_*/TestM3_* funcs live in e2e/ (e2e/m2_test.go, e2e/m3_test.go; helpers e2e/testdata/cmd/{hello-http,conftool}; e2e/main_test.go builds+signs them in TestMain only when $KUBECONFIG is set). The M3 gate is SPLIT: a new single-node hack/acceptance/m3.sh (integration, CI: NodePort + PVC-persist, runtimed+--network direct) vs the two-Mac hack/lab/m3.sh (cross-node mesh/DNS, K3SM_LAB=1); phases.json gains M3-lab/M4-lab rows de-conflating integration from lab. A new non-vacuous guard (hack/lib/conformance.sh) ENUMERATES the required criterion set and turns RED on any missing/failed/SKIPPED criterion — closing the old m2.sh -run guard's PARTIAL-coverage + ALL-SKIP false-greens. The M4 RBAC integration assertion (TestM4_RBACEnforced) gets a CI home in a new non-root hack/acceptance/m4.sh. Name drift fixed: canonical TestM3_PVCPersistsAcrossRestart (hack/lab/m3.sh)."
        deliverables:
          - id: M4.2-d1
            done: true
            desc: "the stockkitty-driven synthetic conformance set runs as build-tagged per-criterion Go tests in e2e/ (//go:build e2e), invoked by m<n>.sh via the shared non-vacuous guard hack/lib/conformance.sh: M2 (ConfigMap/Secret-mode-0400/EmptyDir/DownwardAPI==podIP/EnvFrom/Probes-transitions/FsGroup/GracefulStop/OOMKilled/KubectlTop/InPodKubectl/InPodDNS/DenyUsers + deferred-skipped ImagePullSecrets/DaemonSet) + M3 single-node (NodePort, PVCPersistsAcrossRestart) at the integration tier (CGO_ENABLED=1), M3 cross-node (InPodKubectlAndDNSOnWorker) + M5 lab-tiered (K3SM_LAB=1). Helper images hello-http+conftool built+ad-hoc-signed by TestMain. The reference-workload feature-gap matrix records the assertion→feature mapping. AUTHORED + compile-verified + gate-wired this session; the live integration run is owed (a1)."
        acceptance:
          - id: M4.2-a1
            met: false
            check: "INTEGRATION-PENDING (needs a dev Mac + root; does NOT run in unit CI). hack/acceptance/m2.sh and the new hack/acceptance/m3.sh exit 0 in CI with EVERY required criterion PASS (non-vacuous guard: a missing/failed/skipped required criterion is RED), and the conformance assertions map to stockkitty features. Authored + compile-verified + gate-wired; the live green is the M2/M3 integration legs on a capable host."
            method: integration

  - id: M5
    title: vm RuntimeClass — Virtualization.framework Linux micro-VM (committed)
    status: done
    completed: 2026-09-01
    note: "DELIVERED 2026-09-01, through the M11 lab ledger: hack/lab/m5.sh graduated into hack/lab/m11.sh per the M4-lab precedent (re-point + skeleton flip + old-script delete in one change — hack/acceptance/phases.json's M5 row now points at hack/lab/m11.sh, skeleton:false). The live vm dispatch (M5.1-d2) is delivered by M11.4-d1..d6 + runtimed:M11.2's digest-pinned guest boot artifacts; the reachability acceptance (M5.1-a1) is proven by hack/lab/m11.sh, run 2026-09-01 on a single entitled VZ Mac (multi-node vm is an M14 matter, not an M5 gap)."
    depends_on:
      - apis:M5.1
      - runtimed:M5
      - darwin-net:M5
    subphases:
      - id: M5.1
        title: runtimeClassName=vm dispatch + Linux image + vmnet assembly
        status: done
        deliverables:
          - id: M5.1-d1
            done: true
            desc: "VERIFIABLE FOUNDATION (unit-proven): the provider dispatches a pod by RuntimeClass to runtimed:M5's backend via the apis:M5.1 handler-config — pkg/provider/translate.go toPodBox reads spec.runtimeClassName and resolves runtimev1.DefaultHandlerConfig().Backend(handler), stamping SandboxProfile.Backend: runtimeClassName=vm → SANDBOX_BACKEND_VM (and VmVcpus from ceil(summed cpu milli) + VmMemoryBytes from summed memory, limit-else-request across regular containers, 0=VZ default); empty/no RuntimeClass → SANDBOX_BACKEND_UNSPECIFIED (NOT a hardcoded seatbelt rung — this FIXES the architect-flagged EXEC=1-vs-INPROC=2 mismatch, letting runtimed's reworked SelectBackend(UNSPECIFIED,…) pick the host-OS-gated rung); an unknown handler FAILS CLOSED (toPodBox returns an error wrapping runtimev1.ErrUnknownHandler — never a silent downgrade). The upstream node.k8s.io/RuntimeClass is consumed, not forked. pkg/runtimeclass.Provision idempotently lays down the node.k8s.io/v1 RuntimeClass vm (handler vm) with a scheduling.nodeSelector pinning it to k3sm.io/virtualization-labelled nodes (provisioned in cmd/k3sm/server.go alongside RBAC/policy, log-and-continue); cmd/k3sm/node.go sources the node label from the node's VZ availability via applyVirtualizationLabel(n, nodeVMCapable()). REPORTED cross-repo need (not faked): runtimed's GetRuntimeInfo reports only the selected host-process backend's health, NOT per-backend (VZ) availability, so nodeVMCapable() defaults false → label ABSENT → a vm pod stays Pending/Unschedulable (fail-closed, complementing runtimed's SelectBackend ErrBackendUnavailable backstop). Proven by TestToPodBoxVMRuntimeClass / TestToPodBoxDefaultBackendUnspecified / TestToPodBoxUnknownRuntimeClassFailsClosed (pkg/provider) + TestVMRuntimeClassNodeSelector / TestVMRuntimeClassProvisionIdempotent (pkg/runtimeclass) + TestNodeVirtualizationLabel (cmd/k3sm), -race clean."
          - id: M5.1-d2
            done: true  # 2026-09-01 — delivered by M11.4-d1..d6 (the live vm dispatch's remaining half: capability labels d1, arch truthfulness d2, image-platform pre-pull d3, the guest-network producer wiring d4 — SetupGuest before toPodBox, the in-process runtimed.Deps carrier this row anticipated, no apis change — admission notes d5, the limitations rewrite d6) plus runtimed:M11.2's digest-pinned linux-guest kernel/initramfs (k3sm-io/linux-guest v6.18.48-k3sm.1) served over vmnet. See docs/PHASES.md's M11 block for the full deliverable ledger.
            desc: "LAB REMAINDER (needs a VZ Mac + the com.apple.security.virtualization entitlement): the LIVE vm dispatch — provider → darwin-net podnet.Network.SetupGuest for the guest network → thread the GuestNetwork (guest IP/gateway/NAT-subnet/DNS-VIP) to runtimed's VZ backend → boot a digest-pinned Linux guest (not Mach-O ⇒ codesign/notarization N/A inside the VM; the guest kernel/initramfs is the notarized host asset). darwin-net flagged there is NO transport for GuestNetwork to runtimed yet — the clean fix is a runtimed consumer-side supervisor.GuestNetwork seam (no apis change). Plus: the M4.1 foreign-user VAP should EXEMPT runtimeClassName=vm (a vm guest CAN honor a foreign runAsUser/fsGroup — deferred, observable only once the VM boots); the guest resolv.conf injection (pinned static/immutable per darwin-net's caveat); Rosetta-for-amd64; and the separate-binary virtualization-entitlement signing (M4.0 packaging). This is what runs stockkitty's Linux-only Postgres/pgvector. Also needs the reported runtimed GetRuntimeInfo per-backend-availability extension so the node VZ label can be set truthfully. DELIVERED 2026-09-01 by M11 — see the done:true comment on this row."
        acceptance:
          - id: M5.1-a1
            met: true  # 2026-09-01 — proven by hack/lab/m11.sh legs m11.7-c/d (in-guest cluster DNS VIP resolution of kubernetes.default.svc + a TCP connect to the kubernetes ClusterIP) and m11.10-b (a client reaches the vm-hosted workload through its ClusterIP), run on an entitled VZ Mac, log hack/lab/runs/m11-lab-v0.1.0-dev.22a84ba-2026-09-01.log. Proven single-node on one VZ Mac — the check's "two-Mac/VZ lab" phrasing names the VZ half M5 needed; multi-node vm is an M14 matter, not an M5 gap.
            check: a Linux image runs under runtimeClassName=vm, is reachable via a ClusterIP Service + cluster DNS, and coexists with native arm64 pods (two-Mac/VZ lab)
            method: e2e

  - id: M6
    title: HA — multi-server control plane (kine→Postgres, server-join, identical-CA bundle)
    status: in-progress
    note: "M6.0 (kine→Postgres multi-writer datastore + HA leader-election) AND M6.1 (HA server-join + the AES-256-GCM identical-CA bundle) are CODE-COMPLETE + unit-proven; the live 2-server-on-Postgres acceptance + the watch-staleness soak + the second-server-join/failover are lab (hack/lab/m6.sh, K3SM_LAB=1 + 2 servers + Postgres — never auto-greened). FRAMING: HA is Postgres-FROM-INIT (greenfield) — the single-node kine→SQLite default is byte-unchanged, so there is NO live SQLite→Postgres data conversion (an operator kine dump/restore is the only path; in-place conversion is out of scope). M6.1 reconstructs identical CAs via a server-token-derived AES-256-GCM bundle (PBKDF2/600k + per-seal salt+nonce, AAD-bound), fail-closed import-then-load, datastore-backed node-password sharing, and a built-but-lab-failover client-side apiserver LB + signing-CA admin client cert."
    depends_on:
      - apis:M4.1
      - darwin-net:M3
    subphases:
      - id: M6.0
        title: kine→Postgres datastore for multi-writer HA
        status: in-progress
        strategy: phased (named exception: kine/SQLite datastore migration)
        deliverables:
          - id: M6.0-d1
            done: true
            desc: "kine→Postgres multi-writer datastore + HA leader-election (mimicking k3s's external-datastore HA — 2+ servers share ONE Postgres, the single source of truth, NO etcd quorum; the single-node default stays SQLite). pkg/executor: ADDITIVE Config.DatastoreEndpoint (a Postgres DSN) — empty (zero value) keeps the kine→SQLite WAL default BYTE-UNCHANGED (single-node M1–M5 untouched), non-empty points kine at Postgres via pgx; the apiserver still talks to the LOCAL kine (--etcd-servers 127.0.0.1:<KinePort>), each server runs its own kine against the shared Postgres (the k3s topology). SECRET HANDLING: the DSN password never lands on argv or a log — it is relocated to a 0600 PGPASSFILE handed out-of-band to the kine child (pgx reads it via the libpq env fallback), only the password-stripped DSN reaches kine's --endpoint, and component logs are tightened to 0600. KINE VERSION (SUPERSEDED 2026-08-30 — this deliverable originally described a POSTURE-AWARE two-pin scheme, SQLite on DefaultKineVersion=v1.14.2 and Postgres-HA on DefaultKineVersionHA=v0.16.3; the M7.1 pin collapse retired both, and the shipped constant is now a SINGLE unified DefaultKineVersion=v0.17.0 for BOTH postures, built CGO_ENABLED=0 against kine's pure-Go modernc.org/sqlite backend — pkg/executor/executor.go:202, floor-pinned by datastore_test.go. Corrected here during the M14 encoding so a lab operator reading this row before the M14.5 HA session is not told the two postures run different kine builds). v0.17.0 carries the kine#577 watch-progress-notify fix (defaults --watch-progress-notify-interval=5s + --emulated-etcd-version=3.6.11); HA is greenfield-from-init, so no SQLite→newer-kine upgrade. SPLIT-BRAIN GUARD (fail-closed): Config.Validate rejects an HA server (ServerJoin) without a DatastoreEndpoint (ErrHARequiresDatastore) — a 2nd server can NEVER silently fall back to its own SQLite. LEADER ELECTION: scheduler + KCM --leader-elect is Config-gated (false single-node — unchanged; true in HA so only one server's scheduler/KCM is active — two would double-bind/double-reconcile); only the apiserver is active/active; the leader-election Leases are authorized by the apiserver's auto-created system:kube-scheduler / system:kube-controller-manager bootstrap RBAC binding the components' OWN per-component identities (no new pkg/rbac object). pgx POOL BOUNDS pinned (kine's default is UNLIMITED): 32 max-open/server so 2×32 ≤ Postgres default max_connections (100) + idle/lifetime; doc.go documents Postgres as the operator-managed datastore SPOF (pg_dump/PITR runbook, no _busy_timeout analog → operator statement/lock timeouts, local-WAL-sub-ms→network-RTT write tradeoff; HA buys process redundancy, not datastore redundancy). cmd/k3sm server grows --datastore-endpoint (or $K3SM_DATASTORE_ENDPOINT, off k3sm's own argv) + --server-join. Proven by TestDatastoreEndpointSQLiteDefault / TestDatastoreEndpointPostgres / TestDatastorePasswordRelocation / TestKineVersionPostureAware / TestHARequiresDatastoreEndpoint / TestLeaderElectHAvsSingleNode (pkg/executor, -race clean). The live 2-server-on-Postgres + the kine#577 watch-staleness soak are the lab production-trust gate (hack/lab/m6.sh + e2e/TestM6_*)."
        acceptance:
          - id: M6.0-a1
            met: false
            check: two control-plane servers run against one Postgres; a write on server A is read on server B; killing A leaves the cluster serving via B (lab — postgres + 2 servers)
            method: e2e
      - id: M6.1
        title: HA server-join + identical-CA bootstrap bundle
        status: in-progress
        strategy: phased (named exception: kine/SQLite datastore migration)
        note: "CODE-COMPLETE + unit-proven; the live 2-Mac + Postgres server-join/failover is the lab acceptance (M6.1-a1 met:false). The crypto core + the fail-closed server-join are the must-haves and are done; the client-side apiserver LB is BUILT (pkg/loadbalancer: server-set + health-check + pick-healthy + TCP-forward, unit-proven) but NOT YET WIRED TO A CALLER — it has zero importers in the tree today (see docs/audits/open-items.md #3). APIServers is separately plumbed through the join result and consumed by a simpler first-dialable-endpoint picker in cmd/k3sm/agent.go (advertisedAPIServerHost), not by pkg/loadbalancer — the live cross-Mac kubeconfig-retarget/failover is the lab leg."
        deliverables:
          - id: M6.1-d1
            done: true
            desc: "the M3 worker-join path extended to a SECOND CONTROL-PLANE SERVER reconstructing IDENTICAL cluster + signing CAs (DESIGN §5c), mimicking k3s's datastore-bootstrap-key model. CRYPTO CORE: certs.Hierarchy.Marshal/Unmarshal serialize the 4 CA PEMs (certs owns them); pkg/bootstrap SealBundle/OpenBundle AES-256-GCM-seal the opaque bytes (the seal stays in bootstrap, NOT certs — the bootstrap→certs edge would cycle). Key derived via PBKDF2-HMAC-SHA256 (pinned 600k iters + a crypto/rand 128-bit salt in a versioned envelope) from a MACHINE-GENERATED ≥256-bit server-bootstrap secret (NOT a passphrase, NOT a worker token); a FRESH 12-byte crypto/rand nonce per seal (never a counter — launchctl kickstart resets state); a versioned AAD-bound envelope (magic+version+kdf-id+iters+salt+nonce as GCM AAD); gcm.Open failure is FATAL (tag verified before any plaintext). The sealed envelope is also published to the shared Postgres as a kube-system Secret (the k3s bootstrap-key model); decrypted keys written 0600, never logged. SERVER-CLASS IDENTITY: a server token K10<caHash>::server:<secret> (ServerBootstrapUser system:k3sm-server-bootstrap) DISTINCT from the M3 worker token (system:k3sm-bootstrap); the CA-bundle endpoint (/v1-k3sm/server-bootstrap, Authorization bearer) authorizes the server class ONLY — a leaked worker token can NEVER reconstruct the signing CA. SERVER-JOIN: k3sm server --server-join --server <url> --token reuses the M3 PinnedClient (pinned-CA TLS, no insecure-skip) to fetch the bundle, then IMPORT-THEN-LOAD: decrypt → certs.WriteHierarchy the 4 PEMs into PKIDir → THEN EnsureHierarchy loads them. FAIL CLOSED on any fetch/decrypt/tag failure — never falls through to ensureCA minting divergent CAs (k3sm token create --server mints the server token). DATASTORE-BACKED STORES: the HA node-password store is a kube-system Secret (shared across servers — a name bound on A is enforced on B; the per-process MemoryNodePasswords is kept single-node). CLIENT-LB + ADMIN CERT: pkg/loadbalancer tracks the apiserver set, health-checks, picks a healthy one, and TCP-forwards, but is NOT YET WIRED TO A CALLER — it has zero importers in the tree today (see docs/audits/open-items.md #3); APIServers is separately plumbed through the join result and consumed by a simpler first-dialable-endpoint picker in cmd/k3sm/agent.go (advertisedAPIServerHost), not by pkg/loadbalancer; the HA admin kubeconfig (admin.kubeconfig) uses a signing-CA-issued system:masters CLIENT CERT (reconstructible on every server) + cluster-CA verification, so kubectl works against any server. Proven by TestCABundleSealUnsealRoundTrip/TestCABundleWrongSecretFailsClosed/TestCABundleNonceUniquePerSeal/TestCABundleTamperedAADRejected (crypto), TestServerTokenDistinctFromWorker/TestLoadOrCreateServerSecret + TestCABundleEndpointRejectsWorkerIdentity (server identity), TestServerJoinImportsBundleBeforeEnsureHierarchy/TestServerJoinFailsClosedOnAbsentBundle (fail-closed join), TestHierarchyMarshalUnmarshalRoundTrip/TestWriteHierarchyThenEnsureLoads (certs), TestNodePasswordSharedAcrossServersInHA (datastore store), TestApiserverLBPicksHealthy/TestLoadBalancerForwardsToHealthy + TestAdminKubeconfigUsesClientCert (LB + admin cert), all -race clean. The live 2-Mac + Postgres server-join/failover is the lab leg (e2e/TestM6_SecondServerJoinsReconstructsCAs + hack/lab/m6.sh)."
        acceptance:
          - id: M6.1-a1
            met: false
            check: a second Mac joins as a control-plane server, reconstructs the identical CAs from the bundle, and serves the apiserver against the shared Postgres (lab — 2 macs + postgres)
            method: e2e

  - id: M7
    title: Release engineering for the public open-source launch
    status: todo
    strategy: hard cut
    note: "LEDGER STUB. k3sm is M7-primary (all six sub-phases M7.0–M7.5); apis/runtimed/darwin-net carry small M7 entries (their ci.yml + K3SM_CI_REQUIRE SkipUnless conversions). Gate machinery: hack/acceptance/m7.sh is the single umbrella gate execing hack/acceptance/m7/{ci,docs,hygiene}.sh (a directory OUTSIDE the m[0-9]*.sh orphan glob); manual:false skeletons exit non-zero unconditionally (Res. 2); the M4-lab row re-points to hack/lab/m7.sh (hack/lab/m4.sh deleted, B35 tombstoned — Res. 3). The kine single-pin (≥0.16.x, CGO_ENABLED=0 pure-Go sqlite) is a hard cut ONLY after datastore compat is verified, else it escapes to the named kine/SQLite datastore-migration exception. Launch itself is M9."
    depends_on:
      - apis:M7
      - runtimed:M7
      - darwin-net:M7
    subphases:
      - id: M7.0
        title: Validation-debt burn-down
        status: todo
        deliverables:
          - id: M7.0-d1
            done: false
            desc: "STUB. Human-at-hardware burn-down of the M2–M6 validation debt (never /go): run m2.sh root demo + m3.sh + m4.sh on the dev Mac (flips the met:false integration-pending acceptances M2-root-e2e / M4.1-a1 live RBAC / M4.2-a1 conformance), the hack/lab/m3.sh two-Mac gate (multi-node is the headline claim), and the B28 dev-mac churn soak (hack/acceptance/m7/soak.sh) against the M7.1 kine ≥0.16.x pin. Nightly GH-runner greens are macOS-15 evidence only, never the dev-mac burn-down (A20). On completion M4 flips done on validation runs alone (M4.0 absorbed into M7.1); M5/M6 lab gates ship documented EXPERIMENTAL (not launch-blocking)."
        acceptance:
          - id: M7.0-a1
            met: false
            check: "the existing m2/m3/m4 + hack/lab/m3.sh gates run for real (green) on dev-mac/lab hardware; the B28 soak (hack/acceptance/m7/soak.sh) is green against the M7.1 kine pin OR the accepted-with-known-issue disposition is recorded in limitations.md."
            method: e2e
      - id: M7.1
        title: Release-engineering pipeline (absorbs M4.0-d1/a1)
        status: todo
        note: "phases_ref: k3sm M4.0 — completion writes through to flip M4.0-d1 done / M4.0-a1 met when hack/lab/m7.sh greens in the M7 tail."
        deliverables:
          - id: M7.1-d1a
            done: false
            desc: "LAB-PENDING (M7.1-d1a, B138 — split from d1 by Res. 22). Archive completeness: the release tarball carries every artifact `k3sm install` fail-fasts on, at the layout pkg/install resolves. pkg/install.RequiredSiblings is the ONE home of that contract (derived from executor.PayloadBinaries; exposed unprivileged as `k3sm install --print-required-artifacts`), and the archive's member set is asserted against it rather than a hand-copied list. cp-payload is staged at cp-payload/ BESIDE the binary — NOT libexec/: the shipping code has no CLI override and a unit test pins it, so the plan text was what was wrong. The four downloaded control-plane binaries are sha256-pinned in-repo (pkg/executor/payload_digests.go) and verified fail-closed at StagePayload with set-equality, so a re-pointed third-party tag or an extra release asset stops the release; kine is excluded by design (built by `go install`, sumdb-authenticated). Staging lives in build/, never dist/ (goreleaser owns dist/ and --clean empties it), and every Go build pins GOARCH=arm64 because a Rosetta-defaulted toolchain silently emits x86_64 and dyld hard-terminates on a wrong-arch inserted library. Gates: workspace hack/release-selftest.sh (13 hermetic checks) + hack/acceptance/B58.sh (full derived member set). Flips done ONLY when the archive has been built and verified on release hardware."
          - id: M7.1-d1b
            done: false
            desc: "STUB (M7.1-d1b, split from d1 by Res. 22 — REMAINS LAUNCH-BLOCKING and blocks any SIGNED release). setup.go verify-then-use rewrite: runtime becomes verify-then-use (codesign --verify in place; NO ad-hoc re-sign of the Developer-ID payload — signBinaries' unconditional `codesign -s - -f` with a discarded error would strip release provenance seconds after launchctl bootstrap); fails fast on a missing bundle (the digest-pinned HTTPS fallback is dev-context-only, never under launchd). Build kube-apiserver/scheduler/KCM/kubectl from upstream k/k source at a pinned ref (hack/release/build-cp.sh) so the payload's provenance is ours rather than a third party's — d1a's digest pins are the interim control, not the destination. Drop runtime gh + go toolchain. kine collapses to ONE modern pin ≥0.16.x built CGO_ENABLED=0 (modernc.org/sqlite) — retires B31/B38; a dep-lint asserts no mattn/go-sqlite3 in the shipped artifact; the bundled kine Mach-O is Developer-ID signed + enumerated (Res. 7). This is the release/build slice, tracked internally (Res. 10)."
          - id: M7.1-d2
            done: false
            desc: "STUB. goreleaser (k3sm/.goreleaser.yaml): darwin/arm64 only, CGO=1, -X k3sm.io/k3sm/pkg/version.{Version,Commit,Date} (B57 — NOT the retired main.version), archive = k3sm + k3sm-netd + cp payload + kine + LICENSE/NOTICE; brews: → Formula/k3sm.rb in the public k3sm-io/homebrew-tap with a head build-from-source path that clones the four-repo sibling layout (a lone k3sm clone cannot build). k3sm-netd is a renamed copy of the same k3sm Mach-O (Res. 9)."
          - id: M7.1-d3
            done: false
            desc: "STUB. Signing + the two-artifact netd split (hack/release/{sign,notarize,pkg}.sh + entitlements/{server,netd}.plist). Two signed artifacts: k3sm (io.k3sm.server, runs as _k3sm — entitlement trio allow-jit / allow-unsigned-executable-memory / disable-library-validation, each naming its consumer in sign.sh comments or dropped) and k3sm-netd (io.k3sm.netd, NO entitlements). Bare Mach-Os → notarized tarball (online ticket) + signed+stapled .pkg. NetdPlist.ProgramArguments execs a startable helper (`netd` subcommand token preserved). App-bundle retirement = a named DESIGN §5c/§8-risk-5 + privilege-model edit (A14). m7.sh asserts entitlements bidirectionally."
          - id: M7.1-d4
            done: false
            desc: "STUB. Release workflow + reproducibility (.github/workflows/release.yml): tag-triggered, macos arm64 runner, release environment with a required reviewer + ephemeral keychain; release-environment-scoped secrets (DEVELOPER_ID_APP_P12 / DEVELOPER_ID_INSTALLER_P12 / ASC_* / HOMEBREW_TAP_TOKEN + a cross-repo-checkout GitHub App — Res. 13). Checks out all four repos as siblings at the identical tag (fail if any missing), records the four SHAs in release notes + k3sm version; -trimpath, pinned Go toolchain, pinned k/k ref."
          - id: M7.1-d5
            done: false
            desc: "STUB. Versioning: SemVer v0.x.y (NOT +k3sm1 — k3sm.io/apis must stay go-gettable), same tag across all four repos, four SHAs recorded; k8s alignment via k3sm version + docs/user/versions.md (states the DefaultKubeVersion v1.36.2 vs client-libs v0.35 skew). CHANGELOG.md Keep-a-Changelog. Apple Developer enrollment + certs + ASC key + tap bootstrap are human-only, START IMMEDIATELY (calendar critical path)."
          - id: M7.1-d6
            done: true
            desc: "DONE 2026-08-09 (B137, PR #105 + #106). Gen-1 curl|sh installer (workspace m7-plan Res. 21 — the curl→brew→pkg ladder): k3sm/install.sh at the repo root (k3s convention), served byte-identical at https://k3sm.io/install.sh (workspace hack/verify-install-sync.sh asserts the copy; --live verified against production). POSIX sh, main-at-end truncation guard; darwin preflight fail-closed on sysctl hw.optional.arm64 = 1 (Rosetta-proof) + macOS≥26; latest via the releases/latest 302 or K3SM_INSTALL_VERSION; tarball+checksums fetch; exact-entry sha256 verify (hard-fail on a missing entry, before shasum); unconditional pre-escalation banner; sudo <staging>/k3sm install (re-run = upgrade). Ships FIRST — curl sets no quarantine xattr + the Go linker's ad-hoc arm64 signature (the m9 Amendment-16 mechanism) — but the LIVE channel completes only from the first M7.1-d1-complete release (the archive must add k3sm-execshim + both shim dylibs + the cp-payload; the first public tag waits for that — Res. 21). Gate: hack/acceptance/B137.sh GREEN 20/20 (fully mocked e2e: loopback release server, PATH-stubbed sudo/uname/sw_vers/sysctl, T1-T16 — T15/T16 added 2026-09-01 with the pre-stable published_at fallback + tag validation), red-at-main proven. SHIPPED STATE: the script + page are live but UNLINKED from the homepage (noindex) until M9, and with no release published the live one-liner aborts with the friendly release-not-published message (verified against production) — d6 delivers the mechanism, not a working install; that waits on M7.1-d1."
        acceptance:
          - id: M7.1-a1
            met: false
            check: "hack/acceptance/m7.sh green (goreleaser snapshot build + bidirectional codesign entitlement asserts + formula render + four-repo layout assert + kine-nocgo dep-lint) AND hack/lab/m7.sh green (real certs: spctl/stapler validate; clean-Mac brew install → cluster Ready → reboot → Ready) — the lab run greens the transferred M4.0 acceptance + the ex-M4-lab reboot debt in one pass (writes through M4.0-a1)."
            method: e2e
      - id: M7.2
        title: GitHub Actions CI
        status: todo
        deliverables:
          - id: M7.2-d1
            done: false
            desc: "STUB. Thin per-repo ci.yml on macos arm64 runners calling the existing hack/ci.sh (no logic duplication): unit + -race + symbol-canary on every image; a workspace ci.yml checks out all five repos. A nightly sudo-integration workflow attempts m2/m3/m4.sh under K3SM_CI_REQUIRE (self-skips turn red, not silent — A10) with an out-of-band stale-last-run detector + an auto-filed issue to @kitsumiko (Res. 17). Self-hosted lab-only workflows carry ONLY {schedule, workflow_dispatch, push@main} triggers (allowlist — Res. 14); zizmor beside actionlint; trufflehog is a required status check; DCO promoted to a required check. The spicanary soft-fail in hack/ci.sh is deleted (canary failure becomes fatal)."
        acceptance:
          - id: M7.2-a1
            met: false
            check: "hack/acceptance/m7/ci.sh green: actionlint/zizmor + workflow-manifest assert (a required workflow missing = red) + the self-hosted-trigger allowlist assert + symbol-canary liveness assert + a post-merge run-green check bound to the flip SHA."
            method: integration
      - id: M7.3
        title: User docs
        status: todo
        deliverables:
          - id: M7.3-d1
            done: false
            desc: "STUB. Canonical home k3sm/docs/user/: the machine-asserted page manifest (quickstart/install/upgrade/backup-restore/concepts/limitations/images/multi-node/vm-runtimeclass/ha[EXPERIMENTAL]/storage/kubectl-access/troubleshooting/faq/versions). limitations.md cites UPSTREAM-ALIGNMENT.md + privilege-model.md (not restated) and carries the MLX-trusted-workload-only paragraph. mlx-quickstart.md is RE-HOMED to M8.6 (authored AND gated there — m8-plan R24, 2026-08-29; supersedes A20's authored-here-gated-by-m8.sh split, and M7 is launch-deferred). New examples/ (nodeport/statefulset/vm-linux/probes); README refresh across all repos (the k3sm README becomes the front door)."
        acceptance:
          - id: M7.3-a1
            met: false
            check: "hack/acceptance/m7/docs.sh green: page-manifest assert + hermetic link-check + yaml-applies + a stale-string denylist seeded from the known offenders ('Pre-M0', 'private development'); the network-tier external-link job is split out of the hermetic gate. The quickstart-smoke runs on the clean-Mac hack/lab/m7.sh run."
            method: integration
      - id: M7.4
        title: Website
        status: todo
        deliverables:
          - id: M7.4-d1
            done: false
            desc: "STUB. Hugo (single binary, no node) on k3sm-io.github.io: the stealth vanity dirs move BYTE-IDENTICAL to static/{apis,k3sm,runtimed,darwin-net}/index.html (Hugo copies static/ verbatim — the go-import metas never change). Docs are NOT committed to the site repo: the deploy workflow checks out k3sm at the latest tag and copies docs/user/ → content/docs/ (single-sourced); the site roadmap page is the deploy-time copy of k3sm/ROADMAP.md. /land never touches k3sm-io.github.io — the site repo lands manually; the real deploy is an M9 step."
        acceptance:
          - id: M7.4-a1
            met: false
            check: "hack/verify-vanity.sh green (deploy-blocking): the four go-import metas match the fixtures byte-for-byte. hack/verify-live.sh (curl production + go mod download) runs at M9."
            method: integration
      - id: M7.5
        title: Public-flip hygiene & security scrub
        status: todo
        deliverables:
          - id: M7.5-d1
            done: false
            desc: "STUB. Full-history secret sweep × 6 repos BEFORE the flip (trufflehog primary, gitleaks second opinion); rotate-not-scrub (any finding rotated/revoked first; a history rewrite flips via a fresh-repo push — A18). .claude/ ships in the public repos (scrubbed). MAINTAINERS.md goes real (@kitsumiko); SECURITY.md → GitHub Private Vulnerability Reporting; repo-settings.sh (gh api, idempotent: branch protection, squash-only, topics, discussions, native secret-scanning + push-protection); go-licenses NOTICE verification per repo."
        acceptance:
          - id: M7.5-a1
            met: false
            check: "hack/acceptance/m7/hygiene.sh green: scan-clean = zero unresolved trufflehog --only-verified findings against the reviewed rotated-credentials baseline (Res. 15) + MAINTAINERS/SECURITY content asserts + repo-settings drift check + NOTICE verification."
            method: integration

  - id: M8
    title: MLX — native Apple-Silicon ML serving (the NVIDIA-GPU-Operator analog for Mac)
    status: done
    completed: 2026-08-30  # per-repo done under the lab-ledger carve-out; the WORKSPACE M8 gate stays open until m8.sh runs green on the apple-gpu rig (the recorded lab session)
    strategy: hard cut
    note: "LEDGER STUB. Launch-blocking (user decision: launch WITH MLX v1; m8.sh joins the launch-gate set — the public flip is M9). OWNERSHIP RECONCILED 2026-08-29 (m8-plan R23, resolving the three-owner M8.0 split): k3sm owns M8.0 (spikes S1–S5, agent-run on the lab Mac — R23), M8.3 (node extended-resource + labels), M8.4 (mlx-serve uv image under hack/images/), M8.5 (pkg/mlx operator), M8.6 (the m8.sh gate). apis owns M8.1 (mlx.k3sm.io/v1alpha1 CRD + reserved-band proto carve); runtimed owns M8.2 (Metal SBPL + egress + AdHocSignTree + GPUFacts — it CONSUMES the OCI-layer unpacker, re-homed 2026-07-11 to the runtimed M11.2 wave as M11.2-d7, via its depends edge; M8 is sequenced after that wave in the amended launch chain). M8.6 ALSO AUTHORS examples/mlxmodel.yaml + docs/user/mlx-quickstart.md (2026-08-29, m8-plan R24 — re-homed from M7.2/M7.3, which are launch-deferred with M7). NO M8-lab row — a GPU dev-mac covers it (Res. 15). All wire/API change is additive (new CRD group, reserved-band proto fields default-false)."
    depends_on:
      - apis:M8.1
      - runtimed:M8.2
    subphases:
      - id: M8.0
        title: spikes S1–S5 — lab Mac, agent-driven (k3sm/hack/spike/m8/)
        status: done
        completed: 2026-08-29
        note: "Owner ratified k3sm 2026-08-29 (m8-plan R23; resolves the three-owner split and darwin-net's k3sm:M8.0 edge). ENTRY-INDEPENDENT: precedes the milestone-level depends_on (apis:M8.1 / runtimed:M8.2 bind M8.3+; M8.1 does NOT wait on M8.0 — R23, the illustrative M8.0 → M8.1 DAG edge is non-binding). Runs on the lab rig (Apple M1-family, 64 GiB, apple-gpu); each spike commits a findings file under k3sm/hack/spike/m8/; per-spike halt semantics per m8-plan Res. 17. Lab guardrails (binding): writes confined to the dedicated user-level prefix + k3sm scratch trees; never touch /Library/Sandbox/Profiles, the TCC/Privacy DB, Gatekeeper/SIP posture, or LaunchDaemons outside the prefix; no codesign-check disabling; any allow-set widening beyond a spike's exit criteria is flagged in the findings file, never silently inherited."
        deliverables:
          - id: M8.0-d1  # S1 Metal-under-Seatbelt
            done: true  # 2026-08-29, k3sm#164/#168 — S1 GO — two-rule allow-set; criterion 2 SBPL half green, datapath half owed (see a1)
            desc: "STUB (M8.0). s1.sh + findings-s1.md — a full MLX inference round-trip under a default-deny Seatbelt profile. PRIMARY job (m8-plan R22): VALIDATE the Apple-practice prefix-rule allow-set candidate — a single (iokit-registry-entry-class-prefix \"AGXAcceleratorG\")-style rule plus the S1-derived mach-lookup / shader-cache scope — which covers AGX user-client class variation M1→M4 without a per-family table. FALLBACK (adopted only if the prefix rule under- or over-scopes on the lab rig): denial-log-derived per-chip-family data. Evidence in the findings file: raw sandbox denial-log excerpts, the concrete allow-set, and BOTH exit criteria — (1) tokens are generated under the profile, (2) the HF weight download succeeds through the production datapath (DNS shim → Service-proxy dialer → egress) under the generated allow_internet_egress profile. S1's two exit criteria are the M8 go/no-go."
          - id: M8.0-d2  # S2 nested-dylib signing
            done: true  # 2026-08-29, k3sm#164/#168 — S2 PASS — per-arch verify binding
            desc: "STUB (M8.0). s2.sh + findings-s2.md — walk-verify the mlx-serve rootfs for nested-dylib signing under AMFI. Evidence: the Mach-O count, the signed / unsigned / invalid-signature tally, and the exec-from-clonefile result (whether an ad-hoc-signed tree survives clonefile materialization and executes). Feeds M8.2-d3 (AdHocSignTree) and M8.4-a1's mechanized walk-verify."
          - id: M8.0-d3  # S3 memory visibility & growth
            done: true  # 2026-08-29, k3sm#164/#168 — S3 PASS — footprint 1:1; sampler-only killer
            desc: "STUB (M8.0). s3.sh + findings-s3.md — memory visibility and growth for an MLX serving process: ri_phys_footprint visibility (does the unified-memory/Metal working set show up), per-token growth, jetsam killer-order under pressure, and a process-group coverage verdict (whether sampling the group covers all engine children). Feeds M8.2-d5's contingency and the M8.5 sizing formula."
          - id: M8.0-d4  # S4 image size & materialize latency
            done: true  # 2026-08-29, k3sm#164/#168 — S4 PASS both thresholds; symlink premise PASS; found the build-layer media-type defect (fixed)
            desc: "STUB (M8.0). s4.sh + findings-s4.md — mlx-serve image size and materialize latency: unpacked size, cold-start, tree-sign cost, and clonefile cost, each measured against the >2GB / >1min pruning thresholds. ALSO record whether k3sm-build-packaged symlinks (python-build-standalone's) survive the COPY → layer → runtimed-unpack round-trip — the M8.4 packaging premise."
          - id: M8.0-d5  # S5 engine bake-off
            done: true  # 2026-08-29, k3sm#164/#168 — S5 — engine: vllm-mlx 0.4.1 --continuous-batching; oMLX out on --require-hashes
            desc: "STUB (M8.0). s5.sh + findings-s5.md — engine bake-off: vllm-mlx vs oMLX vs mlx-lm-dev. Evidence: tok/s, OpenAI API fidelity, the /health surface, license, wheel footprint, and process model. OUTPUT: the recorded M8.4 engine decision + the pinned wheel set (the working hypothesis is vllm-mlx; S5 ratifies or replaces it)."
        acceptance:
          - id: M8.0-a1
            met: false  # lab-ledger carve-out: S1 criterion 1 GREEN + criterion 2's SBPL half GREEN (k3sm#164); the production-datapath half needs the privileged lab slice (rootless dev up is network=none), owned by the M8.6 lab session alongside darwin-net M8.1-a1
            check: "every spike script exits 0 on the lab rig and its findings file is COMMITTED under k3sm/hack/spike/m8/ with the named evidence; S1's two exit criteria (tokens under the default-deny profile; HF weight download through the production datapath) are the M8 go/no-go — a failure HALTS the downstream M8 waves per m8-plan Res. 17."
            method: integration
      - id: M8.3
        title: k3sm node — extended resource + translate + Warn VAP
        status: done
        completed: 2026-08-30
        deliverables:
          - id: M8.3-d1
            done: true  # 2026-08-30 — shipped via the backlog drain: advertisement k3sm#167 (real GPUFacts, fail-closed, three-state nil), translate k3sm#172 (limits-not-requests + the egress pairing), Warn VAP k3sm#173 (cross-package discriminator agreement)
            desc: "STUB (M8.3). configureNode (cmd/k3sm/node.go) advertises mlx.k3sm.io/gpu: 1 in Capacity/Allocatable + labels (mlx.k3sm.io/gpu.present=true, /chip [normalized slug per Res. 4], /chip-family, /memory-gb), FAIL-CLOSED off runtimed GPUFacts (facts absent / metal_available=false / VZ-paravirtual discrimination trips → remove the resource + clear the labels, mirroring applyVirtualizationLabel). B63 ships the same plumbing against a stubbed fact source (blocked-on-M8.1 per Res. 8); this flips it to real GPUFacts. translate.go reads the GPU request from LIMITS → SandboxProfile.AllowGpu, the egress annotation (apis constant) → AllowInternetEgress (allow_internet_egress implies allow_network — Res. 12). A Warn VAP (pkg/policy/admission.go) surfaces a hand-set egress annotation on a non-operator pod (single-trust-domain posture; FailurePolicy: Ignore)."
        acceptance:
          - id: M8.3-a1
            met: true  # 2026-08-30 — all three gates green, builder+orchestrator mutants killed; the live advertisement rides m8.sh per this row's own text
            check: "translate table test (limits-not-requests, annotation present/absent, constant-not-literal) + node-advertisement fail-closed unit test (fake GPUFacts, both skew directions) + the Warn VAP test pass. The live GPU advertisement is exercised by m8.sh on an apple-gpu dev-mac."
            method: unit
      - id: M8.4
        title: k3sm runtime image — mlx-serve (parallel with M8.2/M8.3)
        status: done
        completed: 2026-08-30
        deliverables:
          - id: M8.4-d1
            done: true  # 2026-08-30, k3sm#198 — build.sh (pinned interpreter URL + --require-hashes lock, 1835 hashes generated live) + walk-verify (per-arch, media-type-strict) + selftest 32/32; entrypoint argv carries --continuous-batching + --host 0.0.0.0 (two live engine findings)
            desc: "STUB (M8.4). k3sm/hack/images/mlx-serve/: a build script + uv toolchain (uv python install + uv pip install --require-hashes against a checked-in hash-pinned lockfile) assembling python-build-standalone (darwin-arm64) + the spike-S5-winner engine wheels (working hypothesis vllm-mlx) into ghcr.io/k3sm-io/mlx-serve. Entrypoint is the python3 Mach-O directly (argv[0] must be gateSignature-verifiable — never a shell script); process model per S3 (process-group sampling verified or the image pinned single-process). A dedicated versioned GHCR publish workflow (mlx-serve-image.yml); the operator's default Runtime.Image is digest-pinned (tag display-only); pre-M9 the image is private GHCR (stealth). Weights are NEVER in the image (PVC via HF_HOME). BUILD PATH DECIDED 2026-08-29: no new build tool — the tree is host-staged (uv on the build Mac; RUN is never needed) → k3sm build --format oci (COPY-only packaging, FROM scratch) → pushed via the narrow k3sm image push slice (B189, over the already-vendored go-containerregistry). The GHCR publish workflow stays a human-gated M9-adjacent deliverable (dormant-workflow-classified); pre-M9 publishes run from the lab Mac with the resulting digest recorded."
        acceptance:
          - id: M8.4-a1
            met: false  # lab-ledger carve-out: the compiled tier (selftest 32/32 + shellcheck + mutation-checked) is green; the live build/walk-verify/push over the real 1.3GB closure is the M8.6-adjacent lab slice, runbook in hack/images/mlx-serve/README.md
            check: "the image builds reproducibly from the lockfile (--require-hashes), fits the S4 size budget, and a walk-verify asserts every Mach-O in the payload is signed or linker-ad-hoc-signed (S2 evidence, mechanized)."
            method: integration
      - id: M8.5
        title: k3sm operator — pkg/mlx
        status: done
        completed: 2026-08-30
        deliverables:
          - id: M8.5-d1
            done: true  # 2026-08-30, k3sm#194 — crdensure + operator loop + step-4c-bis wiring; RESIDUALS: Config.GPU nil on the server path (fit check skipped in production; follow-up filed on the workspace queue) and mlx.Options empty until M8.4 lands the image/port defaults
            desc: "STUB (M8.5). NEW k3sm/pkg/mlx in-binary controller mirroring pkg/provisioner (informer + single workqueue worker, no stored Context, resync re-delivery; started in the server.go step-4c pattern, drained LIFO before control-plane teardown). Render: MLXModel → StatefulSet (volumeClaimTemplates → per-replica node-pinned local-path cache PVC) + a headless governing Service + a stable ClusterIP Service; persistentVolumeClaimRetentionPolicy whenDeleted:Delete; controller ownerReferences stamped (Res. 2 — else kubectl delete cascades nothing); readiness-only probes, NO liveness/startup until Ready once (Res. 3); fixed guardrail stanzas (kubernetes.io/os:darwin nodeSelector + k3sm.io/provider:NoSchedule toleration + the GPU resource in requests AND limits) else k3sm's own Deny VAP rejects the STS pods; imagePullSecrets for the private GHCR digest (Res. 16). Conditions-first status (+ observedGeneration, subresource; Phase is a derived printer column; ResolvedRevision recorded at Downloading). CRD ensure via SSA in a NEUTRAL package k3sm/pkg/crdensure (applies mlxmodels ONLY from the embedded k3sm.io/apis/config/crd, field manager k3sm, waits for Established). Pre-render validation: spec.Memory vs GPUFacts wired-limit/working-set → Failed/Degraded WITHOUT creating pods; request=limit from spec.Memory."
        acceptance:
          - id: M8.5-a1
            met: true  # 2026-08-30 — the 14-test battery orchestrator-verified (-race in the lane; every-spec-fits mutant red x12)
            check: "render golden (placement stanza + retention policy + requests==limits + headless/ClusterIP pair + ownerReferences + readiness-only probe) + ensure SSA-convergence test (fake apiserver: schema drift converges, Established awaited) + pre-render validation table test + conditions/observedGeneration contract test + the CEL spec.distributed-rejected test (beside pkg/crdensure, Res. 9) pass."
            method: unit
      - id: M8.6
        title: gate — k3sm/hack/acceptance/m8.sh
        status: done
        completed: 2026-08-30
        deliverables:
          - id: M8.6-d1
            done: true  # 2026-08-30, k3sm#200 — the real m8.sh (concurrent leg per the S5 evidence) + mlxmodel.yaml (pinned revision, render-verified) + mlx-quickstart + the de-skeletoned phases.json row + the authorized linter case
            desc: "STUB (M8.6). hack/acceptance/m8.sh, requires [dev-mac, apple-gpu, network] (dev-mac is a phases.json requires-token, NOT a K3SM_CI_REQUIRE taxonomy member — Res. 19); no M8-lab row. Pinned small model repo+revision (e.g. mlx-community/Qwen3-0.6B-4bit at a pinned HF commit), cache pre-seeded. Sequence: apply examples/mlxmodel.yaml → status Ready (conditions, not just Phase) → OpenAI chat completion via the ClusterIP returns tokens → records TTFT + tokens/sec through the ClusterIP path vs the direct backend → delete → GC-clean per the whenDeleted:Delete deletion contract (poll-to-absent, bounded timeout — Res. 2). m8.sh also gates mlx-quickstart.md; M8.6 ALSO AUTHORS examples/mlxmodel.yaml + docs/user/mlx-quickstart.md (2026-08-29, m8-plan R24 — one owner with the gate, re-homed from M7.2/M7.3)."
        acceptance:
          - id: M8.6-a1
            met: true  # 2026-08-30 — M8 GATE GREEN, run5 root tier (rig logs run5-m8-ladder.log): 22/22, apply->Ready 75s, served-id = the shim-resolved mount path, 4/4 concurrent, ClusterIP 267.2 tok/s vs direct 277.0 (the proxy hop +16.9ms TTFT), delete exact (PVC deleted, PV Released/retained). M8.2-a4 + darwin-net M8.1-a1 discharged the same session
            check: "hack/acceptance/m8.sh green on an apple-gpu dev-mac: MLXModel → Ready → an OpenAI completion via the ClusterIP returns tokens → delete → every operator-owned object gone + PVC disposition exactly per whenDeleted:Delete."
            method: e2e

  - id: M9
    title: Public launch — the flip, the gates, the announcement (WITH MLX v1)
    status: todo
    strategy: hard cut
    note: "LEDGER STUB. No new product code — M9 is the launch checklist. IRREVERSIBLE: repos-public + tagged module versions are forever (sumdb pins tags). Gate hack/acceptance/m9.sh is a manual:true phases.json row (a launch is a human act; the release process never auto-greens it) that machine-enumerates the launch-blocking ledger (m2/m3/m4 dev-mac, lab/m3 two-Mac, m7 umbrella + lab/m7 reboot-via-real-brew-artifact, m7/{ci,docs,hygiene}, verify-vanity, m8.sh MLX e2e, B28 disposition, AND — re-sequenced 2026-07-11 — the m11-core row: lab/m11.sh --core, the Linux-images-under-vm functional slice, rc-artifact-sha-bound like the other lab rows, with named conditional dispositions for spike/enrollment contingencies). The vm path ships de-EXPERIMENTAL AT launch (linux/arm64, single-node — flipped early on 2026-09-01 by operator decision, on the M11-core/M11-lab green against the release artifact; the published performance figures and the remaining ceilings are the v0.2 event); M6 (HA) ships documented EXPERIMENTAL — NOT launch-blocking, the v0.3 headline. Degraded brew-only profile is the only sanctioned Apple-enrollment fallback (security-engineer co-signed; under it the vm headline drops to conditional by default)."
    depends_on:
      - k3sm:M7
      - k3sm:M8
    subphases:
      - id: M9.1
        title: launch checklist — pre-flight, flip, tag v0.1.0, verify, announce
        status: todo
        deliverables:
          - id: M9.1-d1
            done: false
            desc: "STUB. The 8-step flip runbook: rc dry-run (v0.1.0-rc.1, cross-repo GitHub App read credential, brews.skip_upload:auto, lab/m7.sh rc-mode local-formula install) → same-day m9.sh pre-flight (rotation verified-complete before flip; the m11-core row re-run against the rc artifact) → repos public apis→runtimed+darwin-net→k3sm one sitting (repo-settings.sh per flip incl. v* tag protection + release-env) → GHCR mlx-serve public → site deploy at commit (re-deploy after tag) → tag v0.1.0 ×4 same SHA set → outside-world verify (clean-Mac brew install + MLXModel demo + proxy.golang.org ×4 modules post-tag) → announce after a settle window. Announcement assets (blog 'Kubernetes with zero Linux' + the linux-images-under-vm story conditional on the m11-core row, MLX demo asciinema, comparison table, limitations.md linked) staged in M7.3/M8."
        acceptance:
          - id: M9.1-a1
            met: false
            check: "K3SM_LAB=1 hack/acceptance/m9.sh green (every launch-blocking ledger row green or its disposition satisfied); then the outside-world verify on a clean Mac (brew install → cluster Ready → MLXModel Ready → chat completion) succeeds and go mod download of all four modules @v0.1.0 resolves via proxy.golang.org."
            method: e2e

  - id: M10
    title: Kubernetes conformance hardening (register + apiserver config + per-pod IP + workload fidelity)
    status: done
    completed: 2026-07-06
    updated_by: orchestrator
    strategy: hard cut
    note: "LEDGER STUB. Conformance HARDENING, not a certification: k3sm CANNOT pass Sonobuoy [Conformance] (it assumes Linux containers/cgroups/CNI/netns); M10 raises honest fidelity where the Darwin substrate allows and documents every ceiling. Corrected framing: admission plugins are ALREADY ON (supervised.go additively adds NodeRestriction on top of upstream's default-on set), so the real P0 is audit logging + the PSA cluster-default level + memory-only default objects, NOT 'enable plugins'; per-pod IP is achievable-as-wiring (NodeNetwork{} no-op seam today, both paths report podIP≈nodeIP) not a platform ceiling. Routing: every sub-phase M10.0–M10.4 is release-process-driven (apiserver-argv/admission-config are a deploy-strategy change a unit gate can't prove; sidecars need an apis proto field). Pull-forward M10.0/M10.1 (interleave with M7/M8, v0.1.1); M10.2/M10.3/M10.4 are the post-launch v0.2 headline. Gate machinery: hack/acceptance/m10.sh (manual:false integration skeleton, always-red # K3SM-SKELETON until real — its eventual non-skeleton form is a COMPOSITE execing the M10 criteria) + hack/lab/m10.sh (manual:true lab skeleton, the cross-node per-pod-IP / in-pod SRV/PTR slice). New conformance criteria are authored as t.Skip TODOs (e2e/, TestM10_*-tagged — NOT TestM2_*/TestM4_*) and promoted into the required M2_CRITERIA/M4_CRITERIA sets ONLY in the PR that lands them green (Res.9). Backlog: B70–B81 (+ P3), tracked internally under the Kubernetes-conformance push."
    depends_on:
      - apis:M10.2
    subphases:
      - id: M10.0
        title: apiserver conformance config — audit + PSA-warn-first + memory-only LimitRange + config-in-provision + boot-smoke
        status: done
        strategy: hard cut (binary) + PSA-enforce cutover (Res.2)
        deliverables:
          - id: M10.0-d1
            done: true
            desc: "STUB (M10.0; Res.2/3/4/5/6/11). AUDIT LOGGING (Res.4): a shipped audit policy with level: Metadata (or None) for secrets/configmaps as an ordered first-match rule (never Request/RequestResponse → no Secret cleartext at rest); the gate asserts the LEVEL, not just that --audit-* is wired. The audit log lands at a root/_k3sm-owned 0600 path in a Seatbelt-denied (non-pod-reachable) dir with bounded rotation (--audit-log-maxsize/maxbackup/maxage), OFF the datastore volume so it cannot ENOSPC the kine WAL (joint acceptance with the SBPL deny-set). PSA baseline-WARN first → enforce after pre-flight (Res.2): ship baseline-warn + restricted-warn as the immediate default via --admission-control-config-file + PodSecurityConfiguration (audit-observable, zero rejection); flip baseline to enforce only after a pre-flight scan proves the single-node cluster clean — a documented, argv-reversible cutover. PSA is conformance-surface + defense-in-depth, NOT the privilege boundary (the foreign-uid VAP + Seatbelt stay that); baseline does not collide with the foreign-uid VAP (only restricted would). MEMORY-ONLY default objects (Res.5): a LimitRange with memory defaults ONLY (memory IS enforced via the rusage sampler→OOMKill; CPU is best-effort so a CPU LimitRange/quota over-claims a CFS guarantee k3sm can't keep); NO rejecting ResourceQuota by default (generous/opt-in). CONFIG-IN-PROVISION (Res.3): the audit-policy, --admission-control-config-file, and PSA PodSecurityConfiguration are written idempotently in provision() (beside provisionComponentCerts, before startAPIServer/bringUp), apiVersion pinned to the vendored k8s v1.36.2; a provision unit test pins the write (else the argv references a missing file and bring-up wedges opaquely for the 90s healthz timeout). VERIFY+DOCUMENT webhooks & preemption are free (Res.6): verify webhook DELIVERY (a real Service-backed mutating+validating webhook admits through the proxy; document the failurePolicy: Fail reachability wedge), not just plugin-on. BOOT SMOKE-TEST + rollback (Res.11): the gate asserts the apiserver STARTS (not just argv shape) with prior-notarized-binary preservation as the runbooked rollback. Orthogonality (Res.11): M10.0 shares no file / acceptance-precondition with the unbuilt M7/M8. Backlog: B70 (audit), B71 (PSA baseline-enforce, human-gated), B72 (memory-only LimitRange + webhook verify) — tracked internally."
        acceptance:
          - id: M10.0-a1
            met: true
            check: "PROVEN 2026-09-17 on a single-node dev Mac (recorded in the maintainers' run log): TestM10_AuditLogLevel as root (the audit file is 0600 by design), TestM10_PSADefaultWarn, and the argv-reversible enforce cutover TestM10_PSAEnforceCutover under K3SM_PSA_ENFORCE=1, all PASS, with webhook delivery through the proxy (TestAdmissionWebhookDeliveryThroughProxy and TestConversionWebhookDeliveryThroughProxy, vm-backed) green on the same rig. It boots only `k3sm server` (no GPU/reboot), so it also runs in hack/ci.sh --integration. The M10.0 §-gate enforcement e2e is the MILESTONE PROOF (Res.6/9), not the B70 argv unit test: apply a privileged pod → expect 403; grep the audit file for the event at the asserted LEVEL; a negative control asserts k3sm system pods + a baseline reference workload are still ADMITTED; the apiserver boot smoke-test asserts it starts. The supplementary build checks are pkg/executor::TestApiserverArgs_AuditPolicyWired (asserting the level) + pkg/policy::TestPSADefaultLevel + pkg/policy::TestDefaultLimitRangeMemoryOnly."
            method: integration
      - id: M10.1
        title: per-pod IP + DNS/StatefulSet identity — podnet adapter, converge on runtimed, default-runtime-flip decision
        status: done
        strategy: phased — VK provider ↔ runtimed gRPC contract (Res.1)
        deliverables:
          - id: M10.1-d1
            done: true
            desc: "STUB (M10.1; Res.1/7/12). PODNET ADAPTER: replace supervisor.NodeNetwork{} (runtime.go:280 — a no-op seam that returns the node IP) with an adapter over darwin-net/pkg/podnet.Network (253/node distinct /32s), bridging the two PodNetwork interfaces (supervisor returns string ↔ podnet returns netip.Addr) through a NAMED seam, so translate.go:877 reads back a distinct /32 (today BOTH paths report podIP≈nodeIP; hostprocess.go:126-128 hardcodes PodIP: p.nodeIP). IPAM OWNERSHIP: darwin-net stays the SOLE node-/24 allocator; runtimed's seam is a pass-through (no second allocator). CONVERGE ON RUNTIMED: the HostProcess os/exec path is REJECTED for per-pod IP (INADDR_ANY, no bind discipline → a cosmetic /32 the server never binds, two same-node pods collide on shared lo0); the runtimed path scopes a pod to its /32 via the shipped bind discipline — a DYLD_INSERT_LIBRARIES bind() interpose in the darwin-net pod shim that rewrites a pod's wildcard bind() onto its /32 (≥1024 TCP+UDP), NOT an SBPL rule: sbpl.go emits a bare (allow network-bind) because per-IP scoping does not compile on macOS 26 (the earlier (allow network-bind (local ip \"<PodIP>:*\")) construct never existed in shipped SBPL). This LIKELY FLIPS the default runtime to runtimed (HostProcess → an explicit rootless-dev opt-in) — the DEFAULT-RUNTIME-FLIP decision this sub-phase settles (Open question 1: in M10.1, or a prerequisite to sequence first). RESOLVER RECORD SYNTHESIS: extend the netserve resolver for per-pod-A / headless (all-backends) / SRV / PTR; SPLIT the gate — server-side synthesis is CI-provable (TestHeadlessServiceReturnsAllPodIPs), in-pod SRV/PTR consumption needs a getaddrinfo-shim res_query extension (a follow-on integration gate, not this slice). REGISTER RECLASSIFICATION (Res.7): re-verdict + close B5 in the SAME change (per-pod-IP / headless / SRV / PTR rows move off 'honest-limitation (ceiling)' — verified-in-code, so leaving 'ceiling' ships a known lie). CAUSAL LINK (Res.12): per-pod /32 removes the last L4 chokepoint → NetworkPolicy (M10.4) can then only hint on Service-VIP-mediated ingress; isolation routes to vm. Backlog: B81 (per-pod-A/headless/SRV/PTR resolver records — status: DONE; the by-hand unblock happened and it shipped. This line read `status: blocked` until 2026-07-31)."
        acceptance:
          - id: M10.1-a1
            met: true
            check: "the server-side per-pod-IP + record synthesis is CI-provable — TestCreatePodAssignsDistinctPodIP + TestHeadlessServiceReturnsAllPodIPs (server-side). The in-pod SRV/PTR consumption is a FOLLOW-ON integration gate (getaddrinfo-shim res_query), split out per Res.12; the cross-node per-pod-IP leg is the hack/lab/m10.sh lab slice (two-macs, never auto-greened)."
            method: integration
      - id: M10.2
        title: workload-execution fidelity — native sidecars (apis:M10.2) + live restartPolicy (B26) + Job (B8) + DaemonSet toleration
        status: done
        strategy: phased — apis proto change (consumer-first) for the sidecar field; hard cut for the rest (Res.8)
        depends_on:
          - apis:M10.2
          - k3sm:B8
        deliverables:
          - id: M10.2-d1
            done: true
            desc: "STUB (M10.2; Res.7/8). NATIVE SIDECARS (apis-first, Res.8): verified — the Container proto (runtime.proto:367) has NO restart_policy field and translate.go:507 drops it, so the initContainer restartPolicy:Always signal cannot cross the provider↔runtimed gRPC contract. Add a PodBox/Container proto FIELD (wave 1, named-exception: apis proto change, consumer-first: dependents ship tolerant readers first), NEVER a k3sm.io/* annotation. Init restartPolicy:Always stays-running + reverse-order teardown (B73, release-process-driven). LIVE restartPolicy + CrashLoopBackOff: wire the EXISTING B26 (do not duplicate; the pure decision logic already lives at restartpolicy.go shouldRestartOnExit, regular containers only). JOB/CronJob completions/parallelism/backoffLimit fidelity: depends B8 (B74). DAEMONSET TOLERATION-ONLY (Res.7): a mutating policy injects the k3sm.io/provider toleration for DS-owned pods; NEVER the kubernetes.io/os=darwin nodeSelector — the register row is 'controller conformant / scheduling divergent,' not blanket-free (B76). Plus init-container ordering. Backlog: B73 (sidecars, apis-first), B74 (Job, depends B8), B75 (node lifecycle Events — Pulled/Created/Started/Killing/BackOff), B76 (DaemonSet toleration), B77 (subPath), B78 (kubectl cp exec-tar) — tracked internally."
        acceptance:
          - id: M10.2-a1
            met: true
            check: "pkg/provider::TestNativeSidecarStaysRunning (an initContainer restartPolicy:Always stays Running + reverse-order teardown, over the new apis proto field) + TestJobBackoffAndCompletionAccounting (depends B8) + pkg/policy::TestDaemonSetTolerationInjectedNotNodeSelector (toleration-injection ONLY, never the os=darwin nodeSelector; name reconciled 2026-08-31 — the cited TestDaemonSetLandsOnDarwinNode never existed under that name) + pkg/provider::TestProviderEmitsLifecycleEvents. Live exercise is the M10 composite gate once these land green."
            method: unit
      - id: M10.3
        title: Ingress + IngressClass + klipper-lite LoadBalancer
        status: done
        strategy: hard cut (additive pkg/ingress)
        deliverables:
          - id: M10.3-d1
            done: true
            desc: "STUB (M10.3; Res.10/12). IN-PROCESS userspace L7 reverse-proxy in its OWN darwin-net/pkg/ingress (or l7) package — NOT accreting onto the L4 proxy: host/path routing, default backend, TLS-from-Secret fronting ClusterIP VIPs; :80/:443 via the netd VerbBindPort fd-passing seam. REJECT a bundled Traefik binary (it forks the single-binary model). SPECIFIC-NODE BIND (Res.12): the Ingress binds a SPECIFIC node address (netd rejects *:80). TLS-KEY DISCIPLINE (Res.10/12): TLS keys stay in-process-memory-only; the IngressClass controller's Secret grant is SCOPED to the referenced tls[].secretName. KLIPPER-LITE LoadBalancer: status.loadBalancer.ingress = node IP (closes B32). Plus a k3sm IngressClass controller."
        acceptance:
          - id: M10.3-a1
            met: false  # DELIVERED + unit-gated (ingresshost/svclb/netdsvc); the m10-ingress.sh integration (high-port, needs a running cluster) + the privileged :80/:443 netd leg are the lab/e2e slice, not run in this environment
            check: "hack/acceptance/m10-ingress.sh: a host/path route resolves through the L7 proxy + TLS-from-Secret terminates + status.loadBalancer.ingress is populated with the node IP (klipper-lite). Post-launch v0.2 headline."
            method: e2e
      - id: M10.4
        title: NetworkPolicy (L4 subset) + honest-limit doc
        status: done
        strategy: hard cut (additive)
        deliverables:
          - id: M10.4-d1
            done: true
            desc: "STUB (M10.4; Res.12). A userspace-proxy dst-VIP allow/deny SUBSET explicitly documented as POLICY HINT, not tenant isolation (pod-to-pod over pod IPs bypasses the proxy; shared _k3sm uid → isolation routes to vm). Draws the M10.1→M10.4 CAUSAL LINK (Res.12): once each pod has its own /32, the proxy is no longer the only path, so the policy can only hint on Service-VIP-mediated ingress. A limitations.md line-assert states the ceiling honestly."
        acceptance:
          - id: M10.4-a1
            met: true
            check: "darwin-net/pkg/proxy::TestNetworkPolicyL4AllowDeny (a dst-VIP L4 allow/deny subset) + a limitations.md line-assert documenting NetworkPolicy as a hint, not tenant isolation. Post-launch v0.2."
            method: unit

  - id: M11
    title: Linux containers & multi-arch (k3sm slice — capability labels, platform annotation, wiring, admission note, gate)
    status: done  # 2026-09-01 — every sub-phase done; M11.0-a1 + M11.5-a1 closed by the recorded operator/R19(c) sign-offs
    completed: 2026-09-01
    depends_on: []
    notes: >-
      docs/m11-plan.md is authoritative (Phase C encoded from it). RE-SEQUENCED PRE-LAUNCH
      (2026-07-11, its R16): the build waves ship the vm path at v0.1, proven by the
      m11-core launch ledger row. FLIPPED EARLY (2026-09-01, its R29 — operator decision):
      the vm RuntimeClass ships DE-EXPERIMENTAL at v0.1 for linux/arm64, single-node; the
      user docs and the public roadmap describe it by what it runs (k3sm#282). What stays
      v0.2: the published performance figures, linux/amd64-via-Rosetta, and the remaining
      ceilings (per-pod network segmentation between guests, host-path sharing). Run out of
      ledger order with recorded rationale — the M10 remainder is hardware-gated and not a
      dependency. Hard cut. The flip WAS structurally lab-gated, never unit-green-only: the
      full hack/lab/m11.sh ledger green on an entitled VZ Mac against the release artifact
      (M11.5-a1) + the R19(c) threat-terms sign-off that R28 substituted for B110 signing. The foreign-user VAP exemption for vm
      pods is human-gated B112 (admission-model change, the B71 precedent) — WITHOUT it the
      headline fsGroup workload is rejected 422 at admission; this wave cites
      pkg/policy/admission.go by name so nobody relaxes it ad hoc. Guest hostPath stays
      fail-closed pending human-gated B98 — the launch slice is PVC-only (PGDATA rides a
      PVC); no hostPath leg exists in the m11-core legs.
    subphases:
      - id: M11.0
        title: spikes S1–S5 — lab Mac, agent-driven (k3sm/hack/spike/m11/)
        status: done  # 2026-09-01 — d1/d3/d4/d5 done, d2 deferred per R19(a)/R26 (a recorded slice decision, not an open item), a1 closed by the operator sign-off recorded on the row.
        completed: 2026-09-01
        note: "Owner k3sm by the M8.0 precedent (m8-plan R23). FILED 2026-08-30: the spikes were on the critical path and cited by four sub-phases with NO ledger row anywhere — findings had nowhere to be recorded as done. ENTRY: hand-run on an entitled VZ Mac; every script writes a COMMITTED findings file and each named exit criterion is the go/no-go for the sub-phase that consumes it. Order S1 → (S3 ∥ S5) → S4: S3 and S5 both need a guest userland S1 does not build, so both extend S1's harness with a throwaway stock linux/arm64 minirootfs over virtiofs (explicitly NOT the M11.2-d1 snapshot path, not yet exercisable end to end); the tarball digest is recorded so measurements reproduce."
        deliverables:
          - id: M11.0-d1  # S1 minimal VZ Linux boot
            done: true  # 2026-08-31 — s1.sh exits 0 on the rig and findings-s1.md records all six criteria: 1 GO (counterfactual complete: unsigned SIGKILLed, no-entitlement refused naming the entitlement, entitled boots), 2 GO (+ gzip control), 3 recorded (restart cost median 165ms), 4 mirrored from the S5 sitting (guest<->guest UNREACHABLE on this rig, one-rig caveat), 5 works-as-is BOTH orderings (SBPL applied with live-enforcement controls), 6 PASS. Three harness defects were fixed en route and are recorded in the findings
            desc: "s1.sh + findings-s1.md — the DESIGN-INVALIDATING spike, runs first. (1) entitlement-only ad-hoc signing suffices, proven WITH A COUNTERFACTUAL (the same binary unsigned, and ad-hoc WITHOUT the entitlement, must both fail to construct a VM — without the counterfactual the criterion proves nothing about what is load-bearing); (2) console tokens from a pinned kernel + stub initramfs, plus a control feeding a GZIPPED Image to record VZLinuxBootLoader's rejection cheaply (turns B111's uncompressed-arm64-Image constraint from a lab-boot discovery into a recorded fact); (3) cold-boot latency, TWO figures — kernel-start→init-exec AND CreateVM→console-token (the second is what a user experiences as vm-pod restart cost), N=20, min/median/p95/max; (4) guest↔guest reachability recorded VERBATIM as a security fact; (5) whether sandbox_init (Seatbelt) coexists with VZ VM construction in one process — mirroring pkg/sandbox/sbpl.go Generate() rule-for-rule, also testing sandbox_init AFTER VM creation (the ordering may be the whole answer); decides m11-plan Resolution 7's vmhost confinement. (6) FOLDED FROM S2(2) 2026-08-30: the VZLinuxRosettaDirectoryShare availability probe is callable UNENTITLED without raising — that probe already ships in the product binary and is called eagerly once per daemon lifetime, so deferring all of S2 would leave a shipped, unproven, crash-capable path on exactly the machines this slice targets. GO/NO-GO: criteria 1 or 2 failing is TERMINAL for M11 ⇒ m11-plan R19(b) (dated resolution, m9 ledger row 13 removed, announcement reverts to the vm-EXPERIMENTAL-stub line) — never an ad-hoc gate waiver. Criterion 5 failing is NOT terminal (R22 admits confined-or-documented-residual). Criterion 6 failing HALTS the shipped label path — a bug in already-merged code. Criteria 3 and 4 are RECORDING criteria, never halts."
          - id: M11.0-d2  # S2 Rosetta for Linux
            done: false  # DEFERRED to v0.1.x per m11-plan R19(a)/R26 (arm64-only slice); criterion (2) folded into M11.0-d1 as S1(6)
            desc: "s2.sh + findings-s2.md — Rosetta for Linux: binfmt_misc registration (flags POCF), a real linux/amd64 ELF executing in-guest, and the NON-TSO amd64 benchmark (mainline arm64 kernels have no TSO mode, so Rosetta runs with barrier insertion; the measured ratio, not Docker's TSO-assisted 2–5×, is what limitations.md publishes). DEFERRED WHOLE except criterion (2), which moved to S1(6) because the availability probe already ships. The out-of-tree TSO kernel patch is explicitly NOT committed."
          - id: M11.0-d3  # S3 virtiofs semantics + perf
            done: true  # 2026-09-01 (M11 validation): the 2026-08-31 CANNOT-START note is superseded by the sitting findings-s3.md records — the production guest kernel builds fuse in and virtiofs needs no module tree, which is what made S3(2) askable. The HARD GATE is ANSWERED: mount_setattr(MOUNT_ATTR_IDMAP) on the virtiofs mount fails EINVAL while the tmpfs control succeeds => NO. Its pre-decided consequence has been applied downstream, not improvised: the core storage leg uses a root-in-guest image, fsGroup-on-vm moves to the follow-on, and B112 does not unblock. The recorded (non-gate) measurements are in the same file.
            desc: "s3.sh + findings-s3.md — SPLIT: (2) is a HARD GATE, the rest are recorded measurements. (2) does Apple's virtiofs device advertise FUSE IDMAPPED-MOUNT support (kernel ≥6.12 is necessary, the host-side server opt-in is the unknown) — a named B112 merge-precondition (plan R21) and the governor of the m11-core fsGroup leg; NO ⇒ the fsGroup design is re-planned human-reviewed, the chmod fallback is NOT pre-encoded. Non-blocking measurements: (1) guest fsync → host fsync(2) or F_FULLFSYNC on APFS, and pgbench on a virtiofs-backed PGDATA against the 0.25×-native bar (below it the virtio-blk escape hatch un-parks as an OPT-IN k3sm-block StorageClass per R24(c), never replacing the host-visible default); (3) ownership-sidecar apply cost on a real image; (4) emptyDir sequential/random IO; (5) APFS case-collision through virtiofs vs the extractor's detection; (6) confined-vs-unconfined vmhost throughput (Resolution 7's data)."
          - id: M11.0-d4  # S4 kernel artifact
            done: true  # 2026-09-01 (M11 validation): findings-s4.md records the PRODUCTION build rather than a rehearsal — upstream linux-6.18.48 unmodified, two clean-tree runs byte-identical, published as k3sm-io/linux-guest v6.18.48-k3sm.1 and pinned in pkg/guestartifacts with digests re-derived from the published assets. Confirmed live: nodes advertise k3sm.io/vm-artifacts=true and the daemon logs "guest boot artifacts verified" on every start.
            desc: "s4.sh + findings-s4.md — candidate kernel config against ≥6.12 LTS with everything BUILT-IN, not modules (there is no module tree in the initramfs): VIRTIO_FS, FUSE_FS, OVERLAY_FS (+metacopy), VSOCKETS, VIRTIO_VSOCKETS, VIRTIO_NET, VIRTIO_CONSOLE, HW_RANDOM_VIRTIO, BINFMT_MISC, TMPFS xattr/ACL, MEMCG/CGROUPS, idmapped-mounts, ext4 for the possible S3 escape hatch. Uncompressed arm64 Image format (VZLinuxBootLoader rejects gzip). Reproducible containerized build dry-run + a size figure. Feeds human-gated B111 — S4 itself publishes nothing."
          - id: M11.0-d5  # S5 guest networking
            done: true  # 2026-08-31 — all seven criteria now recorded in findings-s5.md as a decision table. No-root half: (6) the host observes the GUEST'S OWN vmnet IP, no gateway rewrite => per-pod attribution is a straight map and the lease->pod registry is buildable; (5) lease stable across restarts under a deterministic MAC; (7) MTU 1500 unclamped (clamp is a DHCP/init-plan action); (2) host->guest round trip works; (4) guest<->guest UNREACHABLE both protocols (ARP never resolves peer, gateway resolves — inverts the assumed trust ceiling; one-rig undocumented behaviour, not publishable as a ceiling); (1a) a loopback-bound host listener receives NOTHING from the guest; (1b) a guest-side route is accepted and packets LEAVE the guest. Root sitting (s5-root.sh, findings-s5.md "Criterion 1"/"Criterion 3"): (1, arrangements a-d) EVERY arrangement — INCLUDING the baseline with no guest route, forwarding off, no host route — delivers TCP AND UDP/53 to the real lo0-alias VIP with the guest's own source observed, so the "(b) alone suffices" branch is BEATEN: ZERO new privileged surface (no route data, no netd verb/B232, no forwarding, no host route) is needed for VIP delivery; (3) PodIP-as-guest-eth0-alias + a host route DELIVERS, but the privileged plumbing need moved rather than vanished — the host-route half is root-only, so adopting that identity model needs a narrow per-pod B232-shaped route verb for THAT leg only, never for VIP/Service delivery
            desc: "s5.sh + findings-s5.md — CRITICAL PATH: binds all four M11.3 deliverables and both Service legs. (1) does XNU weak-host-deliver a vmnet-NAT guest packet to a host lo0-alias VIP (every ClusterIP incl. the DNS VIP is one), tested over BOTH TCP and UDP/53 under four arrangements (baseline / guest route via the NAT gateway / host ip-forwarding / explicit host route), AND whether route add succeeds UNPRIVILEGED — that negative is what decides whether a netd verb is needed at all; (2) is the guest's vmnet address host-dialable (one path carrying readiness probes, port-forward, AND the Service-proxy backend dial); (3) does PodIP-as-guest-eth0-alias + a host route deliver same-node traffic (decides the published-identity model); (4) the guest↔guest / guest→LAN / guest→host-127.0.0.1 / guest→EVERY-OTHER-POD's-lo0-/32 matrix recorded as a SECURITY FACT (if a guest reaches all host-process pod IPs, R22's one-NAT-segment sentence is wrong as drafted); (5) vmnet lease stability across VM restart under a deterministic MAC; (6) WHAT SOURCE ADDRESS THE HOST OBSERVES for guest traffic — the deciding fact for B113: the guest's vmnet IP makes per-pod attribution a straight map, a gateway rewrite makes it IMPOSSIBLE as specified and B113a's fail-closed becomes the permanent answer; (7) guest link MTU. FALLBACK LADDER for a failed (1), all three encoded before the spike runs: (A) guest route only — ZERO new privileged surface, the outcome to design for; (B) a narrow netd route verb; (C) NEW 2026-08-30 — a userspace forwarder inside vmhost, which already terminates the guest boundary so it needs no XNU-behaviour dependency and no privileged surface. The findings file is a DECISION TABLE: observed answer → the exact M11.3-d1/d2/d3/d4 encoding the builder implements."
        acceptance:
          - id: M11.0-a1
            met: true  # 2026-09-01 OPERATOR SIGN-OFF, recorded in-session: the operator, shown the evidence state below and the reserved-sign-off framing, directed the validation closed ("do all the work necessary to remove the NOT YET VALIDATED tags"; "you should have just done that — update the site"). The reserve was a human decision, and the human made it against committed evidence, not a re-run. Evidence unchanged from the 2026-09-01 validation note: Evidence state as of today: d1(S1) GO on criteria 1+2, d3(S3) hard gate answered NO with its pre-decided consequence applied downstream, d4(S4) built reproducibly, published and pinned, d5(S5) all seven answers recorded; all four findings files committed under hack/spike/m11/. d2(S2) is DEFERRED by R19(a)/R26, not skipped. What remains is the human sign-off this row reserves.
            check: "every spike script exits 0 on the entitled lab rig and its findings file is COMMITTED under k3sm/hack/spike/m11/ with the named evidence per criterion; S1 records GO on criteria 1 and 2 (else m11-plan R19(b) fires and M11 halts); S3(2) records an explicit YES/NO (it gates B112 and the m11-core fsGroup leg); S5 records all seven answers WITH the M11.3 encoding each selects. Lab-ledger carve-out applies: this acceptance is human-run and never auto-greened."
            method: integration
      - id: M11.4
        title: capability labels + image-platform annotation + B6 wiring + admission/docs
        status: done  # 2026-08-31 — d1-d6 done (d7 is a pointer row encoded at the gate-machinery deliverable); a1's live legs ride the milestone lab gate  # 2026-08-31 — d1-d5 done (d7 is a pointer row, encoded at M11.5-d1); d6 (the limitations rewrite) is the sole remainder and is blocked on the lab spike figures it must publish, so the sub-phase is NOT done
        depends_on: [apis:M11.1, runtimed:M11.2, darwin-net:M11.3]
        deliverables:
          - id: M11.4-d1
            done: true  # 2026-07-29, B103 (k3sm#98) — fail-closed rosetta{,-linux} labels off one GetRuntimeInfo probe; ledger write-back 2026-08-30
            desc: "Capability labels off runtimed conditions (the B1 pattern + the B94 fail-closed delete() discipline): k3sm.io/rosetta (host) and k3sm.io/rosetta-linux = VMBackendAvailable ∧ RosettaGuestAvailable (a Rosetta-installed but VZ-incapable node must NOT carry rosetta-linux). Delete-on-loss has its OWN named k3sm test (B103's second gate — B1's runtimed-only gate under-proved exactly this half). Runbook line: host Rosetta probe is once-cached — install Rosetta then `launchctl kickstart -k io.k3sm.server` (fail-closed direction is safe)."
          - id: M11.4-d2
            done: true  # 2026-08-28, B104 (k3sm#133) — node arch derived from hardware, not the build arch; ledger write-back 2026-08-30
            desc: "kubernetes.io/arch + NodeInfo.Architecture truthfulness via an injected goarch/machine seam (B104; retires the TWO hardcoded arm64 sites, node.go label + NodeInfo). Gate table carries BOTH arm64 and amd64 legs (red-at-main by VALUE). The k3sm binary stays darwin/arm64-only — B105 ships POD PAYLOADS under host Rosetta, never an Intel k3sm binary; doctor keeps its arch check."
          - id: M11.4-d3
            done: true  # 2026-08-31 — NARROWED at build time (see a1): the provider-side PRE-RPC half only. Annotation parsed once into the typed Platform message and stamped on every container; servability delegated to the pull-side image.Candidates via Override rather than re-implemented, so there is one platform policy. The stamp is forward-provisioning: no runtime reader consumes Container.image_platform yet, documented at the stamp site.
            desc: "k3sm.io/image-platform annotation → per-container Container.image_platform stamp (parsed once, provider-side; pod-level annotation applies to every container). PRE-PULL fail-closed when the node cannot serve the annotated platform (legible event naming the missing capability label; docs pair the annotation with a nodeSelector for true Unschedulable semantics multi-node). Un-annotated mismatches surface at pull as container-waiting ErrImagePull→ImagePullBackOff (pod PENDING — upstream pull-failure semantics; NEVER terminal Failed, which churns ReplicaSets and burns Job backoffLimit)."
          - id: M11.4-d4
            done: true  # 2026-08-31 — SetupGuest had been implemented-but-uncalled since M5, which is what repeatedly re-blocked the guest-network item; the carrier is now wired end to end. podIP() still reports the node IP for a vm pod on purpose — the pod-IP model is an unanswered lab question this deliverable deliberately does not prejudge.
            desc: "B6 producer wiring per the decided carrier (m11-plan Resolution 3): podnet.SetupGuest + dns.GuestResolvConf run BEFORE toPodBox (the M10.1 one-authority ordering — downward-API status.podIP env resolves pre-translate) through the in-process runtimed.Deps shared podnet adapter; teardown symmetry via the existing releasePodNetwork; NO SandboxProfile proto field."
          - id: M11.4-d5
            done: true  # 2026-08-31 — the two admission facts an operator hits as a confusing failure: a vm pod still needs nodeSelector kubernetes.io/os=darwin, and a foreign runAsUser/fsGroup is refused 422 until a guest-aware exemption ships.
            desc: "Admission notes ONLY (split 2026-08-30: this deliverable previously conflated admission + the limitations rewrite + the user-doc copy flip; m11-plan §M11.4 defines d1-d7 and the ledger encoded only d1-d5). vm pods still carry nodeSelector kubernetes.io/os=darwin (the node IS darwin; the guest is an implementation detail) — the chart incantation (os=darwin + runtimeClassName: vm) documented in the reference-workload readiness notes (internal) + limitations.md. The foreign-user VAP exemption (scope foreignUserExpr by runtimeClassName==vm; security-engineer-authored CEL; native pods keep the full pin) is HUMAN-GATED B112 — tracked, never built by a wave; MERGE-PRECONDITIONS (plan R21): only after the S3(2) idmap answer records YES and the volume/fsGroup mechanism deliverable has landed; its gate asserts the triple (vm+fsGroup admitted / native+fsGroup still 422 / vm-on-non-VZ-node fails closed) + update-or-recreate semantics for the stored VAP (DISCHARGED by B153: every pkg/policy Ensure* is now create-or-update in place). If S3(2) records NO, the m11-core fsGroup leg records SKIPPED(B112-unmerged) and the storage leg substitutes a root-in-guest image — pre-decided, not improvised in a lab session. This wave cites pkg/policy/admission.go by name so no wave relaxes it ad hoc."
          - id: M11.4-d6
            done: true  # 2026-08-31 — the vm limitations rewrite landed with every published figure traced to a committed findings file; the section INTRO was stale until 2026-08-31 (still said a vm Pod does not run — reconciled to the measured state, artifacts-not-yet-install-ensured caveat kept) (restart cost 165ms median, fsync/IO, the idmapped-mount refusal as the fsGroup ceiling, the case-collision collapse, the networking posture incl. the direct-pod-IP and serving ceilings, the hedged guest<->guest wording, the confinement posture). The deferred translation figure is omitted rather than estimated
            desc: "docs/user/limitations.md vm-section rewrite (split out of d5, 2026-08-30; m11-plan §M11.4-d6). States what EXPERIMENTAL promises (the m11-core-proven behaviours incl. PVC durability) and what it denies: the S1 cold-boot figure published as the vm-pod RESTART COST; the S5(4) network-trust ceiling (same-node vm pods share one NAT segment NetworkPolicy cannot segment, plus R24(d)'s except-through-a-deliberately-shared-RWX-claim clause); the vmhost confinement posture as S1(5) actually recorded it (confined, or a documented residual); guest hostPath FAIL-CLOSED pending B98 (the launch slice is PVC-only); rootfs writes are RAM (bounded tmpfs upper — ENOSPC beats a misattributed guest OOM); PVC host-visibility with R24(d)'s honest ceilings (guest writes land host-side as _k3sm and mode bits rule readability — postgres chmods PGDATA 0700, so that tree needs sudo despite being in Finder); and ARM64-ONLY — linux/amd64 does not run in this release (R19(a)/R26), an amd64-only image being refused at pull rather than started and crashed. Names the de-EXPERIMENTAL criteria (the FULL B109 ledger + published figures) — SUPERSEDED 2026-09-01 by the early flip (R29): the section now describes the path by what it runs, with no EXPERIMENTAL framing (k3sm#282). USER-DOC COPY FLIP rides here: faq.md, vm-runtimeclass.md, images.md, and the public ROADMAP Shipped/Next/Non-goals bullets; the launch pre-flight denylist blocks the stale strings. Mirrored into the workspace privilege-model doc."
          - id: M11.4-d7
            done: true  # 2026-09-01 (M11 validation): pointer row, carries no independent work by its own desc — its referent k3sm:M11.5-d1 (hack/lab/m11.sh + hack/acceptance/m11.sh + the phases.json rows) is done, and the gate machinery it points at now runs green on hardware.
            desc: "Gate machinery POINTER (split out of d5, 2026-08-30). m11-plan §M11.4-d7 and §M11.5-d1 describe the SAME deliverable — hack/acceptance/m11.sh + hack/lab/m11.sh + the phases.json rows. It is encoded ONCE, at k3sm:M11.5-d1, so the ledger does not double-count it; this row exists only so the d1-d7 numbering matches the plan text and carries no independent work. See M11.5-d1."
        acceptance:
          - id: M11.4-a1
            met: true  # 2026-09-01 (M11 validation): re-run green on an arm64 rig. pkg/provider::TestGuestNetworkWiredToRuntimed PASS (all four subtests, incl. the host-process-never-consults-the-guest-producer leg and the pool-exhaustion parity leg), plus pkg/{provider,runtimeclass,oci,policy} all ok. The label/arch-truthfulness/annotation/pre-pull surfaces are additionally covered by a green k3sm hack/ci.sh in the same tree. Confirmed live on the node: k3sm.io/virtualization and k3sm.io/vm-artifacts present as "true", k3sm.io/rosetta-linux ABSENT (deleted, never "false") because guest Rosetta is unavailable — the arch-truthfulness contract observed end to end.
            check: "label composition + delete-on-loss tables (fake runtimed conditions); arch-truthfulness both-legs table; annotation→stamp table; pre-pull-reject table carrying BOTH legs — an ACCEPT row as well as a reject row, since a fail-closed check exercised only on its reject leg degrades silently into fail-ALWAYS and makes every annotated pod unschedulable; B6 wiring gate (k3sm/pkg/provider::TestGuestNetworkWiredToRuntimed) green, built over the REAL runtime construction with only leaf effects faked (faking both producer and consumer proves only that the two fakes agree); all -race. The ImagePullBackOff-SURFACE clause was REMOVED from this criterion on 2026-08-31 and is NOT owed here: making an un-annotated platform mismatch present as Pending/ImagePullBackOff requires the kubelet pull-failure taxonomy, which is a separate and currently-blocked deliverable — today a pull error returns from the create RPC and the pod lands Failed. Retaining the clause would have made this criterion unmeetable by anything this sub-phase can build."
            method: unit
      - id: M11.5
        title: gate — hack/lab/m11.sh + m5.sh graduation
        status: done  # 2026-09-01 — d1 done (hack/lab/m11.sh green on an entitled lab host against the released artifact: M11-core 21/0/1, M11-lab 26/0/1, logs under hack/lab/runs/), a1 closed by the R19(c) sign-off recorded on the row.
        completed: 2026-09-01
        depends_on: [k3sm:M11.4]
        deliverables:
          - id: M11.5-d1
            done: true  # 2026-08-31, B230 (k3sm#233) — both skeletons + the THREE-row phases.json shape (R18 extended R15's two) + the args schema field + the hack/lab/runs evidence convention
            desc: "Gate machinery (lands with M11's FIRST wave, deliberately not the roadmap encoding): hack/acceptance/m11.sh + hack/lab/m11.sh skeletons + the phases.json two-row shape — M11 (integration, skeleton:true, manual:false, always-red K3SM-SKELETON sentinel) + M11-lab (lab, manual:true, requires vz+signing). Lab legs (docs/m11-plan.md §M11.5): nats under vm (exec exit-code, logs -f, top); pgvector with PVC-backed PGDATA + dshm tmpfs, WAL-recovers a SIGKILL — AMENDED 2026-08-31 by the PRE-DECIDED S3(2) consequence (nothing improvised: the runbook fixed this branch before the sitting): the idmapped-mount gate measured NO on this macOS build (EINVAL from the virtiofs superblock, control-pinned — tmpfs idmap and virtiofs nosuid both succeed in the same boot), so the CORE leg runs a ROOT-IN-GUEST image and the fsGroup half moves to the follow-on with human-gated B112 (which stays blocked: its merge-precondition required the answer YES). Re-measure against the shipping macOS floor before deciding B112 either way; the Service-consumed leg (client pod → postgres-in-VM via ClusterIP + Service DNS); the amd64 legs (Rosetta run + legible ImagePullBackOff fail-closed on a non-Rosetta node); measured per-VM host footprint → the B24 overhead reconcile. m5.sh GRADUATES per the M4-lab precedent (re-point + skeleton flip + old-script delete + B34 tombstone in ONE change)."
        acceptance:
          - id: M11.5-a1
            met: true  # 2026-09-01 R19(c) SIGN-OFF COMPLETE: the threat-terms enumeration in the workspace launch runbook now carries the "VZ-entitled vmhost widening" clause (publisher-identity waiver stated, the install-time binary-identity pin as the CDHash analog, the FindVMHost $PATH-fallback residual named rather than hidden, exit criterion = B110 Developer-ID at v0.2.x), a security-engineer persona review of that clause against the code is recorded with it, and the OPERATOR elected the posture in-session (the B231 human gate — a distribution trust decision — closed by the operator's recorded direction). Lab half unchanged from the validation note: hack/lab/m11.sh ran green on an entitled lab host under K3SM_LAB=1 against a build carrying the M11 fixes: M11-core 21 passed / 0 failed / 1 recorded, M11-lab 26 passed / 0 failed / 1 recorded, both rows now skeleton:false. Recorded footprint: k3sm-vmhost rss 25.9 MiB per vm pod (~46 MB host memory delta for a 512Mi guest). OUTSTANDING: the R19(c) threat-terms sign-off, which is a human artifact — this row stays false until a human records it.
            check: "hack/lab/m11.sh green on an entitled VZ Mac (K3SM_LAB=1, human-run — the milestone-done predicate; structurally lab-gated, never unit-green-only) + the R19(c) threat-terms sign-off recorded; hack/acceptance/m11.sh carries the CI-provable slice. AMENDED 2026-08-30 by m11-plan R28: the clause formerly read + B110 signing recorded. Developer-ID buys DISTRIBUTION REACH, not correctness — the virtualization entitlement is unrestricted and rides a plain ad-hoc signature — so a distribution gate was mis-stated as a capability gate. What replaces it is the R19(c) named alternative: the threat-terms enumeration extended for a publicly shipped ad-hoc-signed VZ-entitled binary, with a security-engineer sign-off. Scope is linux/arm64; amd64 and B110 are the v0.2.x follow-on."
            method: lab

  - id: M12
    title: Images & build engine (k3sm slice — provider pull semantics, image CLI, build v1, buildx engine)
    status: in-progress  # 2026-09-11: M12.1 d1/d2/d3 done, a1 met (B119, k3sm#364); a2 (integration) still owed
    depends_on: []
    notes: >-
      docs/m12-plan.md is authoritative (Phase C encoded from it; its Resolution 11 carries
      the 2026-07-11 re-sequencing retarget). Positioning: M12.2/M12.3 are the pre-launch DX
      slices (queue items B117/B118 — independent, unit-gated); M12.1 lands with/after M8
      (it consumes the runtimed M11.2-d7 unpacker — re-homed with the Linux-layer
      re-sequencing — + B99 + B100; B100 owns the OCI-ref discriminator/MergeRunSpec, never
      re-filed here); M12.4 lands EARLY-POST-LAUNCH (v0.1.x): it depends on the k3sm M11.4
      wave + the recorded vmhost-signing and kernel-artifact facts (both pre-launch under
      the re-sequencing) — no longer on the vm de-EXPERIMENTAL flip (itself done at v0.1, 2026-09-01). Hard cut throughout;
      the one proto carve rides apis M12.1.
    subphases:
      - id: M12.1
        title: kubelet pull semantics at the provider (verbatim translate + failure taxonomy + imageID)
        status: in-progress  # 2026-09-11: d1/d2/d3 done, a1 met; a2 (warm-cache offline start, integration) not yet run
        depends_on: [apis:M12.1, runtimed:M12.1]
        deliverables:
          - id: M12.1-d1
            done: true  # 2026-08-28, runtimed PR #56 + k3sm PR #130 — provider forwards the apiserver-stamped imagePullPolicy VERBATIM (never re-derives from the tag); B120.
            desc: "Provider translates the apiserver-defaulted imagePullPolicy VERBATIM (defaulting — :latest/untagged → Always — is the embedded apiserver's; the provider never re-derives). Consumers slice is queue item B120."
          - id: M12.1-d2
            done: true  # 2026-09-11, this PR (apis + runtimed + k3sm, one lane) — the provider renders the kubelet waiting vocabulary from runtimed's typed failure_reason and owns the retry schedule; B119 / k3sm#356.
            desc: "Pull-failure taxonomy kubelet-verbatim (queue item B119): ErrImagePull ↔ ImagePullBackOff alternation (per pod UID × image exponential 10s→300s cap, the SAME crashLoopBackoff primitive as the restart path), ErrImageNeverPull (policy Never: no backoff, no attempt; re-attempted once per resync), CreateContainerConfigError (resync cadence), InvalidImageName (terminal until UpdatePod changes the reference), ContainerCreating/PodInitializing for the create window. Invariants: pod phase stays Pending (derivePhase counts waiting BEFORE running, kubelet getPhase order); restartCount untouched (the retry verb is StartContainer, never RestartContainer); a pull failure never fails CreatePod wholesale (no ReplicaSet churn / registry hammering). Rides an ADDITIVE proto carve — the six decisions of 2026-09-11 rescinded the original \"zero new proto surface\" plan: FailureReason 12-16, ContainerStateWaiting.failure_reason, and the StartContainer rpc, so the cause is typed and switchable instead of matched on message text. Lifecycle events (Failed/BackOff/InspectFailed/ErrImageNeverPull) extend the B75 EventRecorder vocabulary — cite, never duplicate."
          - id: M12.1-d3
            done: true  # 2026-08-29, runtimed e89eb872 (PR #64) + k3sm 0c889e82 (PR #144) — image_id is the resolved CONFIG digest, container_id derives from the existing pgid-based reap identity; B132.
            desc: "status.containerStatuses[].imageID = the resolved repo digest. Image-config USER: ACCEPTED with documented divergence (the workload runs as the service user — non-root by construction; register cross-cite to the no-per-pod-uid ceiling); the vm path stays kubelet-verbatim in-guest. Offline/warm-cache posture + the :latest→Always trap documented in docs/user/limitations.md + images.md; image preload (B117) named as the airgap/outage mitigation."
        acceptance:
          - id: M12.1-a1
            met: true  # 2026-09-11 — TestPullFailureWaitingStates green under -race (pkg/provider), red before the change; B119.
            check: "TestPullFailureWaitingStates: every waiting reason + the forward-compat default, the platform-mismatch row, the ErrImagePull↔ImagePullBackOff alternation on a fake clock, phase-Pending + restartCount-untouched invariants (fake runtime; -race clean)"
            method: unit
          - id: M12.1-a2
            met: false
            check: "warm-cache offline start: IfNotPresent + blackholed network ⇒ Running (a registry outage must not strand cached pods)"
            method: integration
      - id: M12.2
        title: k3sm image CLI — docker interop (load / import / ls / push)
        status: done  # 2026-08-29 — d1 + a1 both landed; B117
        depends_on: []
        deliverables:
          - id: M12.2-d1
            done: true  # 2026-08-29, runtimed PR #71 + k3sm PR #165 — LoadImage stream ingest + load/import streaming verbs, verify-pass mutant proven red; B117.
            desc: "k3sm image load <docker-save.tar> / import <oci-layout> (the buildx OCI output) / ls / push, in ONE plumbing home pkg/oci (shared with M12.3). Store topology: links runtimed's exported store package IN-PROCESS (the one-binary assembly; staged+rename commits are concurrent-writer-safe) — never a second store implementation. Ingest is SELF-AUTHENTICATING: every blob re-hashed against its claimed digest before commit; a digest-mismatched blob and a quarantined-source tarball are REJECTED. Loaded images are provenance-free by design (operator-CLI-only surface, documented). push authenticates as the INVOKING USER (docker config/keychain), never the cluster imagePullSecret resolver. Queue item B117."
        acceptance:
          - id: M12.2-a1
            met: true  # 2026-08-29 — TestImageLoadDockerSaveAndOCILayout and neighbors green under -race; B117.
            check: "TestImageLoadDockerSaveAndOCILayout: golden docker-save + OCI-layout fixtures ingest; digest-mismatched blob rejected; quarantined-source tarball rejected; ls round-trips the index"
            method: unit
      - id: M12.3
        title: k3sm build v1 — COPY-only native Dockerfile builder
        status: done  # 2026-08-30 — d1 + a1 both landed; B118
        depends_on: []
        deliverables:
          - id: M12.3-d1
            done: true  # 2026-08-30, k3sm PR #104 — COPY-only crane-append builder lands, RUN rejected naming the M12.4 vm builder; B118.
            desc: "Dockerfile SUBSET builder (crane-append, pkg/oci): FROM scratch|<ref>, COPY/ADD, ENV/ENTRYPOINT/CMD/WORKDIR/LABEL/EXPOSE; RUN is REJECTED with a legible error naming the M12.4 vm builder as the RUN-capable path. darwin/arm64 default (--platform for metadata targets); output → local store / tarball / OCI layout / --push. Ships the command the user docs describe — the docs become true. Queue item B118."
        acceptance:
          - id: M12.3-a1
            met: true  # 2026-08-30 — TestCopyOnlyDockerfileBuild green (subset parse table, RUN/unknown-verb rejection, deterministic layer digests); B118.
            check: "TestCopyOnlyDockerfileBuild: subset parse table (accepted verbs + RUN rejection + unknown-verb rejection); deterministic layer digests for a golden context; entrypoint/env/workdir metadata round-trip"
            method: unit
      - id: M12.4
        title: buildx engine — managed buildkitd-in-vm builder + bundled buildx
        status: todo
        depends_on: [k3sm:M11.4]
        deliverables:
          - id: M12.4-d1
            done: true  # 2026-09-02, k3sm PR #300 (+ #301/#302/#304 fixes) — `k3sm builder up|down|delete` manages a guest-root buildkitd vm pod + PVC-backed cache + ClusterIP Service; the image defaults to the upstream digest matching the (still-private) GHCR mirror pin, `--mirror` flips to it once B121 populates the mirror.
            desc: "k3sm builder up|down manages a buildkitd vm pod (Linux arm64 + Rosetta amd64, PVC-backed cache); buildkitd runs guest-root inside its dedicated micro-VM (the VM boundary IS the isolation; the pod spec declares no foreign securityContext). The buildkitd image is consumed ONLY from the k3sm GHCR mirror, digest-pinned in code (ghcr.io/k3sm-io/mirror/buildkit@sha256:… via pkg/images; populated per Res. 12 by the committed hack/images/mirror.yaml manifest + digest-verified copy workflow, B121/B122; human-merged bumps; airgap = pre-seed via k3sm image load). k3sm build (full path) drives the BUNDLED buildx over the NAT-dial path proven by the vm networking spike (a Service/pod-IP dial — never a new vmhost socket forward); COPY-only Dockerfiles auto-route to the M12.3 native fast-path."
          - id: M12.4-d2
            done: false
            desc: "Packaging (named, never assumed): buildx SOURCE-BUILT at a pinned upstream tag (the control-plane-payload provenance precedent — never re-sign a prebuilt); committed pin file (version+sha256); release workflow fifth-checkout + sibling assert; archive-manifest + nested-code enumeration + bidirectional entitlement row (buildx carries NONE); brew source-build leg; install path + uninstall-manifest coverage; k3sm doctor builder probe; release image-pin gate: hack/verify-image-pins.sh --live proves every pkg/images pin exists on GHCR at its recorded digest with linux/arm64+linux/amd64, anonymously, wired into release.yml before the first tagged release consuming images.Buildkitd; legible-absence contract (builder stack absent ⇒ the full path errors naming the install step; the COPY-only fast-path is unaffected). Third-party attribution: license tooling run AGAINST the buildx checkout at its pinned ref + its LICENSE shipped (the module-graph generator cannot see a separately-compiled binary); hygiene gate extended to verify."
        acceptance:
          - id: M12.4-a1
            met: true  # 2026-09-02, k3sm PR #302 — validated live end-to-end on a vm-capable Mac: RUN build → OCI export → `k3sm image push` → a pod ran the RUN-baked /proof.txt; `builder down` kept the cache PVC.
            check: "a Dockerfile WITH RUN steps builds green against the managed builder on a vm-capable Mac (K3SM_LAB=1, human-run); the COPY-only fast-path routes natively; builder-absent degrades legibly"
            method: lab
          - id: M12.4-a2
            met: false
            check: "vmhost release signing (B110) + the guest kernel artifact (B111) are RECORDED facts before this sub-phase merges — the acceptance-clause pattern for human-gated preconditions (queue-item ids are not depends_on vocabulary)"
            method: build
          - id: M12.4-a3
            met: false
            check: "the GHCR mirror infra (B121 mirror manifest + workflow, B122 pkg/images pins + verify) is MERGED with gates green — recorded facts per the M12.4-a2 pattern (Res. 12; queue-item ids are not depends_on vocabulary)"
            method: build
  - id: M13
    title: Signing & notarization (distribution reach — post-launch, nice-to-have)
    status: todo
    depends_on: []
    notes: >-
      OPERATOR DIRECTIVE 2026-08-27, on empirical evidence from the two-Mac lab. Apple code
      signing buys k3sm DISTRIBUTION REACH ONLY — it is NOT a runtime or privilege
      requirement — so it is re-scoped OUT of the launch critical path into this
      nice-to-have follow-up milestone. PROVEN THE SAME DAY on the lab host with a binary that
      is `Signature=adhoc`, `TeamIdentifier=not set`, zero entitlements, and which
      `spctl -a` REJECTS: `sudo k3sm install` laid down BOTH root LaunchDaemons
      (io.k3sm.netd as root, io.k3sm.server as _k3sm), the control plane came up healthy via
      the unprivileged user, uninstall was clean, and the m0/m1/m3/m4 gates ran GREEN with
      m2 at 9/10 (its one failure is in-pod DNS, unrelated to signing). Root does not
      require a signing identity on macOS; arm64 requires only SOME signature (ad-hoc
      satisfies AMFI), and the netd DR TeamID pin is NOT implemented today — peercred.go
      states the load-bearing control is the LOCAL_PEERCRED uid check, with code identity a
      deferred cgo defense-in-depth TODO. Homebrew ships the same way (its bottles are
      ad-hoc, TeamIdentifier not set, spctl-rejected) because curl-fetched files carry no
      com.apple.quarantine xattr, so Gatekeeper is never consulted. WHAT THIS MILESTONE
      ADDS, and it is reach not security: browser-downloadable and `.pkg` artifacts,
      `spctl --assess` acceptance, a notarization ticket to staple, and the OPTION to arm
      the publisher-identity DR pin. CONSEQUENCE for the launch runbook: the curl-channel
      profile in docs/m9-plan.md is the BASELINE launch profile, no longer a degraded
      fallback awaiting enrollment.
    subphases:
      - id: M13.1
        title: Developer ID signing + notarization pipeline
        status: todo
        depends_on: []
        deliverables:
          - id: M13.1-d1
            done: false
            desc: "Developer ID Application enrollment + the signing/notarization credentials held by a human (never in the repo, never on a hosted runner). This is the human_gate — the milestone-grain analog of an operator-supplied credential, and the reason the rest of this milestone cannot be autopilot work."
          - id: M13.1-d2
            done: false
            desc: "goreleaser sign/notarize stanzas UNCOMMENTED (they ship commented today, secrets only via {{.Env.*}} — see .goreleaser.yaml and the B58 lineage) + the .pkg artifact and stapling. Re-scope the signs: block from artifacts:binary to cover the k3sm-netd copy + checksums (the B58 forward-looking flag)."
          - id: M13.1-d3
            done: false
            desc: "Re-arm the enumerated asserts m9-plan drops in the curl-only profile: spctl --assess acceptance, stapler validate, and the netd DR TeamID pin (DESIGN §5c). The DR pin additionally needs the deferred code-identity check (audit-token -> SecCodeCreateWithAuditToken -> SecCodeCheckValidity) which requires Security.framework via cgo; darwin-net is CGO_ENABLED=0 today, so that carve is part of this deliverable, not an assumption."
        acceptance:
          - id: M13.1-a1
            met: false
            check: "hack/lab/m7.sh runs its FULL profile (not the named degraded profile): spctl --assess accepts the shipped artifact, stapler validate passes, and a browser-downloaded .pkg installs without a Gatekeeper block on a clean Mac"
            method: lab
          - id: M13.1-a2
            met: false
            check: "the M4-lab/M7-lab phases.json rows (requires: signing) run green; they are the ONLY two rows in the manifest that require signing, which is what bounds this milestone"
            method: lab

  - id: M14
    title: Multi-node & HA de-EXPERIMENTAL graduation (v0.3)
    status: in-progress
    strategy: hard cut
    depends_on:
      - darwin-net:M3
    note: "Authoritative input: docs/m14-plan.md (workspace) — Phase C encodes ONLY from that doc. M14 is a CROSS-MILESTONE PROGRAM with no user-visible feature of its own: M3 (multi-node/mesh) and M6 (HA) are already CODE-COMPLETE, and this milestone exists to make them PROVABLE on real hardware and therefore graduable out of EXPERIMENTAL at v0.3. It does NOT restructure the M3/M6 blocks — their acceptances flip by phases_ref WRITE-THROUGH exactly as M4.0-a1 flips through M7.1 (see M4.0's tombstone note). It exists because the public two-Macs tutorial ships four true caveats: the tutorial's own e2e run is unrecorded; kubectl logs/exec breaks cluster-wide once a second node joins (B213 + the five sibling lab defects B222–B226); the kubelet-port auth hardening is still in review (B176 / PR k3sm#192); and multi-node ships EXPERIMENTAL. The caveats are rewritten LAST (M14.6), from recorded evidence, never ahead of it. HARD CUT throughout: the hazard-class sub-phase (M14.2 server-side mesh bring-up) deliberately AVOIDS the wireguard MeshPeer/AllowedIPs named exception by scoping the egress source-bind at the DIALER — a unilateral per-node decision no peer observes — so old and new binaries interoperate in any restart order; the operational contract it still owes is a stated cutover criterion (server restarts FIRST, then node-by-node launchctl kickstart -k io.k3sm.*, brief per-node downtime acknowledged). The three lab sub-phases are K3SM_LAB=1 human sessions, never auto-greened (ROADMAP.md gate rules). GATE-MANIFEST OBLIGATION (verified against hack/acceptance/phases_test.go, not assumed): no phases.json row is added at encoding time, but the no_orphan_gate_scripts inverse check globs hack/acceptance/m[0-9]*.sh — which MATCHES m14-servermesh.sh and m14-flip.sh — while TestPhasesGatePathsResolve requires every row's gate to already resolve on disk. So each of those two gates ships WITH its own phases.json row in the same PR that creates the script (M14-servermesh and M14-flip, both tier integration), never earlier and never later. B213.sh is a B<n> gate and matches neither glob, so it needs no row."
    subphases:
      - id: M14.0
        title: kubelet serving cert chains to the cluster CA on mesh clusters (B213)
        status: in-progress
        strategy: hard cut
        depends_on: []
        note: "Routed to the unattended queue as B213, which depends_on B176 — PR k3sm#192 merges FIRST because this edits the very functions it reshaped (kubeletServingTLS's auth parameter, agentNodeOptions' CA plumb, the vkadapter fail-closed pairing). Cert-class merge precondition: the named gate run green in a human lab session (M14.3) + a recorded security-engineer sign-off."
        deliverables:
          - id: M14.0-d1
            done: true
            desc: "nodeOptions carries an optional cluster-CA-issued serving pair (kubeletServingCertPEM/KeyPEM); kubeletServingTLS consumes it via tls.X509KeyPair instead of certs.SelfSignedServing when both are set, still flowing through auth.ServingTLS so B176's client-auth stamping is untouched (it sets ClientAuth/ClientCAs, never Certificates). Exactly one of the pair set is an ERROR, mirroring the pairing discipline B176 documented. Empty pair = the self-signed single-node/dev default, pinned by its own test."
          - id: M14.0-d2
            done: true
            desc: "the WORKER consumes the join-delivered pair: runAgent fails fast on an empty res.KubeletServingCertPEM/KeyPEM (the mesh path never silently falls back to self-signed — the same refusal shape as the empty-ClientCAPEM check), agentNodeOptions passes both through. The pair is held IN MEMORY ONLY and re-derived by the fresh bootstrap.Join every agent start — no new key file, so pkg/executor/rotate.go's artifact fence gains no path. This persistence choice is deliberate and stated, not incidental."
          - id: M14.0-d3
            done: true
            desc: "the mesh SERVER mints its own — the control-plane node never joins, so runServer's meshIP-and-hierarchy block mints via hierarchy.Cluster.IssueServing(nodeName, {nodeName, localhost}, ips, 365*24h) and sets the two nodeOpts fields. ips = dedup of meshIP, opts.nodeIP, proxyableNodeIP(nodeOpts), 127.0.0.1 — proxyableNodeIP is INCLUDED because the no-datapath posture lets the registered InternalIP diverge from the advertised one, and a narrowed SAN list would reproduce B213 as a SAN mismatch instead of an issuer mismatch. A CA-issuance failure FAILS CLOSED, never degrades to self-signed. WITHOUT THIS HALF the defect remains cluster-wide — it was observed on the control-plane node's own kubelet."
          - id: M14.0-d4
            done: true
            desc: "rotation honesty: the new artifact is added to pkg/executor/rotate.go's reissuedArtifacts() in the SAME PR. That list is the RotationReport's completeness contract, and an artifact that IS re-minted on restart but absent from Reissued breaks the report's stated honesty invariant just as badly as the reverse. LANDED as kubeletServingArtifact (pkg/executor/rotate.go:328,332-352, PR #275): since the pair has no path (d2's memory-only decision), Present is read off the on-disk WITNESS instead — the apiserver serving cert minted in the same --mesh-ip branch — with Path rendered as the literal string '(in memory — never written to disk)' rather than a filesystem path. That satisfies the completeness contract without contradicting d2."
          - id: M14.0-d5
            done: true
            desc: "doc deliverables — pkg/certs/serving.go's doc comment (SelfSignedServing is now ONLY the single-node/dev/standalone-`k3sm node` cert; its current text states the now-false premise that no --kubelet-certificate-authority is configured) and docs/DESIGN.md §5c's Node-verbs bullet, which today ASSERTS this fix already exists. After M14.0 it becomes true; reword it to name both halves so it describes mechanism, not aspiration."
        acceptance:
          - id: M14.0-a1
            met: false  # 2026-09-17 ledger reconciliation — the FIX is landed and live-proven; the NAMED GATE run is still owed. Landed: d1-d5 all true, merged as k3sm#275. Live evidence: on 2026-09-01 the joined worker's :10250 presented issuer=CN=k3sm-cluster-ca where it had presented a self-signed CN=k3sm-kubelet before, and the two-Mac M3 gate went full green including the leg that reads pod logs through the apiserver (run id m3-lab-twomac-2026-09-01.log, run 6); on 2026-09-17 a pod log was read across the mesh from the worker Mac and that gate passed again on the current build (run id parked-lab-2026-09-17.log, runs 16-17), both recorded in the maintainers' run log. NOT recorded, and the reason this stays false: hack/acceptance/B213.sh has never been run at its integration tier on the rig — that run is M14.3-d1's — and the single-node leg (a boot that still presents a serving cert which does NOT chain to the cluster CA) has no recorded execution at all.
            check: "hack/acceptance/B213.sh — unit ladder (issued-pair / self-signed-default / half-pair-rejected / mint-from-cluster-CA with the no-datapath divergent SAN case / CA-unavailable-fails-closed / --kubelet-certificate-authority emitted iff Config.KubeletCAFile) plus integration on a `--mesh-ip 127.0.0.1 --network none` boot (the FLAG alone, no mesh device, so this does not secretly depend on M14.2): openssl s_client chain-verifies :10250 against tls/cluster-ca.crt, kubectl logs completes the apiserver round trip, and a single-node boot still presents a cert that does NOT chain to the cluster CA"
            method: integration
      - id: M14.1
        title: the five sibling mesh lab defects (D1–D5)
        status: in-progress
        strategy: hard cut
        depends_on: []
        note: "Routed to /go as B222 (D1 loopback probe/kubeconfig), B223 (D2 KCM --root-ca-file), B224 (D3 MeshPeer CRD), B225 (D4 NodeRestriction label), B226 (D5 SA token BoundObjectRef) — the per-item gates and human_gate justifications are tracked internally (all false; each argued individually rather than in bulk). D1, D3 and D4 gate M14.2; D2 is owed by the lab's in-pod-API criterion; D5 is lab-independent. B223 and B226 carry the cert-class merge precondition."
        deliverables:
          - id: M14.1-d1
            done: true
            desc: "B222/D1 — derive the apiserver probe + in-process kubeconfig host from the EFFECTIVE bind (cfg.BindAddress -> NodeIP -> 127.0.0.1, the self-defaulting chain apiServerArgs already uses) instead of the 127.0.0.1 hardcode in pkg/executor/setup.go, which wedges any non-loopback --mesh-ip boot at the healthz wait because a mesh server binds the apiserver to meshIP only. Prerequisite for ANY realistic mesh boot, hence for the two-Mac lab."
          - id: M14.1-d2
            done: true
            desc: "B223/D2 — Config.RootCAFile set to the cluster CA in the mesh block so pods' projected kube-root-ca.crt can verify the apiserver's actual (cluster-CA-issued) serving leaf. BINDING: the branch predicate is the SAME cfg.ServingCertFile != \"\" that gates --tls-cert-file, so the two flags can never disagree about which CA is live; an unconditional repoint would break in-pod TLS on single-node, and the gate therefore asserts BOTH branches."
          - id: M14.1-d3
            done: true
            desc: "B224/D3 — apis grows MeshPeerCRDName + a named MeshPeerCRD() accessor (the MLXModelCRD() shape) and rewrites the embed.go paragraph whose claim that MeshPeer is applied out-of-band is FALSE; k3sm crdensures the CRD fail-closed in the mesh block before newMeshEnroller, since a missing CRD silently 500s every worker join. The accessor's own reservation comment owes a MESH-REGRESSION CHECK — that leg is part of this item's gate, not a follow-up."
          - id: M14.1-d4
            done: true
            desc: "B225/D4 — delete the vendored virtual-kubelet default label kubernetes.io/role in configureNode; NodeRestriction forbids it (neither kubeletLabels nor an allowed namespace), so a joined worker's Node create/update is rejected while the in-process server node escapes only via system:masters. The gate is dependency-bump proof: a table over the full nodeutil.NewNode label set, evaluated across more than one reconcile tick, so a future vendor bump fails loudly instead of silently reopening it."
          - id: M14.1-d5
            done: true
            desc: "B226/D5 — projected SA tokens gain BoundObjectRef{Kind: Pod, APIVersion: v1, Name, UID} via pod-identity context plumbing. The EXACT ref is the acceptance, not merely 'has a BoundObjectRef': upstream's guarantee is pod-lifetime invalidation plus the pod-name/pod-uid TokenReview extras identity consumers read, so a ServiceAccount-kind or UID-less ref would pass a literal reading while restoring none of the semantic. Fail closed when the pod identity is absent."
        acceptance:
          - id: M14.1-a1
            met: false  # 2026-09-17 ledger reconciliation — the SECOND clause is proven, the first is not. No hand-applied shim remains necessary to bring up a two-node mesh cluster: on 2026-09-17 a second Mac joined the control plane with `k3sm install --agent` and no CRD, label, certificate or wireguard configuration was applied by hand at any point, after which the two-Mac M3 gate passed (run id parked-lab-2026-09-17.log, runs 16-17). All five fixes are landed (k3sm#229 D1, #231 D2, #232 D3, #228 D4, #230 D5). But "B222-B226 all closed with their named gates green" is not yet true: only the D4 item is terminal (unit tier); the other four still carry K3SM_LAB rungs their own rows track internally, so this acceptance stays false.
            check: "B222–B226 all closed with their named gates green (each proven red-at-main first); no hand-applied shim remains necessary to bring up a two-node mesh cluster"
            method: integration
      - id: M14.2
        title: server-side wireguard mesh bring-up (the M3-lab blocker)
        status: in-progress
        strategy: hard cut
        depends_on: []
        note: "ATTENDED milestone work, NEVER the unattended queue — the run log names it 'an architectural datapath change carrying an explicit breaks-ALL-backend-dials hazard; that is not unattended work'. Needs M14.1-d1/d3/d4 merged first. MERGE PRECONDITION, ATTACHED BY HAND: this mints and persists a new wireguard PRIVATE KEY but lives in cmd/k3sm/enroll.go, which the path-based cert/secret force-pattern in hack/go-selftest.sh does not match — so its PR carries the cert-class boxes explicitly (named gate green in a human lab session + a recorded security-engineer sign-off) even though no mechanical check will add them. CUTOVER CRITERION: restart the SERVER first (so its MeshPeer exists when workers reconcile), then each worker, node-by-node via launchctl kickstart -k io.k3sm.*. Rollback leaves the index-0 MeshPeer object behind — harmless, but the runbook must say so, or an on-call reader misreads it as a live server mesh."
        deliverables:
          - id: M14.2-d1
            done: true
            desc: "darwin-net (see darwin-net:M14.0): destination-scoped egress source-binding, replacing the unconditional bind that is the 'breaks ALL backend dials' hazard. Consumed here — k3sm sets netserve.Config.MeshEgressIP only once that lands."
          - id: M14.2-d2
            done: true
            desc: "a persistent server wireguard identity: load-or-create a private key (helper mode provisions under install.MeshKeyDir and passes the ref via mode.MeshOptions; direct/root uses mesh.WithPrivateKey), persisted 0600 so the public key survives launchctl kickstart."
          - id: M14.2-d3
            done: true
            desc: "EnrollSelf writes the INDEX-0 MeshPeer (PodCIDR = podnet.NodeCIDR(ClusterPodCIDR, 0), MeshIP = its .1, Endpoint = the UNDERLAY LAN address:meshPort, since a worker must reach wg before any mesh exists). It ASSERTS-OR-CREATES index 0 explicitly and must NOT run the worker free-index scanner: defaultNodePodCIDR() hard-codes 100.64.0.0/24 and feeds it to the server's routing locality and pod IPAM, so a self-assigned different index would split what the mesh routes here from what this node's pods are, and mesh.BuildPlan's self-exclusion keys on exact CIDR equality. Idempotent on rejoin; FAIL CLOSED if index 0 is held by a different node name. Same change fixes the WORKER assignment to lowest-unused-index >= 1 (enroll.go's len(existing)+1 skips and double-counts once index 0 is occupied), and corrects the misleading --server help string (the join must reach meshIP:9345 before any mesh exists, so that address is in practice an underlay one)."
          - id: M14.2-d4
            done: true
            desc: "ORDERING, load-bearing: EnrollSelf runs through the SAME e.mu-guarded meshEnroller instance the join RPC handler uses, and is list-back-verified COMPLETE BEFORE startBootstrapServer begins accepting. Without that happens-before, the free-index fix in d3 makes index 0 a legitimately assignable slot to a worker joining in the window before the server's own write lands — two peers claiming one AllowedIPs, which wireguard cannot admit. Mesh bring-up itself is ordered after apiserver-healthy + the D3 CRD ensure + RBAC, and strictly BEFORE netserve.New, because mesh.Start plumbs the mesh-egress lo0 alias the proxy's source-bind depends on."
          - id: M14.2-d5
            done: true
            desc: "wire the proxy: set netserve.Config.MeshEgressIP and seed PeerMeshEgressIPs from the MeshPeer list at construction (the follow-up server.go already names), closing the fail-open NetworkPolicy attribution gap for already-enrolled peers. KNOWN AND ACCEPTED for v0.3: that seed is a BOOT-TIME SNAPSHOT, so an already-running worker recognizes a newly-joined server peer for NetworkPolicy attribution only after its own restart, while its wireguard peer set reconverges live via the informer. The posture is fail-open widen-only ('never a wrong deny') and NetworkPolicy is opt-in, so the gap degrades attribution, not connectivity."
          - id: M14.2-d6
            done: true
            desc: "share the bring-up helper: extract the agent's bringUpMesh into a helper taking DISCRETE FIELDS (podCIDR, meshIP, private key, peers) rather than *bootstrap.JoinResult — the server has no JoinResult and never will, and reusing a network-received wire DTO for a locally synthesized value invites a later reader to assume delivery-trust properties (CA-pinned PinnedClient) that do not hold on the server path."
          - id: M14.2-d7
            done: true
            desc: "FAILURE POSTURE: server-side mesh bring-up is LOG-AND-CONTINUE, following the explicit precedent beside it ('a node that refuses to start is strictly worse than a node missing an advisory'). Under launchd KeepAlive a fatal error here is an unbounded respawn loop on the one process that also hosts apiserver + kine + scheduler — a mesh-only defect must never take the control plane down."
          - id: M14.2-d8
            done: true
            desc: "doc deliverable: docs/DESIGN.md §5b gains server-mesh participation and the destination-scoped egress rule; the 'k3sm server does not bring up its own wireguard mesh yet' comment is deleted along with the behavior it described."
        acceptance:
          - id: M14.2-a1
            met: false  # 2026-09-17 ledger reconciliation — BUILT AND LIVE, named gate unrun. Landed: the server's own enroll writing the index-0 MeshPeer (k3sm#264, cmd/k3sm/servermesh.go + meshEnroller.EnrollSelf in cmd/k3sm/enroll.go), the underlay endpoint and the one persistent mesh key (k3sm#267), the installer carrying --mesh-ip so a server owns its mesh across a reinstall (k3sm#386) and provisioning the helper key for both roles (k3sm#412). Live on 2026-09-17: the control-plane Mac served a real non-loopback mesh IP, the joining worker reported peers=2 with both MeshPeers present, and cross-node NodePort, storage and in-pod-API traffic passed the M3 gate (run id parked-lab-2026-09-17.log, runs 16-17). Still owed, which is why this stays false: hack/acceptance/m14-servermesh.sh has never been run at its root tier (K3SM_LAB=1 + root on one Mac), and the two-Mac evidence is NOT a substitute — the hazard-regression leg is a SAME-NODE ClusterIP round trip under -race with the mesh-egress source wired, which no cross-Mac run exercises.
            check: "hack/acceptance/m14-servermesh.sh on a single Mac WITH --mesh-ip set (the hazard proof must live here: hack/acceptance/m3.sh boots WITHOUT --mesh-ip and cannot exercise a single line of this change, so citing it as regression evidence would be vacuous) — the index-0 MeshPeer exists with the right name/CIDR/MeshIP and a non-empty public key; utun and the mesh-egress lo0 alias are up; THE HAZARD-REGRESSION LEG: a same-node ClusterIP round trip still completes with MeshEgressIP wired, run under -race with concurrent local- and remote-destination dials in flight; a self-enroll-vs-simulated-join race test pins the d4 happens-before; unit tables cover the scoping decision for BOTH TCP and UDP and the lowest-free-index assignment"
            method: integration
      - id: M14.3
        title: hardening lab session — B213 live, B176 two-Mac slice, sign-offs, merges
        status: todo
        strategy: hard cut
        depends_on: []
        note: "HUMAN SESSION, K3SM_LAB=1, two-Mac rig. Follow B176's own runbook line: UPGRADE AGENTS FIRST (an old agent keeps :10250 open until its daemon kickstarts; a new agent against a not-yet-upgraded server refuses to start, which is the safe direction). Also re-assert the M14.2 destination scoping against REAL cross-Mac traffic — the same-node acceptance leg cannot exercise the actual wireguard egress path, and this defect class is precisely what has blocked M3-lab historically."
        deliverables:
          - id: M14.3-d1
            done: false  # 2026-09-17 ledger reconciliation — PART discharged. Merged: PR k3sm#192 (B176) and the M14.0/M14.1 PRs (k3sm#275, #228-#232), with the security-engineer sign-offs recorded on the cert-class items. Recorded: k3sm/pkg/provider::TestKubeletEndpointRequiresClientCert green on a dev boot on 2026-09-01 (run id b176-devslice-local-2026-09-01.log), and the recorded expectation held — logs/exec could not work until the serving-cert fix landed. NOT done: hack/acceptance/B213.sh has not been run on the rig and the two-Mac half of the client-cert slice has not been run, so d1 stays false.
            desc: "run hack/acceptance/B213.sh live on the rig; run k3sm/pkg/provider::TestKubeletEndpointRequiresClientCert live across a dev boot AND a two-Mac join; record the security-engineer sign-offs; merge PR k3sm#192 (B176) and the M14.0/M14.1 PRs. Recorded expectation: the B176 slice CANNOT show working logs/exec until B213 lands — the handshake fails on the SERVING-cert direction before the client-identity predicate is exercised — so that gap is expected, not a new failure."
        acceptance:
          - id: M14.3-a1
            met: false  # 2026-09-17 ledger reconciliation — no run to cite for the two legs this check turns on: B213.sh exit 0 on the rig, and an unauthenticated connection to a worker's :10250 refused. The merged-PR and sign-off clauses are satisfied (see d1). The 2026-09-01 spot-check that a worker's :10250 presents the cluster-CA issuer is evidence for M14.0's serving-cert direction, not for this check's client-auth legs.
            check: "on the two-Mac rig: B213.sh exit 0, the kubelet-endpoint client-cert gate green, an unauthenticated connection to a worker's :10250 refused, and both recorded sign-offs present on the merged PRs"
            method: lab
      - id: M14.4
        title: the recorded two-Mac run — M3-lab green and the tutorial executed as written
        status: done  # 2026-09-17 — both M14.4-d1 and M14.4-a1 discharged: the gate half and the tutorial-as-written half both recorded on the two-Mac rig
        completed: 2026-09-17
        strategy: hard cut
        depends_on: []
        note: "HUMAN SESSION, K3SM_LAB=1. phases_ref: k3sm M3.3 — M3.3-a1 flips met:true ONLY via this write-through when hack/lab/m3.sh greens here, NOT on any M3-local completion, so M3 does not falsely flip done. The run must use ZERO hand-applied shims (no manual CRD apply, label, cert, or wireguard config — the negation of D1–D5 is the point), and the evidence line records date, hardware, binary SHAs and that no-shims statement explicitly."
        deliverables:
          - id: M14.4-d1
            done: true  # 2026-09-17 — BOTH HALVES DISCHARGED. The gate half: K3SM_LAB=1 hack/lab/m3.sh exit 0 on the two-Mac rig, both Macs on the identical installed build 0.1.6-lab.56963a3, the worker joined with no hand-applied configuration, m3.0 PASS and all three TestM3_* PASS from the control-plane Mac, M3 gate exit 0 (the maintainers' run log, run 17; first discharged 2026-09-10, run id m3-lab-local-2026-09-10.log). The tutorial half, previously blocked because the tutorial was stale against the shipped installer flow: the tutorial was rewritten to match that flow and then executed exactly as written on 2026-09-17 on build 0.1.6-lab.44bde26 (k3sm main 44bde26, darwin-net main 5a25cbe) on an M1 Max control-plane Mac and an M2 laptop worker — step 1 on the control-plane Mac (`sudo k3sm install --mesh-ip 100.64.0.1`, then `sudo k3sm token create`), step 2 on the second Mac (the token in a root-only file, `sudo k3sm install --agent --server <the control-plane Mac's LAN address> --token-file …`), step 3 from the control-plane Mac (`k3sm kubectl get nodes -o wide` showed both nodes Ready), with no CRD, label, certificate or wireguard configuration applied by hand at any point (the maintainers' run log, run 19). Noted honestly: step 2's first attempt, six seconds after the server restart, was refused by the join preflight before anything was written, and the retry a minute later joined.
            desc: "on merged main, execute K3SM_LAB=1 hack/lab/m3.sh to exit 0 (NodePort reachable, StatefulSet persistence, in-pod kubectl + cluster DNS from a pod on the JOINED node), then execute site/content/tutorials/07-two-macs.md start to finish exactly as written and record it. Retires the tutorial's 'this tutorial's own end-to-end run has not yet been recorded' caveat, which M14.6 then rewrites."
        acceptance:
          - id: M14.4-a1
            met: true  # 2026-09-17 — BOTH CLAUSES DISCHARGED. Clause one, K3SM_LAB=1 hack/lab/m3.sh exit 0 on two real Macs with no hand-applied shims: green on 2026-09-01 (run id m3-lab-twomac-2026-09-01.log, run 6 — M3: 3 passed, 0 failed) and again on 2026-09-17 on the current build (the maintainers' run log, run 17) — an M1 Max control-plane Mac and an M2 laptop worker, both on the identical installed build 0.1.6-lab.56963a3 (staged from k3sm main 56963a3; the gate driven from the control-plane Mac): m3.0 PASS (2 Ready nodes, worker identified), TestM3_NodePort PASS (1.95s), TestM3_PVCPersistsAcrossRestart PASS (2.04s), TestM3_InPodKubectlAndDNSOnWorker PASS (2.03s), m3.A PASS; the worker joined by `k3sm install --agent` and NO CRD, label, certificate or wireguard configuration was applied by hand at any point. Clause two, previously undischarged because the tutorial was stale against the shipped installer flow (not a missing run): the tutorial was rewritten to match that flow and then executed exactly as written on 2026-09-17, on build 0.1.6-lab.44bde26 (k3sm main 44bde26, darwin-net main 5a25cbe), on an M1 Max control-plane Mac and an M2 laptop worker — install with `--mesh-ip` and `token create` on the control-plane Mac, `install --agent --server … --token-file …` on the second Mac, `k3sm kubectl get nodes -o wide` showing both nodes Ready from the control-plane Mac — with no CRD, label, certificate or wireguard configuration applied by hand (the maintainers' run log, run 19; the first join attempt was refused by the preflight before any write and the retry a minute later succeeded, recorded honestly). Both required legs of this check now hold; writes through per the check below.
            check: "K3SM_LAB=1 hack/lab/m3.sh exits 0 on two real Macs with no hand-applied shims, and the tutorial's command sequence has been executed as written and recorded; writes through to flip k3sm:M3.3-a1 met:true and M3 status:done"
            method: lab
      - id: M14.5
        title: HA lab — two Macs on one Postgres, with the production-trust soak
        status: todo
        strategy: hard cut
        depends_on: []
        note: "HUMAN SESSION, K3SM_LAB=1, two Macs + Postgres. phases_ref: k3sm M6.0 + M6.1 — M6.0-a1 and M6.1-a1 flip met:true ONLY via this write-through when hack/lab/m6.sh greens here. THE SOAK FLOOR IS BINDING: K3SM_M6_SOAK_DURATION=24h minimum for the v0.3 flip, NOT the script's 20s smoke default, because the fallback this posture originally rested on is gone — ConsistentListFromCache=false is GA-LOCKED true in the pinned k8s build and the apiserver refuses to start with it set, leaving kine's watch-progress-notify plus this soak as the only remaining controls over a low-frequency, load-dependent staleness failure. The evidence line records the duration actually run."
        deliverables:
          - id: M14.5-d1
            done: false
            desc: "execute K3SM_LAB=1 hack/lab/m6.sh to exit 0: write-on-A/read-on-B, single-active leader election, a second server joining and reconstructing the identical CAs from the sealed bundle, the failover leg, and the watch-staleness soak at >= 24h."
        acceptance:
          - id: M14.5-a1
            met: false
            check: "K3SM_LAB=1 hack/lab/m6.sh exits 0 on two Macs + Postgres with the soak at >= 24h and the duration recorded; writes through to flip k3sm:M6.0-a1 and k3sm:M6.1-a1 met:true and M6 status:done"
            method: lab
      - id: M14.6
        title: the de-EXPERIMENTAL flip — docs, site, and the v0.3 close
        status: todo
        strategy: hard cut
        depends_on: []
        note: "Runs ONLY after M14.4 AND M14.5 evidence is recorded; a reviewer must not merge the flip on the strength of the plan alone. TWO RULES GOVERN THE EDIT SURFACE, both of which produced a wrong answer once during this program's own drafting. (1) SOURCES VS GENERATED COPIES: edit docs/user/{multi-node,ha,limitations,faq,README}.md and ROADMAP.md, then regenerate — site/content/docs/* AND site/content/roadmap.md are GENERATED (each carries a DO-NOT-EDIT header; the workspace ROADMAP.md is likewise derived, /roadmap-sync only). Site-AUTHORED and edited directly: tutorials/07-two-macs.md, capabilities.md, compare.md, _index.md, support.md, tutorials/12-what-wont-work.md, data/gates.yaml. (2) ONLY THE M3/M6 SENTENCES MOVE: when this rule was written most EXPERIMENTAL occurrences in those files described the vm RuntimeClass, which shares none of this evidence — limitations.md even carries both features under one heading — so a whole-file keyword-absence gate would either have forced a false public claim about vm or never gone green. The vm RuntimeClass since graduated on its own evidence (v0.1, 2026-09-01, k3sm#282), which changes nothing here: the gate asserts the SPECIFIC rewritten M3/M6 sentences, in the hack/acceptance/B214.sh style, never grep -c EXPERIMENTAL, and never re-touches the vm copy."
        deliverables:
          - id: M14.6-d1
            done: false
            desc: "flip the multi-node/HA status banners in the doc SOURCES and regenerate the site copies; rewrite the tutorial's caveat block so the three 'not yet' bullets retire in favour of the recorded run's date and hardware; set site/data/gates.yaml M3: validated and M6: validated (the 'proven end to end on real hardware by its named test' rank); update the hack/verify-tutorial-live.sh and hack/acceptance/B212.sh skip REASONS from 'not yet proven' to the recorded run (the skips themselves stay — CI still has one machine)."
          - id: M14.6-d2
            done: false
            desc: "ha.md MUST state the access model honestly: there is no floating apiserver VIP — hack/lab/m6.sh proves survival by switching to server B's kubeconfig, so client failover is a MANUAL KUBECONFIG SWAP, not transparent. A reader who sees the EXPERIMENTAL badge disappear otherwise imports the upstream assumption (apiserver behind a load balancer, clients ride through a server loss); removing the badge without adding this sentence converts a flagged preview-quality gap into a silent surprise."
        acceptance:
          - id: M14.6-a1
            met: false
            check: "hack/acceptance/m14-flip.sh — sentence-scoped asserts prove the named M3/M6 sentences are rewritten (never a whole-file EXPERIMENTAL grep — the vm RuntimeClass copy in the same files graduated separately at v0.1 and is not this gate's subject), site/data/gates.yaml reads M3: validated and M6: validated, ha.md carries the no-VIP access-model sentence, and hack/verify-docs-sync.sh + hack/verify-site-clean.sh are green"
            method: integration
  - id: M15
    title: container-vm RuntimeClass (k3sm slice — the class, the label, the capability, the docs, the gates)
    status: todo
    strategy: phased (multi-node launchd rolling restart)
    depends_on:
      - runtimed:M15.2
    note: "Authoritative input: docs/m15-plan.md (workspace) — Phase C encodes ONLY from that doc; the B267 spike's answers are binding. The deploy contract: a pre-M15 node has no container-vm handler row and never sets the k3sm.io/container-vm label, so the scheduler never places a container-vm pod on it and a forced one fails closed (guard #2); the control-plane Mac restarts LAST because it provisions the class; window one release line; rollback = revert + reinstall, a leftover class object is harmless. The M15 gate rows ship in this block's B268 encoding as honest skeletons (TestLabSkeletonHonesty pins them) and M15.3 replaces hack/lab/m15.sh's body with the real ladder, flipping skeleton to false in the same change (m11-plan R27). Merge precondition inherited by M15.2: the operator runs hack/lab/m11.sh --core on the rc artifact first — the GuestBackend generalization's hardware-level vm regression guard is that manual gate."
    subphases:
      - id: M15.3
        title: the container-vm class, label, capability, status row, user doc, and the real lab ladder
        status: todo
        strategy: phased (multi-node launchd rolling restart)
        depends_on: []
        deliverables:
          - id: M15.3-d1
            done: false
            desc: "pkg/runtimeclass refactored from a single Name const to a class list; the container-vm class provisioned beside vm (nodeSelector k3sm.io/container-vm, Overhead measured from the spike's helper RSS + the guest size — never copied from vm); NodeCapabilities.ContainerVMBackend + applyContainerVMLabel (presence-only via setLabelPresence); the imagePlatformPolicy case; the k3sm status row naming any missing probe term."
          - id: M15.3-d2
            done: false
            desc: "docs/user/container-vm-runtimeclass.md in the vm-runtimeclass.md contract shape: the supported list, linux/arm64 only, single node, the amd64 refusal message verbatim, an 'advertised, not yet honored' section for anything the spike narrowed, the three-memory-figures rule restated; EXPERIMENTAL as an attribute; the dependency named once as a fact (the open-source Containerization Swift package), never as the feature."
          - id: M15.3-d3
            done: false
            desc: "hack/lab/m15.sh: the REAL ladder replacing the B268 placeholder (skeleton → false in the same change): preflight (label present, class provisioned, the probe never touched the container CLI — a negative assertion), boot (uname -sm = Linux aarch64 AND uname -r = the pinned kernel string; never /proc/1/comm), logs --tail=N exact, exec exit-code propagation, a published image with a bare-name entrypoint, PVC survives helper SIGKILL, in-guest network (lease, cluster DNS, ClusterIP), the amd64 NEGATIVE, footprint recorded; the full ledger adds service, logs -f, /stats/summary, Attach semantics, and the live cross-backend segment measurement whose sentence lands in docs/CONTAINER-VM-GUEST.md and docs/privilege-model.md; B112's fsGroup exemption, when it lands, re-verified by its own rung."
        acceptance:
          - id: M15.3-a1
            met: false
            check: "hack/lab/m15.sh --core green on the rc artifact on a VZ Mac (rungs 1–9), the run log in hack/lab/runs/ with the machine named; the M15 skeleton row flipped to its real composite; k3sm hack/ci.sh green"
            method: lab
      - id: M15.4
        title: site sentence + the de-EXPERIMENTAL bar
        status: todo
        strategy: hard cut
        depends_on: []
        deliverables:
          - id: M15.4-d1
            done: false
            desc: "site: the what-runs third-path sentence and the compare page's resource-cost cell, only after M15-core is green; the de-EXPERIMENTAL bar written the way m11-plan R28 did (rungs 1–9 green on the rc artifact, two named machines)."
        acceptance:
          - id: M15.4-a1
            met: false
            check: "hack/site.sh verify green with the new sentence; the graduation bar recorded in docs/m15-plan.md"
            method: unit
  - id: M16
    title: MLX serving fleet — an upstream-compatible inference control plane over native MLX workers
    status: todo
    strategy: hard cut
    depends_on:
      - k3sm:M8
      - k3sm:M11
    note: "Authoritative input: docs/m16-plan.md (workspace) — Phase C encodes ONLY from that doc; its research findings F1-F9 and its BINDING resolutions R1-R16 are the inputs, and nothing in this block is re-derived from upstream by hand. M16 is a SIBLING of M8, not its successor: MLXModel stays the one-object way to serve one model, and this is the fleet layer above it (a native-Darwin mlx-worker running the M8 engine in-process behind the upstream backend contract, a node capacity policy for mlx.k3sm.io/gpu, four conformance and confinement proofs k3sm owes anyway, and the install recipe/example/doc/gate for running the upstream control plane as vm Pods with native workers beneath). THE RIG (R16): M16 develops and gates on the laptop dev Mac running as its OWN single-node k3sm server, reached over key-auth ssh through K3SM_M16_HOST; the workstation cluster is never a target, and every performance figure is taken on that laptop against hack/acceptance/m8.sh run on the same machine, never against a bigger Mac's numbers. Its 8 GiB budget is planned rather than discovered: system reserve max(2Gi, 10%), the operator and frontend vm guests at the M11 idle figure, two workers at the slot floor S0(2) measures. THE SINGLE-SLOT EDGE: if two engines do not fit beside the control plane, R5 clamps capacity to 1 on this rig, and the warm-prefix routing rung then needs a second node — so on that branch ONLY it is conditionally behind k3sm:M14; on the two-slot branch it runs on this one node and is required. DEPLOY CONTRACT (hard cut): no proto, no CRD field, no datastore encoding and no mesh change anywhere in M16 — the upstream framework's CRDs are additive objects owned by its own operator, and k3sm's one behavior change is a per-node capacity policy on the existing mlx.k3sm.io/gpu extended resource, which a single node takes with launchctl kickstart -k io.k3sm.server; rollback is revert plus reinstall, and helm uninstall removes the operator and frontend but NOT the CRDs or surviving CRs, which the user doc's finalizer runbook covers. TRUST: human_gate is none on every M16 item — R11 takes the two decisions once, here (the upstream operator's cluster-scoped RBAC grant, pinned as a golden test by B290 and re-asserted live by the gate's RBAC rung, and its conversion-webhook cert-controller, which is machine-minted internal PKI no human chooses or supplies) — and the only two human touches are public-REGISTRY WRITES, not gates: the mirror push (R12) and the mlx-worker publish (M16.3-d2). The k3sm leaves filed against this block are B286, B287, B288 and B290; B289 is the runtimed leaf."
    subphases:
      - id: M16.0
        title: spikes S0-S4 — preconditions, the Darwin build, the control plane, the engine, the worker
        status: todo
        strategy: hard cut
        depends_on: []
        note: "AGENT-RUN over ssh on the R16 rig, never a human lab session: method is integration, requires dev-mac + apple-gpu + vz + network, and the phases.json M16.0 row is manual:false with hack/spike/m16/run.sh as its gate, so the spikes ARE the acceptance and the findings are the write-back. Scripts live in hack/spike/m16/ in the M8 spike shape (a driver ships a lab-side payload over ssh; K3SM_M16_HOST is required and has no default, because naming an operator's machine here would put a private host in a public repo), with one findings-s<n>.md per rung. Two contracts make the ladder reviewable and honest: --plan is parsed BEFORE anything that requires the host, so the shape of every rung is readable on a machine with no GPU and no cluster; and the exit contract is 0 PASS / 1 FAIL / 2 RECORDED (a measurement with no verdict), defined once in hack/spike/m16/lib.sh. EVERY HALT IS BINDING AND EVERY HALT'S SUBSTITUTION IS PRE-DECIDED, so no halt needs a human to continue and the next cycle sees an unambiguous ledger."
        deliverables:
          - id: M16.0-d1
            done: false
            desc: "S0 — k3sm preconditions, no framework. (1) a trivial ClusterIP-backed VALIDATING webhook AND a trivial CRD CONVERSION webhook, both registered with clientConfig.service (never url) and both backed by a runtimeClassName: vm pod, so the path under test is the apiserver's ClusterIP service resolver into darwin-net's proxy; the apiserver reaches both and failurePolicy: Fail behaves. (2) TWO vllm-mlx engines as HOST PROCESSES (the M8 S5 bake-off method — no scratch binary, no reinstall) on the smallest pinned model class that fits two engines beside the control plane on 8 GiB, driven through the S3 sustained 1 200-token methodology at N = the engine's --max-num-seqs ceiling, recording aggregate tok/s, PER-REQUEST LATENCY PERCENTILES and wired memory against the one-engine control; IOKit/Metal cross-process interference is recorded as not evaluated if it is not measured. (3) a vm guest dials a native pod's own lo0-alias pod IP:port directly, AND the reverse (native pod to the vm guest's published IP), each recorded — both outcomes are consequential, because reachable also means the guest bypasses the proxy and the NetworkPolicy L4 hint, which is a trust-domain fact to document. HALTS: (1) fails goes to R4(a), v1alpha1 only with no conversion in the path; (2) thrashes or doubles p99 raises R5's slot floor (a smaller model or a larger slot) and re-runs S0(2), single-slot only if no small model fits two; (3) blocked goes to R4(b), the native-Darwin control plane per F2."
          - id: M16.0-d2
            done: false
            desc: "S1 — Darwin build plus infrastructure-free smoke. The documented macOS flow (cmake + protobuf, rustup, uv venv, maturin develop) run in the spike prefix with the RUST TOOLCHAIN AND MATURIN VERSION RECORDED, not defaulted; python3 -m dynamo.frontend --help answers; a frontend plus the in-tree mocker with --discovery-backend file returns tokens for one completion. Records the resolved upstream commit (this is the pin R2 promotes), the built wheel's sha256, and whether the maturin-built extension arrives linker-ad-hoc-signed, which is what hack/images/*/walk-verify.sh assumes. HALT: if dynamo-memory / nixl-sys will not build on darwin/arm64, the worker re-plans on the Rust backend contract (which does not pull dynamo-memory) BEFORE any build wave starts."
          - id: M16.0-d3
            done: false
            desc: "S2 — the upstream control plane on k3sm, GPU-free. The pinned chart installed from the mirror (R12; until the mirror push lands it runs against the upstream registry BY DIGEST, so nothing in M16.0 waits on a human) with etcd.install=false, nats.install=false, discoveryBackend=kubernetes and the operator on runtimeClassName: vm; findings-s2.md RECORDS THE OPERATOR ClusterRole's FULL verb/resource set (R11's input, and what B290 pins); the nine CRDs reach Established; the conversion webhook answers a v1alpha1 read of a v1beta1 object; the CPU-only mocker deployment serves a completion THROUGH THE FRONTEND'S ClusterIP; and the frontend's dial to the worker's PUBLISHED address is observed in the worker's own logs, because the request plane dials addresses, not VIPs. HALT: discovery or that dial fails goes to R4(b)."
          - id: M16.0-d4
            done: false
            desc: "S3 — the engine decision. (1) vllm-mlx's AsyncEngineCore driven from TOKEN IDs outside the server process, constructed with continuous batching and the pinned max_kv_size / max_num_seqs the M8 sizing formula yields, aborting mid-stream, observing block hashes stored and evicted, and MEASURING the cost of the KV push call on the hot path (sync versus async) — the number that decides whether routing metadata can ride the request path at all. (2) vllm-metal run against the M8 baseline on the same rig as a control, RECORDED and never gating. HALT: (1) fails goes to R3's HTTP sidecar shape onto mlx-serve, where the block size is unset, routing degrades to round-robin by contract, and the user doc says so."
          - id: M16.0-d5
            done: false
            desc: "S4 — the worker end to end. An MLXEngine in S3's shape behind the upstream backend contract, its conformance kit green, and frontend to worker to tokens through the ClusterIP with mlx.k3sm.io/gpu: 1 requested. Stretch, recorded rather than required here: the router preferring the warm worker. M16.3 productizes exactly this shape; nothing S4 leaves undecided is decided later by a build wave."
        acceptance:
          - id: M16.0-a1
            met: false
            check: "hack/spike/m16/run.sh exits 0 on the R16 rig with K3SM_M16_HOST set (the phases.json M16.0 row, manual:false), every rung reaching a verdict rather than a bare recording, and findings-s0.md through findings-s4.md written back with each halt's pre-decided substitution landed in the same write-back; hack/spike/m16/run.sh --plan exits 0 with no host set"
            method: integration
      - id: M16.2
        title: node capacity, the two webhook proofs, the memory-medium verdict, and the fleet status row
        status: todo
        strategy: hard cut
        depends_on: []
        note: "Starts BEFORE M16.0 completes — only d3's slot-floor constant waits on S0(2), and it is a constant a follow-up commit may revise, not a blocker on the policy function. These are conformance and confinement proofs k3sm owes whether or not the fleet ships; the leaves B286, B287, B288 and B290 carry them, and B289 (the kine-port deny) is runtimed's."
        deliverables:
          - id: M16.2-d1
            done: false
            desc: "B286 (R14): BOTH webhook delivery paths, proven, not inferred — TestAdmissionWebhookDeliveryThroughProxy AND TestConversionWebhookDeliveryThroughProxy, both with a clientConfig.service ref (so the apiserver's ClusterIP service resolver is what runs, which is the mechanism the proof is about) and both backed by a runtimeClassName: vm pod (a native backend would pass without exercising the guest leg). The two conformance-register rows flip TOGETHER with the tests named: the admission row loses its deferred-verification caveat and the CRD-conversion row loses its unqualified static verdict, because proving one dispatch path proves nothing about the other's failure surface."
          - id: M16.2-d2
            done: false
            desc: "B287: the emptyDir medium: Memory verdict on the NATIVE path — today it is silently disk-backed there while the vm path classifies it as tmpfs, a pre-existing cluster-wide conformance gap that M16 only makes more visible. Honor it or refuse it with a reason; TestTranslateEmptyDirMemoryMedium is the proof, and the outcome is what lets R6's sharedMemory: 0 be revisited."
          - id: M16.2-d3
            done: false
            desc: "B288 (R5): the literal gpuDeviceCount is replaced on BOTH branches by a TESTED policy function over GPUFacts — N = min(2, floor(ceiling / slot floor)), where the ceiling is recommended_max_working_set_bytes falling back to iogpu_wired_limit_bytes and NEVER mem_bytes (the proto's own comment names the binding constraint, and ValidateFit already checks it, so two headroom models over one physical resource would let the scheduler admit what the Degraded condition refuses), and a 0-sentinel ceiling yields 1. Admission gains a CUMULATIVE FIT beside ValidateFit: the sum of admitted GPU pods' memory requests stays under the ceiling, because the extended resource is a count and not a byte budget. TestGPUCapacityPolicy covers the table including the clamp, the fallback order and the 0 sentinel. The doc-comment states what N = 2 claims: a MEASURED-WORKLOAD capacity under BENIGN CO-TENANCY (one operator, one trust boundary), NOT an isolated slot — co-resident workers are not isolated from each other. Raising N above 2 is a later spike, never a constant edit."
          - id: M16.2-d4
            done: false
            desc: "pkg/mlxfleet: ONE home for the upstream GVK strings the status path needs (they are literals today wherever they appear), pinned by TestFleetGVKsMatchPin against the recorded chart version so a re-pin that moves a group or version goes red instead of silently reading nothing; plus the k3sm status fleet row — control plane detected, workers registered, and the node's CAPACITY N together with the per-slot memory floor, so the number the scheduler is using is readable without reading the code."
        acceptance:
          - id: M16.2-a1
            met: false
            check: "k3sm::TestGPUCapacityPolicy, k3sm::TestTranslateEmptyDirMemoryMedium, k3sm::TestFleetGVKsMatchPin and k3sm::TestFleetOperatorRBACPinned pass -race; hack/acceptance/status.sh asserts the `k3sm status` fleet row with capacity N and the slot floor; hack/ci.sh green"
            method: unit
          - id: M16.2-a2
            met: false
            check: "k3sm::TestAdmissionWebhookDeliveryThroughProxy and k3sm::TestConversionWebhookDeliveryThroughProxy pass against a running cluster on a dev-mac (integration tier, so the leaf lands lab-pending and this rung is what discharges it), and the two conformance-register rows name those tests"
            method: integration
      - id: M16.3
        title: the mlx-worker image — shared staging logic, the pinned wheel, and the digest-pinned publish
        status: todo
        strategy: hard cut
        depends_on: []
        note: "Depends on M16.0-d2 (the Darwin build flow and the wheel's recorded sha256) and M16.0-d4 (the in-process engine shape). The wheel hash is a REPRODUCIBILITY RECORD, not independent provenance — no published darwin wheel exists to pin against — and the user doc must say exactly that rather than implying a supply-chain guarantee the artifact does not carry."
        deliverables:
          - id: M16.3-d1
            done: false
            desc: "hack/images/lib/pybuild.sh FIRST — the staging logic mlx-serve already carries (python-build-standalone with its asserted interpreter pin, the hashed wheel closure, the Mach-O entrypoint, walk-verify) factored out before a second image copies it, because two copies drift and the lockfiles are the thing that must not. Then hack/images/mlx-worker/build.sh: python-build-standalone plus the vllm-mlx closure installed with --require-hashes (TestMLXImagesEnginePinLockstep pins BOTH images' lockfiles to ONE vllm-mlx version, so the fleet worker and the single-model server can never serve different engines); plus the darwin-built upstream runtime wheel (R2) built from the pinned tag and its Cargo.lock with a PINNED Rust toolchain and maturin version (RUST_TOOLCHAIN / MATURIN_MIN, asserted the way the interpreter pin already is, because a compiled extension's behavior depends on the compiler and not only on the source), with assert_wheel_pin comparing the just-built sha256 to the recorded one BEFORE staging, fail-closed; plus the upstream framework package; plus the mlx_worker package at hack/images/mlx-worker/src/mlx_worker/, whose OWN tests run from selftest.sh and assert the continuous-batching and pinned-KV invariants on the in-process path (the CLI flags that carry those invariants for mlx-serve are bypassed entirely when the engine is constructed in-process, so without these tests the invariants have no gate at all)."
          - id: M16.3-d2
            done: false
            desc: "the operator-run digest-pinned publish — HUMAN TOUCH 2, staged by the build as a single command and run by the operator because it is a public-registry write while Actions are dormant. The published digest is what the example and the gate consume; the built runtime wheel's sha256 rides the image as LABEL io.k3sm.mlx-worker.runtime-wheel, so the artifact carries its own reproducibility record. The publish is a MERGE PRECONDITION on M16.4, not a gate on this subphase: the wave is done on the build plus selftest.sh."
        acceptance:
          - id: M16.3-a1
            met: false
            check: "hack/images/mlx-worker/build.sh completes on the R16 rig with assert_wheel_pin and the interpreter/toolchain assertions green, hack/images/mlx-worker/selftest.sh exits 0 (including the mlx_worker package's own continuous-batching and pinned-KV invariant tests), walk-verify.sh reports every Mach-O signed, and k3sm::TestMLXImagesEnginePinLockstep passes"
            method: integration
      - id: M16.4
        title: example manifests, the user doc, the paragraph M8 owed, and the pin register's reader
        status: todo
        strategy: hard cut
        depends_on: []
        note: "The naming rule is load-bearing throughout this subphase: the k3sm feature is the MLX fleet (mlx-worker, mlx-fleet.md, examples/mlx-fleet/, pkg/mlxfleet, m16.sh), and THE UPSTREAM FRAMEWORK IS NAMED ONCE AS A COMPATIBILITY FACT, NEVER AS THE FEATURE — the way OpenAI-compatible is used — with its licence stated only as Apache-2.0. R10 bounds the claims: no page says disaggregated, KV offload, or autoscaling as a k3sm capability."
        deliverables:
          - id: M16.4-d1
            done: false
            desc: "examples/mlx-fleet/values-k3sm.yaml: mirror image refs BY DIGEST (R12 — m16.0 asserts digests, never tags, because a tag can be repointed and these images carry cluster RBAC), etcd and NATS install off, kubernetes discovery, runtimeClassName: vm plus the placement stanza on the operator and the frontend, EXPLICIT MEMORY REQUESTS on both (the system-reserved carve-out is scheduling-only and jetsam picks the largest RSS, not the most important process, so a zero-request control-plane pod is admitted for free and then killed first), and sharedMemory: 0 until B287 records the medium: Memory verdict (R6). And examples/mlx-fleet/fleet.yaml: the guardrail stanza with mlx.k3sm.io/gpu in requests AND limits (the M8.5-d1 lesson) and memory request == limit == R5's slot floor, both gate-asserted."
          - id: M16.4-d2
            done: false
            desc: "docs/user/mlx-fleet.md, with R7's security section written honestly IN ITS OWN WORDS: the worker's grant is allow_network, which renders UNFILTERED network-outbound, -bind and -inbound under deny default (not the gloss that it dials one ClusterIP); same-node pods share one trust domain; co-resident workers on a multi-slot node are NOT isolated from each other; the vm control plane contains a compromised CONTROL-PLANE PROCESS only, and since every request crosses the native worker, END-TO-END UNTRUSTED-TENANT SERVING IS OUT OF SCOPE; and kine's port stays reachable from every networked pod until B289 lands. Plus the round-robin fallback under R3's substitution, the vm Service-only rule, the helm-uninstall and CRD-leftover runbook, and the upstream framework named once as a compatibility fact, never as the feature. AND the paragraph M8 called launch-critical and never shipped: the trusted-workloads-only statement written into docs/user/limitations.md and docs/user/mlx-quickstart.md, where limitations.md today disclaims MLX to its own page and the quickstart carries none of it."
          - id: M16.4-d3
            done: false
            desc: "ROADMAP.md: the public Future bullet this block's encoding lands (beside the autoscaling and distributed-inference bullets, stating its relation to both) is rewritten for what actually shipped, under R10's claim rules — and the site sentences land only after the M16 gate is green on the rig, never on the strength of a merged wave."
          - id: M16.4-d4
            done: false
            desc: "the upstream pin register is a WORKSPACE register (frontmatter pinned_upstream_commit, pinned_chart_version, pinned_runtime_wheel_sha256; advisory-only, no new sweep, re-pinning is an operator act under R2), so it is NOT written in this repo. The deliverable HERE is the k3sm-side reader that surfaces those three pins in the workspace Versions table, so a drifted pin is visible where every other external pin already is."
        acceptance:
          - id: M16.4-a1
            met: false
            check: "hack/verify-examples.sh --lint-only green over examples/mlx-fleet/; hack/verify-image-pins.sh accepts the values file (digests, never tags); docs/user/mlx-fleet.md carries the allow_network grant sentence, the co-resident-workers sentence and the out-of-scope sentence, and names the upstream framework exactly once as a compatibility fact; docs/user/limitations.md and docs/user/mlx-quickstart.md both carry the trusted-workloads paragraph; hack/ci.sh green"
            method: unit
      - id: M16.5
        title: the gate — the real m16.sh ladder, and the conditional lab row
        status: todo
        strategy: hard cut
        depends_on: []
        note: "The phases.json M16 row ships in this block's encoding as an honest always-red skeleton (manual:false, skeleton:true, the # K3SM-SKELETON sentinel pinned by TestNonManualSkeletonsAlwaysRed, because a CI-runnable gate's exit 0 is trusted as milestone proven); M16.5 replaces the body with the real ladder and flips skeleton to false IN THE SAME CHANGE, the M11.5/M15.3 precedent. The M16-lab row and hack/lab/m16.sh are written ONLY on the single-slot branch, where the routing rung needs a second node; on the two-slot branch no lab row is added and the milestone never reports complete-pending-lab."
        deliverables:
          - id: M16.5-d1
            done: false
            desc: "hack/acceptance/m16.sh gets its real ten-rung ladder, replacing the skeleton and flipping the phases.json skeleton flag in the same change: m16.0 preflight (a GPU node, the vm class, the examples on disk, and the MIRROR DIGESTS resolving); m16.1 chart install with the nine CRDs Established, the operator Ready as a vm pod, and memory requests present on the operator and the frontend; m16.1b the RBAC assertion re-asserted LIVE against the pinned grant (R11); m16.2 conversion — a v1alpha1 read of a v1beta1 object; m16.3 fleet.yaml applied, the worker Running, mlx.k3sm.io/gpu requests == limits and memory request == limit; m16.4 the worker named in the discovery metadata; m16.5 /v1/models; m16.6 a chat completion through the ClusterIP within a PLACEHOLDER BUDGET (TTFT at most 3x and tok/s at least 0.5x the hack/acceptance/m8.sh direct figure ON THE SAME MACHINE, tightened by a later milestone) with per-hop timing recorded (client to frontend, frontend to worker, engine), because a measured-but-unbounded metric is documentation and not a gate; m16.7 the conformance kit plus the in-process invariants test; m16.8 REQUIRED on the two-slot branch (SKIP-class only under R3's sidecar substitution, where round-robin is the documented contract) — scale the worker to 2 replicas on this node, both Running, which proves R5 live, then send a repeated prefix and assert FROM ROUTER METRICS that the second request went to the warm pod and that its TTFT beat the cold pod's by a recorded margin; m16.9 delete, with every fleet object gone, zero Terminating, and the M8 PVC untouched; m16.10 launchctl kickstart, re-run m16.1 through m16.6, and record the time to serving, because a kickstart kills every vm Pod and the restart cost is part of the deploy contract."
        acceptance:
          - id: M16.5-a1
            met: false
            check: "hack/acceptance/m16.sh exits 0 on the R16 rig (rungs m16.0 through m16.10, with m16.8 required unless R3's substitution was taken), the phases.json M16 row reads skeleton:false so TestNonManualSkeletonsAlwaysRed no longer selects it, and the run is recorded; hack/ci.sh green"
            method: integration
---

# k3sm — Phase roadmap

> Per-repo slice of the k3sm milestones (product design: `docs/DESIGN.md` §5c/§7/§9). The YAML
> frontmatter above is **authoritative**; this prose mirrors it. Status: ✅ done · 🟡 in-progress · ⛔ blocked · ⬜ todo.

`k3sm` is **Wave 3**: it imports all of `apis`, `runtimed`, `darwin-net` and assembles the distribution, so it
lands last in every wave and owns the end-to-end exit demos. **CGO is `CGO_ENABLED=1`** (runtimed's cgo probes; kine runs as a pinned child process, not embedded); keep the `replace google.golang.org/genproto` in `go.mod`.

## M0 — Walking skeleton ✅
Validated 2026-06-24: a native control plane runs on macOS/arm64, `k3sm node` registers a darwin Virtual
Kubelet node, and the `pkg/provider` HostProcess runtime executes a `kubectl`-applied Pod as a real native
process — zero Linux. Code: `cmd/k3sm/{main,node}.go`, `pkg/provider/hostprocess.go`.

## M1 — k3sm server + images + Services + DNS (single node) ✅
Landed 2026-06-25 (PR #1). As-built (correcting the original "in-process embed" design): M1.1 ships a
**child-process `Supervised` executor** (`pkg/executor`) — apiserver + scheduler + KCM + kine as supervised
child processes, prebuilt darwin/arm64 binaries + cgo-built kine, ad-hoc-signed, kine→SQLite WAL, scoped KCM
`--controllers`. The from-source in-process `Embedded` path is a deferred stub (`ErrEmbeddedNotImplemented`).
M1.2 provisions the `os=darwin` ValidatingAdmissionPolicy + the provider taint + kubelet-serving TLS. M1.3 wires
the runtimed image runtime behind a consumer-side `Runtime` interface (`--runtime` selects hostprocess|runtimed).
M1.4 hosts darwin-net's Service proxy + CoreDNS config via `pkg/netserve`. Note: `ConsistentListFromCache` is
GA-locked `true` on the pinned k8s v1.36.2; the lo0/DNS data-path leg is root-gated (asserted by
`hack/acceptance/m1.sh` on a capable host). Gate: `hack/acceptance/m1.sh`.

## M2 — Isolation, resources & pod-spec fidelity 🟡
The runtime-independent pod surface a real workload needs, on top of
the runtimed daemon split + isolation + resources work. **All k3sm sub-phases M2.0–M2.6 are done** (proven by
named unit tests at the seam, `-race` clean); only the workspace-root e2e gate `hack/acceptance/m2.sh`
(single-node confinement/OOMKill/pod-to-pod/in-pod-kubectl/exec, needs root on a Mac) remains for the
milestone. Sub-phases:
- ✅ **M2.0** — kubectl ergonomics: `k3sm kubectl` passthrough + `k3sm kubeconfig` print/`--write` merge into
  `~/.kube/config` (atomic + backup; refuses insecure-skip off loopback, embeds a CA via
  `--certificate-authority`). *Implemented + unit-tested on this branch; lands with it.*
- ✅ **M2.1** — provider translates volumes/mounts (configMap/secret/emptyDir/downwardAPI/projected-SA-token),
  downward-API env + `envFrom`, `securityContext`, `terminationGracePeriodSeconds` (apis:M2.1) + the paired
  `ContainerStatus` (lossless mirror). Env is resolved provider-side into literal values (runtimed reads only
  `EnvVar.value`); ConfigMap/Secret/SA-token + imagePullSecret data flow through the apiserver-backed
  `mount.Resolver`/`CredentialResolver` runtimed seams.
- ✅ **M2.2** — provider-served liveness/readiness/startup probes → conditions + endpoints + restart. `pkg/provider`
  runs a goroutine per (container, probe) bounded by the pod ctx, applies k8s threshold counting +
  startup-gates-liveness, overlays committed readiness onto the `Ready`/`ContainersReady` conditions (a NotReady
  pod drops from the EndpointSlice) and adds the liveness-driven restart count. Handlers: httpGet/tcpSocket/exec
  (named ports resolve via the `ports` table; dial host = bound pod IP). The provider owns the restart
  decision + count; the literal per-container re-exec rides the runtime `RestartContainer` RPC — the `restartFunc`
  seam, nil here, is wired at **M2.6**. Proven by `TestM2_{ReadinessGatesEndpoints,LivenessRestarts,StartupGatesLiveness,ProbeHandlers,ProbeThresholds}`.
- ✅ **M2.3** — runtimed `proc_pid_rusage` (`ri_phys_footprint`) → Summary API (`kubectl top`) via the optional
  `StatsSource` capability; memory limit rides the `k3sm.io/memory-limit-bytes` PodBox annotation (interim seam,
  superseded by the typed `PodBox.memory_limit_bytes` at **M2.6**); `terminationGracePeriodSeconds` →
  `DeletePodRequest.grace_period_seconds` (k8s 30s default applied when unset); `OOMKilled` surfaces verbatim.
  CPU = best-effort QoS, NOT CFS millicores.
- ✅ **M2.4** — in-cluster API access: the shared `kubeResolver` mints the projected SA token for the pod's
  **own** `spec.serviceAccountName` (was always `default`), bound per-CreatePod via the request context the
  provider threads to `mount.Materialize` in-process — no runtimed/apis seam change. The apiserver serving CA
  (`kube-root-ca.crt`) + namespace land at `/var/run/secrets/kubernetes.io/serviceaccount`; `kubernetes.default.svc`
  is reachable because `--advertise-address` defaults to loopback single-node (the in-process proxy reaches it;
  M3.3 rewrites per-node for a routable NodeIP). Authz under RBAC at M4; in-pod DNS needs the exec-shim. Proven by
  `TestM2_InPodKubectl`.
- ✅ **M2.5** — provider `RunInContainer`/`AttachToContainer`/`PortForward` (NotFound in M1) wired to the existing
  `runtime/v1` Exec/Attach/PortForward bidi RPCs behind a `StreamingRuntime` capability; `runtimed_exec.go` bridges
  the VK `AttachIO` (+ port-forward byte stream) to an in-process `streamPipe` (mirroring `watchStream`/`logSink`),
  mapping a non-zero exec exit to a `CodeExitError`. Frozen apis contract — no apis change. (runtimed's server verbs
  still return Unimplemented — runtimed:M2 — which the provider surfaces, not panics.) Proven by
  `TestM2_Exec`/`TestM2_Attach`/`TestM2_PortForward`.
- ✅ **M2.6** — consume the **apis:M2.2 typed contract** (the k3sm half of the swap): `translate.go` sets the typed
  `PodBox.memory_limit_bytes` + `qos_class` (`computePodQOS` reproduces the kubelet Guaranteed/Burstable/BestEffort
  classification → the apis `QOSClass` enum; the `k3sm.io/memory-limit-bytes` annotation stays as a transitional
  fallback); the probe runner's `restartFunc` seam is wired to `runtimedRuntime.restartContainer` → the
  `RestartContainer` RPC (a committed liveness failure re-execs the container, not just bookkeeping); and
  `GetStatsSummary` consumes the typed `ListPodStats` RPC (per-container `PodStats`/`MemoryStats`,
  footprint→working-set) in place of the in-proc `PodMetrics` path. Provider-side consume of a frozen apis contract
  — no apis/runtimed change. Proven by `TestTypedMemoryLimitWritten`/`TestProbeRestartInvokesRPC`/`TestStatsSummaryFromListPodStats`.

## M3 — Multi-node, mesh, NodePort & persistent storage 🟡
- ✅ **M3.0** — multi-node **worker** bootstrap + trust (the security Wave-0 core). `pkg/certs` stands up a real
  two-CA PKI — a **cluster CA** (the pinned serving anchor + kubelet-serving issuer) and a **signing CA**
  (system:node client-cert issuer) — with `VerifyPinnedChain` doing CA-hash-pinned join **without**
  `insecure-skip-tls-verify`. `pkg/bootstrap`: `k3sm token create` mints `K10<sha256(cluster-CA)>::<user>:<secret>`
  TTL-bounded tokens (bcrypt-hashed, identity `system:k3sm-bootstrap`, **never** `system:masters`); the
  anti-impersonation node-password is bcrypt-hashed + constant-time-compared + first-write-wins (local copy
  `0600`); the HTTP-CSR approver mints `CN=system:node:<name>, O=system:nodes` bound to the authenticated node +
  InternalIP (rejects a cross-node SAN); kubelet-serving certs are issued from the cluster CA; the MeshPeer
  write-guard lets a node write only its own peer (controller-mediated enroll). `k3sm agent --server --token`
  runs the pinned-CA join → writes a `system:node` kubeconfig (`0600`, cluster-CA-verified — **off** the admin
  token) → mesh-enrolls (writes its `MeshPeer`, apis net/v1) → drives darwin-net `mesh.New`/`NewWatcher`.
  `pkg/executor` binds the apiserver to the **wireguard mesh interface only** + `--anonymous-auth=false` +
  `--client-ca-file` (so M4's `Node,RBAC` flip is a pure authorizer switch) + `--kubelet-certificate-authority`
  + a cluster-CA-signed serving cert (gated on `k3sm server --mesh-ip`; single-node loopback/self-signed path
  unchanged). Proven by `TestCAHierarchyAndPinnedJoin`/`TestNodePasswordHashedConstantTime`/
  `TestCSRIssuesSystemNodeIdentity`/`TestJoinTokenTTLAndNotAdmin`/`TestMeshPeerWriteGuardOwnNodeOnly`/
  `TestApiserverFlagsMeshBindAnonOff` (`-race` clean). The live two-Mac join (+ MeshPeer CRD install, mesh utun
  bring-up, the apiserver secure-cutover boot) is the **K3SM_LAB** e2e leg. (HA server-join + the identical-CA
  bundle are **M6**.)
- ⬜ **M3.1** — wire darwin-net's NodePort (`*:nodePort`, TCP) — no apis change (NodePort already in `net/v1`).
- ⬜ **M3.2** — APFS local-path provisioner (PVC→PV via runtimed:M3, same-volume, decoupled lifecycle) +
  StatefulSet (stable storage+name; network identity needs per-pod IPs).
- ⬜ **M3.3** — per-node CoreDNS bound to the DNS VIP + node-local `kubernetes` endpoint so infra VIPs aren't
  blackholed over the mesh (with darwin-net:M3.3).
Exit (§9 M3): two Macs, one cluster, cross-node pod-to-pod + ClusterIP + a NodePort + a persistent StatefulSet.

## M4 — Install/launchd, packaging, Homebrew, hardening 🟡
- 🪦 **M4.0** — **DESCOPED 2026-07 → k3sm:M7.1** (release-engineering pipeline). The single-server packaging/launchd/
  install + codesign/notarize/`.pkg` + goreleaser → `k3sm-io/homebrew-tap` + admin-kubeconfig-to-`~/.kube/config`
  deliverable **and its reboot-survival acceptance transferred verbatim** to M7.1 (which carries `phases_ref: k3sm M4.0`);
  **no M4-scope work remains**. The retired "app-bundle-wrapped" **shape is NOT carried over** (retired by the DESIGN
  §5c/§8 app-bundle-retirement amendment — M7.1 is authoritative: raw-utun/pf, no app bundle, two signed artifacts
  `k3sm` + `k3sm-netd`). `M4.0-a1` stays `met:false` and flips **only** via the M7.1 `phases_ref` write-through when
  `hack/lab/m7.sh` greens in the M7 tail — so M4 does not falsely flip `done`. (NodeNetwork no-op recording convention.)
- 🟡 **M4.1** — RBAC enforcement (**hard cut**), CODE-COMPLETE + unit-proven. The apiserver default authorizer flips
  `AlwaysAllow → Node,RBAC` + the additive `NodeRestriction` admission plugin (`pkg/executor`); the flip is a **pure
  authorizer switch** because the VK node / provisioners keep the static admin token (`system:masters`, RBAC-exempt) and
  the scheduler + KCM carry their **own per-component client certs** (`system:kube-scheduler` /
  `system:kube-controller-manager`, #14) that the apiserver's bootstrap RBAC binds — the M4.1 **component-identity
  divergence**, since narrowed to the VK node + provisioning client. `pkg/rbac.Provision` (NEW; Create-tolerate-
  `AlreadyExists`, no watch-cache LIST-to-decide) lays down, **fail-closed before the node/join-supervisor start**, the
  **node-datapath ClusterRole** (`system:nodes` ⇒ read `services`/`endpointslices`/`meshpeers` — the grant the Node
  authorizer/stock `system:node` role do *not* give a joined worker, keeping its Service proxy + DNS + mesh watcher
  alive) + the minimal **in-pod reader** RoleBinding for the in-pod-kubectl reference SA. The MeshPeer write-guard stays
  **permanent** (`NodeRestriction` never covers the `net.k3sm.io/MeshPeer` CRD). Proven by `TestRBACNodeDatapathClusterRole`/
  `TestRBACInPodReaderBinding`/`TestRBACProvisionIdempotent`/`TestRBACProvisionFailClosed` + `TestApiserverArgsNodeRBAC`
  (`-race` clean). The **live authz flip** is the build-tagged `e2e/TestM4_RBACEnforced` (integration tier, dev Mac) —
  **M4.1-a1 stays `met:false`, integration-pending** (does not run in unit CI).
- 🟡 **M4.2** — the synthetic conformance gate, **authored + compile-verified + gate-wired** (live integration
  green owed). Per-criterion `TestM2_*`/`TestM3_*` funcs live in `e2e/` (`//go:build e2e`), invoked by
  `m<n>.sh` via the shared **non-vacuous guard** `hack/lib/conformance.sh` (enumerates the required criterion
  set; a missing/failed/**skipped** required criterion is RED — closing the old `-run` guard's partial-coverage +
  all-skip false-greens). The M3 gate is **split**: single-node `hack/acceptance/m3.sh` (integration, CI:
  NodePort + PVC-persist) vs two-Mac `hack/lab/m3.sh` (cross-node mesh/DNS, `K3SM_LAB=1`); `m4.sh` gives
  `TestM4_RBACEnforced` a CI home; `phases.json` gains `M3-lab`/`M4-lab` rows. **M4.2-a1 `met:false`
  (integration-pending** — the M2/M3 integration legs need a dev Mac + root).

## M5 — vm RuntimeClass (committed) ✅
Promoted from a stretch goal to a committed milestone to run stockkitty's **Linux-only** Postgres/pgvector
(the HYBRID decision — native arm64 for everything else). `runtimeClassName: vm` dispatches to runtimed:M5's
Virtualization.framework Linux micro-VM via the apis:M5.1 `runtime.k3sm.io` handler-config (mapping the value
to the existing `SANDBOX_BACKEND_VM`; the upstream `node.k8s.io/RuntimeClass` is consumed, not forked). Linux
guest images are digest-pinned (codesign/notarization is meaningless inside the VM); networking is vmnet/bridged
with a guest-side resolver (darwin-net:M5). Confirm the `com.apple.security.virtualization` entitlement against
DESIGN §5c.
- ✅ **M5.1-d1 (verifiable foundation, code-complete + unit-proven)** — the **provider RuntimeClass→backend
  dispatch**: `pkg/provider/translate.go` `toPodBox` reads `spec.runtimeClassName`, resolves it via the apis
  `runtimev1.DefaultHandlerConfig().Backend(handler)`, and stamps `SandboxProfile.Backend` — `vm` →
  `SANDBOX_BACKEND_VM` (+ `VmVcpus`/`VmMemoryBytes` guest sizing from the pod's cpu/memory, limit-else-request,
  `0`=VZ default), empty → `SANDBOX_BACKEND_UNSPECIFIED`, unknown → **fail closed** (`ErrUnknownHandler`). The
  empty→`UNSPECIFIED` default **fixes the architect-flagged `SEATBELT_EXEC`(=1)-vs-`SEATBELT_INPROC`(=2)
  mismatch** (was a hardcoded `EXEC`): runtimed's reworked `SelectBackend(UNSPECIFIED,…)` now picks the
  host-OS-gated rung. The **`vm` RuntimeClass + node-capability gate** (`pkg/runtimeclass`): an idempotent
  `node.k8s.io/v1` RuntimeClass `vm` (handler `vm`) with `scheduling.nodeSelector k3sm.io/virtualization`,
  provisioned in `cmd/k3sm/server.go` alongside RBAC/policy; the node label is sourced **fail-closed** from VZ
  availability (`cmd/k3sm/node.go` `applyVirtualizationLabel`/`nodeVMCapable`). **Cross-repo need reported (not
  faked):** runtimed's `GetRuntimeInfo` reports only the *selected* host-process backend's health, **not**
  per-backend (VZ) availability, so the label defaults **ABSENT** → a `vm` pod stays `Pending`/`Unschedulable`
  (correct for a non-VZ cluster, complementing runtimed's `SelectBackend` `ErrBackendUnavailable` backstop).
  Proven by `TestToPodBoxVMRuntimeClass`/`TestToPodBoxDefaultBackendUnspecified`/
  `TestToPodBoxUnknownRuntimeClassFailsClosed` + `TestVMRuntimeClassNodeSelector`/
  `TestVMRuntimeClassProvisionIdempotent` + `TestNodeVirtualizationLabel` (`-race` clean).
- ✅ **M5.1-d2 (lab remainder — needs a VZ Mac + the entitlement)** — the **live** VM dispatch: provider →
  darwin-net `podnet.Network.SetupGuest` → thread the `GuestNetwork` (guest IP/gateway/NAT-subnet/DNS-VIP) to
  runtimed's VZ backend → boot the Linux guest. darwin-net flagged **no transport for `GuestNetwork`** to
  runtimed yet — the clean fix is a runtimed consumer-side `supervisor.GuestNetwork` seam (no apis change).
  Plus the foreign-user VAP **exemption** for `runtimeClassName: vm` (deferred — observable only once the VM
  boots), the guest `resolv.conf` injection (pinned static/immutable), Rosetta-for-amd64, and the
  separate-binary virtualization-entitlement signing (M4.0 packaging).
Exit (§9 M5): a Linux image runs under `runtimeClassName: vm`, Service/DNS-reachable, beside native pods.
**DELIVERED 2026-09-01** — proven by `hack/lab/m11.sh` on a single entitled VZ Mac (M11 absorbed the M5 lab
remainder); `hack/lab/m5.sh` graduated into the M11 lab gate per the M4-lab precedent (re-point + skeleton
flip + old-script delete in one change).

## M6 — HA: multi-server control plane (last phase) 🟡
Moved here from M4 so HA is the **final** milestone (single-server is sufficient through M5; HA is the last,
most complex ops capability). Two sub-phases:
- 🟡 **M6.0** — kine→**Postgres** multi-writer datastore + HA **leader-election**, **CODE-COMPLETE + unit-proven**
  (live 2-server + soak are lab). **Strategy: phased (named exception: kine/SQLite datastore migration)** — but HA is
  **Postgres-from-init** (greenfield): the single-node kine→SQLite default is **byte-unchanged**, so there is **no
  live SQLite→Postgres data conversion** (an operator kine dump/restore is the only path; in-place conversion is out
  of scope). As-built: additive `Config.DatastoreEndpoint` (Postgres DSN; empty ⇒ the unchanged SQLite WAL default),
  the DSN **password kept off argv/logs** (relocated to a 0600 `PGPASSFILE` for the kine child, password-stripped DSN
  on `--endpoint`, 0600 component logs), a **posture-aware kine version** (`DefaultKineVersion` v1.14.2 stays for
  SQLite; `DefaultKineVersionHA` **v0.16.3** — a go-install-verified ≥0.15 release with the kine#577
  watch-progress-notify fix — for Postgres), a **fail-closed split-brain guard** (`Config.Validate` ⇒
  `ErrHARequiresDatastore` if an HA server has no datastore — never a per-server SQLite fallback), **leader election**
  (scheduler/KCM `--leader-elect` true only in HA so one server is active; only the apiserver is active/active), and
  **pinned pgx pool bounds** (kine's default is unlimited ⇒ 2×32 ≤ Postgres `max_connections` 100) + the
  **Postgres-SPOF** docs (operator-managed: pg_dump/PITR; write-latency tradeoff; HA = process redundancy, not
  datastore redundancy). Proven by `TestDatastoreEndpointSQLiteDefault`/`TestDatastoreEndpointPostgres`/
  `TestDatastorePasswordRelocation`/`TestKineVersionPostureAware`/`TestHARequiresDatastoreEndpoint`/
  `TestLeaderElectHAvsSingleNode`. The live two-server-on-Postgres write-A-read-B, the single-active-leader, the
  kill-A→serve-via-B failover, and the **kine#577 watch-staleness soak** (the production-trust gate) are
  `hack/lab/m6.sh` + `e2e/TestM6_*` (`K3SM_LAB=1`, 2 servers + Postgres).
- 🟡 **M6.1** — HA **server-join** + the **AES-256-GCM identical-CA bundle** (DESIGN §5c), **CODE-COMPLETE +
  unit-proven** (the live 2-Mac + Postgres join/failover is lab). **Strategy: phased (named exception: kine/SQLite
  datastore migration)** — same exception family as M6.0 (HA). Mimics k3s's datastore-bootstrap-key model.
  **Crypto core:** `certs.Hierarchy.Marshal/Unmarshal` serialize the four CA PEMs; `bootstrap.SealBundle/OpenBundle`
  AES-256-GCM-seal the opaque bytes (the seal stays in `bootstrap`, not `certs` — the `bootstrap→certs` edge would
  cycle). The key is **PBKDF2-HMAC-SHA256** (pinned 600k iters + a `crypto/rand` 128-bit salt) over a
  **machine-generated ≥256-bit server-bootstrap secret** (not a passphrase, not a worker token); a **fresh 12-byte
  `crypto/rand` nonce per seal** (never a counter); a **versioned, AAD-bound envelope** (magic+version+kdf-id+iters+
  salt+nonce as GCM AAD); a `gcm.Open` failure is **fatal** (tag verified before any plaintext). The sealed envelope is
  published to Postgres as a kube-system Secret (the k3s bootstrap-key model). **Server-class identity:** a server token
  `K10<caHash>::server:<secret>` (`system:k3sm-server-bootstrap`) **distinct** from the worker token; the CA-bundle
  endpoint (`/v1-k3sm/server-bootstrap`) authorizes the **server class only** — a leaked worker token can never
  reconstruct the signing CA. **Fail-closed server-join:** `k3sm server --server-join --server <url> --token` reuses
  the M3 `PinnedClient` to fetch the bundle, then **import-then-load** (decrypt → `WriteHierarchy` the PEMs into
  `PKIDir` → **then** `EnsureHierarchy` loads them); any fetch/decrypt/tag failure halts bring-up — it **never** mints
  divergent CAs. **Datastore-backed node-password store** (a kube-system Secret) shares the anti-impersonation binding
  across HA servers. **Client-side apiserver LB** (`pkg/loadbalancer`: server-set + health-check + pick-healthy + TCP
  forward, with `JoinResult.APIServers` plumbed) + an **admin kubeconfig using a signing-CA-issued `system:masters`
  client cert** (usable against any server). Proven by `TestCABundle{SealUnsealRoundTrip,WrongSecretFailsClosed,
  NonceUniquePerSeal,TamperedAADRejected}`, `TestServerTokenDistinctFromWorker`, `TestCABundleEndpointRejectsWorkerIdentity`,
  `TestServerJoin{ImportsBundleBeforeEnsureHierarchy,FailsClosedOnAbsentBundle}`, `TestNodePasswordSharedAcrossServersInHA`,
  `TestApiserverLBPicksHealthy`, `TestAdminKubeconfigUsesClientCert` (`-race` clean). Exit: 2 servers on shared Postgres;
  a second Mac joins reconstructing identical CAs; kill one → the cluster keeps serving (**lab** — `e2e/TestM6_SecondServerJoinsReconstructsCAs` + `hack/lab/m6.sh`, **M6.1-a1 `met:false`**).

## M7 — Release engineering for the public open-source launch ⬜
Ledger stub. `k3sm` is **M7-primary** (all six sub-phases); `apis`/`runtimed`/`darwin-net` carry small M7 entries (their `ci.yml`
+ `K3SM_CI_REQUIRE` `SkipUnless` conversions). **Strategy: hard cut** (release infra is additive) — the one
watchpoint is the **kine single-pin** (both pins → one modern ≥0.16.x, `CGO_ENABLED=0` pure-Go sqlite), a hard cut
only after datastore-compat is verified, else it escapes to the named kine/SQLite datastore-migration exception.
- ⬜ **M7.0** — validation-debt burn-down (human-at-hardware: m2/m3/m4.sh + `hack/lab/m3.sh` two-Mac + the B28
  dev-mac churn soak `hack/acceptance/m7/soak.sh` against the M7.1 kine pin). On completion M4 flips `done` on
  validation runs alone; the M6 lab gate ships documented **EXPERIMENTAL** (the M5 remainder was absorbed by M11, which shipped de-EXPERIMENTAL at v0.1).
- ⬜ **M7.1** — release-engineering pipeline (**absorbs M4.0**, `phases_ref: k3sm M4.0`): `setup.go` verify-then-use
  (build cp binaries from pinned k/k, ship under `libexec/` → root-owned `/Library/k3sm/bin` via a named `pkg/install`
  payload copy; fail-fast on a missing bundle); the kine single-pin + nocgo dep-lint; goreleaser + the two signed
  artifacts (`k3sm` `io.k3sm.server` entitlement trio / `k3sm-netd` `io.k3sm.netd` none); the tag-triggered release
  workflow (four sibling repos at one tag, four SHAs); SemVer `v0.x.y`. App-bundle retirement is a named DESIGN
  §5c/§8 + privilege-model edit.
- ⬜ **M7.2** — GitHub Actions CI: thin per-repo `ci.yml` wrapping `hack/ci.sh`; a nightly sudo-integration run under
  `K3SM_CI_REQUIRE` (self-skips turn red); self-hosted trigger allowlist; trufflehog + DCO required checks; the
  spicanary soft-fail deleted (canary failure fatal).
- ⬜ **M7.3** — user docs (`docs/user/` page manifest + `limitations.md` citing UPSTREAM-ALIGNMENT/privilege-model;
  `mlx-quickstart.md` authored here but gated by `m8.sh`); README refresh across all repos.
- ⬜ **M7.4** — website (Hugo on `k3sm-io.github.io`; stealth vanity dirs move byte-identical; docs single-sourced
  from k3sm at the latest tag; `/land` never touches the site repo).
- ⬜ **M7.5** — public-flip hygiene & security scrub (full-history secret sweep × 6, rotate-not-scrub; MAINTAINERS/
  SECURITY go real; `repo-settings.sh`; NOTICE verification).
Gate machinery: `hack/acceptance/m7.sh` is the single umbrella gate execing `hack/acceptance/m7/{ci,docs,hygiene}.sh`
(a directory **outside** the `m[0-9]*.sh` orphan glob); manual:false skeletons exit non-zero unconditionally; the
`M4-lab` row **re-points to `hack/lab/m7.sh`** (`hack/lab/m4.sh` deleted, B35 tombstoned). Launch itself is **M9**.

## M8 — MLX: native Apple-Silicon ML serving ✅
Ledger stub. **Launch-blocking** (launch
WITH MLX v1; `m8.sh` joins the launch-gate set — the public flip is M9). **Strategy: hard cut** (a NEW CRD group
`mlx.k3sm.io/v1alpha1` + reserved-band proto fields default-false). k3sm owns:
- ✅ **M8.0** — the five spikes **S1–S5** (`hack/spike/m8/`), **owner k3sm** (ratified 2026-08-29, m8-plan R23 — resolves
  the three-owner split and darwin-net's `k3sm:M8.0` edge), **agent-run on the lab Mac** (Apple M1-family, 64 GiB,
  `apple-gpu`), each spike committing a findings file as its evidence. **Entry-independent** — M8.1 does not wait on
  it; S1's two exit criteria (tokens under default-deny; HF weight download through the production datapath) are the
  **M8 go/no-go**, halting downstream per Res. 17. Standing lab guardrails bind every session (see the ledger note).
- ✅ **M8.3** — node extended resource + translate + Warn VAP: `configureNode` advertises `mlx.k3sm.io/gpu: 1` +
  labels **fail-closed** off runtimed GPUFacts (VZ-paravirtual discriminated); `translate.go` reads the GPU request
  from **limits** → `AllowGpu` and the egress annotation → `AllowInternetEgress`; a Warn VAP surfaces a hand-set
  egress annotation (single-trust-domain posture).
- ✅ **M8.4** — the `mlx-serve` runtime image (`hack/images/mlx-serve/`, uv-built `--require-hashes`,
  python-build-standalone + the S5-winner engine; `python3` Mach-O entrypoint; digest-pinned GHCR publish; weights
  never in-image). **Build path decided 2026-08-29** — no new build tool: host-staged uv tree on the build Mac →
  `k3sm build --format oci` (COPY-only, `FROM scratch`) → push via the narrow `k3sm image push` slice (**B189**). The
  GHCR publish workflow stays a **human-gated, M9-adjacent** deliverable (dormant-workflow-classified); pre-M9
  publishes run from the lab Mac with the digest recorded.
- ✅ **M8.5** — the `pkg/mlx` in-binary operator (MLXModel → StatefulSet + headless + ClusterIP Services, ownerRefs,
  `whenDeleted:Delete`, readiness-only probes, fixed guardrail stanzas, conditions-first status, SSA CRD ensure via a
  neutral `pkg/crdensure`, pre-render validation vs GPUFacts).
- ✅ **M8.6** — the `hack/acceptance/m8.sh` gate (`requires [dev-mac, apple-gpu, network]`; **no M8-lab row** — a GPU
  dev-mac covers it): pinned small model → Ready → OpenAI completion via ClusterIP → GC-clean per the deletion
  contract; **authors + gates** `mlx-quickstart.md` and `examples/mlxmodel.yaml` (R24, re-homed 2026-08-29 from M7.2/M7.3).
Prerequisite (runtimed M11.2-d7 — the OCI-layer unpacker, re-homed 2026-07-11 from M8.2-d0 with the
Linux-layer re-sequencing): the whole M8 product path is blocked on it; the MLX runtimed slice consumes it
via its **d7-only** depends edge (narrowed 2026-08-29 from the whole M11.2 wave — d1–d5 need only d7's output). k3sm's M8.3
consumes GPUFacts once M8.2 lands (B63 ships the plumbing against a stubbed fact source first).

## M10 — Kubernetes conformance hardening ⬜
Ledger stub. **Conformance HARDENING, not a certification:** k3sm **cannot** pass
Sonobuoy `[Conformance]` (it assumes Linux containers/cgroups/CNI/netns); M10 raises honest fidelity where the
Darwin substrate allows and documents every ceiling. **Corrected framing:** admission plugins are **already on**
(`supervised.go` additively adds `NodeRestriction` on top of upstream's default-on set), so the real P0 is audit
logging + the PSA cluster-default level + memory-only default objects, **not** "enable plugins"; per-pod IP is
**achievable-as-wiring** (the `NodeNetwork{}` no-op seam today, both paths report `podIP≈nodeIP`), not a platform
ceiling. **Strategy: hard cut** for the docs/ledger encoding; each runtime sub-phase carries its own anchor.
Every sub-phase is driven by the release/build process. Pull-forward M10.0/M10.1 (interleave with M7/M8, v0.1.1);
M10.2/M10.3/M10.4 are the post-launch **v0.2** headline.
- ✅ **M10.0** — apiserver conformance config (**hard cut (binary) + a PSA-enforce cutover**, Res.2): audit logging
  (a shipped policy at `level: Metadata`, `secrets`/`configmaps` pinned to Metadata/None as an ordered first-match
  rule → no Secret cleartext at rest; the gate asserts the LEVEL; 0600 + Seatbelt-denied + off the datastore
  volume, Res.4); PSA **baseline-warn first → enforce after a clean pre-flight scan** (argv-reversible cutover;
  conformance-surface + defense-in-depth, NOT the privilege boundary — the foreign-uid VAP + Seatbelt stay that,
  Res.2); a **memory-only** default LimitRange (memory IS enforced via the rusage sampler→OOMKill; no rejecting
  ResourceQuota, Res.5); the config files written idempotently in `provision()` **before** bring-up, apiVersion
  pinned to v1.36.2 (Res.3); verify webhook **delivery** through the proxy (Res.6). Proof = the M10.0 §-gate
  enforcement e2e (privileged pod → 403 + audit-event at the asserted level + a negative control; boot smoke-test),
  CI-integration-tier — the argv unit test is a supplementary build check (Res.6/9). Backlog B70/B71/B72.
- ⬜ **M10.1** — per-pod IP + DNS/StatefulSet identity (**phased — VK provider ↔ runtimed gRPC contract**, Res.1):
  replace `supervisor.NodeNetwork{}` with a **named-seam adapter** over `darwin-net/pkg/podnet.Network`, bridging
  the two `PodNetwork` interfaces (`string` ↔ `netip.Addr`), so `translate.go` reads back a distinct `/32`;
  darwin-net stays the sole node-`/24` allocator; **converge on the runtimed path** (the HostProcess `os/exec`
  path is REJECTED — no bind discipline → a cosmetic `/32`), which **likely flips the default runtime to
  runtimed** (HostProcess → a rootless-dev opt-in — the default-runtime-flip decision this sub-phase settles).
  Resolver record synthesis for per-pod-A / headless / SRV / PTR (split gate: server-side is CI-provable, in-pod
  SRV/PTR is a follow-on integration gate). Re-verdict + close **B5** in the same change (Res.7). Causal link
  (Res.12): per-pod `/32` removes the last L4 chokepoint → M10.4 can then only hint. Backlog B81 (`status: done` — the by-hand
  unblock happened and it shipped; this read `blocked` until 2026-07-31).
- ⬜ **M10.2** — workload-execution fidelity (**phased — apis proto change (consumer-first)** for the sidecar
  field, Res.8): native sidecars need a **`PodBox`/`Container` proto field** (the proto has no `restart_policy`
  field, `translate.go:507` drops it) — **apis-first / orchestrate**, never a `k3sm.io/*` annotation; live
  restartPolicy + CrashLoopBackOff wires the existing **B26**; Job/CronJob fidelity depends **B8**; DaemonSet is
  **toleration-injection ONLY** (never the `os=darwin` nodeSelector — "controller conformant / scheduling
  divergent", Res.7). Backlog B73/B74/B75/B76/B77/B78.
- ⬜ **M10.3** — Ingress + IngressClass + klipper-lite LoadBalancer (**hard cut**, additive `darwin-net/pkg/ingress`):
  an in-process userspace L7 reverse-proxy in its OWN package (reject a bundled Traefik), host/path routing +
  TLS-from-Secret fronting ClusterIP VIPs via the netd fd-passing seam; **specific-node bind** (netd rejects
  `*:80`); TLS keys **in-process-memory-only**, the IngressClass controller's Secret grant scoped to the
  referenced `tls[].secretName` (Res.10/12); `status.loadBalancer.ingress` = node IP (closes **B32**). Gate
  `hack/acceptance/m10-ingress.sh`. Post-launch v0.2 headline.
- ⬜ **M10.4** — NetworkPolicy (L4 subset) + honest-limit doc (**hard cut**, additive): a userspace-proxy dst-VIP
  allow/deny subset documented as **policy hint, not tenant isolation** (pod-to-pod over pod IPs bypasses the
  proxy; shared uid → isolation routes to `vm`); draws the M10.1→M10.4 causal link (Res.12).
Gate machinery: `hack/acceptance/m10.sh` (manual:false integration **skeleton**, always-red `# K3SM-SKELETON`
until real — its eventual non-skeleton form is a **composite** execing the M10 criteria) + `hack/lab/m10.sh`
(manual:true lab **skeleton**, the cross-node per-pod-IP / in-pod SRV/PTR slice). New conformance criteria are
authored as `t.Skip` TODOs (`e2e/`, **`TestM10_*`**-tagged, not `TestM2_*`/`TestM4_*`) and promoted into the
required `M2_CRITERIA`/`M4_CRITERIA` sets **only in the PR that lands them green** (Res.9). Register: elevate
`docs/UPSTREAM-ALIGNMENT.md` to a full-surface register (keep the 7-verdict legend verbatim, add only `🟡
planned+B#`, pin v1.36.2) + a new `docs/conformance-profile.md` (Res.7/10). Backlog B70–B81 (+ P3).

## Next
M3.0 (the multi-node bootstrap + trust core) is **done** (named unit tests, `-race` clean). Remaining M3:
**M3.1** wire darwin-net's NodePort, **M3.2** the local-path provisioner + StatefulSet, **M3.3** the per-node
CoreDNS + node-local `kubernetes` endpoint rewrite. The
live two-Mac join is the `K3SM_LAB` e2e leg (it also needs the MeshPeer CRD installed in the apiserver). M2's
only remaining item is the root e2e gate `hack/acceptance/m2.sh` (needs root on a Mac). **M4.1** (RBAC
enforcement) is now **code-complete + unit-proven** (`pkg/rbac` + the `Node,RBAC`+`NodeRestriction` apiserver
default); its sole remaining item is the live authz flip — the integration-tier `e2e/TestM4_RBACEnforced` on a
dev Mac (**M4.1-a1 `met:false`, integration-pending**). M4 still owes **M4.0** (packaging/launchd) and **M4.2**
(the conformance gate green in CI). **HA is M6 (last phase): M6.0 (kine→Postgres + leader-election) and M6.1 (HA
server-join + the AES-256-GCM identical-CA bundle) are both code-complete + unit-proven; the live 2-Mac + Postgres
write-A-read-B, single-active-leader, watch-staleness soak, second-server-join (identical CAs), and kill-A→serve-via-B
failover are the `hack/lab/m6.sh` / `e2e/TestM6_*` lab legs (`K3SM_LAB=1`, never auto-greened).**

## M11 — Linux containers & multi-arch (k3sm slice) ✅
`docs/m11-plan.md` is authoritative (encoded 2026-07-10; done 2026-09-01). M11 **de-EXPERIMENTALs the
`vm` RuntimeClass** — flipped early at v0.1 (its R29, 2026-09-01) for `linux/arm64`, single-node;
the published performance figures, `linux/amd64`, and the remaining ceilings are the v0.2 event.
**Hard cut.** The flip was **structurally lab-gated** (the full `hack/lab/m11.sh` ledger green on an
entitled VZ Mac against the release artifact + the R19(c) threat-terms sign-off) — never
unit-green-only.

### M11.4 — capability labels + image-platform annotation + B6 wiring + admission/docs ⬜
**Cross-repo dep:** `apis:M11.1` + `runtimed:M11.2` + `darwin-net:M11.3`.
**Deliverables** — frontmatter `M11.4-d1…d5`: d1 `k3sm.io/rosetta{,-linux}` labels (B1 pattern,
B94 delete-on-loss with its **own named k3sm test** — B103); d2 arch truthfulness via an injected
seam, both-legs table (B104; the k3sm binary stays darwin/arm64 — B105 is pod payloads, never an
Intel binary); d3 `k3sm.io/image-platform` → per-container stamp, pre-pull fail-closed for
annotated pods, **`ImagePullBackOff`/Pending** (never terminal Failed) for un-annotated mismatches;
d4 B6 producer wiring (`SetupGuest` **before** `toPodBox`, in-process `runtimed.Deps` carrier — no
proto field); d5 admission + docs (os=darwin incantation; the fsGroup VAP exemption is
**human-gated B112**, cited by name so no wave relaxes `pkg/policy/admission.go` ad hoc;
`limitations.md` vm rewrite with the published S1/S2/S3 figures and the honest ceilings).
Guest hostPath stays fail-closed pending human-gated B98 — stockkitty acceptance is
**PVC-backed PGDATA**.

### M11.5 — gate ⬜
`hack/lab/m11.sh` + `hack/acceptance/m11.sh` + the phases.json two-row shape (`M11`
integration-skeleton + `M11-lab` manual, requires vz+signing) land with M11's **first wave** (kept
out of the docs-only roadmap encoding). Lab legs per `docs/m11-plan.md` §M11.5 — incl. the
Service-consumed guest leg and the amd64 fail-closed leg; measured per-VM footprint files the B24
overhead reconcile. `hack/lab/m5.sh` graduates per the M4-lab precedent (re-point + skeleton flip +
old-script delete + B34 tombstone in one change).

## M16 — MLX serving fleet ⬜
`docs/m16-plan.md` is authoritative (encoded 2026-09-16). M16 makes k3sm a place where an
**upstream inference-serving control plane** — OpenAI-compatible frontend, worker discovery,
KV-cache-aware routing, multi-model deployment objects — runs over **native Apple-Silicon MLX
workers**. It is a **sibling of M8, not its successor**: `MLXModel` stays the one-object way to
serve one model, and the fleet layer sits above it. **Hard cut** — no proto, CRD-field, datastore
or mesh change anywhere in the milestone; the upstream CRDs are additive objects owned by their own
operator, and k3sm's single behavior change is a per-node capacity policy on the existing
`mlx.k3sm.io/gpu` extended resource. The whole ladder develops and gates on **one 8 GiB laptop
running its own single-node `k3sm server`** (the plan's R16), driven over ssh; every figure is
compared against `hack/acceptance/m8.sh` on that same machine, never against a bigger Mac's numbers.

What M16 demonstrates by "two workers sharing routing" is stated plainly, because the two are
easily blurred: it is **prefix-cache-aware routing** — two `mlx-worker` pods each hold their own
warm prefixes and the router steers a repeated prefix to the pod that already has it. One
sequence's KV cache shared between two processes mid-request is prefill/decode disaggregation,
which is NIXL-bound, Linux-only, and **out of M16** with only its seam named.

### M16.0 — spikes S0–S4 ⬜
Agent-run over ssh, `method: integration`, **never a lab session**: the `phases.json` `M16.0` row
is `manual: false` with `hack/spike/m16/run.sh` as its gate, so the spikes *are* the acceptance and
`findings-s0.md`…`findings-s4.md` are the write-back. **S0** proves the k3sm preconditions with no
framework in the picture: both webhook paths (validating **and** CRD conversion) through a
`clientConfig.service` ref onto a `runtimeClassName: vm` backend; two `vllm-mlx` engines as host
processes under a sustained 1 200-token load with percentiles; and the `vm`-guest → native-pod-IP
dial in both directions, whose two outcomes are equally consequential (reachable also means the
guest bypasses the proxy and the NetworkPolicy hint). **S1** is the documented macOS build with a
recorded Rust/maturin toolchain and an infrastructure-free `--discovery-backend file` smoke.
**S2** puts the control plane on k3sm GPU-free and records the operator `ClusterRole` verbatim.
**S3** decides the engine shape from the in-process `AsyncEngineCore`. **S4** is the worker end to
end. Every halt is binding and **every halt's substitution is pre-decided**, so no rung needs a
human to continue.

### M16.2 — node capacity + the conformance proofs ⬜
The leaves k3sm owes whether or not the fleet ships: **B286** both webhook-delivery tests with the
two register rows flipped together (proving one dispatch path proves nothing about the other's
failure surface), **B287** the `emptyDir{medium: Memory}` verdict on the native path, **B288** the
literal `gpuDeviceCount` replaced by a tested policy function over `GPUFacts` against the **wired**
ceiling with a cumulative fit check, and **B290** the operator RBAC grant pinned as a golden test.
`pkg/mlxfleet` gives the upstream GVK strings one home, and `k3sm status` gains a fleet row that
prints the capacity `N` and the per-slot memory floor. `B289` (the kine-port deny) is `runtimed`'s.

### M16.3 — the `mlx-worker` image ⬜
`hack/images/lib/pybuild.sh` is factored out of `mlx-serve` **first**, because two copies of the
staging logic drift and the lockfiles are what must not: `TestMLXImagesEnginePinLockstep` pins both
images to one `vllm-mlx` version. The upstream runtime wheel is **built on darwin** from the pinned
tag under a pinned Rust toolchain and maturin, with `assert_wheel_pin` comparing the just-built
sha256 to the recorded one **before** staging. That hash is a **reproducibility record, not
independent provenance** — no published darwin wheel exists to pin against — and the user doc says
so. The publish is the operator's, and its digest is what the example and the gate consume.

### M16.4 — example, docs, and the pin register ⬜
`examples/mlx-fleet/` carries digest-pinned mirror images, explicit memory requests on the
control-plane `vm` Pods (the system-reserved carve-out is scheduling-only; jetsam picks the largest
RSS, not the most important process), and `mlx.k3sm.io/gpu` in requests **and** limits with memory
request == limit. `docs/user/mlx-fleet.md` states the security posture in its own words — the
worker's grant is `allow_network`, which renders unfiltered network access under `(deny default)`;
co-resident workers are not isolated from each other; every request crosses the native worker, so
**end-to-end untrusted-tenant serving is out of scope** — and the trusted-workloads paragraph M8
called launch-critical, and never shipped, finally lands in `limitations.md` and
`mlx-quickstart.md`. The upstream framework is **named once as a compatibility fact, never as the
feature**.

### M16.5 — gate ⬜
`hack/acceptance/m16.sh` ships in this encoding as an honest always-red skeleton (`manual: false`,
`skeleton: true`, the `# K3SM-SKELETON` sentinel pinned by `TestNonManualSkeletonsAlwaysRed`) and
M16.5 replaces it with the real ten-rung ladder, flipping `skeleton` to `false` in the same change
— the M11.5 / M15.3 precedent. The ladder runs from preflight and mirror-digest resolution through
the chart install, the live RBAC re-assertion, conversion, the worker's guardrails, discovery,
`/v1/models`, a completion **inside a placeholder budget with per-hop timing**, the conformance
kit, the warm-prefix routing rung, deletion with zero `Terminating` objects, and a `kickstart`
re-run that records the time back to serving. The `M16-lab` row and `hack/lab/m16.sh` are written
**only** on the single-slot branch, where the routing rung needs a second node.

## Retroactive record — `pkg/datavol`, the data-volume feature ✅

**This is a retroactive record, not a forward-planned phase.** Every milestone above it was
named in advance by a `phases:` entry and, for the larger ones, a `docs/m<n>-plan.md`. This
feature was neither: it shipped through three ordinary reviewed PRs with no milestone number and
no plan document of its own, and it is written up here, after the fact, only so `docs/PHASES.md`
stops being silent about ~2,600 LOC of shipped, tested product code. It is deliberately **not** a
numbered `M<n>` (M0–M16 are all claimed, and there is no plan to justify minting `M17`), **not** a
`phases:` YAML entry, and it is **not** folded into M7.1's deliverable list — M7.1 is the release
packaging phase and predates this feature; it never scoped it.

**Shape.** `sudo k3sm install --data-volume[=SIZE]` puts the k3sm data root (`/var/lib/k3sm`) on a
dedicated, k3sm-owned APFS volume instead of a plain directory on the boot disk — quota'd
(`--data-volume-size`, 100 GiB default, 32 GiB floor) and optionally encrypted
(`--data-volume-encrypt`, a random passphrase generated locally and kept in the login keychain).
Three `k3sm datavol` subcommands manage the volume directly: `mount` (idempotent; what the
`io.k3sm.datavol` oneshot LaunchDaemon runs at boot), `status` (human and `-o json`: the volume,
its quota, its usage, and any leftover pre-migration copy), and `datavol delete --yes` (the
package's one destructive path, gated behind an explicit confirmation and a check that neither
`io.k3sm.netd` nor the server daemon is loaded). `k3sm status` carries a `datavol` row — `ok` once
the volume has mounted, `fail` if the last run did not, with a `sudo k3sm datavol mount` remedy.
See `docs/user/storage.md` §"The Data Volume" for the operator-facing description this record
backs.

**Commits** (from `git log`, not the README):
- `2524670` (#372, 2026-09-14) `feat(install): put the data root on a k3sm-owned APFS volume` — the
  feature's birth: `pkg/datavol` (create/adopt/mount/migrate/delete/fstab/plist/size, plus the
  guard and indexing helpers, all over three fakeable seams — Volumes, Keychain, Indexing — with
  `datavoltest.Fake` the one exported double), the `dataroot.Record` second-declaration source, the
  three `k3sm datavol` subcommands (`cmd/k3sm/datavol.go`), the `install --data-volume*` flag
  family, and every `_test.go` file this record cites.
- `d531e55` (#391, 2026-09-17) `feat(status): report the agent daemon and its credential on a
  worker` — a broader worker-role status change (not datavol-specific) that threaded a
  `dataroot.Role` parameter through the datavol status surface (`dataRootRow`, `installRow`); it
  touched `pkg/status/datavol_test.go`'s call sites but added no new datavol test function.
- `4e742d6` (#427, 2026-09-17) `fix(status): render no control-plane rows on a worker` — the same
  worker-status line of work, again updating `pkg/status/datavol_test.go`'s call sites for the
  role-aware signature; also added no new datavol test function.

**Evidence, per capability.** 23 test functions in total, across `pkg/datavol/*_test.go`,
`cmd/k3sm/datavol_test.go`, `pkg/install/datavol_test.go` and `pkg/status/datavol_test.go`:
- creating or adopting the volume, never taking over one that is not k3sm's and never leaving one
  behind that it decided not to keep: `TestEnsureCreatesOrAdopts`.
- the destructive path's gates (no confirmation, a loaded daemon) and its actual sequence (mount,
  volume, fstab line, record and mount point, in that order): `TestDeleteRefuses`,
  `TestDeleteSequence`.
- the second, fstab, declaration — added on creation, left untouched on adoption:
  `TestEnsureFstabLine`, `TestRemoveFstabLine`.
- the two Spotlight/indexing markers, run against a real temp directory because the obvious tools
  (`mdutil`, `tmutil`) do not work on a `nobrowse` volume: `TestIndexingMarkers`.
- migrating a plain data root onto the volume, fail-safe on any verification gap — a lost file, a
  byte mismatch, or an outright copy failure all destroy the new volume and change nothing:
  `TestMigrateFailsSafe`.
- the idempotent boot-time mount, including a locked encrypted volume unlocked from the keychain
  and a transient-vs-permanent `diskutil` failure split, plus refusing an implausible or mismatched
  mount point: `TestMountRecordedIsIdempotent`, `TestMountRecordedRefuses`.
- the `security` CLI plist-dict parsing seam, and the `ParseSize`/`FormatSize` pair the
  `--data-volume-size` flag and the `status` text screen both use: `TestPlistDictReader`,
  `TestParseSize`, `TestFormatSize`.
- the `install --data-volume*` flag contract — defaults, refusals, and "no flag touches no disk":
  `TestInstallFlagsDataVolume`.
- `k3sm datavol status`'s machine (`-o json`) and human shapes, and which probe (`statfs` vs. APFS
  container capacity) its usage figure comes from — `statfs` answers the quota-less case wrong on a
  shared APFS container: `TestDatavolStatusJSONShape`, `TestDatavolStatusUsedSource`.
- `install`'s ordering of the data-volume block relative to `EnsureServiceUser` and the daemon
  plists, and the `io.k3sm.datavol` oneshot LaunchDaemon's boot contract (root, `RunAtLoad`,
  `KeepAlive` only on failure, throttled): `TestInstallWithDataVolumeSequencing`, `TestDatavolPlist`,
  `TestRenderPlistKeepAliveOnFailure`.
- the `k3sm status` `datavol` row across a quota'd volume, a pre-volume leftover copy, a legacy
  fstab-only device, and the oneshot daemon's own row (which must not read a completed oneshot as a
  failure): `TestDataRootRowNamesVolume`, `TestPreVolumeRowPartialWalk`,
  `TestDataRootRowLegacyDevice`, `TestOneshotRow`, `TestInstallRowCountsDatavolPlist`.

**Method, honestly.** All 23 tests above are **unit-tier**: they run against the
`datavoltest.Fake` double (its `Volumes`/`Keychain`/`Indexing` seams) or an in-memory/temp-dir
filesystem — never against a real `diskutil`, a real Keychain, or a real APFS volume. The real-APFS
proof lives in `hack/acceptance/B248.sh`'s `K3SM_LAB=1` tier (rungs L0–L6: create, quota with the
block-boundary tolerance, encrypt via the System keychain, mount, migrate a 200-file tree with a
hash-verified datastore copy, delete — trap-armed cleanup and UUID-scoped teardown), first run
green on the rig 2026-09-14 with a security sign-off, re-run green at head on a lab machine
2026-09-24 (35/35, no leftover volumes). An earlier revision of this record claimed no such gate
existed; that was wrong — the lab rungs live in `hack/acceptance/`, not `hack/lab/`, and the
correction is this sentence. CI still runs only the unit tier; the lab tier stays opt-in.
