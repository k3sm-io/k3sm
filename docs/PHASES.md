---
repo: k3sm
schema: phases/v1
current_phase: M6
updated: 2026-06-27
updated_by: orchestrator

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
            check: a pod without the os=darwin selector is rejected by admission; kubectl logs work over the proxy (non-follow)
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
    status: in-progress
    note: "All k3sm sub-phases M2.0–M2.6 are done (proven by named unit tests at the seam, -race clean); only the workspace-root e2e gate hack/acceptance/m2.sh (single-node confinement/OOMKill/pod-to-pod/in-pod-kubectl/exec, needs root on a Mac) remains for the milestone."
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
    status: in-progress
    note: "M3.0 (multi-node bootstrap + trust core) done. M3.1/M3.2/M3.3 are now CODE-COMPLETE + unit-proven + workspace-integration-green (hack/ci.sh), under the user-space netd-helper posture: M3.1 NodePort (direct wildcard *:nodePort >=1024 in-process — NOT via the helper; +honest-gap Warn admission for externalTrafficPolicy:Local & UDP) ; M3.2 local-path provisioner (pure API-object controller, Retain SC, UID-named PV + nodeAffinity) + StatefulSet (storage+name identity; network identity gapped — needs per-pod IPs) ; M3.3 worker netserve bringup + per-node DNS resolver on the DNS VIP + infra-VIP exemption + mesh-egress source + Seatbelt egress VIPs threaded. DIVERGENCE (open, documented): the per-node resolver is an IN-PROCESS A-record+forward server, NOT CoreDNS-the-binary (darwin-net has no embeddable DNS and CoreDNS can't inherit the helper-passed fd under launchd) — no SRV/PTR/headless, IPv4-only; full CoreDNS parity is a follow-up tied to the per-pod-IP gap. The SOLE remaining acceptance is the live two-Mac K3SM_LAB e2e (hack/lab/m3.sh: NodePort reachable, StatefulSet persistence, in-pod kubectl+DNS on the joined node) — never auto-greened. Open production-trust gate: the kine bump-vs-soak decision before PV/PVC under load."
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
        status: in-progress
        deliverables:
          - id: M3.1-d1
            done: true
            desc: "surface darwin-net:M3's NodePort listener (*:nodePort, TCP) through the server so a NodePort Service is reachable on the host port — no apis change (ServicePort.NodePort already exists). Bound as a DIRECT wildcard *:nodePort in-process (>=1024; NOT via the netd helper, which rejects wildcards); apiserver pins --service-node-port-range 30000-32767 so the unprivileged _k3sm proxy binds it; <1024 NodePort unsupported. Honest-gap Warn VAPs added: externalTrafficPolicy:Local (userspace splice doesn't preserve client src IP) and UDP Service ports (no UDP datapath yet); foreign-user Deny VAP extended to runAsGroup/supplementalGroups/ephemeralContainers. UDP NodePort deferred with darwin-net's UDP relay. CODE-COMPLETE + unit-proven; live reachability is the lab e2e."
        acceptance:
          - id: M3.1-a1
            met: false
            check: a Deployment behind a NodePort Service is reachable on *:nodePort
            method: e2e
      - id: M3.2
        title: APFS local-path provisioner + StatefulSet
        status: in-progress
        deliverables:
          - id: M3.2-d1
            done: true
            desc: "a local-path provisioner controller watches PVCs and provisions a PV via runtimed:M3 (stable per-PVC dir on the same APFS volume as /var/lib/k3sm, empty-create, lifecycle decoupled from the pod dir, honors ReclaimPolicy); StatefulSet support — stable STORAGE + NAME identity on the hostprocess runtime; stable NETWORK identity requires per-pod IPs (runtimed M2 path)."
        acceptance:
          - id: M3.2-a1
            met: false
            check: a StatefulSet + PVC writes data, the pod restarts, and the SAME data is present (persistence across restart)
            method: e2e
      - id: M3.3
        title: Per-node CoreDNS + node-local kubernetes endpoint (infra-VIP mesh exemption)
        status: in-progress
        deliverables:
          - id: M3.3-d1
            done: true
            desc: "per-node DNS resolver bound to the DNS VIP + node-local kubernetes endpoint (with darwin-net:M3.3) so infra VIPs (10.43.0.1/10.43.0.10) are never steered over the wireguard mesh where no peer's AllowedIPs covers them. Implemented: worker netserve bringup (runAgent now builds the proxy+resolver post-enroll so the mesh-egress source is known); the proxy steps aside for the DNS VIP via WithInfraVIPExemptions while OWNING the API VIP 10.43.0.1:443 (L4-forward to the apiserver endpoint over the mesh with WithMeshEgressSource — pod keeps dialing 10.43.0.1 so the serving-cert SAN holds; default/kubernetes is NOT mutated — the lease reconciler owns it); the <1024 DNS/API VIP binds go through the netd helper BindPort (specific address); per-pod Seatbelt egress scoped to the real DNS VIP (10.43.0.10) + API VIP (10.43.0.1:443) via runtimed Posture. DIVERGENCE: the resolver is IN-PROCESS (A-record + upstream forward, IPv4-only, no SRV/PTR/headless), NOT CoreDNS-the-binary — darwin-net exposes no embeddable DNS server and CoreDNS can't inherit the helper-passed socket fd under launchd; documented in pkg/netserve. CODE-COMPLETE + unit-proven; the cross-node in-pod kubectl+DNS is the lab e2e."
        acceptance:
          - id: M3.3-a1
            met: false
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
        title: Packaging + launchd + install (single-server)
        status: todo
        deliverables:
          - id: M4.0-d1
            done: false
            desc: "app-bundle-wrapped root LaunchDaemon + k3sm install/uninstall (launchctl bootstrap/kickstart); codesign + notarize + .pkg (raw root utun/pf, no NE); goreleaser → k3sm-io/homebrew-tap; admin kubeconfig dropped to ~/.kube/config on install (k3sm kubeconfig --write). Single-server datastore (kine→SQLite); multi-server HA is M6 (last phase)."
        acceptance:
          - id: M4.0-a1
            met: false
            check: brew install → sudo k3sm install server → cluster; survives reboot (launchd)
            method: e2e
      - id: M4.1
        title: RBAC enforcement (AlwaysAllow → Node,RBAC)
        status: in-progress
        strategy: hard cut
        deliverables:
          - id: M4.1-d1
            done: true
            desc: "the apiserver default authorizer flips AlwaysAllow → Node,RBAC + the additive NodeRestriction admission plugin (pkg/executor Config.AuthorizationMode default Node,RBAC; --enable-admission-plugins=NodeRestriction; --anonymous-auth=false retained). The flip is a PURE authorizer switch: the in-process VK node / scheduler / KCM / provisioners / enroller keep the static admin token (system:masters, RBAC-exempt) — a documented component-identity divergence (moving them to component certs is deferred, would break the pure-switch property). pkg/rbac.Provision (NEW package; Create-tolerate-AlreadyExists, never a watch-cache LIST-to-decide under kine v1.14.2 ConsistentListFromCache=true) provisions ONLY k3sm-named objects — it NEVER creates/mutates the apiserver's auto-reconciled system:* defaults: (1) a node-datapath ClusterRole + ClusterRoleBinding to the system:nodes group granting get/list/watch on services (core) + endpointslices (discovery.k8s.io) + meshpeers (net.k3sm.io) — THE fix that keeps a joined worker's Service proxy + DNS resolver + mesh watcher (system:node:<name>) alive after the flip, since the Node authorizer/stock system:node role grant none of these; (2) the minimal in-pod reader Role+RoleBinding for the in-pod-kubectl reference SA (default/snapshot-manager, exported constants) so the M2 in-pod-kubectl path stays green under default-deny. FAIL-CLOSED: runs in cmd/k3sm/server.go's step-3 slot (apiserver healthy, BEFORE startNode + the bootstrap-join server so worker bindings pre-exist) with a bounded retry; a provisioning failure halts bring-up, NOT the log-and-continue admission pattern. The MeshPeer write-guard (bootstrap.AuthorizeMeshPeerWrite) stays load-bearing + PERMANENT (NodeRestriction is core-resource-only, never covers the net.k3sm.io/MeshPeer CRD). On multi-node the kickstart rolls node-by-node, control-plane Mac last, bindings pre-existing so no node is denied mid-roll (no binary-version skew → not the rolling-restart exception). Proven by TestRBACNodeDatapathClusterRole / TestRBACInPodReaderBinding / TestRBACProvisionIdempotent / TestRBACProvisionFailClosed (pkg/rbac) + TestApiserverArgsNodeRBAC (pkg/executor), -race clean."
        acceptance:
          - id: M4.1-a1
            met: false
            check: "INTEGRATION-PENDING (needs a running apiserver on a dev Mac — does NOT run in unit CI). The unit tests prove the RBAC GRAPH (the ClusterRole/RoleBinding objects + read verbs + system:nodes subject) + the apiserver args (Node,RBAC default + NodeRestriction). The live flip is the build-tagged e2e/TestM4_RBACEnforced: a self-issued CN=system:node:<name>,O=system:nodes cert is DENIED a cross-node Node write + a non-granted verb but AUTHORIZED for the services/endpointslices/meshpeers datapath reads; a restricted SA (the conformance in-pod reader SA) is allowed its granted verb and denied secrets. The admin + control-plane SAs remain authorized (system:masters) across the flip."
            method: integration
      - id: M4.2
        title: Synthetic conformance gate in CI
        status: in-progress
        note: "M4.2-d1 is AUTHORED + compile-verified (CGO_ENABLED=1 go vet -tags e2e ./e2e/...) + gate-wired; the LIVE green is integration-tier (dev Mac + root), so M4.2-a1 stays met:false (integration-pending) — NOT faked. Per-criterion TestM2_*/TestM3_* funcs live in e2e/ (e2e/m2_test.go, e2e/m3_test.go; helpers e2e/testdata/cmd/{hello-http,conftool}; e2e/main_test.go builds+signs them in TestMain only when $KUBECONFIG is set). The M3 gate is SPLIT: a new single-node hack/acceptance/m3.sh (integration, CI: NodePort + PVC-persist, runtimed+--network direct) vs the two-Mac hack/lab/m3.sh (cross-node mesh/DNS, K3SM_LAB=1); phases.json gains M3-lab/M4-lab rows de-conflating integration from lab. A new non-vacuous guard (hack/lib/conformance.sh) ENUMERATES the required criterion set and turns RED on any missing/failed/SKIPPED criterion — closing the old m2.sh -run guard's PARTIAL-coverage + ALL-SKIP false-greens. The M4 RBAC integration assertion (TestM4_RBACEnforced) gets a CI home in a new non-root hack/acceptance/m4.sh. Name drift fixed: canonical TestM3_PVCPersistsAcrossRestart (hack/lab/m3.sh)."
        deliverables:
          - id: M4.2-d1
            done: true
            desc: "the stockkitty-driven synthetic conformance set runs as build-tagged per-criterion Go tests in e2e/ (//go:build e2e), invoked by m<n>.sh via the shared non-vacuous guard hack/lib/conformance.sh: M2 (ConfigMap/Secret-mode-0400/EmptyDir/DownwardAPI==podIP/EnvFrom/Probes-transitions/FsGroup/GracefulStop/OOMKilled/KubectlTop/InPodKubectl/InPodDNS/DenyUsers + deferred-skipped ImagePullSecrets/DaemonSet) + M3 single-node (NodePort, PVCPersistsAcrossRestart) at the integration tier (CGO_ENABLED=1), M3 cross-node (InPodKubectlAndDNSOnWorker) + M5 lab-tiered (K3SM_LAB=1). Helper images hello-http+conftool built+ad-hoc-signed by TestMain. See docs/stockkitty-readiness.md for the assertion→feature mapping. AUTHORED + compile-verified + gate-wired this session; the live integration run is owed (a1)."
        acceptance:
          - id: M4.2-a1
            met: false
            check: "INTEGRATION-PENDING (needs a dev Mac + root; does NOT run in unit CI). hack/acceptance/m2.sh and the new hack/acceptance/m3.sh exit 0 in CI with EVERY required criterion PASS (non-vacuous guard: a missing/failed/skipped required criterion is RED), and the conformance assertions map to stockkitty features. Authored + compile-verified + gate-wired; the live green is the M2/M3 integration legs on a capable host."
            method: integration

  - id: M5
    title: vm RuntimeClass — Virtualization.framework Linux micro-VM (committed)
    status: in-progress
    note: "M5.1 VERIFIABLE FOUNDATION code-complete + unit-proven (the live VM boot is the lab remainder, never auto-greened). The provider RuntimeClass→backend dispatch landed (pkg/provider/translate.go toPodBox reads spec.runtimeClassName, resolves it via apis runtimev1.DefaultHandlerConfig().Backend, stamps SandboxProfile.Backend: vm→VM + VmVcpus/VmMemoryBytes guest sizing, empty→UNSPECIFIED, unknown→fail-closed) — this also FIXED the architect-flagged EXEC(=1)-vs-INPROC(=2) mismatch: the default is now UNSPECIFIED (was a hardcoded SEATBELT_EXEC), so runtimed's reworked SelectBackend(UNSPECIFIED,…) picks the host-OS-gated rung. The vm RuntimeClass (pkg/runtimeclass) + node-capability gate are provisioned idempotently: a node.k8s.io/v1 RuntimeClass vm (handler vm) with scheduling.nodeSelector k3sm.io/virtualization, and the matching node label sourced fail-closed from VZ availability. CROSS-REPO NEED REPORTED (not faked): runtimed's GetRuntimeInfo reports only the selected host-process backend's health, NOT per-backend (VZ) availability, so the node label defaults ABSENT → a vm pod stays Unschedulable (correct for a non-VZ cluster). The live VM leg (M5.1-d2) needs a VZ Mac + the com.apple.security.virtualization entitlement."
    depends_on:
      - apis:M5.1
      - runtimed:M5
      - darwin-net:M5
    subphases:
      - id: M5.1
        title: runtimeClassName=vm dispatch + Linux image + vmnet assembly
        status: in-progress
        deliverables:
          - id: M5.1-d1
            done: true
            desc: "VERIFIABLE FOUNDATION (unit-proven): the provider dispatches a pod by RuntimeClass to runtimed:M5's backend via the apis:M5.1 handler-config — pkg/provider/translate.go toPodBox reads spec.runtimeClassName and resolves runtimev1.DefaultHandlerConfig().Backend(handler), stamping SandboxProfile.Backend: runtimeClassName=vm → SANDBOX_BACKEND_VM (and VmVcpus from ceil(summed cpu milli) + VmMemoryBytes from summed memory, limit-else-request across regular containers, 0=VZ default); empty/no RuntimeClass → SANDBOX_BACKEND_UNSPECIFIED (NOT a hardcoded seatbelt rung — this FIXES the architect-flagged EXEC=1-vs-INPROC=2 mismatch, letting runtimed's reworked SelectBackend(UNSPECIFIED,…) pick the host-OS-gated rung); an unknown handler FAILS CLOSED (toPodBox returns an error wrapping runtimev1.ErrUnknownHandler — never a silent downgrade). The upstream node.k8s.io/RuntimeClass is consumed, not forked. pkg/runtimeclass.Provision idempotently lays down the node.k8s.io/v1 RuntimeClass vm (handler vm) with a scheduling.nodeSelector pinning it to k3sm.io/virtualization-labelled nodes (provisioned in cmd/k3sm/server.go alongside RBAC/policy, log-and-continue); cmd/k3sm/node.go sources the node label from the node's VZ availability via applyVirtualizationLabel(n, nodeVMCapable()). REPORTED cross-repo need (not faked): runtimed's GetRuntimeInfo reports only the selected host-process backend's health, NOT per-backend (VZ) availability, so nodeVMCapable() defaults false → label ABSENT → a vm pod stays Pending/Unschedulable (fail-closed, complementing runtimed's SelectBackend ErrBackendUnavailable backstop). Proven by TestToPodBoxVMRuntimeClass / TestToPodBoxDefaultBackendUnspecified / TestToPodBoxUnknownRuntimeClassFailsClosed (pkg/provider) + TestVMRuntimeClassNodeSelector / TestVMRuntimeClassProvisionIdempotent (pkg/runtimeclass) + TestNodeVirtualizationLabel (cmd/k3sm), -race clean."
          - id: M5.1-d2
            done: false
            desc: "LAB REMAINDER (needs a VZ Mac + the com.apple.security.virtualization entitlement): the LIVE vm dispatch — provider → darwin-net podnet.Network.SetupGuest for the guest network → thread the GuestNetwork (guest IP/gateway/NAT-subnet/DNS-VIP) to runtimed's VZ backend → boot a digest-pinned Linux guest (not Mach-O ⇒ codesign/notarization N/A inside the VM; the guest kernel/initramfs is the notarized host asset). darwin-net flagged there is NO transport for GuestNetwork to runtimed yet — the clean fix is a runtimed consumer-side supervisor.GuestNetwork seam (no apis change). Plus: the M4.1 foreign-user VAP should EXEMPT runtimeClassName=vm (a vm guest CAN honor a foreign runAsUser/fsGroup — deferred, observable only once the VM boots); the guest resolv.conf injection (pinned static/immutable per darwin-net's caveat); Rosetta-for-amd64; and the separate-binary virtualization-entitlement signing (M4.0 packaging). This is what runs stockkitty's Linux-only Postgres/pgvector. Also needs the reported runtimed GetRuntimeInfo per-backend-availability extension so the node VZ label can be set truthfully."
        acceptance:
          - id: M5.1-a1
            met: false
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
            desc: "kine→Postgres multi-writer datastore + HA leader-election (mimicking k3s's external-datastore HA — 2+ servers share ONE Postgres, the single source of truth, NO etcd quorum; the single-node default stays SQLite). pkg/executor: ADDITIVE Config.DatastoreEndpoint (a Postgres DSN) — empty (zero value) keeps the kine→SQLite WAL default BYTE-UNCHANGED (single-node M1–M5 untouched), non-empty points kine at Postgres via pgx; the apiserver still talks to the LOCAL kine (--etcd-servers 127.0.0.1:<KinePort>), each server runs its own kine against the shared Postgres (the k3s topology). SECRET HANDLING: the DSN password never lands on argv or a log — it is relocated to a 0600 PGPASSFILE handed out-of-band to the kine child (pgx reads it via the libpq env fallback), only the password-stripped DSN reaches kine's --endpoint, and component logs are tightened to 0600. POSTURE-AWARE kine version (the deferred bump-vs-soak decision, resolved via k3s): SQLite stays DefaultKineVersion=v1.14.2 (UNCHANGED, zero migration risk for the installed base), Postgres-HA pins DefaultKineVersionHA=v0.16.3 — a real, go-install-verified ≥0.15 release carrying the kine#577 watch-progress-notify fix (defaults --watch-progress-notify-interval=5s + --emulated-etcd-version=3.6.11; greenfield-from-init, so no SQLite→newer-kine upgrade). SPLIT-BRAIN GUARD (fail-closed): Config.Validate rejects an HA server (ServerJoin) without a DatastoreEndpoint (ErrHARequiresDatastore) — a 2nd server can NEVER silently fall back to its own SQLite. LEADER ELECTION: scheduler + KCM --leader-elect is Config-gated (false single-node — unchanged; true in HA so only one server's scheduler/KCM is active — two would double-bind/double-reconcile); only the apiserver is active/active; the leader-election Leases are authorized by the components' system:masters admin token + the apiserver's auto-created system:* bootstrap RBAC (no new pkg/rbac object). pgx POOL BOUNDS pinned (kine's default is UNLIMITED): 32 max-open/server so 2×32 ≤ Postgres default max_connections (100) + idle/lifetime; doc.go documents Postgres as the operator-managed datastore SPOF (pg_dump/PITR runbook, no _busy_timeout analog → operator statement/lock timeouts, local-WAL-sub-ms→network-RTT write tradeoff; HA buys process redundancy, not datastore redundancy). cmd/k3sm server grows --datastore-endpoint (or $K3SM_DATASTORE_ENDPOINT, off k3sm's own argv) + --server-join. Proven by TestDatastoreEndpointSQLiteDefault / TestDatastoreEndpointPostgres / TestDatastorePasswordRelocation / TestKineVersionPostureAware / TestHARequiresDatastoreEndpoint / TestLeaderElectHAvsSingleNode (pkg/executor, -race clean). The live 2-server-on-Postgres + the kine#577 watch-staleness soak are the lab production-trust gate (hack/lab/m6.sh + e2e/TestM6_*)."
        acceptance:
          - id: M6.0-a1
            met: false
            check: two control-plane servers run against one Postgres; a write on server A is read on server B; killing A leaves the cluster serving via B (lab — postgres + 2 servers)
            method: e2e
      - id: M6.1
        title: HA server-join + identical-CA bootstrap bundle
        status: in-progress
        strategy: phased (named exception: kine/SQLite datastore migration)
        note: "CODE-COMPLETE + unit-proven; the live 2-Mac + Postgres server-join/failover is the lab acceptance (M6.1-a1 met:false). The crypto core + the fail-closed server-join are the must-haves and are done; the client-side apiserver LB is BUILT (pkg/loadbalancer: server-set + health-check + pick-healthy + TCP-forward, unit-proven) with APIServers plumbed through the join result — the live cross-Mac kubeconfig-retarget/failover is the lab leg."
        deliverables:
          - id: M6.1-d1
            done: true
            desc: "the M3 worker-join path extended to a SECOND CONTROL-PLANE SERVER reconstructing IDENTICAL cluster + signing CAs (DESIGN §5c), mimicking k3s's datastore-bootstrap-key model. CRYPTO CORE: certs.Hierarchy.Marshal/Unmarshal serialize the 4 CA PEMs (certs owns them); pkg/bootstrap SealBundle/OpenBundle AES-256-GCM-seal the opaque bytes (the seal stays in bootstrap, NOT certs — the bootstrap→certs edge would cycle). Key derived via PBKDF2-HMAC-SHA256 (pinned 600k iters + a crypto/rand 128-bit salt in a versioned envelope) from a MACHINE-GENERATED ≥256-bit server-bootstrap secret (NOT a passphrase, NOT a worker token); a FRESH 12-byte crypto/rand nonce per seal (never a counter — launchctl kickstart resets state); a versioned AAD-bound envelope (magic+version+kdf-id+iters+salt+nonce as GCM AAD); gcm.Open failure is FATAL (tag verified before any plaintext). The sealed envelope is also published to the shared Postgres as a kube-system Secret (the k3s bootstrap-key model); decrypted keys written 0600, never logged. SERVER-CLASS IDENTITY: a server token K10<caHash>::server:<secret> (ServerBootstrapUser system:k3sm-server-bootstrap) DISTINCT from the M3 worker token (system:k3sm-bootstrap); the CA-bundle endpoint (/v1-k3sm/server-bootstrap, Authorization bearer) authorizes the server class ONLY — a leaked worker token can NEVER reconstruct the signing CA. SERVER-JOIN: k3sm server --server-join --server <url> --token reuses the M3 PinnedClient (pinned-CA TLS, no insecure-skip) to fetch the bundle, then IMPORT-THEN-LOAD: decrypt → certs.WriteHierarchy the 4 PEMs into PKIDir → THEN EnsureHierarchy loads them. FAIL CLOSED on any fetch/decrypt/tag failure — never falls through to ensureCA minting divergent CAs (k3sm token create --server mints the server token). DATASTORE-BACKED STORES: the HA node-password store is a kube-system Secret (shared across servers — a name bound on A is enforced on B; the per-process MemoryNodePasswords is kept single-node). CLIENT-LB + ADMIN CERT: pkg/loadbalancer tracks the apiserver set, health-checks, picks a healthy one, and TCP-forwards (the join result carries APIServers); the HA admin kubeconfig (admin.kubeconfig) uses a signing-CA-issued system:masters CLIENT CERT (reconstructible on every server) + cluster-CA verification, so kubectl works against any server. Proven by TestCABundleSealUnsealRoundTrip/TestCABundleWrongSecretFailsClosed/TestCABundleNonceUniquePerSeal/TestCABundleTamperedAADRejected (crypto), TestServerTokenDistinctFromWorker/TestLoadOrCreateServerSecret + TestCABundleEndpointRejectsWorkerIdentity (server identity), TestServerJoinImportsBundleBeforeEnsureHierarchy/TestServerJoinFailsClosedOnAbsentBundle (fail-closed join), TestHierarchyMarshalUnmarshalRoundTrip/TestWriteHierarchyThenEnsureLoads (certs), TestNodePasswordSharedAcrossServersInHA (datastore store), TestApiserverLBPicksHealthy/TestLoadBalancerForwardsToHealthy + TestAdminKubeconfigUsesClientCert (LB + admin cert), all -race clean. The live 2-Mac + Postgres server-join/failover is the lab leg (e2e/TestM6_SecondServerJoinsReconstructsCAs + hack/lab/m6.sh)."
        acceptance:
          - id: M6.1-a1
            met: false
            check: a second Mac joins as a control-plane server, reconstructs the identical CAs from the bundle, and serves the apiserver against the shared Postgres (lab — 2 macs + postgres)
            method: e2e
---

# k3sm — Phase roadmap

> Per-repo slice of the k3sm milestones (workspace matrix: `../../ROADMAP.md`; product design:
> `docs/DESIGN.md` §5c/§7/§9; reference-workload readiness: `../../docs/stockkitty-readiness.md`). The YAML
> frontmatter above is **authoritative**; this prose mirrors it. Status: ✅ done · 🟡 in-progress · ⛔ blocked · ⬜ todo.

`k3sm` is **Wave 3**: it imports all of `apis`, `runtimed`, `darwin-net` and assembles the distribution, so it
lands last in every wave and owns the end-to-end exit demos. **CGO is `CGO_ENABLED=1` from M1** (embeds kine →
`mattn/go-sqlite3`); keep the `replace google.golang.org/genproto` in `go.mod`.

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
The runtime-independent pod surface a real workload needs (see `../../docs/stockkitty-readiness.md`), on top of
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
- ⬜ **M4.0** — app-bundle root LaunchDaemon + `k3sm install/uninstall`; codesign/notarize + `.pkg`; goreleaser →
  `k3sm-io/homebrew-tap`; admin kubeconfig → `~/.kube/config`. **Single-server** (kine→SQLite); multi-server HA is M6.
- 🟡 **M4.1** — RBAC enforcement (**hard cut**), CODE-COMPLETE + unit-proven. The apiserver default authorizer flips
  `AlwaysAllow → Node,RBAC` + the additive `NodeRestriction` admission plugin (`pkg/executor`); the flip is a **pure
  authorizer switch** because the in-process components keep the static admin token (`system:masters`, RBAC-exempt) — a
  documented **component-identity divergence** (component certs deferred). `pkg/rbac.Provision` (NEW; Create-tolerate-
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

## M5 — vm RuntimeClass (committed) 🟡
Promoted from a stretch goal to a committed milestone to run stockkitty's **Linux-only** Postgres/pgvector
(the HYBRID decision — native arm64 for everything else). `runtimeClassName: vm` dispatches to runtimed:M5's
Virtualization.framework Linux micro-VM via the apis:M5.1 `runtime.k3sm.io` handler-config (mapping the value
to the existing `SANDBOX_BACKEND_VM`; the upstream `node.k8s.io/RuntimeClass` is consumed, not forked). Linux
guest images are digest-pinned (codesign/notarization is meaningless inside the VM); networking is vmnet/bridged
with a guest-side resolver (darwin-net:M5). Confirm the `com.apple.security.virtualization` entitlement against
DESIGN §5c.
- 🟡 **M5.1-d1 (verifiable foundation, code-complete + unit-proven)** — the **provider RuntimeClass→backend
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
- ⬜ **M5.1-d2 (lab remainder — needs a VZ Mac + the entitlement)** — the **live** VM dispatch: provider →
  darwin-net `podnet.Network.SetupGuest` → thread the `GuestNetwork` (guest IP/gateway/NAT-subnet/DNS-VIP) to
  runtimed's VZ backend → boot the Linux guest. darwin-net flagged **no transport for `GuestNetwork`** to
  runtimed yet — the clean fix is a runtimed consumer-side `supervisor.GuestNetwork` seam (no apis change).
  Plus the foreign-user VAP **exemption** for `runtimeClassName: vm` (deferred — observable only once the VM
  boots), the guest `resolv.conf` injection (pinned static/immutable), Rosetta-for-amd64, and the
  separate-binary virtualization-entitlement signing (M4.0 packaging).
Exit (§9 M5): a Linux image runs under `runtimeClassName: vm`, Service/DNS-reachable, beside native pods.

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

## Next
M3.0 (the multi-node bootstrap + trust core) is **done** (named unit tests, `-race` clean). Remaining M3:
**M3.1** wire darwin-net's NodePort, **M3.2** the local-path provisioner + StatefulSet, **M3.3** the per-node
CoreDNS + node-local `kubernetes` endpoint rewrite — see `../../docs/m3-plan.md` for the 5-persona re-plan. The
live two-Mac join is the `K3SM_LAB` e2e leg (it also needs the MeshPeer CRD installed in the apiserver). M2's
only remaining item is the root e2e gate `hack/acceptance/m2.sh` (needs root on a Mac). **M4.1** (RBAC
enforcement) is now **code-complete + unit-proven** (`pkg/rbac` + the `Node,RBAC`+`NodeRestriction` apiserver
default); its sole remaining item is the live authz flip — the integration-tier `e2e/TestM4_RBACEnforced` on a
dev Mac (**M4.1-a1 `met:false`, integration-pending**). M4 still owes **M4.0** (packaging/launchd) and **M4.2**
(the conformance gate green in CI). **HA is M6 (last phase): M6.0 (kine→Postgres + leader-election) and M6.1 (HA
server-join + the AES-256-GCM identical-CA bundle) are both code-complete + unit-proven; the live 2-Mac + Postgres
write-A-read-B, single-active-leader, watch-staleness soak, second-server-join (identical CAs), and kill-A→serve-via-B
failover are the `hack/lab/m6.sh` / `e2e/TestM6_*` lab legs (`K3SM_LAB=1`, never auto-greened).**
