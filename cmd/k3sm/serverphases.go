/*
Copyright The k3sm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	crdconfig "k3sm.io/apis/config/crd"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/crdensure"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/linkgraph"
	"k3sm.io/k3sm/pkg/mlx/operator"
	"k3sm.io/k3sm/pkg/provisioner"
	"k3sm.io/k3sm/pkg/rbac"
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/k3sm/pkg/svclb"
)

// The post-bring-up phases of `k3sm server`, in runServer's order. Each one that
// owns a goroutine returns a stop func that cancels the phase's derived context
// and then waits for the goroutine; runServer defers it at the phase's position,
// so the defers still run in reverse registration order (LIFO).

// noStop is the stop func of a phase that started nothing.
func noStop() {}

// provisionServerCluster is steps 3–3c: the cluster-scoped admission policies +
// the vm RuntimeClass, the fail-closed RBAC graph, and the embedded add-ons.
func provisionServerCluster(ctx context.Context, plan serverPlan, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) error {
	opts := plan.opts
	// 3. Provision the cluster-scoped admission policies + the vm RuntimeClass.
	// Extracted so the SET is testable against a fake clientset: what this
	// binary provisions is a posture-INDEPENDENT product decision, and a silently
	// absent policy is otherwise invisible until a real cluster admits something it
	// should have rejected.
	provisionClusterPolicies(ctx, cs, plan.mode, os.Geteuid(), opts.deniedLocalPorts(), logger)

	// 3b. Provision the RBAC graph BEFORE the VK node (step 5) and the
	// worker-join supervisor (step 4d) start, so a joining worker's system:node
	// datapath bindings already exist when the Node,RBAC authorizer (the apiserver
	// shipped default) evaluates its first request. FAIL-CLOSED: unlike the
	// advisory admission policies above (log-and-continue), a provisioning failure
	// HALTS bring-up — a half-applied graph under an enforcing authorizer silently
	// locks workers out of services/endpointslices/meshpeers. It runs under the
	// retained system:masters admin client (RBAC-exempt) with a bounded retry, so it
	// succeeds even though the authorizer is already on (no two-phase restart).
	if err := rbac.Provision(ctx, cs); err != nil {
		return fmt.Errorf("provision rbac graph: %w", err)
	}
	logger.Info("provisioned RBAC graph (node-datapath + in-pod reader + registry-advertisement reader); authorizer is Node,RBAC")

	// 3c. SSA-converge the EMBEDDED add-on manifest set. The manifests are
	// compiled into this binary (embed.FS), never read from disk: the work dir is
	// writable by every pod (all pods share the _k3sm uid and it is outside runtimed's
	// sandbox-protected prefixes) and this client is the system:masters admin, so a
	// directory ingress would hand cluster-admin to every pod on the node. See
	// pkg/addons/doc.go. Runs AFTER the fail-closed RBAC graph so a slow or failing
	// add-on can never delay it. Converge-only — it issues apply patches and never a
	// delete or a list. Log-and-continue like the sibling boot provisioners, by the
	// repo's one rule for a fault on this process: UNSURVIVABLE faults exit (a dead
	// control-plane child does, and the crash-loop breaker bounds the respawns);
	// SURVIVABLE ones continue, and a manifest that will not apply is survivable —
	// the control plane is up without it. The shipped set is EMPTY of product
	// manifests today, so this is inert until the first add-on lands.
	if ar, err := addons.NewFromConfig(addons.FS(), restCfg); err != nil {
		logger.Error("build embedded add-on reconciler", "err", err)
	} else if err := ar.Converge(ctx); err != nil {
		logger.Error("converge embedded add-on manifests", "err", err)
	}
	return nil
}

// startHelmController launches the HelmChart controller (the k3s
// helm-controller analog). Launched before the manifest directory
// (startManifestDir) so the helm.k3sm.io CRDs are being established by the time
// the manifest directory's first sweep can carry a HelmChart; a chart that sweep
// cannot map yet is retried on the next one. Same lifetime as the manifest
// directory: its own goroutine, every failure logged and contained there (a
// missing helm, a CRD the apiserver will not take), and drained before the control
// plane stops (runServer defers the returned stop after exec.Stop's, so LIFO runs
// it first). Leader-elected on a Lease, so only one server of an HA pair
// reconciles.
func startHelmController(ctx context.Context, plan serverPlan, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	hcCtx, hcCancel := context.WithCancel(ctx)
	hcDone := make(chan struct{})
	go func() {
		defer close(hcDone)
		runHelmController(hcCtx, restCfg, cs, plan.opts.workDir, plan.opts.nodeName, logger)
	}()
	return func() {
		hcCancel()
		<-hcDone
	}
}

// startManifestDir is step 3c': the operator's auto-deploy manifest directory
// (install.ManifestDir, the k3s server/manifests analog). Unlike 3c it reads from
// disk, so it is safe only because of three things pkg/addons documents: the
// directory and every file in it must be root-owned and not group/other-writable
// (the service user, and so every pod, cannot write it); the applies run as the
// bounded k3sm-manifests ServiceAccount, never this system:masters client, which
// is used only to provision that identity and mint its token; and RBAC and
// admission objects are refused outright. Apply-only: nothing is ever deleted. It
// runs in its own goroutine, so a slow identity provisioning or a bad manifest
// never delays bring-up, logs every failure itself, and is drained before the
// control plane stops (runServer defers the returned stop after exec.Stop's, so
// LIFO runs it first). A missing directory is the normal case and applies nothing.
func startManifestDir(ctx context.Context, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	mdCtx, mdCancel := context.WithCancel(ctx)
	mdDone := make(chan struct{})
	go func() {
		defer close(mdDone)
		runManifestDir(mdCtx, restCfg, cs, logger)
	}()
	return func() {
		mdCancel()
		<-mdDone
	}
}

// startServerRegistry is step 3d: the node-local OCI ingest registry
// (--registry-port; 0 disables, which is the default). It runs after the
// apiserver is healthy, because bringing it up also publishes the KEP-1755
// local-registry-hosting ConfigMap — discovery needs a cluster to publish into.
//
// It is torn down BEFORE the control plane: runServer defers the returned stop
// AFTER exec.Stop's, so LIFO runs it first. That ordering is not cosmetic — the
// registry child holds a port and an open blob store, and a control plane that
// went away underneath it would leave both to the process reaper.
//
// NEVER FATAL: startIngestRegistry logs and returns a no-op teardown if the
// registry cannot come up. See its doc for why that is the right posture here
// and the wrong one at step 3b. A disabled or unbuildable registry returns noStop.
//
// vmCapable is whether this node can host vm guests, asked by runServer before
// the registry and the datapath are constructed and long before the VK node
// exists — through runtimed's own safe host probe (vmBackendAvailable) rather
// than through the node's advertised capability, which is not answerable yet. It
// has two consumers: the registry relay's vmnet-gateway bind here, which is the
// only address a Linux-guest Pod can reach a host listener at, and the
// NetworkPolicy table's fail-closed unknown-vm-source branch (step 4c), scoped
// to the segment macOS's vmnet is expected to hand guests. False leaves both
// byte-identical to a node that runs no guests.
//
// It also yields the PULLER WIRING — how runtimed should spell this node's own
// registry — which is handed to the node so a reference naming the Service
// address is classified exactly as a loopback one is. The zero value (no
// registry) leaves runtimed's classification unchanged.
func startServerRegistry(ctx context.Context, plan serverPlan, cs kubernetes.Interface, vmCapable bool, logger *slog.Logger) (stop func(), puller registryPullerWiring) {
	opts := plan.opts
	if opts.registryPort == 0 {
		return noStop, puller
	}
	svc, err := registrysvc.New(registryConfig(opts, plan.cfg.PayloadBinDir, logger))
	if err != nil {
		logger.Error("ingest registry disabled", "err", err)
		return noStop, puller
	}
	return startIngestRegistry(ctx, ingestRegistry{
		svc:      svc,
		port:     opts.registryPort,
		nodeName: opts.nodeName,
		// The mesh address is what peers are advertised at and what the
		// relay binds; empty (single node) publishes no advertisement and
		// leaves the registry loopback-only, which is the whole truth there.
		meshIP: opts.meshIP,
		// The vm NAT segment contributes the relay's gateway bind — the only
		// address a Linux-guest Pod on this Mac can reach a host listener at
		// (it cannot reach loopback). A node that cannot host guests names no
		// segment and gets no such bind.
		vmNetSubnet: guestNATSubnet(vmCapable),
		hostingCMs:  cs.CoreV1().ConfigMaps(registrysvc.HostingNamespace),
		advertCMs:   cs.CoreV1().ConfigMaps(registrysvc.AdvertisementNamespace),
		// The per-node registry Service + its hand-written EndpointSlice,
		// in the SAME namespace as the advertisement: one cluster address
		// a native Pod, a vm guest and the host all reach this node's
		// registry at. Written with the retained admin client, exactly as
		// the advertisement is — the node identities that READ them
		// already hold cluster-wide services/endpointslices through
		// k3sm:node-datapath (pkg/rbac).
		clusterSvcs:   cs.CoreV1().Services(registrysvc.AdvertisementNamespace),
		clusterSlices: cs.DiscoveryV1().EndpointSlices(registrysvc.AdvertisementNamespace),
		clusterDomain: opts.domain,
		logger:        logger,
	})
}

// serverMesh is what step 4b leaves behind for the phases after it.
type serverMesh struct {
	// enroller is the ONE mesh enroller the self-enroll and the join supervisor
	// share; nil off the mesh path.
	enroller *meshEnroller
	// nodePasswords is the ONE node-password store: this node's own enroll binds
	// its name in it, and the join supervisor checks every worker against it.
	nodePasswords bootstrap.NodePasswordStore
	// down is the mesh teardown handle runServer's deferred teardown runs.
	down meshTeardown
	// podCIDR is the control-plane node's pod /24: the reserved index-0 carve of
	// the cluster pod CIDR — the ONE value the routing-table locality (step 4c)
	// and the node's podnet adapter (step 5) both allocate against.
	podCIDR string
	// egressIP is the mesh-egress source the proxy binds for cross-node backend
	// dials, and peerEgress the peer mesh-egress /32s the NetworkPolicy table
	// always-allows. Empty until this node is on its own mesh — an empty
	// MeshEgressIP is the honest "no mesh here".
	egressIP   string
	peerEgress []string
	// links is this node's direct-link loop: the join supervisor serves its
	// link-local join listeners and pairing beacons on the ports it configured.
	// Nil off the mesh path and under --network none.
	links *directLinkRuntime
	// restCfg is the admin REST config the direct-link resolver runs over; nil
	// off the mesh path.
	restCfg *rest.Config
}

// enrollServerMesh is step 4b: THIS SERVER JOINS ITS OWN MESH.
//
// The enroller is constructed here, not at the supervisor (step 4d), because both
// callers must share ONE instance: its mutex is what serializes this node's
// index-0 claim against a worker join, and two instances would contend on
// nothing. Its construction stays FAIL-CLOSED — a supervisor that cannot enroll
// is a control plane that rejects every join.
//
// The self-enroll itself is LOG-AND-CONTINUE, following the precedent
// provisionClusterPolicies sets and the repo's one rule for a fault on this
// process: UNSURVIVABLE faults exit (a dead control-plane child does, and the
// crash-loop breaker bounds the respawns); SURVIVABLE ones continue. A mesh-only
// defect is survivable — the control plane serves without it — so it must never
// take the process down. What is lost on failure is named in the log line,
// because "the server is not on its own mesh" is otherwise only visible as
// cross-node traffic that silently goes nowhere.
//
// It completes BEFORE step 4c builds the proxy (mesh.Start plumbs the mesh-egress
// lo0 alias the proxy's source bind depends on) and BEFORE step 4d opens the join
// listener (EnrollSelf list-back verifies the index-0 claim, so no worker can be
// assigned index 0 in the window).
//
// meshDown is the teardown handle runServer has already deferred; the returned
// serverMesh.down is that handle, re-armed when the bring-up got far enough to
// own a utun.
func enrollServerMesh(ctx context.Context, plan serverPlan, restCfg *rest.Config, cs kubernetes.Interface, kubeconfig string, meshDown meshTeardown, logger *slog.Logger) (serverMesh, error) {
	opts := plan.opts
	// The node-password store is built HERE, ahead of this node's own enroll, and
	// the SAME instance is handed to the join supervisor at step 4d. One instance
	// is the point: the binding this server takes for its OWN name has to live in
	// the store the join handler checks.
	//
	// It is datastore-backed on EVERY server (a kube-system Secret per node), so a
	// binding survives a restart: an in-memory store forgot every binding when the
	// process stopped, leaving each worker's name claimable by any join-token
	// holder until that worker rejoined. In HA the same Secrets are what make a
	// name bound on one server enforced on its siblings. It is built after the
	// apiserver is healthy (step 2's client) and before the join listener (step
	// 4d). There is NO backfill: workers bound before an upgrade to this store, or
	// before a datastore wipe, stay unbound until their next join.
	nodePasswords := serverNodePasswordStore(cs, logger)
	sm := serverMesh{nodePasswords: nodePasswords, down: meshDown, podCIDR: defaultNodePodCIDR()}
	if opts.meshIP == "" || plan.hierarchy == nil {
		return sm, nil
	}
	e, err := newMeshEnroller(restCfg, logger)
	if err != nil {
		return sm, fmt.Errorf("build mesh enroller: %w", err)
	}
	sm.enroller = e
	sm.restCfg = restCfg
	if plan.mode.DataPath() {
		selfCIDR, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, serverNodeIndex)
		if err == nil {
			if links, lerr := newServerDirectLinks(sm.enroller, opts, selfCIDR.String(), kubeconfig, logger); lerr != nil {
				logger.Warn("this control-plane node runs no direct links (the mesh stays tunnel-only)", "err", lerr)
			} else {
				sm.links = links
			}
		}
	}
	if res, down, err := enrollSelfAndBringUpMesh(ctx, sm.enroller, nodePasswords, opts, plan.mode, kubeconfig, sm.links, logger); err != nil {
		msg, attrs := serverMeshBringUpFailure(opts, err)
		logger.Error(msg, attrs...)
		// A bring-up that failed part-way still owns a utun, so the handle is
		// armed even here; it is a no-op when nothing came up.
		sm.down = down
	} else {
		// Arms the teardown runServer deferred, which runs SYNCHRONOUSLY on the way
		// out and after the control plane has stopped. The mesh watcher's own
		// Close is only a fallback — it runs after ctx is cancelled and races
		// process death, which on SIGTERM leaves the per-peer routes installed.
		sm.down = down
		sm.podCIDR = res.PodCIDR
		if plan.mode.DataPath() {
			sm.egressIP = res.MeshIP
			// A boot-time SNAPSHOT. A peer that enrolls after this
			// point reconverges in wireguard via the MeshPeer watch but is
			// not in this table until the next restart; the posture is
			// fail-open widen-only ("never a wrong deny"), so the gap
			// degrades attribution, not connectivity.
			sm.peerEgress = peerMeshEgressIPs(res.Peers)
		}
	}
	return sm, nil
}

// startJoinSupervisor is step 4d: the worker-join supervisor (mesh-bound; mints
// node certs + enrolls peers), plus the CA-bundle endpoint in the HA posture. Only
// when multi-node is enabled (sm.enroller non-nil); the live two-Mac join is the
// K3SM_LAB gate (step 4a has already ensured the MeshPeer CRD the enroller's write
// lands in, and step 4b has already claimed index 0 through this same enroller).
//
// The returned stop closes the local etcd admin client the HA member routes use;
// it is noStop when no such client was built.
func startJoinSupervisor(ctx context.Context, plan serverPlan, cs kubernetes.Interface, sm serverMesh, logger *slog.Logger) (stop func()) {
	stop = noStop
	if sm.enroller == nil {
		return stop
	}
	// The direct-link resolver lives exactly as long as the join supervisor (both
	// are the mesh path's), so its stop rides this phase's.
	stopLinks := startLinkResolver(ctx, plan, sm, sm.restCfg, cs, logger)
	stop = stopLinks
	opts := plan.opts
	tokens := bootstrap.NewFileTokenStore(bootstrap.TokensPath(opts.workDir), nil)
	deps := bootstrapServerDeps{
		hierarchy: plan.hierarchy,
		meshIP:    opts.meshIP,
		// THIS process's own node name, which the join handler refuses to serve
		// any request for. It is opts.nodeName and never a cluster-wide value:
		// in HA every server protects its own name here, and its siblings'
		// names are protected by their own processes plus the shared
		// node-password bindings step 4b takes.
		selfNodeName: opts.nodeName,
		tokens:       tokens,
		// The store step 4b already bound this node's own name in.
		nodePasswords: sm.nodePasswords,
		enroller:      sm.enroller,
		apiServers:    []string{fmt.Sprintf("%s:%d", opts.meshIP, opts.apiPort)},
		// Direct links: the publish/read verb always (the enroller writes the
		// DirectLink), and the cable-port listeners, beacons and pairing verb when
		// this node runs a direct-link loop.
		directLinks: sm.enroller,
		links:       sm.links,
		fileTokens:  tokens,
		workDir:     opts.workDir,
		podCIDR:     sm.podCIDR,
		pairEvents:  nodeEventRecorder{cs: cs, node: opts.nodeName, component: "k3sm-pairing"},
	}
	// Serve the AES-256-GCM CA bundle authorized by the
	// SERVER-class token ONLY (never a worker), sealing the live hierarchy; publish
	// the sealed envelope to the shared datastore (the k3s bootstrap-key model).
	if opts.etcdPosture() {
		bundle := &liveBundleSource{hierarchy: plan.hierarchy, secret: plan.serverSecret}
		deps.bundle = bundle
		deps.serverAuth = bootstrap.NewStaticServerSecret(plan.serverSecret)
		if sealed, err := bundle.SealedBundle(ctx); err != nil {
			logger.Error("seal bootstrap bundle for datastore", "err", err)
		} else if err := publishBootstrapBundle(ctx, cs, sealed); err != nil {
			logger.Warn("publish bootstrap bundle to datastore", "err", err)
		}
		// The etcd member routes: a joining server is added as a learner and
		// later promoted by THIS server, against its own member over loopback
		// with its etcd client identity. Not served if the client cannot be
		// built — a server that cannot admit members still serves everything
		// else, and a joiner retries.
		if admin, err := executor.NewLocalEtcdAdmin(ctx, opts.workDir, opts.kinePort); err != nil {
			logger.Error("etcd member routes disabled: cannot reach the local etcd member", "err", err)
		} else {
			stop = func() { stopLinks(); _ = admin.Close() }
			deps.members = localMemberJoiner{admin: admin}
		}
	}
	go func() {
		if err := startBootstrapServer(ctx, deps, logger); err != nil && ctx.Err() == nil {
			logger.Error("worker-join supervisor", "err", err)
		}
	}()
	return stop
}

// startProvisioner is step 4e: the APFS local-path provisioner, a pure API-object
// controller that registers the local-path StorageClass and creates a Retain,
// node-affinity-pinned PV for each PVC the scheduler has placed. It does NO
// filesystem I/O — runtimed empty-creates the per-(namespace, claim) dir on the
// consuming node. The class BasePath is the RESOLVED runtime root (opts.podRoot —
// the same root runtimed derives per-PVC dirs against), NOT the root-only
// storagev1.DefaultBasePath. Started once the apiserver is healthy and drained
// BEFORE exec.Stop tears the control plane down: runServer defers the returned
// stop AFTER exec.Stop's defer, so LIFO runs it FIRST — the provisioner never
// writes a PV against a draining apiserver. provCtx lets the drain cancel it even
// if startNode returns an error (ctx not yet cancelled), avoiding a shutdown hang.
func startProvisioner(ctx context.Context, plan serverPlan, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	prov := provisioner.New(cs, provisioner.ClassForRoot(plan.opts.podRoot), logger)
	provCtx, provCancel := context.WithCancel(ctx)
	provDone := make(chan struct{})
	go func() {
		defer close(provDone)
		if err := prov.Run(provCtx); err != nil && provCtx.Err() == nil {
			logger.Error("local-path provisioner", "err", err)
		}
	}()
	return func() {
		provCancel()
		<-provDone
	}
}

// startMLXOperator is step 4f: the MLX operator, which ensures the MLXModel CRD,
// then reconciles each MLXModel into a StatefulSet plus its headless and ClusterIP
// Services. Same lifetime and the same reasoning as the provisioner — started
// once the apiserver is healthy, and drained BEFORE exec.Stop tears the control
// plane down by a defer registered after it, so LIFO runs this one first. A
// client or operator that cannot be built is logged and stop is noStop.
//
// The GPU source is LIVE on this path. The pre-render fit check reads
// the node-local runtime's GPU facts, and this process is about to bring up
// that node in-process — so the source is created here, wired into the
// operator now, and ATTACHED to the node's runtime at step 5 bring-up
// (nodeOptions.attachRuntimeInfo). It is the same GetRuntimeInfo the
// node's capability probe reads, off the same runtime; no second connection.
//
// Until that attach lands — and forever, on a posture with no runtimed at all
// (--runtime hostprocess) — the source reports unknown, which SKIPS the fit
// check with a logged warning exactly as a nil source did. A wiring fault
// degrades; it never refuses a model and never crashes the reconcile.
func startMLXOperator(ctx context.Context, plan serverPlan, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) (mlxGPU *operator.RuntimeGPU, stop func()) {
	mlxGPU = operator.NewRuntimeGPU(logger)
	dynClient, err := dynamic.NewForConfig(restCfg)
	if err != nil {
		logger.Error("build dynamic client for the mlx operator", "err", err)
		return mlxGPU, noStop
	}
	crdClient, err := apiextensionsclient.NewForConfig(restCfg)
	if err != nil {
		logger.Error("build apiextensions client for the mlx operator", "err", err)
		return mlxGPU, noStop
	}
	mlxOp, err := operator.New(mlxOperatorConfig(cs, dynClient, crdClient, mlxGPU, plan.opts.domain, logger))
	if err != nil {
		logger.Error("build the mlx operator", "err", err)
		return mlxGPU, noStop
	}
	mlxCtx, mlxCancel := context.WithCancel(ctx)
	mlxDone := make(chan struct{})
	go func() {
		defer close(mlxDone)
		if err := mlxOp.Run(mlxCtx); err != nil && mlxCtx.Err() == nil {
			logger.Error("mlx operator", "err", err)
		}
	}()
	return mlxGPU, func() {
		mlxCancel()
		<-mlxDone
	}
}

// startServerLBHosting is steps 4g/4h: ingress hosting + svclb, beside the
// netserve datapath (step 4c) and like it skipped under --network none (they
// splice/route to ClusterIP VIPs, which need the proxy's datapath).
//
// Both bind the WILDCARD and both advertise the node's DERIVED
// globally-unicast InternalIP — see lbHostingConfigs, which owns the
// whole decision. opts.nodeIP is READ, never written back: it feeds the
// apiserver's --advertise-address/--bind-address.
//
// 4g: darwin-net's L7 ingress (RouteTable + SNI CertStore + class-filtered
// Watcher + Server) runs IN THIS PROCESS (SERVER-PROCESS-ONLY — multi-node
// ingress is a named follow-up), fed by the same in-process ADMIN client:
// referenced TLS Secrets are fetched by name under it, so key bytes only
// ever live in the control-plane process and no RBAC is widened.
// --ingress-http-port/--ingress-https-port select the explicit high-port
// integration mode (never a silent fallback).
//
// 4h: svclb (klipper-lite) binds *:port listeners for every LoadBalancer
// Service and splices them to the Service's ClusterIP VIP, advertising
// status.loadBalancer ONLY once a listener is actually bound.
//
// ORDER IS LOAD-BEARING: the ingress host is started BEFORE svclb, so the
// ingress listeners take 80/443 first if a user LoadBalancer Service also
// claims them (svclb additionally has an apiserver informer cache-sync to
// complete before its first bind). The reserved-port set deliberately does
// NOT include 80/443 — those are legitimate LoadBalancer ports — so the
// residual race is a documented ceiling, not a guarded invariant.
func startServerLBHosting(ctx context.Context, plan serverPlan, cs kubernetes.Interface, nodeOpts nodeOptions, logger *slog.Logger) {
	opts, mode := plan.opts, plan.mode
	if !mode.DataPath() {
		return
	}
	lbCfg, ingressCfg, err := lbHostingConfigs(cs, nodeOpts, netdSocketFor(mode), opts.ingressHTTPPort, opts.ingressHTTPSPort, logger)
	if err != nil {
		logger.Error("ingress + svclb hosting disabled", "err", err)
		return
	}
	// Ensure the advertised address answers on this host BEFORE anything
	// advertises it (the wildcard listener cannot witness it).
	ensureAdvertisedNodeAlias(ctx, nodeOpts, logger)
	if ingressCfg.HTTPPort != 0 || ingressCfg.HTTPSPort != 0 {
		ih, err := ingresshost.New(ingressCfg)
		if err != nil {
			logger.Error("ingress hosting disabled", "err", err)
		} else {
			go func() {
				if err := ih.Run(ctx); err != nil && ctx.Err() == nil {
					logger.Error("ingress hosting", "err", err)
				}
			}()
		}
	} else {
		logger.Info("ingress hosting disabled (--ingress-http-port 0 --ingress-https-port 0)")
	}
	lb, err := svclb.New(lbCfg)
	if err != nil {
		logger.Error("svclb disabled", "err", err)
		return
	}
	go func() {
		if err := lb.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("svclb loadbalancer controller", "err", err)
		}
	}()
}

// repairServerNodeLabels clears, through the ADMIN client, the one piece of Node
// metadata an upgraded server's node can no longer manage itself: a
// kubernetes.io/role label recorded while the node ran as system:masters. Under
// its system:node identity NodeRestriction would refuse the status patch that
// removes it, every time.
func repairServerNodeLabels(ctx context.Context, cs kubernetes.Interface, nodeName string, logger *slog.Logger) error {
	stripped, err := stripStaleNodeRoleLabel(ctx, cs.CoreV1().Nodes(), nodeName)
	if err != nil {
		return err
	}
	if stripped {
		logger.Info("removed a stale label this node can no longer remove itself under its node identity", "node", nodeName, "label", staleNodeRoleLabel)
	}
	return nil
}

// ensureDirectLinkCRD server-side-applies the net.k3sm.io/v1alpha1 DirectLink CRD
// through the same applier as the MeshPeer one, on the mesh path only. A failure
// is logged, not returned: the mesh runs without it, and only direct links are
// lost.
func ensureDirectLinkCRD(ctx context.Context, meshIP string, newClient crdClientFactory, logger *slog.Logger) {
	if meshIP == "" {
		return
	}
	c, err := newClient()
	if err == nil {
		_, err = crdensure.Ensure(ctx, c, crdconfig.DirectLinkCRD(), crdensure.Options{Log: logger})
	}
	if err != nil {
		logger.Error("the DirectLink CRD was not ensured: no node can publish its cable ports, so every cable stays unused and pod traffic rides the tunnel", "crd", crdconfig.DirectLinkCRDName, "err", err)
		return
	}
	logger.Info("ensured the DirectLink CRD", "crd", crdconfig.DirectLinkCRDName)
}

// startLinkResolver runs the direct-link resolver (pkg/linkgraph) on the mesh
// path. It writes every DirectLink's status and the advisory direct-links label;
// the returned stop cancels it.
//
// It first ensures the DirectLink CRD (ensureDirectLinkCRD). Both run after the
// apiserver serves and the MeshPeer CRD exists (step 4a), on the mesh path only.
func startLinkResolver(ctx context.Context, plan serverPlan, sm serverMesh, restCfg *rest.Config, cs kubernetes.Interface, logger *slog.Logger) (stop func()) {
	if sm.enroller == nil {
		return noStop
	}
	ensureDirectLinkCRD(ctx, plan.opts.meshIP, func() (crdensure.CRDClient, error) {
		return apiextensionsclient.NewForConfig(restCfg)
	}, logger)
	c, err := linkgraph.NewController(restCfg, cs, logger)
	if err != nil {
		logger.Error("the direct-link resolver is not running: no cable is ever reported up", "err", err)
		return noStop
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := c.Run(rctx); err != nil && rctx.Err() == nil {
			logger.Error("direct-link resolver stopped", "err", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
