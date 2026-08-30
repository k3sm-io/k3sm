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
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/ingresshost"
	"k3sm.io/k3sm/pkg/mlx/operator"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/ports"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/provisioner"
	"k3sm.io/k3sm/pkg/rbac"
	"k3sm.io/k3sm/pkg/runtimeclass"
	"k3sm.io/k3sm/pkg/svclb"
)

// serverOptions configures `k3sm server` — the all-in-one control plane + node.
type serverOptions struct {
	workDir  string
	nodeName string
	nodeIP   string
	meshIP   string // wireguard mesh IP; set => multi-node worker-join supervisor (M3.0)
	podRoot  string
	rtName   string
	dnsShim  string
	pathShim string
	apiPort  int
	kinePort int // kine (etcd shim) listen port; per-server, so two control planes on one host never share a datastore
	// kubeletPort is the port the in-process node serves the kubelet HTTP API
	// (logs/exec/stats) on. Per-server for the same reason kinePort is: it is a
	// singleton listener, so two control planes on one Mac cannot both have the
	// default. Only the PORT is configurable — the bind stays the wildcard
	// serverKubeletListenOn builds, and the API's auth posture is untouched.
	kubeletPort int
	// schedulerPort / controllerManagerPort are the two co-located control-plane
	// components' secure-serving ports. Per-server for the same reason as the
	// two above — each is a singleton listener — and they were the LAST fixed
	// ones, so with these a second control plane on one Mac contends for nothing.
	// Only the PORT is configurable: both components stay bound to loopback,
	// which executor.LoopbackServingArgs renders and does not take from here.
	schedulerPort         int
	controllerManagerPort int
	clusterIP             string // DNS VIP CoreDNS binds + pods resolve against
	domain                string
	network               string // host-network backend: auto (default) | none | direct | helper

	datastoreEndpoint string // kine datastore DSN (postgres://… => HA multi-writer); empty = single-node SQLite (M6.0)
	serverJoin        bool   // declare HA control-plane intent (requires --datastore-endpoint; split-brain guard)
	joinServer        string // existing server's mesh host to fetch the identical-CA bundle from (M6.1 HA server-join)
	token             string // server-class join token (K10<caHash>::server:<secret>) for the HA server-join (M6.1)

	psaEnforceBaseline bool // flip the PSA cluster-default enforce level privileged→baseline (the B71 cutover; default = warn-only, M10.0)

	ingressHTTPPort  int // ingress HTTP listener port, bound on the wildcard (M10.3/B116; 0 disables; 80 = production, an explicit high port = integration tier)
	ingressHTTPSPort int // ingress HTTPS listener port (same contract as ingressHTTPPort; 443 = production)
}

// executorConfig renders the control-plane Config these flags describe. It is
// PURE and lives outside runServer for one reason: every port on it is a
// singleton listener that a second control plane on the same Mac has to be able
// to move, and a flag that is parsed but never assigned here reproduces that
// defect exactly — an operator-supplied port silently replaced by the default,
// with the collision surfacing as whichever component loses the bind. runServer
// fills the rest of the Config (payload dir, datastore, mesh) from the
// environment, which is not testable this way and not what keeps colliding.
func (opts serverOptions) executorConfig(logger *slog.Logger) executor.Config {
	return executor.Config{
		WorkDir:               opts.workDir,
		APIServerPort:         opts.apiPort,
		KinePort:              opts.kinePort,
		SchedulerPort:         opts.schedulerPort,
		ControllerManagerPort: opts.controllerManagerPort,
		NodeIP:                opts.nodeIP,
		// M10.0/B71: false ships baseline-WARN; true is the enforce cutover (see the
		// flag comment above — executor.Config.PSAEnforceBaseline is the single seam).
		PSAEnforceBaseline: opts.psaEnforceBaseline,
		Logger:             logger,
	}
}

// runServer brings up the control plane (via the executor) and a Virtual Kubelet
// node in one process, then hosts darwin-net's Service proxy + CoreDNS config +
// DNS shim and provisions the os=darwin admission policy. It blocks until
// interrupted, then shuts the control plane down cleanly.
func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := serverOptions{}
	// The work-dir default is POSTURE-AWARE (decoupled from the root-only
	// DefaultWorkDir const): root → /var/lib/k3sm/server, the unprivileged _k3sm
	// control plane → <home>/server (the root const would EACCES). A resolve error
	// (unprivileged with no home) is surfaced after Parse so an explicit --work-dir
	// can still override it.
	defaultWorkDir, workDirErr := executor.ResolveWorkDir()
	fs.StringVar(&opts.workDir, "work-dir", defaultWorkDir, "control-plane state root (binaries, kine DB, certs, kubeconfig); posture-aware default")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "127.0.0.1", "node InternalIP to advertise")
	fs.StringVar(&opts.meshIP, "mesh-ip", "", "wireguard mesh IP to bind the apiserver + worker-join supervisor on (enables multi-node join; empty = single-node)")
	fs.StringVar(&opts.podRoot, "pod-root", "", "runtimed on-disk root (image cache + pod dirs); empty derives <work-dir parent> so the SBPL work-dir resides under the daemon home — set this to move PVCs off /Users, which the sandbox always denies")
	addRuntimeFlag(fs, &opts.rtName)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.pathShim, "path-shim", "", "path-rebase DYLD shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", executor.DefaultAPIServerPort, "apiserver secure port")
	// The datastore port is per-SERVER, not per-host: two control planes on one Mac
	// sharing it is not a bind contest but a silent datastore takeover — the second
	// server finds the port already serving and comes up healthy against the first
	// server's database. The executor refuses that outright; this flag is how a
	// second control plane on the same host gets a datastore of its own.
	fs.IntVar(&opts.kinePort, "kine-port", executor.DefaultKinePort, "kine (etcd shim) listen port on 127.0.0.1 — every control plane on a host needs its own")
	// The node's kubelet-API port. Same per-server reasoning as --kine-port, one
	// process further down the bring-up: a second server on the default port gets
	// a healthy control plane and then a node that dies with "listen tcp :10250:
	// bind: address already in use". This renumbers the LISTENER ONLY; it does not
	// change the bind address or the API's authn posture.
	fs.IntVar(&opts.kubeletPort, "kubelet-port", ports.KubeletAPIPort, "kubelet HTTP API (logs/exec/stats) listen port — every node on a host needs its own")
	// The scheduler's and controller-manager's secure ports, the last two fixed
	// singletons in a server's listener set. A second server on the defaults gets
	// a healthy apiserver and then a controller-manager that dies on the bind —
	// which used to surface downstream as a namespace bootstrap that never
	// completes, because nothing was running the service-account controller.
	// These flags renumber loopback listeners; they cannot publish one.
	fs.IntVar(&opts.schedulerPort, "scheduler-port", executor.DefaultSchedulerPort, "kube-scheduler secure-serving port on 127.0.0.1 — every control plane on a host needs its own")
	fs.IntVar(&opts.controllerManagerPort, "controller-manager-port", executor.DefaultControllerManagerPort, "kube-controller-manager secure-serving port on 127.0.0.1 — every control plane on a host needs its own")
	// M10.0 PSA (Res.2). The SHIPPED default is baseline-WARN only (enforce stays
	// privileged; warn=baseline + audit=restricted — audit-observable, zero
	// rejection). This flag is the documented, REVERSIBLE cutover MECHANISM for the
	// B71 baseline-enforce flip: set it only after a pre-flight scan proves the
	// cluster clean (B71 owns flipping it); dropping the flag reverts the posture on
	// the next boot. It is an operator argv toggle of a single apiserver config
	// value, not a runtime feature-flag code path.
	fs.BoolVar(&opts.psaEnforceBaseline, "psa-enforce-baseline", false, "flip the cluster-wide Pod Security Admission default ENFORCE level from privileged to baseline (the B71 cutover; the shipped default is baseline-warn only)")
	// M10.3 ingress listener ports. 80/443 is the production posture; an EXPLICIT
	// high-port pair (e.g. 8080/8443) is the integration-tier mode. There is
	// deliberately NO silent fallback between the two — a failed bind is logged and
	// boundedly retried, never re-ported. Since B116 the listeners bind the WILDCARD
	// in-process (a wildcard bind is unprivileged on Darwin at any port), so no netd
	// authorization is involved; they are started BEFORE svclb so they win a contest
	// for these ports against a user LoadBalancer Service declaring them.
	fs.IntVar(&opts.ingressHTTPPort, "ingress-http-port", 80, "ingress HTTP listener port, bound on ALL interfaces (80 = production; an explicit high port is the integration-tier mode; 0 disables the HTTP listener)")
	fs.IntVar(&opts.ingressHTTPSPort, "ingress-https-port", 443, "ingress HTTPS listener port, bound on ALL interfaces (443 = production; an explicit high port is the integration-tier mode; 0 disables the HTTPS listener)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP CoreDNS binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (control-plane-only, no datapath/probe) | direct (force lo0, root) | helper (force netd helper)")
	// M6.0 HA datastore. The DSN may carry a password; prefer the env so it stays off
	// k3sm's own argv (mirrors --token/$K3SM_TOKEN). k3sm relocates the password off
	// the kine child's argv too (a 0600 PGPASSFILE), so `ps` never sees the secret.
	fs.StringVar(&opts.datastoreEndpoint, "datastore-endpoint", os.Getenv("K3SM_DATASTORE_ENDPOINT"), "kine datastore DSN (postgres://user:pass@host:port/db?sslmode=…) for HA multi-writer; empty = single-node kine→SQLite (or $K3SM_DATASTORE_ENDPOINT)")
	fs.BoolVar(&opts.serverJoin, "server-join", false, "this server joins/forms an HA control plane — REQUIRES --datastore-endpoint (split-brain guard) and sets the HA leader-election. With --server it also fetches the identical-CA bundle from an existing server (M6.1)")
	// M6.1 HA server-join: a SECOND control-plane server reconstructs the identical
	// cluster + signing CAs from the first server's AES-256-GCM bundle. --token is the
	// SERVER-class token (off argv via $K3SM_TOKEN, like the agent).
	fs.StringVar(&opts.joinServer, "server", "", "existing server's mesh host to fetch the identical-CA bootstrap bundle from (HA server-join, M6.1; requires --server-join --mesh-ip --token)")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "server-class join token (K10<caHash>::server:<secret>) for the HA server-join (or $K3SM_TOKEN)")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if opts.ingressHTTPPort < 0 || opts.ingressHTTPPort > 65535 {
		return fmt.Errorf("--ingress-http-port %d out of range 0-65535", opts.ingressHTTPPort)
	}
	if opts.ingressHTTPSPort < 0 || opts.ingressHTTPSPort > 65535 {
		return fmt.Errorf("--ingress-https-port %d out of range 0-65535", opts.ingressHTTPSPort)
	}
	if opts.workDir == "" {
		if workDirErr != nil {
			return fmt.Errorf("resolve control-plane work-dir: %w (pass --work-dir)", workDirErr)
		}
		return fmt.Errorf("control-plane work-dir is empty (pass --work-dir)")
	}
	// Fail fast if the work-dir is not writable (the unprivileged control plane
	// must not EACCES mid-bring-up against the root-owned default).
	if err := executor.EnsureWorkDirWritable(opts.workDir); err != nil {
		return err
	}
	// runtimed's on-disk root is the work-dir's parent (so the SBPL Posture.WorkDir
	// resides under the daemon home and its containment check is active).
	if opts.podRoot == "" {
		opts.podRoot = executor.RuntimeRoot(opts.workDir)
	}

	// ONE construction-time decision (the `--network` backend): auto → root uses the
	// direct ops, unprivileged (the _k3sm control plane) routes the proxy/mesh
	// privileged ops through the root k3sm-netd helper; none → control-plane-only
	// (no datapath, no probe — CI/dev). Fail fast if the helper is selected but
	// unreachable, rather than wedging every pod in ContainerCreating.
	mode, err := hostnet.Resolve(opts.network)
	if err != nil {
		return err
	}
	logger.Info("host-network backend", "network", opts.network, "backend", mode.Backend.String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := mode.Probe(ctx); err != nil {
		return err
	}

	// 1. Control plane (child-process executor). Stop tears it down in reverse.
	cfg := opts.executorConfig(logger)
	// Packaged install: `k3sm install` stages the control-plane payload at
	// <install-dir>/bin beside the daemon binary; boot seeds the workdir from it
	// so it never shells out to gh/go (absent under launchd as _k3sm). Dev shells
	// (no bin/ sibling) keep the acquisition fallbacks.
	if exe, err := os.Executable(); err == nil {
		if fi, serr := os.Stat(filepath.Join(filepath.Dir(exe), "bin")); serr == nil && fi.IsDir() {
			cfg.PayloadBinDir = filepath.Join(filepath.Dir(exe), "bin")
		}
	}
	// M6.0 HA: a Postgres datastore endpoint (or --server-join) puts kine on the shared
	// Postgres — the same pinned kine build as single-node, a driver choice not a second
	// version — and turns on scheduler/KCM leader election so only one server is active. The executor fail-closes (ErrHARequiresDatastore) if HA is
	// requested without the endpoint — never a silent per-server SQLite (split-brain).
	cfg.DatastoreEndpoint = opts.datastoreEndpoint
	cfg.ServerJoin = opts.serverJoin
	if opts.datastoreEndpoint != "" || opts.serverJoin {
		logger.Info("HA datastore mode: kine→Postgres (shared multi-writer datastore); scheduler/KCM leader-elected", "server-join", opts.serverJoin)
	}
	// Standalone (non-HA-join): --token is the STATIC ADMIN bearer token — it must be
	// BOTH what the apiserver loads into its token-auth-file (system:masters) AND what
	// `k3sm install` wrote into the admin kubeconfig, or every admin request is
	// Unauthorized (the live M2-gate failure). Empty (a bare `k3sm server`) lets the
	// executor generate one + write its own kubeconfig. In the HA server-join path
	// --token is instead the JOIN token (consumed above to fetch the CA bundle); the
	// executor generates its own static token and HA admin auth is a client cert, so
	// the join token must NOT become the apiserver's static credential.
	if !opts.serverJoin {
		cfg.Token = opts.token
	}
	// M6.1 HA server-join: a SECOND control-plane server reconstructs the IDENTICAL
	// cluster + signing CAs from the first server's AES-256-GCM bootstrap bundle BEFORE
	// EnsureHierarchy (which then LOADS them). FAIL CLOSED — an import failure halts
	// bring-up; we never fall through to minting fresh, divergent CAs (cluster trust
	// split). Requires --mesh-ip (the joining server binds its own apiserver +
	// supervisor on the mesh) + --token (the server-class token).
	if opts.serverJoin && opts.joinServer != "" {
		if opts.meshIP == "" {
			return fmt.Errorf("--server-join with --server requires --mesh-ip (the joining server binds its apiserver + supervisor on the mesh)")
		}
		if opts.token == "" {
			return fmt.Errorf("--server-join with --server requires --token (the server-class join token)")
		}
		if err := importServerCABundle(ctx, opts, logger); err != nil {
			return fmt.Errorf("HA server-join: %w", err)
		}
	}

	// M3.0 multi-node: bind the apiserver + the worker-join supervisor on the mesh
	// interface ONLY, serve a cluster-CA-signed cert, wire --client-ca-file +
	// --kubelet-certificate-authority + --anonymous-auth=false. Empty --mesh-ip keeps
	// the single-node loopback/self-signed path (M1/M2) unchanged.
	var hierarchy *certs.Hierarchy
	var serverSecret string
	if opts.meshIP != "" {
		h, err := certs.EnsureHierarchy(opts.workDir)
		if err != nil {
			return fmt.Errorf("ensure CA hierarchy: %w", err)
		}
		hierarchy = h
		// M6.1: the server-bootstrap secret (machine-generated ≥256-bit) — minted +
		// persisted on the first server, already saved by importServerCABundle on a
		// joining server. It is the CA-bundle endpoint credential AND the bundle's KDF
		// passphrase.
		serverSecret, err = bootstrap.LoadOrCreateServerSecret(serverSecretPath(opts.workDir))
		if err != nil {
			return fmt.Errorf("server-bootstrap secret: %w", err)
		}
		// M6.1 deliverable 5b: an admin kubeconfig authenticated by a signing-CA-issued
		// system:masters CLIENT CERT (reconstructible on every server from the shared
		// signing CA) + cluster-CA server verification — so kubectl works against ANY HA
		// server. Written beside the executor's loopback token kubeconfig (which the
		// in-process components keep). Log-and-continue: it is an operator convenience,
		// not a bring-up dependency.
		if err := writeAdminClientCertKubeconfig(adminKubeconfigPath(opts.workDir), fmt.Sprintf("https://%s:%d", opts.meshIP, opts.apiPort), h); err != nil {
			logger.Error("write HA admin kubeconfig", "err", err)
		} else {
			logger.Info("wrote HA admin kubeconfig (signing-CA client cert; usable against any server)", "path", adminKubeconfigPath(opts.workDir))
		}
		// The MESH rewrite. It runs here, at mesh bring-up, and must stay STRICTLY
		// BEFORE the pod-CIDR advertise derivation (advertisedNodeIP, applied inside
		// startNode / lbHostingConfigs): applied the other way round, a mesh server
		// would advertise the pod /24's 100.64.0.1 while its peers — and every HA
		// server, which all compute the SAME index-0 podCIDR — know it by its mesh
		// IP, so two Macs would publish one EXTERNAL-IP.
		if isLoopbackDefault(opts.nodeIP) {
			opts.nodeIP = opts.meshIP
		}
		servingCert, servingKey, err := writeAPIServerServingCert(opts.workDir, h.Cluster, opts.meshIP)
		if err != nil {
			return err
		}
		anonFalse := false
		cfg.NodeIP = opts.meshIP
		cfg.BindAddress = opts.meshIP
		cfg.ClientCAFile = certs.SigningCACertPath(opts.workDir)
		cfg.KubeletCAFile = certs.ClusterCACertPath(opts.workDir)
		cfg.AnonymousAuth = &anonFalse
		cfg.ServingCertFile = servingCert
		cfg.ServingKeyFile = servingKey
		logger.Info("multi-node mode: apiserver + join supervisor bound to the mesh interface", "mesh-ip", opts.meshIP)
	}
	exec := executor.NewSupervised(cfg)
	logger.Info("bringing up k3sm control plane", "work-dir", opts.workDir, "api-port", opts.apiPort)
	if err := exec.Start(ctx); err != nil {
		return fmt.Errorf("start control plane: %w", err)
	}
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := exec.Stop(shutCtx); err != nil {
			logger.Error("control-plane shutdown", "err", err)
		}
	}()
	log.Printf("k3sm control plane healthy (kubeconfig=%s)", exec.Kubeconfig())

	// 2. Client for the post-bring-up provisioning + Service watch.
	restCfg, err := clientcmd.BuildConfigFromFlags("", exec.Kubeconfig())
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	// 3. Provision the cluster-scoped admission policies + the vm RuntimeClass.
	// Extracted so the SET is testable against a fake clientset (B153): what this
	// binary provisions is a posture-INDEPENDENT product decision, and a silently
	// absent policy is otherwise invisible until a real cluster admits something it
	// should have rejected.
	provisionClusterPolicies(ctx, cs, mode, os.Geteuid(), logger)

	// 3b. M4.1 — provision the RBAC graph BEFORE the VK node (step 5) and the
	// worker-join supervisor (step 4b) start, so a joining worker's system:node
	// datapath bindings already exist when the Node,RBAC authorizer (the apiserver
	// default since M4.1) evaluates its first request. FAIL-CLOSED: unlike the
	// advisory admission policies above (log-and-continue), a provisioning failure
	// HALTS bring-up — a half-applied graph under an enforcing authorizer silently
	// locks workers out of services/endpointslices/meshpeers. It runs under the
	// retained system:masters admin client (RBAC-exempt) with a bounded retry, so it
	// succeeds even though the authorizer is already on (no two-phase restart).
	if err := rbac.Provision(ctx, cs); err != nil {
		return fmt.Errorf("provision rbac graph: %w", err)
	}
	logger.Info("provisioned RBAC graph (node-datapath + in-pod reader); authorizer is Node,RBAC")

	// 3c. B170 — SSA-converge the EMBEDDED add-on manifest set. The manifests are
	// compiled into this binary (embed.FS), never read from disk: the work dir is
	// writable by every pod (all pods share the _k3sm uid and it is outside runtimed's
	// sandbox-protected prefixes) and this client is the system:masters admin, so a
	// directory ingress would hand cluster-admin to every pod on the node. See
	// pkg/addons/doc.go. Runs AFTER the fail-closed RBAC graph so a slow or failing
	// add-on can never delay it. Converge-only — it issues apply patches and never a
	// delete or a list. Log-and-continue like the sibling boot provisioners: the launchd
	// job is KeepAlive, so a startup-fatal manifest error would be an unbounded respawn
	// loop. The shipped set is EMPTY of product manifests today, so this is inert until
	// the first add-on lands.
	if ar, err := addons.NewFromConfig(addons.FS(), restCfg); err != nil {
		logger.Error("build embedded add-on reconciler", "err", err)
	} else if err := ar.Converge(ctx); err != nil {
		logger.Error("converge embedded add-on manifests", "err", err)
	}

	// 4. M1.4/M3.3 — host the node-local datapath: darwin-net's Service proxy
	// (exempted from the DNS VIP, which the per-node resolver below owns) + the
	// per-node cluster DNS resolver bound to the DNS VIP + the pod DNSConfig the
	// shim consumes. The NetdSocket routes the proxy/resolver privileged lo0/port
	// ops through the root helper when unprivileged (empty in root mode → direct
	// ops); Disabled (--network none) runs no datapath.
	//
	// MeshEgressIP is intentionally left empty on the server: `k3sm server` does not
	// bring up its own wireguard mesh device yet (that is the M3.0 two-Mac lab leg),
	// so there is no mesh-egress /32 lo0 alias to source from. Because the proxy's
	// backend dialer binds the mesh-egress source UNCONDITIONALLY (every dial,
	// including same-node loopback), setting a non-local value here would break ALL
	// backend dials. It is wired the moment the server-side mesh bring-up lands.
	// The control-plane node's pod /24: the reserved index-0 carve of the cluster
	// pod CIDR — the ONE value both the routing-table locality below and the
	// node's podnet adapter (step 5) allocate against (M10.1; the mesh enroller
	// reserves index 0 for this node, workers enroll 1+).
	//
	// M10.4: the NetworkPolicy table's always-allow set is seeded from this config
	// (NodeIP only here — MeshEgressIP is empty for the no-server-mesh reason
	// above, and no peer mesh-egress /32s are known at construction: workers
	// enroll DYNAMICALLY via the MeshPeer path after netserve is built). That is
	// the documented dynamic-peer gap (netserve.Config.PeerMeshEgressIPs): an
	// unseeded peer's node-origin dials are unattributable at this proxy and FAIL
	// OPEN with a throttled Warn — widen-only, never a wrong deny. Seeding peers
	// here rides the same follow-up as the server-side mesh bring-up.
	serverPodCIDR := defaultNodePodCIDR()
	// The kubernetes-VIP backend: ONLY the loopback-advertise posture (single
	// node) pins the static proxy backend at the apiserver's real loopback listen
	// address — upstream validation rejects loopback endpoint addresses, so no
	// kubernetes EndpointSlice can exist there. A mesh apiserver binds/advertises
	// the mesh IP, publishes its OWN valid endpoints, and the proxy must follow
	// that real slice (a static loopback pin would route the VIP at a
	// non-listening address).
	apiServerEndpoint := ""
	if isLoopbackDefault(opts.nodeIP) {
		apiServerEndpoint = "127.0.0.1:" + strconv.Itoa(opts.apiPort)
	}
	net := netserve.New(netserve.Config{
		Client:            cs,
		WorkDir:           opts.workDir,
		DNSVIP:            opts.clusterIP,
		ClusterDomain:     opts.domain,
		APIServerEndpoint: apiServerEndpoint,
		NodeIP:            opts.nodeIP,
		PodCIDR:           serverPodCIDR,
		NetdSocket:        mode.Socket,
		Disabled:          !mode.DataPath(),
		Logger:            logger,
	})
	go func() {
		if err := net.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("darwin-net services", "err", err)
		}
	}()

	// 4b. M3.0/M6.1 — the worker-join supervisor (mesh-bound; mints node certs + enrolls
	// peers), plus the M6.1 CA-bundle endpoint in the HA posture. Only when multi-node is
	// enabled; the live two-Mac join is the K3SM_LAB gate (the MeshPeer CRD must be
	// installed for the enroller's write to land).
	if opts.meshIP != "" && hierarchy != nil {
		tokens := bootstrap.NewFileTokenStore(bootstrap.TokensPath(opts.workDir), nil)
		enroller, err := newMeshEnroller(restCfg, logger)
		if err != nil {
			return fmt.Errorf("build mesh enroller: %w", err)
		}
		// M6.1 deliverable 4: in HA the node-password binding must be SHARED across
		// servers (a name bound on A is enforced on B), so it is datastore-backed (a
		// kube-system Secret on the shared Postgres). A single multi-node server keeps
		// the in-memory store.
		ha := opts.datastoreEndpoint != "" || opts.serverJoin
		var nodePasswords bootstrap.NodePasswordStore = bootstrap.NewMemoryNodePasswords()
		if ha {
			nodePasswords = newSecretNodePasswords(cs)
		}
		deps := bootstrapServerDeps{
			hierarchy:     hierarchy,
			meshIP:        opts.meshIP,
			tokens:        tokens,
			nodePasswords: nodePasswords,
			enroller:      enroller,
			apiServers:    []string{fmt.Sprintf("%s:%d", opts.meshIP, opts.apiPort)},
		}
		// M6.1 deliverables 1+2: serve the AES-256-GCM CA bundle authorized by the
		// SERVER-class token ONLY (never a worker), sealing the live hierarchy; publish
		// the sealed envelope to the shared datastore (the k3s bootstrap-key model).
		if ha {
			bundle := &liveBundleSource{hierarchy: hierarchy, secret: serverSecret}
			deps.bundle = bundle
			deps.serverAuth = bootstrap.NewStaticServerSecret(serverSecret)
			if sealed, err := bundle.SealedBundle(ctx); err != nil {
				logger.Error("seal bootstrap bundle for datastore", "err", err)
			} else if err := publishBootstrapBundle(ctx, cs, sealed); err != nil {
				logger.Warn("publish bootstrap bundle to datastore", "err", err)
			}
		}
		go func() {
			if err := startBootstrapServer(ctx, deps, logger); err != nil && ctx.Err() == nil {
				logger.Error("worker-join supervisor", "err", err)
			}
		}()
	}

	// 4c. M3.2 — the APFS local-path provisioner: a pure API-object controller that
	// registers the local-path StorageClass and creates a Retain, node-affinity-pinned
	// PV for each PVC the scheduler has placed. It does NO filesystem I/O — runtimed
	// empty-creates the per-(namespace, claim) dir on the consuming node. The class
	// BasePath is the RESOLVED runtime root (opts.podRoot — the same root runtimed
	// derives per-PVC dirs against), NOT the root-only storagev1.DefaultBasePath.
	// Started now (the apiserver is healthy) and drained BEFORE exec.Stop tears the
	// control plane down: the drain defer below is registered AFTER exec.Stop's defer,
	// so LIFO runs it FIRST — the provisioner never writes a PV against a draining
	// apiserver. provCtx lets the drain cancel it even if startNode returns an error
	// (ctx not yet cancelled), avoiding a shutdown hang.
	prov := provisioner.New(cs, provisioner.ClassForRoot(opts.podRoot), logger)
	provCtx, provCancel := context.WithCancel(ctx)
	provDone := make(chan struct{})
	go func() {
		defer close(provDone)
		if err := prov.Run(provCtx); err != nil && provCtx.Err() == nil {
			logger.Error("local-path provisioner", "err", err)
		}
	}()
	defer func() {
		provCancel()
		<-provDone
	}()

	// 4c-bis. M8.5 — the MLX operator: ensures the MLXModel CRD, then reconciles
	// each MLXModel into a StatefulSet plus its headless and ClusterIP Services.
	// Same lifetime and the same reasoning as the provisioner above — started now
	// that the apiserver is healthy, and drained BEFORE exec.Stop tears the control
	// plane down by a defer registered after it, so LIFO runs this one first.
	//
	// The GPU source is LIVE on this path (B195). The pre-render fit check reads
	// the node-local runtime's GPU facts, and this process is about to bring up
	// that node in-process — so the source is created here, wired into the
	// operator now, and ATTACHED to the node's runtime at step 5 bring-up
	// (nodeOptions.attachRuntimeInfo below). It is the same GetRuntimeInfo the
	// node's capability probe reads, off the same runtime; no second connection.
	//
	// Until that attach lands — and forever, on a posture with no runtimed at all
	// (--runtime hostprocess) — the source reports unknown, which SKIPS the fit
	// check with a logged warning exactly as a nil source did. A wiring fault
	// degrades; it never refuses a model and never crashes the reconcile.
	mlxGPU := operator.NewRuntimeGPU(logger)
	if dynClient, err := dynamic.NewForConfig(restCfg); err != nil {
		logger.Error("build dynamic client for the mlx operator", "err", err)
	} else if crdClient, err := apiextensionsclient.NewForConfig(restCfg); err != nil {
		logger.Error("build apiextensions client for the mlx operator", "err", err)
	} else if mlxOp, err := operator.New(mlxOperatorConfig(cs, dynClient, crdClient, mlxGPU, opts.domain, logger)); err != nil {
		logger.Error("build the mlx operator", "err", err)
	} else {
		mlxCtx, mlxCancel := context.WithCancel(ctx)
		mlxDone := make(chan struct{})
		go func() {
			defer close(mlxDone)
			if err := mlxOp.Run(mlxCtx); err != nil && mlxCtx.Err() == nil {
				logger.Error("mlx operator", "err", err)
			}
		}()
		defer func() {
			mlxCancel()
			<-mlxDone
		}()
	}

	// The in-process node's options are built HERE, before the LB/ingress block,
	// and the LB/ingress configuration is derived from this same value — so the
	// address `kubectl get svc` shows as EXTERNAL-IP and the address the Node
	// object advertises cannot diverge (they read one podCIDR, one nodeIP, one
	// netMode through one shared derivation, advertisedNodeIP).
	//
	// The kubelet endpoint's client-identity anchor is read here, off the work dir's
	// PKI: EnsureHierarchy has run (the mesh block above, or the executor's
	// provisionComponentCerts during exec.Start), so the signing CA certificate
	// exists in EVERY posture — single-node, `k3sm dev`, mesh and HA alike. It is
	// the same CA the apiserver's --client-ca-file trusts and the issuer of the
	// --kubelet-client-certificate the executor just minted, so the node and the
	// apiserver agree on the identity by construction rather than by configuration.
	// A read failure stops the server: :10250 is not served unauthenticated (B176).
	kubeletClientCA, err := os.ReadFile(certs.SigningCACertPath(opts.workDir))
	if err != nil {
		return fmt.Errorf("read the kubelet endpoint's client-identity CA: %w", err)
	}
	nodeOpts := nodeOptions{
		kubeconfig: exec.Kubeconfig(),
		nodeName:   opts.nodeName,
		listen:     serverKubeletListenOn(opts.kubeletPort),
		podRoot:    opts.podRoot,
		nodeIP:     opts.nodeIP,
		runtime:    opts.rtName,
		dnsShim:    opts.dnsShim,
		pathShim:   opts.pathShim,
		dnsVIP:     opts.clusterIP, // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		domain:     opts.domain,    // SAME cluster domain CoreDNS serves → in-pod shim search list (B18)
		podCIDR:    serverPodCIDR,  // the reserved index-0 /24 (same source as the netserve locality above, M10.1)
		netMode:    mode,           // the resolved --network backend the podnet alias plumbing follows
		serveTLS:   true,           // M1.2: serve kubelet API over TLS so logs/exec work via the proxy

		kubeletClientCAPEM: kubeletClientCA, // B176: :10250 requires the apiserver's client cert

		// Close the loop opened at step 4c-bis: the node publishes its in-process
		// runtime here, and the MLX operator's fit check starts reading live GPU
		// facts off it. A hostprocess node never calls it, leaving the fit check
		// skipped — the honest answer where there is no runtimed to ask.
		attachRuntimeInfo: mlxGPU.Attach,
	}

	// 4d/4e. M10.3 — ingress hosting + svclb, beside the netserve datapath
	// (step 4) and like it skipped under --network none (they splice/route to
	// ClusterIP VIPs, which need the proxy's datapath).
	//
	// Both bind the WILDCARD and both advertise the node's DERIVED
	// globally-unicast InternalIP (B116) — see lbHostingConfigs, which owns the
	// whole decision. opts.nodeIP is READ, never written back: it feeds the
	// apiserver's --advertise-address/--bind-address above.
	//
	// 4d: darwin-net's L7 ingress (RouteTable + SNI CertStore + class-filtered
	// Watcher + Server) runs IN THIS PROCESS (SERVER-PROCESS-ONLY — multi-node
	// ingress is a named follow-up), fed by the same in-process ADMIN client:
	// referenced TLS Secrets are fetched by name under it, so key bytes only
	// ever live in the control-plane process and no RBAC is widened.
	// --ingress-http-port/--ingress-https-port select the explicit high-port
	// integration mode (never a silent fallback).
	//
	// 4e: svclb (klipper-lite, B32) binds *:port listeners for every LoadBalancer
	// Service and splices them to the Service's ClusterIP VIP, advertising
	// status.loadBalancer ONLY once a listener is actually bound.
	//
	// ORDER IS LOAD-BEARING: the ingress host is started BEFORE svclb, so the
	// ingress listeners take 80/443 first if a user LoadBalancer Service also
	// claims them (svclb additionally has an apiserver informer cache-sync to
	// complete before its first bind). The reserved-port set deliberately does
	// NOT include 80/443 — those are legitimate LoadBalancer ports — so the
	// residual race is a documented ceiling, not a guarded invariant.
	if mode.DataPath() {
		lbCfg, ingressCfg, err := lbHostingConfigs(cs, nodeOpts, opts.ingressHTTPPort, opts.ingressHTTPSPort, logger)
		if err != nil {
			logger.Error("ingress + svclb hosting disabled", "err", err)
		} else {
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
			} else {
				go func() {
					if err := lb.Run(ctx); err != nil && ctx.Err() == nil {
						logger.Error("svclb loadbalancer controller", "err", err)
					}
				}()
			}
		}
	}

	// 5. The Virtual Kubelet node (reuse runNode's bring-up).
	log.Printf("starting k3sm node %q (runtime=%s)", opts.nodeName, opts.rtName)
	return startNode(ctx, nodeOpts)
}

// writeAPIServerServingCert issues the apiserver's serving cert from the cluster CA
// (so a joining node that pinned the cluster CA verifies the apiserver via its
// kubeconfig) with SANs covering the mesh IP, loopback, the kubernetes service IP,
// and the in-cluster DNS names. It writes the cert 0644 and the key 0600 under the
// PKI dir and returns their paths for --tls-cert-file / --tls-private-key-file.
func writeAPIServerServingCert(workDir string, clusterCA *certs.CA, meshIP string) (certFile, keyFile string, err error) {
	dnsNames := []string{
		"kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local", "localhost",
	}
	ips := []net.IP{net.ParseIP(meshIP), net.ParseIP("127.0.0.1"), net.ParseIP("10.43.0.1")}
	certPEM, keyPEM, err := clusterCA.IssueServing("kube-apiserver", dnsNames, ips, 365*24*time.Hour)
	if err != nil {
		return "", "", fmt.Errorf("issue apiserver serving cert: %w", err)
	}
	certFile = certs.APIServerServingCertPath(workDir)
	keyFile = certs.APIServerServingKeyPath(workDir)
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write apiserver serving cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write apiserver serving key: %w", err)
	}
	return certFile, keyFile, nil
}

// provisionClusterPolicies lays down the cluster-scoped admission policies and the
// vm RuntimeClass on a freshly-healthy control plane. Every step is
// LOG-AND-CONTINUE: none of them can halt bring-up (unlike the fail-closed RBAC
// graph that follows), because a node that refuses to start is strictly worse than
// a node missing an advisory.
//
// The set is POSTURE-INDEPENDENT — mode is logged, never branched on. That is the
// B153 fix: the foreign-user ceiling used to be provisioned only under the netd
// helper backend, so a `--network none`/`direct` cluster ran with no such policy
// object at all and admitted the very pods the ceiling exists to reject.
//
// euid is the effective uid of this process; the foreign-user policy's allowed
// identity is derived from it by provider.PodExecutionUID, which answers "what uid
// do pods here actually execute as" rather than "what uid is the server".
func provisionClusterPolicies(ctx context.Context, cs kubernetes.Interface, mode hostnet.Mode, euid int, logger *slog.Logger) {
	allowedUID := provider.PodExecutionUID(euid)
	logger.Info("provisioning cluster admission policies",
		"network-backend", mode.Backend.String(), "pod-execution-uid", allowedUID)
	// M1.2 — the os=darwin ValidatingAdmissionPolicy (intent guard).
	if err := policy.EnsureDarwinAdmission(ctx, cs); err != nil {
		logger.Error("provision admission policy", "err", err)
	}
	// M3.1 — honest-gap Warn advisories on Services: externalTrafficPolicy: Local
	// is not honored (the userspace splice does not preserve client source IP) and
	// UDP ports have no datapath yet (the proxy opens no UDP listener). They warn at
	// the API (never reject) so the divergence is visible in kubectl. Provisioned
	// unconditionally — these are inherent Service-model limits, not mode-specific.
	if err := policy.EnsureExternalTrafficPolicyLocalWarn(ctx, cs); err != nil {
		logger.Error("provision externalTrafficPolicy=Local warn policy", "err", err)
	}
	if err := policy.EnsureUDPServiceWarn(ctx, cs); err != nil {
		logger.Error("provision UDP-service warn policy", "err", err)
	}
	// B116 — DENY a type: LoadBalancer Service declaring a port k3sm's own wildcard
	// listeners own (the NodePort range, the kubelet API port). Log-and-continue
	// like every sibling Ensure*, but the message NAMES the consequence: a silently
	// absent Deny VAP is otherwise indistinguishable from a present one, and the
	// operator would only meet the collision as an unexplained <pending> Service
	// (svclb still refuses the bind — that is the datapath half of the guard).
	if err := policy.EnsureRejectReservedLoadBalancerPort(ctx, cs); err != nil {
		logger.Error("provision reserved-loadbalancer-port DENY policy: a LoadBalancer Service declaring a k3sm-reserved port (NodePort range / kubelet API port) will now be ACCEPTED by the API instead of rejected; svclb still refuses to bind it, so such a Service stays <pending> with only a log line to explain it", "err", err)
	}
	// B17 — honest-gap Warn advisory on Pods: a pod with no toleration for the
	// provider taint (k3sm.io/provider:NoSchedule, on EVERY node) is left
	// Unschedulable by the scheduler. Warn at the API (never reject — a non-tolerating
	// pod is valid k8s) so a directly-created pod's omission is visible in kubectl.
	// Provisioned UNCONDITIONALLY (not mode-gated): the taint is on every node.
	if err := policy.EnsureProviderTolerationWarn(ctx, cs); err != nil {
		logger.Error("provision provider-toleration warn policy", "err", err)
	}
	// B91/B209 — honest-plumbing Warn advisory on Pods: a pod carrying a HAND-SET
	// k3sm.io/internet-egress annotation (without the operator-managed discriminator
	// label pkg/mlx.Render stamps) opts its sandbox into allow_internet_egress. The
	// policy + its unit tests landed with B91 but were never called from bring-up, so
	// a running cluster provisioned six policies and hand-setting the annotation warned
	// nothing — the same test-passes-wiring-absent class as B195. Provisioned
	// UNCONDITIONALLY like its siblings: the annotation is read on every runtime path,
	// not only under MLX. Log-and-continue — it is advisory, never a boundary.
	if err := policy.EnsureEgressAnnotationWarn(ctx, cs); err != nil {
		logger.Error("provision hand-set-internet-egress warn policy", "err", err)
	}
	// B76 — MUTATING policy on Pods: a DaemonSet-owned pod is created by the DS
	// controller (KCM), so the B17 CREATE-Warn advisory never reaches its author and
	// the pod sits Unschedulable against the provider taint. Inject the provider
	// toleration (never the os=darwin nodeSelector — Res.7) so DS pods schedule.
	// CHANGES the stored object, unlike the Warn/Deny VAPs. Log-and-continue; requires
	// the executor's v1beta1 runtime-config + MutatingAdmissionPolicy feature gate.
	if err := policy.EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		logger.Error("provision daemonset-toleration mutating policy", "err", err)
	}
	// B153 — every pod runs as ONE uid (no per-pod uid isolation), so REJECT a pod
	// requesting a foreign runAsUser/runAsGroup/fsGroup/supplementalGroups at
	// admission rather than letting it wedge at spawn. Provisioned UNCONDITIONALLY,
	// like its siblings: the ceiling is a product-wide property. It used to sit
	// behind `if mode.UsesHelper()` — a deliberate choice, on the reasoning that a
	// root server can honor a real drop and `none` is CI-only — but that made the
	// networking-backend selector stand in for "can the runtime honor a uid drop",
	// so `--network none`/`direct` clusters had NO policy object and admitted the
	// pods the ceiling exists to reject. Accepted cost of the operator's ratified
	// Option A: a root server no longer serves a foreign-fsGroup pod it could
	// genuinely have honored.
	if err := policy.EnsureNoForeignUserAdmission(ctx, cs, allowedUID); err != nil {
		logger.Error("provision foreign-user admission policy: a pod requesting a foreign runAsUser/fsGroup will now be ADMITTED and then wedge at spawn (or silently run as the wrong identity) instead of being rejected at the API", "err", err)
	}
	// M10.0 (Res.5) — the memory-only default LimitRange in the `default` namespace:
	// containers that omit resources get honest memory defaults (memory IS enforced
	// via the rusage sampler→OOMKill); deliberately NO cpu key (best-effort only).
	// Create-or-update like every sibling Ensure* (B153 — see pkg/policy.ensure:
	// a create-only provisioner freezes the shipped defaults at whatever a cluster
	// was first created with); log-and-continue like the sibling advisories.
	if err := policy.EnsureDefaultLimitRange(ctx, cs); err != nil {
		logger.Error("provision default memory limitrange", "err", err)
	}
	// M5.1 — provision the vm RuntimeClass (node.k8s.io/v1 "vm", handler vm, with a
	// scheduling.nodeSelector pinning it to VZ-capable nodes via
	// k3sm.io/virtualization). Log-and-continue (NOT fail-closed like rbac): a missing
	// RuntimeClass cannot lock workers out — it only makes a vm pod unschedulable / a
	// vm-pod admission rejected — so it never halts bring-up. No node advertises the
	// VZ label today (runtimed reports no per-backend availability), so a vm pod stays
	// Pending — the correct posture for this non-VZ foundation.
	if err := runtimeclass.Provision(ctx, cs); err != nil {
		logger.Error("provision vm runtime class", "err", err)
	}
}
