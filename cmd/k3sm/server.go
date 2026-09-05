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
	"slices"
	"strconv"
	"syscall"
	"time"

	apiextensionsclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	crdconfig "k3sm.io/apis/config/crd"
	"k3sm.io/darwin-net/pkg/dns"

	"k3sm.io/k3sm/pkg/addons"
	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/crdensure"
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
	"k3sm.io/k3sm/pkg/registrysvc"
	"k3sm.io/k3sm/pkg/runtimeclass"
	"k3sm.io/k3sm/pkg/svclb"
)

// serverOptions configures `k3sm server` — the all-in-one control plane + node.
type serverOptions struct {
	workDir  string
	nodeName string
	nodeIP   string
	meshIP   string // wireguard mesh IP; set => multi-node worker-join supervisor
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

	datastoreEndpoint string // kine datastore DSN (postgres://… => HA multi-writer); empty = single-node SQLite
	serverJoin        bool   // declare HA control-plane intent (requires --datastore-endpoint; split-brain guard)
	joinServer        string // existing server's mesh host to fetch the identical-CA bundle from (HA server-join)
	token             string // server-class join token (K10<caHash>::server:<secret>) for the HA server-join

	psaEnforceBaseline bool // flip the PSA cluster-default enforce level privileged→baseline (the baseline-enforce cutover; default = warn-only)

	ingressHTTPPort  int // ingress HTTP listener port, bound on the wildcard (0 disables; 80 = production, an explicit high port = integration tier)
	ingressHTTPSPort int // ingress HTTPS listener port (same contract as ingressHTTPPort; 443 = production)

	// registryPort is the loopback port the node-local OCI ingest registry serves
	// on. 0 DISABLES it, and that is the shipped default: the registry stages and
	// runs a pinned zot child, which is real disk and a real process, and a server
	// that never ingests a locally built image should pay for neither.
	registryPort int
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
		// false ships baseline-WARN; true is the enforce cutover (see the
		// flag comment above — executor.Config.PSAEnforceBaseline is the single seam).
		PSAEnforceBaseline: opts.psaEnforceBaseline,
		Logger:             logger,
	}
}

// registerServerFlags binds `k3sm server`'s flags onto fs and returns the error
// (if any) from resolving the posture-aware --work-dir DEFAULT, which the caller
// surfaces after Parse so an explicit --work-dir can still override it.
//
// It is a function rather than an inline block in runServer for the same reason
// registerAgentFlags is: the REGISTERED SURFACE is then assertable without
// parsing argv through a live bring-up — including the negative assertions,
// which are the ones that cannot be written any other way. The dev-only
// guest-artifact directory override is exactly such a negative
// (TestGuestArtifactsDirOverrideIsDevOnly): a flag whose absence is the
// requirement can only be checked against the real flag set.
func registerServerFlags(fs *flag.FlagSet, opts *serverOptions) error {
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
	// Pod Security Admission. The SHIPPED default is baseline-WARN only (enforce stays
	// privileged; warn=baseline + audit=restricted — audit-observable, zero
	// rejection). This flag is the documented, REVERSIBLE cutover MECHANISM for the
	// baseline-enforce flip: set it only after a pre-flight scan proves the cluster
	// clean; dropping the flag reverts the posture on the next boot. It is an operator argv toggle of a single apiserver config
	// value, not a runtime feature-flag code path.
	fs.BoolVar(&opts.psaEnforceBaseline, "psa-enforce-baseline", false, "flip the cluster-wide Pod Security Admission default ENFORCE level from privileged to baseline (the baseline-enforce cutover; the shipped default is baseline-warn only)")
	// Ingress listener ports. 80/443 is the production posture; an EXPLICIT
	// high-port pair (e.g. 8080/8443) is the integration-tier mode. There is
	// deliberately NO silent fallback between the two — a failed bind is logged and
	// boundedly retried, never re-ported. The listeners bind the WILDCARD
	// in-process (a wildcard bind is unprivileged on Darwin at any port), so no netd
	// authorization is involved; they are started BEFORE svclb so they win a contest
	// for these ports against a user LoadBalancer Service declaring them.
	fs.IntVar(&opts.ingressHTTPPort, "ingress-http-port", 80, "ingress HTTP listener port, bound on ALL interfaces (80 = production; an explicit high port is the integration-tier mode; 0 disables the HTTP listener)")
	fs.IntVar(&opts.ingressHTTPSPort, "ingress-https-port", 443, "ingress HTTPS listener port, bound on ALL interfaces (443 = production; an explicit high port is the integration-tier mode; 0 disables the HTTPS listener)")
	// The node-local OCI ingest registry (pkg/registrysvc). DISABLED by default —
	// it is opt-in capacity, not part of a control plane. When enabled it binds
	// LOOPBACK ONLY and that is not configurable: pull is anonymous and push is
	// plain HTTP, so the whole posture rests on nothing off-host being able to
	// reach it. `k3sm dev` enables it on a per-instance allocated port.
	fs.IntVar(&opts.registryPort, "registry-port", 0, "node-local OCI ingest registry port on 127.0.0.1 — push locally built images here and pull them by `localhost:<port>/<ref>` (0 disables; "+strconv.Itoa(executor.DefaultRegistryPort)+" is the suggested port)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP CoreDNS binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (control-plane-only, no datapath/probe) | direct (force lo0, root) | helper (force netd helper)")
	// HA datastore. The DSN may carry a password; prefer the env so it stays off
	// k3sm's own argv (mirrors --token/$K3SM_TOKEN). k3sm relocates the password off
	// the kine child's argv too (a 0600 PGPASSFILE), so `ps` never sees the secret.
	fs.StringVar(&opts.datastoreEndpoint, "datastore-endpoint", os.Getenv("K3SM_DATASTORE_ENDPOINT"), "kine datastore DSN (postgres://user:pass@host:port/db?sslmode=…) for HA multi-writer; empty = single-node kine→SQLite (or $K3SM_DATASTORE_ENDPOINT)")
	fs.BoolVar(&opts.serverJoin, "server-join", false, "this server joins/forms an HA control plane — REQUIRES --datastore-endpoint (split-brain guard) and sets the HA leader-election. With --server it also fetches the identical-CA bundle from an existing server")
	// HA server-join: a SECOND control-plane server reconstructs the identical
	// cluster + signing CAs from the first server's AES-256-GCM bundle. --token is the
	// SERVER-class token (off argv via $K3SM_TOKEN, like the agent).
	fs.StringVar(&opts.joinServer, "server", "", "existing server's mesh host to fetch the identical-CA bootstrap bundle from (HA server-join; requires --server-join --mesh-ip --token)")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "server-class join token (K10<caHash>::server:<secret>) for the HA server-join (or $K3SM_TOKEN)")
	return workDirErr
}

// runServer brings up the control plane (via the executor) and a Virtual Kubelet
// node in one process, then hosts darwin-net's Service proxy + CoreDNS config +
// DNS shim and provisions the os=darwin admission policy. It blocks until
// interrupted, then shuts the control plane down cleanly.
func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := serverOptions{}
	workDirErr := registerServerFlags(fs, &opts)
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if opts.ingressHTTPPort < 0 || opts.ingressHTTPPort > 65535 {
		return fmt.Errorf("--ingress-http-port %d out of range 0-65535", opts.ingressHTTPPort)
	}
	if opts.ingressHTTPSPort < 0 || opts.ingressHTTPSPort > 65535 {
		return fmt.Errorf("--ingress-https-port %d out of range 0-65535", opts.ingressHTTPSPort)
	}
	if opts.registryPort < 0 || opts.registryPort > 65535 {
		return fmt.Errorf("--registry-port %d out of range 0-65535 (0 disables)", opts.registryPort)
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
	// HA: a Postgres datastore endpoint (or --server-join) puts kine on the shared
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
	// Unauthorized (an observed live-hardware failure). Empty (a bare `k3sm server`) lets the
	// executor generate one + write its own kubeconfig. In the HA server-join path
	// --token is instead the JOIN token (consumed above to fetch the CA bundle); the
	// executor generates its own static token and HA admin auth is a client cert, so
	// the join token must NOT become the apiserver's static credential.
	if !opts.serverJoin {
		cfg.Token = opts.token
	}
	// HA server-join: a SECOND control-plane server reconstructs the IDENTICAL
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

	// Multi-node: bind the apiserver + the worker-join supervisor on the mesh
	// interface ONLY, serve a cluster-CA-signed cert, wire --client-ca-file +
	// --kubelet-certificate-authority + --anonymous-auth=false. Empty --mesh-ip keeps
	// the single-node loopback/self-signed path unchanged.
	var hierarchy *certs.Hierarchy
	var serverSecret string
	if opts.meshIP != "" {
		h, err := certs.EnsureHierarchy(opts.workDir)
		if err != nil {
			return fmt.Errorf("ensure CA hierarchy: %w", err)
		}
		hierarchy = h
		// The server-bootstrap secret (machine-generated ≥256-bit) — minted +
		// persisted on the first server, already saved by importServerCABundle on a
		// joining server. It is the CA-bundle endpoint credential AND the bundle's KDF
		// passphrase.
		serverSecret, err = bootstrap.LoadOrCreateServerSecret(serverSecretPath(opts.workDir))
		if err != nil {
			return fmt.Errorf("server-bootstrap secret: %w", err)
		}
		// An admin kubeconfig authenticated by a signing-CA-issued
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
		// The CA that ISSUED that serving leaf is what the controller-manager must
		// republish as every namespace's kube-root-ca.crt — the anchor every Pod uses to
		// verify the apiserver. Set here, beside the serving cert, because the two are one
		// posture: the executor derives --root-ca-file off the same predicate as
		// --tls-cert-file, so they cannot name CAs from different modes. Without it the
		// KCM would be pointed at the apiserver's SELF-SIGNED --cert-dir file, which on a
		// mesh boot the apiserver never writes (bring-up dies on "error parsing
		// root-ca-file"), and which on a work dir that once booted single-node is a stale
		// CA that anchors nothing — in-pod API TLS then fails cluster-wide.
		cfg.RootCAFile = certs.ClusterCACertPath(opts.workDir)
		// The supervisor is deliberately NOT mesh-bound: a joining worker reaches
		// it over the underlay, having no mesh until that join completes (see
		// bootstrapListenAddr).
		logger.Info("multi-node mode: apiserver bound to the mesh interface; the worker-join supervisor listens on every interface", "mesh-ip", opts.meshIP)
	}
	// 1b. The mesh IP has to be an address this host ANSWERS on before the
	// apiserver is told to bind it. Nothing used to plumb it this early: the only
	// writer was mesh.Start, at step 4b, so the first real `--mesh-ip 100.64.0.1`
	// boot died at step 1 with "listen tcp 100.64.0.1:6444: bind: can't assign
	// requested address" and a human had to alias it by hand. FAIL-FAST, unlike
	// the log-and-continue mesh bring-up at 4b: that stage degrades a live control
	// plane, this one decides whether there is a control plane at all.
	if err := ensureMeshIPAlias(ctx, opts.meshIP, mode, logger); err != nil {
		return err
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
	// Extracted so the SET is testable against a fake clientset: what this
	// binary provisions is a posture-INDEPENDENT product decision, and a silently
	// absent policy is otherwise invisible until a real cluster admits something it
	// should have rejected.
	provisionClusterPolicies(ctx, cs, mode, os.Geteuid(), logger)

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
	// delete or a list. Log-and-continue like the sibling boot provisioners: the launchd
	// job is KeepAlive, so a startup-fatal manifest error would be an unbounded respawn
	// loop. The shipped set is EMPTY of product manifests today, so this is inert until
	// the first add-on lands.
	if ar, err := addons.NewFromConfig(addons.FS(), restCfg); err != nil {
		logger.Error("build embedded add-on reconciler", "err", err)
	} else if err := ar.Converge(ctx); err != nil {
		logger.Error("converge embedded add-on manifests", "err", err)
	}

	// Whether this node can host vm guests, asked HERE — before the
	// registry and the datapath are constructed and long before the VK node exists
	// — through runtimed's own safe host probe rather than through the node's
	// advertised capability, which is not answerable yet (see vmBackendAvailable).
	// It has two consumers: the registry relay's vmnet-gateway bind (step 3d),
	// which is the only address a Linux-guest Pod can reach a host listener at, and
	// the NetworkPolicy table's fail-closed unknown-vm-source branch (step 4c),
	// scoped to the segment macOS's vmnet is expected to hand guests. False leaves
	// both byte-identical to a node that runs no guests.
	vmCapable := vmBackendAvailable()

	// 3d. The node-local OCI ingest registry (--registry-port; 0 disables, which
	// is the default). It runs HERE, after the apiserver is healthy, because
	// bringing it up also publishes the KEP-1755 local-registry-hosting ConfigMap
	// — discovery needs a cluster to publish into.
	//
	// It is torn down BEFORE the control plane: this defer is registered AFTER
	// exec.Stop's, so LIFO runs it first. That ordering is not cosmetic — the
	// registry child holds a port and an open blob store, and a control plane that
	// went away underneath it would leave both to the process reaper.
	//
	// NEVER FATAL: startIngestRegistry logs and returns a no-op teardown if the
	// registry cannot come up. See its doc for why that is the right posture here
	// and the wrong one at step 3b.
	//
	// It also yields the PULLER WIRING — how runtimed should spell this node's own
	// registry — which is handed to the node below so a reference naming the
	// Service address is classified exactly as a loopback one is. The zero value
	// (no registry) leaves runtimed's classification unchanged.
	var registryPuller registryPullerWiring
	if opts.registryPort != 0 {
		svc, err := registrysvc.New(registryConfig(opts, cfg.PayloadBinDir, logger))
		if err != nil {
			logger.Error("ingest registry disabled", "err", err)
		} else {
			stopRegistry, puller := startIngestRegistry(ctx, ingestRegistry{
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
			defer stopRegistry()
			registryPuller = puller
		}
	}

	// 4a. The MeshPeer CRD, on the MESH path only, BEFORE anything that can
	// write a MeshPeer exists. Nothing used to apply it: the manifest shipped in
	// k3sm.io/apis and every worker join 500'd at the enroller's write until a human
	// installed the CRD by hand.
	//
	// The ORDER is the point. It must precede newMeshEnroller (step 4b) and therefore
	// the join listener startBootstrapServer opens, because the first worker to reach
	// that listener writes a MeshPeer — a CRD ensured afterwards would still lose
	// whichever join won the race. It also precedes this server's OWN
	// enroll, which is the very first MeshPeer written on a fresh cluster.
	//
	// FAIL-CLOSED, like the RBAC graph at step 3b and unlike the log-and-continue
	// admission policies at step 3: a missing MeshPeer CRD is not a missing advisory,
	// it is a control plane that accepts worker joins and then fails every one of
	// them. Halting with the reason beats serving a supervisor that cannot enroll.
	//
	// Single-node (--mesh-ip empty) provisions NOTHING — no MeshPeer is ever written
	// there — and ensureMeshPeerCRD returns before it builds any client, so this call
	// adds no failure mode to the single-node bring-up path.
	if err := ensureMeshPeerCRD(ctx, opts.meshIP, func() (crdensure.CRDClient, error) {
		return apiextensionsclient.NewForConfig(restCfg)
	}, logger); err != nil {
		return err
	}

	// 4b. THIS SERVER JOINS ITS OWN MESH.
	//
	// The enroller is constructed here, not at the supervisor (step 4d), because both
	// callers must share ONE instance: its mutex is what serializes this node's
	// index-0 claim against a worker join, and two instances would contend on
	// nothing. Its construction stays FAIL-CLOSED — a supervisor that cannot enroll
	// is a control plane that rejects every join.
	//
	// The self-enroll itself is LOG-AND-CONTINUE, following the precedent
	// provisionClusterPolicies sets: under launchd KeepAlive a fatal error on this
	// path is an unbounded respawn loop on the one process that also hosts the
	// apiserver, kine and the scheduler, and a mesh-only defect must never take the
	// control plane down. What is lost on failure is named in the log line, because
	// "the server is not on its own mesh" is otherwise only visible as cross-node
	// traffic that silently goes nowhere.
	//
	// It completes BEFORE step 4c builds the proxy (mesh.Start plumbs the mesh-egress
	// lo0 alias the proxy's source bind depends on) and BEFORE step 4d opens the join
	// listener (EnrollSelf list-back verifies the index-0 claim, so no worker can be
	// assigned index 0 in the window).
	var enroller *meshEnroller
	// serverPodCIDR is the control-plane node's pod /24: the reserved index-0 carve
	// of the cluster pod CIDR — the ONE value the routing-table locality (step 4c)
	// and the node's podnet adapter (step 5) both allocate against.
	serverPodCIDR := defaultNodePodCIDR()
	// The mesh-egress source the proxy binds for cross-node backend dials, and the
	// peer mesh-egress /32s the NetworkPolicy table always-allows. Empty until this
	// node is on its own mesh — an empty MeshEgressIP is the honest "no mesh here".
	var serverMeshEgressIP string
	var peerMeshEgress []string
	if opts.meshIP != "" && hierarchy != nil {
		e, err := newMeshEnroller(restCfg, logger)
		if err != nil {
			return fmt.Errorf("build mesh enroller: %w", err)
		}
		enroller = e
		if res, err := enrollSelfAndBringUpMesh(ctx, enroller, opts, mode, exec.Kubeconfig(), logger); err != nil {
			logger.Error("server mesh bring-up failed; this node is NOT on its own mesh, so cross-node pod traffic to it has no path and its Service proxy will source backend dials from the kernel default", "err", err)
		} else {
			serverPodCIDR = res.PodCIDR
			if mode.DataPath() {
				serverMeshEgressIP = res.MeshIP
				// A boot-time SNAPSHOT. A peer that enrolls after this
				// point reconverges in wireguard via the MeshPeer watch but is
				// not in this table until the next restart; the posture is
				// fail-open widen-only ("never a wrong deny"), so the gap
				// degrades attribution, not connectivity.
				peerMeshEgress = peerMeshEgressIPs(res.Peers)
			}
		}
	}

	// 4c. Host the node-local datapath: darwin-net's Service proxy
	// (exempted from the DNS VIP, which the per-node resolver below owns) + the
	// per-node cluster DNS resolver bound to the DNS VIP + the pod DNSConfig the
	// shim consumes. The NetdSocket routes the proxy/resolver privileged lo0/port
	// ops through the root helper when unprivileged (empty in root mode → direct
	// ops); Disabled (--network none) runs no datapath.
	//
	// MeshEgressIP and PeerMeshEgressIPs are seeded from step 4b's enroll. The
	// dialer's source bind is DESTINATION-SCOPED (darwin-net binds it only for a
	// destination inside the cluster pod CIDR and outside this node's own /24), so
	// wiring a real mesh-egress source here does not disturb loopback, ClusterIP or
	// node-LAN dials — an unscoped source bind is what made this wiring unsafe
	// before.
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
		MeshEgressIP:      serverMeshEgressIP,
		PeerMeshEgressIPs: peerMeshEgress,
		VMBackend:         vmCapable,
		VMNetSubnet:       netserve.DefaultVMNetSubnet,
		NetdSocket:        mode.Socket,
		Disabled:          !mode.DataPath(),
		Logger:            logger,
	})
	go func() {
		if err := net.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("darwin-net services", "err", err)
		}
	}()

	// 4d. The worker-join supervisor (mesh-bound; mints node certs + enrolls
	// peers), plus the CA-bundle endpoint in the HA posture. Only when multi-node is
	// enabled; the live two-Mac join is the K3SM_LAB gate (step 4a has already ensured
	// the MeshPeer CRD the enroller's write lands in, and step 4b has already claimed
	// index 0 through this same enroller).
	if enroller != nil {
		tokens := bootstrap.NewFileTokenStore(bootstrap.TokensPath(opts.workDir), nil)
		// In HA the node-password binding must be SHARED across
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
		// Serve the AES-256-GCM CA bundle authorized by the
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

	// 4e. The APFS local-path provisioner: a pure API-object controller that
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

	// 4f. The MLX operator: ensures the MLXModel CRD, then reconciles
	// each MLXModel into a StatefulSet plus its headless and ClusterIP Services.
	// Same lifetime and the same reasoning as the provisioner above — started now
	// that the apiserver is healthy, and drained BEFORE exec.Stop tears the control
	// plane down by a defer registered after it, so LIFO runs this one first.
	//
	// The GPU source is LIVE on this path. The pre-render fit check reads
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
	// A read failure stops the server: :10250 is not served unauthenticated.
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
		domain:     opts.domain,    // SAME cluster domain CoreDNS serves → in-pod shim search list
		podCIDR:    serverPodCIDR,  // the reserved index-0 /24 (same source as the netserve locality above)
		netMode:    mode,           // the resolved --network backend the podnet alias plumbing follows
		serveTLS:   true,           // serve kubelet API over TLS so logs/exec work via the proxy

		kubeletClientCAPEM: kubeletClientCA, // :10250 requires the apiserver's client cert

		// Close the loop opened at step 4f: the node publishes its in-process
		// runtime here, and the MLX operator's fit check starts reading live GPU
		// facts off it. A hostprocess node never calls it, leaving the fit check
		// skipped — the honest answer where there is no runtimed to ask.
		attachRuntimeInfo: mlxGPU.Attach,
		// The Service proxy this same process just built (step 4) is where the
		// provider publishes a vm pod's live guest lease, so a Service backed by a
		// guest is dialed at the address that carries bytes while everything else
		// keys on the /32 the pod publishes. nil under --network none, where there
		// is no proxy to feed.
		transportOverrides: nodeTransportOverrides(net, mode),
		// How runtimed spells this node's own ingest registry (step 3d): the
		// loopback authority a bare "app:v1" resolves against first, and the
		// non-loopback spellings of the same registry — a reference naming one of
		// them is node-relative in exactly the sense a `localhost:<port>/…`
		// reference is, so it gets the same plain-HTTP transport and the same
		// peer-mirror brokering. Zero on a node with no registry.
		localRegistryHost: registryPuller.LocalHost,
		clusterRegistries: registryPuller.ClusterRegistries,
	}

	// 4f-bis. The control-plane node's OWN kubelet serving cert.
	//
	// A worker receives one in its join response; this node never joins, so nothing
	// hands it one and it self-signed — against its own apiserver, which the mesh
	// block above started with --kubelet-certificate-authority=<cluster CA>. That is
	// the defect in its purest form: `kubectl logs` against the control-plane node
	// failed with "x509: certificate signed by unknown authority" on the very machine
	// holding the CA that could have signed it. It runs HERE because the SAN set is
	// read off the finished nodeOpts (below), and it fails the whole bring-up on a
	// mint error rather than degrading to the self-signed cert that is the defect.
	if err := setServerKubeletServing(&nodeOpts, hierarchy, opts.meshIP); err != nil {
		return err
	}

	// 4g/4h. Ingress hosting + svclb, beside the netserve datapath
	// (step 4c) and like it skipped under --network none (they splice/route to
	// ClusterIP VIPs, which need the proxy's datapath).
	//
	// Both bind the WILDCARD and both advertise the node's DERIVED
	// globally-unicast InternalIP — see lbHostingConfigs, which owns the
	// whole decision. opts.nodeIP is READ, never written back: it feeds the
	// apiserver's --advertise-address/--bind-address above.
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

// crdClientFactory builds the apiextensions client a CRD ensure applies through.
//
// It is a FACTORY rather than a client so that a bring-up which provisions no CRD
// constructs none: `k3sm server` without --mesh-ip has no MeshPeer consumer, and a
// client built unconditionally would add a new way for the single-node path to fail
// at a step it never needed.
type crdClientFactory func() (crdensure.CRDClient, error)

// ensureMeshPeerCRD server-side-applies the MeshPeer CustomResourceDefinition and
// blocks until the API server reports it Established, on the MESH path only.
//
// meshIP empty is the single-node posture: it returns nil having called newClient
// zero times. That gate lives HERE, not at the call site, so "which bring-up
// provisions the CRD" has one answer that a test can drive both sides of.
//
// The manifest is k3sm.io/apis' own bytes (crdconfig.MeshPeerCRD) applied through
// pkg/crdensure — the same applier the MLX operator uses for MLXModel — so there is
// no second apply path and no shadow copy of the schema. An error is returned, never
// logged and swallowed: the caller fail-closes on it (see step 4a in runServer).
func ensureMeshPeerCRD(ctx context.Context, meshIP string, newClient crdClientFactory, logger *slog.Logger) error {
	if meshIP == "" {
		return nil
	}
	c, err := newClient()
	if err != nil {
		return fmt.Errorf("build apiextensions client for the %s crd: %w", crdconfig.MeshPeerCRDName, err)
	}
	if _, err := crdensure.Ensure(ctx, c, crdconfig.MeshPeerCRD(), crdensure.Options{Log: logger}); err != nil {
		return fmt.Errorf("ensure the %s crd (worker joins cannot enroll without it): %w", crdconfig.MeshPeerCRDName, err)
	}
	logger.Info("ensured the MeshPeer CRD; worker enroll writes can now land", "crd", crdconfig.MeshPeerCRDName)
	return nil
}

// kubeletServingValidFor is the lifetime of the control-plane node's kubelet
// serving cert. It is pinned to the SAME 365d writeAPIServerServingCert gives the
// apiserver's leaf: both are re-minted by every boot of the same process, so a
// shorter life here would only mean the node's cert expired first on a long-lived
// server — a second expiry date to reason about, buying nothing.
const kubeletServingValidFor = 365 * 24 * time.Hour

// setServerKubeletServing mints the control-plane node's kubelet serving keypair
// from the CLUSTER CA and stores it on nodeOpts, for the posture where the
// apiserver was told to verify node certs against that CA.
//
// meshIP == "" is the single-node/dev posture: it leaves the fields EMPTY, so
// kubeletServingTLS self-signs exactly as before. That branch is load-bearing — a
// single-node apiserver configures no --kubelet-certificate-authority, so a
// cluster-CA leaf would buy nothing and the self-signed path stays the default this
// change does not disturb.
//
// The pair is held in MEMORY and re-minted on every boot: nothing is written to
// disk, so no new private key file joins the work dir and pkg/executor's rotation
// fence needs no new path (the artifact is nevertheless REPORTED there — see
// reissuedArtifacts — because a credential re-issued on every boot belongs in the
// rotation report whether or not it lands on a filesystem).
//
// It FAILS CLOSED. A cluster CA that cannot issue is an error the caller must
// propagate: falling back to a self-signed leaf here would silently reproduce the
// exact defect this function exists to remove, and would do it in the one case
// (broken PKI) where an operator most needs to be told.
func setServerKubeletServing(nodeOpts *nodeOptions, hierarchy *certs.Hierarchy, meshIP string) error {
	if meshIP == "" {
		return nil
	}
	// Checked BEFORE issuing, and down to the key: a CA loaded without its private
	// half cannot sign, and x509.CreateCertificate's reaction to one is not a
	// diagnosable error. Refusing here names the real fault — the work dir's PKI —
	// where an operator can act on it.
	if hierarchy == nil || hierarchy.Cluster == nil || hierarchy.Cluster.Cert == nil || hierarchy.Cluster.Key == nil {
		return fmt.Errorf("mint the control-plane node's kubelet serving cert: no usable cluster CA (the multi-node posture needs the signing half of the CA hierarchy the apiserver's --kubelet-certificate-authority names)")
	}
	certPEM, keyPEM, err := hierarchy.Cluster.IssueServing(
		nodeOpts.nodeName,
		[]string{nodeOpts.nodeName, "localhost"},
		serverKubeletServingIPs(*nodeOpts, meshIP),
		kubeletServingValidFor,
	)
	if err != nil {
		return fmt.Errorf("mint the control-plane node's kubelet serving cert: %w", err)
	}
	nodeOpts.kubeletServingCertPEM = certPEM
	nodeOpts.kubeletServingKeyPEM = keyPEM
	return nil
}

// serverKubeletServingIPs is the IP SAN set of that cert: every address the
// apiserver might dial this node's :10250 at, deduplicated, unparseable entries
// dropped.
//
//   - meshIP — what peers know this node by, and what a mesh apiserver binds;
//   - the ADVERTISED address (advertisedNodeIP) and the raw nodeOpts.nodeIP — the
//     two can differ, and startNode advertises the derived one;
//   - the REGISTERED InternalIP (proxyableNodeIP of the advertised opts, exactly as
//     startNode computes it). This is the address --kubelet-preferred-address-types
//     =InternalIP makes the apiserver dial, and in the NO-DATAPATH posture it
//     legitimately diverges from the advertised address — so omitting it would
//     reproduce the broken-logs/exec defect as a SAN mismatch instead of an issuer
//     mismatch, which is the
//     same broken logs/exec with a less legible error;
//   - 127.0.0.1 — the same-host dial.
//
// A superset is the safe direction here: every address in the set is one this node
// already serves on (the listen is the wildcard), so naming it in a SAN grants no
// reach that did not exist. Omitting one silently breaks logs/exec.
func serverKubeletServingIPs(nodeOpts nodeOptions, meshIP string) []net.IP {
	advertised := nodeOpts
	advertised.nodeIP = advertisedNodeIP(nodeOpts)
	candidates := []string{
		meshIP,
		nodeOpts.nodeIP,
		advertised.nodeIP,
		proxyableNodeIP(advertised),
		"127.0.0.1",
	}
	var ips []net.IP
	for _, c := range candidates {
		ip := net.ParseIP(c)
		if ip == nil || slices.ContainsFunc(ips, ip.Equal) {
			continue
		}
		ips = append(ips, ip)
	}
	return ips
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
// The fix: the foreign-user ceiling used to be provisioned only under the netd
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
	// The os=darwin ValidatingAdmissionPolicy (intent guard).
	if err := policy.EnsureDarwinAdmission(ctx, cs); err != nil {
		logger.Error("provision admission policy", "err", err)
	}
	// Honest-gap Warn advisories on Services: externalTrafficPolicy: Local
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
	// DENY a type: LoadBalancer Service declaring a port k3sm's own wildcard
	// listeners own (the NodePort range, the kubelet API port). Log-and-continue
	// like every sibling Ensure*, but the message NAMES the consequence: a silently
	// absent Deny VAP is otherwise indistinguishable from a present one, and the
	// operator would only meet the collision as an unexplained <pending> Service
	// (svclb still refuses the bind — that is the datapath half of the guard).
	if err := policy.EnsureRejectReservedLoadBalancerPort(ctx, cs); err != nil {
		logger.Error("provision reserved-loadbalancer-port DENY policy: a LoadBalancer Service declaring a k3sm-reserved port (NodePort range / kubelet API port) will now be ACCEPTED by the API instead of rejected; svclb still refuses to bind it, so such a Service stays <pending> with only a log line to explain it", "err", err)
	}
	// Honest-gap Warn advisory on Pods: a pod with no toleration for the
	// provider taint (k3sm.io/provider:NoSchedule, on EVERY node) is left
	// Unschedulable by the scheduler. Warn at the API (never reject — a non-tolerating
	// pod is valid k8s) so a directly-created pod's omission is visible in kubectl.
	// Provisioned UNCONDITIONALLY (not mode-gated): the taint is on every node.
	if err := policy.EnsureProviderTolerationWarn(ctx, cs); err != nil {
		logger.Error("provision provider-toleration warn policy", "err", err)
	}
	// Honest-plumbing Warn advisory on Pods: a pod carrying a HAND-SET
	// k3sm.io/internet-egress annotation (without the operator-managed discriminator
	// label pkg/mlx.Render stamps) opts its sandbox into allow_internet_egress. The
	// policy + its unit tests landed before any call site existed, so a running
	// cluster provisioned six policies and hand-setting the annotation warned
	// nothing — the same tests-pass-but-wiring-absent class as the operator's
	// unwired GPU source above. Provisioned
	// UNCONDITIONALLY like its siblings: the annotation is read on every runtime path,
	// not only under MLX. Log-and-continue — it is advisory, never a boundary.
	if err := policy.EnsureEgressAnnotationWarn(ctx, cs); err != nil {
		logger.Error("provision hand-set-internet-egress warn policy", "err", err)
	}
	// MUTATING policy on Pods: a DaemonSet-owned pod is created by the DS
	// controller (KCM), so the CREATE-Warn advisory above never reaches its author and
	// the pod sits Unschedulable against the provider taint. Inject the provider
	// toleration (never the os=darwin nodeSelector — Res.7) so DS pods schedule.
	// CHANGES the stored object, unlike the Warn/Deny VAPs. Log-and-continue; requires
	// the executor's v1beta1 runtime-config + MutatingAdmissionPolicy feature gate.
	if err := policy.EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		logger.Error("provision daemonset-toleration mutating policy", "err", err)
	}
	// Every pod runs as ONE uid (no per-pod uid isolation), so REJECT a pod
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
	// The memory-only default LimitRange in the `default` namespace:
	// containers that omit resources get honest memory defaults (memory IS enforced
	// via the rusage sampler→OOMKill); deliberately NO cpu key (best-effort only).
	// Create-or-update like every sibling Ensure* (see pkg/policy.ensure:
	// a create-only provisioner freezes the shipped defaults at whatever a cluster
	// was first created with); log-and-continue like the sibling advisories.
	if err := policy.EnsureDefaultLimitRange(ctx, cs); err != nil {
		logger.Error("provision default memory limitrange", "err", err)
	}
	// Provision the vm RuntimeClass (node.k8s.io/v1 "vm", handler vm, with a
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
