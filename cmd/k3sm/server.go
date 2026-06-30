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
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/policy"
	"k3sm.io/k3sm/pkg/provisioner"
	"k3sm.io/k3sm/pkg/rbac"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// serverOptions configures `k3sm server` — the all-in-one control plane + node.
type serverOptions struct {
	workDir   string
	nodeName  string
	nodeIP    string
	meshIP    string // wireguard mesh IP; set => multi-node worker-join supervisor (M3.0)
	podRoot   string
	rtName    string
	dnsShim   string
	apiPort   int
	clusterIP string // DNS VIP CoreDNS binds + pods resolve against
	domain    string
	network   string // host-network backend: auto (default) | none | direct | helper

	datastoreEndpoint string // kine datastore DSN (postgres://… => HA multi-writer); empty = single-node SQLite (M6.0)
	serverJoin        bool   // declare HA control-plane intent (requires --datastore-endpoint; split-brain guard)
	joinServer        string // existing server's mesh host to fetch the identical-CA bundle from (M6.1 HA server-join)
	token             string // server-class join token (K10<caHash>::server:<secret>) for the HA server-join (M6.1)
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
	fs.StringVar(&opts.podRoot, "pod-root", "", "runtimed on-disk root (image cache + pod dirs); empty derives <work-dir parent> so the SBPL work-dir resides under the daemon home")
	fs.StringVar(&opts.rtName, "runtime", "hostprocess", "pod runtime: hostprocess or runtimed")
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", executor.DefaultAPIServerPort, "apiserver secure port")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP CoreDNS binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", "cluster.local", "cluster DNS domain")
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
	cfg := executor.Config{
		WorkDir:       opts.workDir,
		APIServerPort: opts.apiPort,
		NodeIP:        opts.nodeIP,
		Logger:        logger,
	}
	// M6.0 HA: a Postgres datastore endpoint (or --server-join) puts kine on the shared
	// Postgres (DefaultKineVersionHA) and turns on scheduler/KCM leader election so only
	// one server is active. The executor fail-closes (ErrHARequiresDatastore) if HA is
	// requested without the endpoint — never a silent per-server SQLite (split-brain).
	cfg.DatastoreEndpoint = opts.datastoreEndpoint
	cfg.ServerJoin = opts.serverJoin
	if opts.datastoreEndpoint != "" || opts.serverJoin {
		logger.Info("HA datastore mode: kine→Postgres (shared multi-writer datastore); scheduler/KCM leader-elected", "server-join", opts.serverJoin)
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
		if opts.nodeIP == "127.0.0.1" {
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

	// 3. M1.2 — provision the os=darwin ValidatingAdmissionPolicy (intent guard).
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
	// B17 — honest-gap Warn advisory on Pods: a pod with no toleration for the
	// provider taint (k3sm.io/provider:NoSchedule, on EVERY node) is left
	// Unschedulable by the scheduler. Warn at the API (never reject — a non-tolerating
	// pod is valid k8s) so a directly-created pod's omission is visible in kubectl.
	// Provisioned UNCONDITIONALLY (not mode-gated): the taint is on every node.
	if err := policy.EnsureProviderTolerationWarn(ctx, cs); err != nil {
		logger.Error("provision provider-toleration warn policy", "err", err)
	}
	// Unprivileged posture: every pod runs as the single _k3sm uid (no per-pod uid
	// isolation), so REJECT a pod requesting a foreign runAsUser/fsGroup at
	// admission rather than letting it wedge at runtime (a privilege drop needs
	// root). The allowed uid is the control plane's own (the _k3sm uid). Only the
	// helper backend is the unprivileged-_k3sm posture; root (direct) can honor a
	// drop and none (CI) is not production, so the policy is provisioned only there.
	if mode.UsesHelper() {
		if err := policy.EnsureNoForeignUserAdmission(ctx, cs, int64(os.Geteuid())); err != nil {
			logger.Error("provision foreign-user admission policy", "err", err)
		}
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

	// 4. M1.4/M3.3 — host the node-local datapath: darwin-net's Service proxy
	// (exempted from the DNS VIP, which the per-node resolver below owns) + the
	// per-node cluster DNS resolver bound to the DNS VIP + the pod DNSConfig the
	// shim consumes. The NetdSocket routes the proxy/resolver privileged lo0/port
	// ops through the root helper when unprivileged (empty in root mode → direct
	// ops); Disabled (--network none) writes the Corefile but runs no datapath.
	//
	// MeshEgressIP is intentionally left empty on the server: `k3sm server` does not
	// bring up its own wireguard mesh device yet (that is the M3.0 two-Mac lab leg),
	// so there is no mesh-egress /32 lo0 alias to source from. Because the proxy's
	// backend dialer binds the mesh-egress source UNCONDITIONALLY (every dial,
	// including same-node loopback), setting a non-local value here would break ALL
	// backend dials. It is wired the moment the server-side mesh bring-up lands.
	net := netserve.New(netserve.Config{
		Client:        cs,
		WorkDir:       opts.workDir,
		DNSVIP:        opts.clusterIP,
		ClusterDomain: opts.domain,
		NodeIP:        opts.nodeIP,
		NetdSocket:    mode.Socket,
		Disabled:      !mode.DataPath(),
		Logger:        logger,
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

	// 5. The Virtual Kubelet node (reuse runNode's bring-up).
	log.Printf("starting k3sm node %q (runtime=%s)", opts.nodeName, opts.rtName)
	return startNode(ctx, nodeOptions{
		kubeconfig: exec.Kubeconfig(),
		nodeName:   opts.nodeName,
		listen:     ":10250",
		podRoot:    opts.podRoot,
		nodeIP:     opts.nodeIP,
		runtime:    opts.rtName,
		dnsShim:    opts.dnsShim,
		dnsVIP:     opts.clusterIP, // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		serveTLS:   true,           // M1.2: serve kubelet API over TLS so logs/exec work via the proxy
	})
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
	dir := certs.PKIDir(workDir)
	certFile = filepath.Join(dir, "apiserver.crt")
	keyFile = filepath.Join(dir, "apiserver.key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write apiserver serving cert: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write apiserver serving key: %w", err)
	}
	return certFile, keyFile, nil
}
