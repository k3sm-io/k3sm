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
	// M3.0 multi-node: bind the apiserver + the worker-join supervisor on the mesh
	// interface ONLY, serve a cluster-CA-signed cert, wire --client-ca-file +
	// --kubelet-certificate-authority + --anonymous-auth=false. Empty --mesh-ip keeps
	// the single-node loopback/self-signed path (M1/M2) unchanged.
	var hierarchy *certs.Hierarchy
	if opts.meshIP != "" {
		h, err := certs.EnsureHierarchy(opts.workDir)
		if err != nil {
			return fmt.Errorf("ensure CA hierarchy: %w", err)
		}
		hierarchy = h
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

	// 4b. M3.0 — the worker-join supervisor (mesh-bound; mints node certs + enrolls
	// peers). Only when multi-node is enabled; the live two-Mac join is the K3SM_LAB
	// gate (the MeshPeer CRD must be installed for the enroller's write to land).
	if opts.meshIP != "" && hierarchy != nil {
		tokens := bootstrap.NewFileTokenStore(bootstrap.TokensPath(opts.workDir), nil)
		enroller, err := newMeshEnroller(restCfg, logger)
		if err != nil {
			return fmt.Errorf("build mesh enroller: %w", err)
		}
		go func() {
			if err := startBootstrapServer(ctx, hierarchy, opts.meshIP, tokens, enroller, logger); err != nil && ctx.Err() == nil {
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
