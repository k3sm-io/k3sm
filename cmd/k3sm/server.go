package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/policy"
)

// serverOptions configures `k3sm server` — the all-in-one control plane + node.
type serverOptions struct {
	workDir   string
	nodeName  string
	nodeIP    string
	podRoot   string
	rtName    string
	dnsShim   string
	apiPort   int
	clusterIP string // DNS VIP CoreDNS binds + pods resolve against
	domain    string
}

// runServer brings up the control plane (via the executor) and a Virtual Kubelet
// node in one process, then hosts darwin-net's Service proxy + CoreDNS config +
// DNS shim and provisions the os=darwin admission policy. It blocks until
// interrupted, then shuts the control plane down cleanly.
func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	opts := serverOptions{}
	fs.StringVar(&opts.workDir, "work-dir", executor.DefaultWorkDir, "control-plane state root (binaries, kine DB, certs, kubeconfig)")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "127.0.0.1", "node InternalIP to advertise")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	fs.StringVar(&opts.rtName, "runtime", "hostprocess", "pod runtime: hostprocess or runtimed")
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", executor.DefaultAPIServerPort, "apiserver secure port")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP CoreDNS binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", "cluster.local", "cluster DNS domain")
	_ = fs.Parse(args)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 1. Control plane (child-process executor). Stop tears it down in reverse.
	exec := executor.NewSupervised(executor.Config{
		WorkDir:       opts.workDir,
		APIServerPort: opts.apiPort,
		NodeIP:        opts.nodeIP,
		Logger:        logger,
	})
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

	// 4. M1.4 — host darwin-net's Service proxy + CoreDNS config + DNS shim.
	net := netserve.New(netserve.Config{
		Client:        cs,
		WorkDir:       opts.workDir,
		DNSVIP:        opts.clusterIP,
		ClusterDomain: opts.domain,
		NodeIP:        opts.nodeIP,
		Logger:        logger,
	})
	go func() {
		if err := net.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("darwin-net services", "err", err)
		}
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
		serveTLS:   true, // M1.2: serve kubelet API over TLS so logs/exec work via the proxy
	})
}
