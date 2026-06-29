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
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/darwin-net/pkg/mesh"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/netserve"
)

// meshKeyRef is the conventional file name (under the root-only mesh key dir)
// the netd helper resolves to this node's wireguard private key in helper mode;
// the key itself never crosses the socket.
const meshKeyRef = "node.key"

// agentOptions configures `k3sm agent` — joining this Mac to an existing cluster as a
// WORKER node.
type agentOptions struct {
	server    string // control-plane mesh host (the join + apiserver target)
	token     string // K10<caHash>::<user>:<secret>
	nodeName  string
	nodeIP    string // this node's mesh InternalIP (bound into the issued certs)
	workDir   string
	podRoot   string
	rtName    string
	dnsShim   string
	apiPort   int
	meshPort  int
	network   string // host-network backend: auto (default) | none | direct | helper
	clusterIP string // DNS VIP the per-node resolver binds + pods resolve against
	domain    string // cluster DNS domain
}

// runAgent joins this Mac to an existing cluster: it CA-pins the server (via the
// token's cluster-CA hash), submits a node-password + CSRs, receives a node-scoped
// system:node credential (NOT the admin kubeconfig), enrolls into the wireguard mesh,
// and registers as a Virtual Kubelet node off its node cert. The mesh bring-up (root
// utun) and the live two-Mac round-trip are the K3SM_LAB gate.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	opts := agentOptions{}
	fs.StringVar(&opts.server, "server", "", "control-plane mesh host (e.g. 100.64.0.1) to join")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "K10 join token (or $K3SM_TOKEN)")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's mesh InternalIP (required; bound into the issued certs)")
	fs.StringVar(&opts.workDir, "work-dir", "/var/lib/k3sm/agent", "agent state root (node kubeconfig, node-password, certs)")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	fs.StringVar(&opts.rtName, "runtime", "hostprocess", "pod runtime: hostprocess or runtimed")
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", 6444, "apiserver secure port on the control-plane host")
	fs.IntVar(&opts.meshPort, "mesh-port", mesh.DefaultListenPort, "UDP port this node's wireguard listens on")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (no mesh datapath/probe) | direct (force utun, root) | helper (force netd helper)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP the per-node resolver binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", "cluster.local", "cluster DNS domain")
	_ = fs.Parse(args)

	if opts.server == "" || opts.token == "" || opts.nodeIP == "" {
		return fmt.Errorf("--server, --token, and --node-ip are required")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ONE construction-time decision (the `--network` backend): auto routes the mesh
	// datapath through the root netd helper when unprivileged / uses the direct utun
	// device as root; none skips the mesh datapath (and the probe) entirely. Fail
	// fast if the helper is selected but unreachable.
	mode, err := hostnet.Resolve(opts.network)
	if err != nil {
		return err
	}
	logger.Info("host-network backend", "network", opts.network, "backend", mode.Backend.String())
	if err := mode.Probe(ctx); err != nil {
		return err
	}

	if err := os.MkdirAll(opts.workDir, 0o755); err != nil {
		return fmt.Errorf("create agent work dir: %w", err)
	}

	// node-password: mint once, persist 0600, reuse across restarts so the
	// first-write-wins binding keeps matching.
	password, err := loadOrCreateNodePassword(opts.workDir)
	if err != nil {
		return err
	}

	bootstrapURL := fmt.Sprintf("https://%s:%d", opts.server, bootstrapPort)
	logger.Info("joining cluster", "server", bootstrapURL, "node", opts.nodeName, "nodeIP", opts.nodeIP)
	res, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
		Server:       bootstrapURL,
		Token:        opts.token,
		NodeName:     opts.nodeName,
		NodeIP:       opts.nodeIP,
		NodePassword: password,
		MeshEndpoint: fmt.Sprintf("%s:%d", opts.nodeIP, opts.meshPort),
	})
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	logger.Info("joined", "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))

	apiserverURL := fmt.Sprintf("https://%s:%d", opts.server, opts.apiPort)
	kubeconfigPath := filepath.Join(opts.workDir, "node.kubeconfig")
	if err := writeNodeKubeconfig(kubeconfigPath, apiserverURL, opts.nodeName, res); err != nil {
		return err
	}

	// Bring up the wireguard mesh (the root utun leg, direct or via the helper) and
	// keep it converging via the MeshPeer watch, THEN the node-local datapath (the
	// Service proxy + per-node cluster DNS resolver). `--network none` skips both
	// (control-plane-only / CI join); the node still registers below.
	if mode.DataPath() {
		if err := bringUpMesh(ctx, res, opts.meshPort, kubeconfigPath, mode, logger); err != nil {
			return fmt.Errorf("mesh bring-up: %w", err)
		}
		// Built AFTER join+mesh: the proxy's mesh-egress source is this node's
		// assigned /32 (res.MeshIP, now an lo0 alias plumbed by mesh.Start) and the
		// routing-table locality is its assigned pod /24 (res.PodCIDR) — neither is
		// known before enroll. Without this a joined worker has no Service proxy and
		// no DNS, so a pod on it can't resolve names or reach the API VIP (M3.3).
		if err := startWorkerNetserve(ctx, opts, res, mode, kubeconfigPath, logger); err != nil {
			return err
		}
	} else {
		logger.Info("network datapath disabled (--network none): skipping wireguard mesh + node-local datapath")
	}

	// Register as a VK node off the system:node kubeconfig (NOT the admin token).
	log.Printf("starting k3sm node %q off its system:node credential (runtime=%s)", opts.nodeName, opts.rtName)
	return startNode(ctx, nodeOptions{
		kubeconfig: kubeconfigPath,
		nodeName:   opts.nodeName,
		listen:     ":10250",
		podRoot:    opts.podRoot,
		nodeIP:     opts.nodeIP,
		runtime:    opts.rtName,
		dnsShim:    opts.dnsShim,
		dnsVIP:     opts.clusterIP, // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		serveTLS:   true,
	})
}

// bringUpMesh constructs the node's wireguard mesh for its assigned pod /24, brings
// the device up (root utun), programs the initial peer snapshot, and starts the
// MeshPeer watch so endpoint/key changes reconverge. The device Up/Apply calls are
// the privileged legs exercised live (the two-Mac lab gate).
func bringUpMesh(ctx context.Context, res *bootstrap.JoinResult, meshPort int, kubeconfigPath string, mode hostnet.Mode, logger *slog.Logger) error {
	self, err := netip.ParsePrefix(res.PodCIDR)
	if err != nil {
		return fmt.Errorf("parse assigned podCIDR %q: %w", res.PodCIDR, err)
	}
	meshOpts := []mesh.Option{mesh.WithListenPort(meshPort), mesh.WithLogger(logger)}
	if mode.UsesHelper() {
		// Helper mode: the root netd daemon owns the utun/wireguard datapath and
		// resolves the private key from a root-only path (the key never crosses the
		// socket). Provision the key to that path (best-effort: in the pure _k3sm
		// posture the root-only dir is privileged, so a privileged install/netd step
		// owns provisioning — the agent passes only the ref).
		if err := os.WriteFile(filepath.Join(install.MeshKeyDir, meshKeyRef), []byte(res.WGPrivateKeyB64), 0o600); err != nil {
			logger.Warn("could not provision mesh private key to the root-only path (provision it via the privileged install step)", "path", filepath.Join(install.MeshKeyDir, meshKeyRef), "err", err)
		}
		meshOpts = append(meshOpts, mode.MeshOptions(meshKeyRef)...)
	} else {
		meshOpts = append(meshOpts, mesh.WithPrivateKey(res.WGPrivateKeyB64))
	}
	m, err := mesh.New(self, meshOpts...)
	if err != nil {
		return fmt.Errorf("build mesh: %w", err)
	}
	if err := m.Start(ctx); err != nil {
		return fmt.Errorf("start mesh device: %w", err)
	}
	if err := m.Reconcile(ctx, res.Peers); err != nil {
		logger.Error("initial mesh reconcile", "err", err)
	}

	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fmt.Errorf("load node kubeconfig for mesh watch: %w", err)
	}
	watcher, err := mesh.NewWatcher(restCfg, m, logger)
	if err != nil {
		return fmt.Errorf("build mesh watcher: %w", err)
	}
	go func() {
		if err := watcher.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("mesh watcher", "err", err)
		}
		_ = m.Close(context.WithoutCancel(ctx))
	}()
	return nil
}

// startWorkerNetserve brings up the joined worker's node-local datapath — the
// userspace Service proxy (ClusterIP + NodePort, sourced from this node's
// mesh-egress /32) and the per-node cluster DNS resolver bound to the DNS VIP — as
// a goroutine that runs until ctx. It is launched after join+mesh so the
// mesh-egress source and pod /24 are known. A client build failure is fatal (a
// worker with no datapath cannot run pods usefully); a runtime error is logged.
func startWorkerNetserve(ctx context.Context, opts agentOptions, res *bootstrap.JoinResult, mode hostnet.Mode, kubeconfigPath string, logger *slog.Logger) error {
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return fmt.Errorf("load node kubeconfig for node-local datapath: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("build client for node-local datapath: %w", err)
	}
	cfg := workerNetserveConfig(opts, res, mode, logger)
	cfg.Client = cs
	srv := netserve.New(cfg)
	go func() {
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("node-local datapath (Service proxy + cluster DNS)", "err", err)
		}
	}()
	return nil
}

// workerNetserveConfig builds the node-local datapath config for a joined worker
// from the join result + resolved backend. The mesh-egress source is this node's
// assigned /32 (res.MeshIP) so cross-node backend dials are not blackholed by
// wireguard; the routing-table locality is its assigned pod /24 (res.PodCIDR); the
// proxy/resolver privileged ops route through the netd helper when unprivileged
// (mode.Socket). The caller sets Client. It is pure (no I/O) so the worker wiring
// is unit-tested without a live join.
func workerNetserveConfig(opts agentOptions, res *bootstrap.JoinResult, mode hostnet.Mode, logger *slog.Logger) netserve.Config {
	return netserve.Config{
		WorkDir:       opts.workDir,
		DNSVIP:        opts.clusterIP,
		ClusterDomain: opts.domain,
		NodeIP:        opts.nodeIP,
		PodCIDR:       res.PodCIDR,
		MeshEgressIP:  res.MeshIP,
		NetdSocket:    mode.Socket,
		Disabled:      !mode.DataPath(),
		Logger:        logger,
	}
}

// loadOrCreateNodePassword reads the node's persisted node-password (0600), minting
// and persisting a fresh one on first run. Reusing it across restarts keeps the
// server's first-write-wins binding matching.
func loadOrCreateNodePassword(workDir string) (string, error) {
	path := filepath.Join(workDir, "node-password")
	if b, err := os.ReadFile(path); err == nil {
		return string(b), nil
	}
	pw, err := bootstrap.GenerateNodePassword()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(pw), 0o600); err != nil {
		return "", fmt.Errorf("persist node-password: %w", err)
	}
	return pw, nil
}

// writeNodeKubeconfig writes a 0600 kubeconfig that authenticates as the issued
// system:node identity (client cert + key) and verifies the apiserver against the
// cluster CA the join returned — NOT an insecure-skip-tls-verify admin token.
func writeNodeKubeconfig(path, server, nodeName string, res *bootstrap.JoinResult) error {
	b64 := base64.StdEncoding.EncodeToString
	content := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: k3sm
  cluster:
    server: %q
    certificate-authority-data: %s
contexts:
- name: k3sm
  context:
    cluster: k3sm
    user: %s
current-context: k3sm
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
`,
		server,
		b64(res.ClusterCAPEM),
		"system:node:"+nodeName,
		"system:node:"+nodeName,
		b64(res.NodeClientCertPEM),
		b64(res.NodeClientKeyPEM),
	)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write node kubeconfig: %w", err)
	}
	return nil
}
