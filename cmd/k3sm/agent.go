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
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/netserve"
)

// meshKeyRef is the conventional file name (under the root-only mesh key dir)
// the netd helper resolves to this node's wireguard private key in helper mode;
// the key itself never crosses the socket.
const meshKeyRef = "node.key"

// agentOptions configures `k3sm agent` — joining this Mac to an existing cluster as a
// WORKER node.
type agentOptions struct {
	server    string // control-plane UNDERLAY host (the join target; apiserver fallback only)
	token     string // K10<caHash>::<user>:<secret>
	nodeName  string
	nodeIP    string // this node's mesh InternalIP (bound into the issued certs)
	workDir   string
	podRoot   string
	rtName    string
	dnsShim   string
	pathShim  string // path-rebase DYLD shim dylib path (runtimed only)
	apiPort   int
	meshPort  int
	network   string // host-network backend: auto (default) | none | direct | helper
	clusterIP string // DNS VIP the per-node resolver binds + pods resolve against
	domain    string // cluster DNS domain
}

// registerAgentFlags binds `k3sm agent`'s flags onto fs. It is a function rather
// than an inline block in runAgent so the registered surface — notably that BOTH
// pod-support shims are overridable here, as they are on `k3sm server` / `k3sm
// node` — is unit-testable without parsing argv through a live join.
func registerAgentFlags(fs *flag.FlagSet, opts *agentOptions) {
	fs.StringVar(&opts.server, "server", "", "control-plane host to join — in practice an UNDERLAY address (a LAN IP or DNS name), because the join must reach <host>:9345 before this node has any mesh to route over")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "K10 join token (or $K3SM_TOKEN)")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's mesh InternalIP (required; bound into the issued certs)")
	fs.StringVar(&opts.workDir, "work-dir", "/var/lib/k3sm/agent", "agent state root (node kubeconfig, node-password, certs)")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	addRuntimeFlag(fs, &opts.rtName)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.pathShim, "path-shim", "", "path-rebase DYLD shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", 6444, "apiserver secure port to dial on the control plane (the HOST is not this flag: it comes from the apiserver endpoint the join advertises — the server's mesh IP — falling back to --server)")
	fs.IntVar(&opts.meshPort, "mesh-port", mesh.DefaultListenPort, "UDP port this node's wireguard listens on")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (no mesh datapath/probe) | direct (force utun, root) | helper (force netd helper)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP the per-node resolver binds and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain")
}

// runAgent joins this Mac to an existing cluster: it CA-pins the server (via the
// token's cluster-CA hash), submits a node-password + CSRs, receives a node-scoped
// system:node credential (NOT the admin kubeconfig), enrolls into the wireguard mesh,
// and registers as a Virtual Kubelet node off its node cert. The mesh bring-up (root
// utun) and the live two-Mac round-trip are the K3SM_LAB gate.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	opts := agentOptions{}
	registerAgentFlags(fs, &opts)
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

	// The wireguard identity: minted once, persisted 0600, reused across restarts
	// for the same reason — the public key derived from it is what every peer
	// programs, so a per-start key rotates this node's MeshPeer on every restart and
	// strands the mesh until each peer re-reconciles.
	meshPriv, meshPub, err := loadOrCreateMeshKey(opts.workDir, meshKeyRef)
	if err != nil {
		return err
	}
	logger.Info("mesh identity", "node", opts.nodeName, "publicKey", meshPub, "keyRef", meshKeyRef)

	// The join client is built HERE rather than left to bootstrap.Join so its dialer
	// can report which of this Mac's addresses reaches the control plane — the one
	// fact the mesh endpoint below has to be derived from. It is still the CA-pinned
	// client; pinnedJoinClient layers only the dialer onto it.
	tok, err := bootstrap.ParseToken(opts.token)
	if err != nil {
		return err
	}
	joinClient, joinDialer, err := pinnedJoinClient(tok.CAHash)
	if err != nil {
		return err
	}
	joinHost := net.JoinHostPort(opts.server, strconv.Itoa(bootstrapPort))
	joinDialer.probe(ctx, joinHost)

	// The advertised wireguard endpoint is an UNDERLAY address, never opts.nodeIP:
	// that flag carries this node's MESH InternalIP, and a peer must dial the
	// underlay to open the handshake that creates the mesh in the first place.
	meshEndpoint, err := underlayMeshEndpoint(joinDialer.localIP(), opts.nodeIP, opts.meshPort)
	if err != nil {
		return err
	}

	bootstrapURL := "https://" + joinHost
	logger.Info("joining cluster", "server", bootstrapURL, "node", opts.nodeName,
		"nodeIP", opts.nodeIP, "meshEndpoint", meshEndpoint)
	res, err := bootstrap.Join(ctx, bootstrap.JoinOptions{
		Server:       bootstrapURL,
		Token:        opts.token,
		NodeName:     opts.nodeName,
		NodeIP:       opts.nodeIP,
		NodePassword: password,
		MeshEndpoint: meshEndpoint,
		HTTPClient:   joinClient,
		// The persisted identity, NOT a per-join mint: res.WGPrivateKeyB64 comes
		// back as exactly this value and is what bringUpMesh programs below.
		WGPrivateKeyB64: meshPriv,
	})
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	logger.Info("joined", "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))

	// The apiserver this worker targets is the SERVER'S MESH address, not the
	// underlay --server it just joined over (see workerAPIServerURL). Writing the
	// kubeconfig here — before bringUpMesh — is only a file write; every dial
	// against this URL happens after the tunnel exists (the MeshPeer watcher's
	// informer starts after mesh.Start, and the datapath + node clients are built
	// later still), which is the ordering the mesh-IP URL requires.
	apiserverURL := workerAPIServerURL(res, opts.server, opts.apiPort)
	kubeconfigPath := filepath.Join(opts.workDir, "node.kubeconfig")
	logger.Info("apiserver target for this node", "url", apiserverURL, "advertised", res.APIServers)
	if err := writeNodeKubeconfig(kubeconfigPath, apiserverURL, opts.nodeName, res); err != nil {
		return err
	}

	// Bring up the wireguard mesh (the root utun leg, direct or via the helper) and
	// keep it converging via the MeshPeer watch, THEN the node-local datapath (the
	// Service proxy + per-node cluster DNS resolver). `--network none` skips both
	// (control-plane-only / CI join); the node still registers below.
	//
	// datapath is the Server the in-process node feeds vm-pod transport overrides
	// into; it stays nil under `--network none`, where there is no proxy to feed.
	var datapath *netserve.Server
	if mode.DataPath() {
		if err := bringUpMesh(ctx, meshBringUp{
			podCIDR:       res.PodCIDR,
			meshIP:        res.MeshIP,
			privateKeyB64: res.WGPrivateKeyB64,
			keyRef:        meshKeyRef,
			peers:         res.Peers,
			listenPort:    opts.meshPort,
			kubeconfig:    kubeconfigPath,
		}, mode, logger); err != nil {
			return fmt.Errorf("mesh bring-up: %w", err)
		}
		// Built AFTER join+mesh: the proxy's mesh-egress source is this node's
		// assigned /32 (res.MeshIP, now an lo0 alias plumbed by mesh.Start) and the
		// routing-table locality is its assigned pod /24 (res.PodCIDR) — neither is
		// known before enroll. Without this a joined worker has no Service proxy and
		// no DNS, so a pod on it can't resolve names or reach the API VIP (M3.3).
		datapath, err = startWorkerNetserve(ctx, opts, res, mode, kubeconfigPath, logger)
		if err != nil {
			return err
		}
	} else {
		logger.Info("network datapath disabled (--network none): skipping wireguard mesh + node-local datapath")
	}

	// Register as a VK node off the system:node kubeconfig (NOT the admin token).
	log.Printf("starting k3sm node %q off its system:node credential (runtime=%s)", opts.nodeName, opts.rtName)
	return startNode(ctx, agentNodeOptions(opts, res, kubeconfigPath, mode, datapath))
}

// agentNodeOptions builds the joined worker's in-process node options from the
// agent options + join result. Like workerNetserveConfig it is pure (no I/O), so
// the worker's node wiring — in particular that BOTH pod-support shim flags reach
// the node, the same wiring `k3sm server` has — is unit-tested without a live join.
//
// The shims are passed through UNRESOLVED: runtimedConfig applies the one shared
// precedence (an explicit flag, else the sibling-dylib lookup), so the agent path
// cannot acquire a second resolution idiom.
func agentNodeOptions(opts agentOptions, res *bootstrap.JoinResult, kubeconfigPath string, mode hostnet.Mode, datapath *netserve.Server) nodeOptions {
	return nodeOptions{
		kubeconfig: kubeconfigPath,
		nodeName:   opts.nodeName,
		listen:     serverKubeletListen,
		podRoot:    opts.podRoot,
		nodeIP:     opts.nodeIP,
		runtime:    opts.rtName,
		dnsShim:    opts.dnsShim,
		pathShim:   opts.pathShim,
		dnsVIP:     opts.clusterIP, // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		domain:     opts.domain,    // SAME cluster domain CoreDNS serves → in-pod shim search list (B18)
		podCIDR:    res.PodCIDR,    // the ENROLLED /24 (mesh AllowedIPs == pod IPAM — one source, M10.1)
		netMode:    mode,           // the resolved --network backend the podnet alias plumbing follows
		serveTLS:   true,

		// B176: the cluster's client-identity (signing) CA, received in the join
		// response — the anchor this worker's :10250 verifies the apiserver's client
		// cert against. It is the SAME CA that issued this node's own system:node
		// credential, so a worker that joined successfully always has it; an empty
		// value (a server predating the field) makes startNode refuse, which is the
		// intended failure — a worker's kubelet endpoint is LAN-reachable on the
		// wildcard bind and is never served unauthenticated.
		kubeletClientCAPEM: res.ClientCAPEM,

		// The worker's own Service proxy is where its vm pods' live guest leases
		// are published; nil when the worker runs no datapath.
		transportOverrides: nodeTransportOverrides(datapath, mode),
	}
}

// bringUpMesh constructs a node's wireguard mesh for its assigned pod /24, brings
// the device up (root utun), programs the initial peer snapshot, and starts the
// MeshPeer watch so endpoint/key changes reconverge. The device Up/Apply calls are
// the privileged legs exercised live (the two-Mac lab gate).
//
// It takes DISCRETE fields (meshBringUp) rather than the join result it was born
// from, because BOTH node roles bring a mesh up: a worker off a network-received
// JoinResult, and the control-plane node off values it synthesizes locally
// (enrollSelfAndBringUpMesh). See meshBringUp for why the wire DTO does not
// travel down here.
func bringUpMesh(ctx context.Context, in meshBringUp, mode hostnet.Mode, logger *slog.Logger) error {
	self, err := netip.ParsePrefix(in.podCIDR)
	if err != nil {
		return fmt.Errorf("parse assigned podCIDR %q: %w", in.podCIDR, err)
	}
	meshOpts := []mesh.Option{mesh.WithListenPort(in.listenPort), mesh.WithLogger(logger)}
	if mode.UsesHelper() {
		// Helper mode: the root netd daemon owns the utun/wireguard datapath and
		// resolves the private key from a root-only path (the key never crosses the
		// socket), so this process provisions the key there and passes only the ref.
		in.provisionHelperKey(logger)
		meshOpts = append(meshOpts, mode.MeshOptions(in.keyRef)...)
	} else {
		meshOpts = append(meshOpts, mesh.WithPrivateKey(in.privateKeyB64))
	}
	m, err := mesh.New(self, meshOpts...)
	if err != nil {
		return fmt.Errorf("build mesh: %w", err)
	}
	// The mesh derives its own mesh-egress /32 from the self prefix. If that
	// disagrees with the /32 the enroll assigned, this node's routing locality and
	// its mesh identity have diverged — fail rather than plumb an lo0 alias the
	// proxy will never source from.
	if in.meshIP != "" && m.MeshIP().String() != in.meshIP {
		return fmt.Errorf("mesh device derives mesh-egress %s from podCIDR %s, but the enroll assigned %s", m.MeshIP(), in.podCIDR, in.meshIP)
	}
	if err := m.Start(ctx); err != nil {
		return fmt.Errorf("start mesh device: %w", err)
	}
	if err := m.Reconcile(ctx, in.peers); err != nil {
		logger.Error("initial mesh reconcile", "err", err)
	}

	restCfg, err := clientcmd.BuildConfigFromFlags("", in.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig for mesh watch: %w", err)
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
//
// It RETURNS the Server so the worker's in-process node can feed it vm-pod
// transport overrides (nodeTransportOverrides): the provider holds both halves of
// a guest's two-address identity and this is the proxy that must learn the live
// one.
func startWorkerNetserve(ctx context.Context, opts agentOptions, res *bootstrap.JoinResult, mode hostnet.Mode, kubeconfigPath string, logger *slog.Logger) (*netserve.Server, error) {
	restCfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("load node kubeconfig for node-local datapath: %w", err)
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, fmt.Errorf("build client for node-local datapath: %w", err)
	}
	// The vm-capability question is asked HERE, before the datapath is built and
	// before the VK node exists — through runtimed's own safe host probe, the same
	// verdict the node will later advertise (see vmBackendAvailable).
	cfg := workerNetserveConfig(opts, res, mode, vmBackendAvailable(), logger)
	cfg.Client = cs
	srv := netserve.New(cfg)
	go func() {
		if err := srv.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("node-local datapath (Service proxy + cluster DNS)", "err", err)
		}
	}()
	return srv, nil
}

// workerNetserveConfig builds the node-local datapath config for a joined worker
// from the join result + resolved backend. The mesh-egress source is this node's
// assigned /32 (res.MeshIP) so cross-node backend dials are not blackholed by
// wireguard; the routing-table locality is its assigned pod /24 (res.PodCIDR); the
// proxy/resolver privileged ops route through the netd helper when unprivileged
// (mode.Socket). The caller sets Client. It is pure (no I/O) so the worker wiring
// is unit-tested without a live join.
func workerNetserveConfig(opts agentOptions, res *bootstrap.JoinResult, mode hostnet.Mode, vmCapable bool, logger *slog.Logger) netserve.Config {
	return netserve.Config{
		WorkDir:           opts.workDir,
		DNSVIP:            opts.clusterIP,
		ClusterDomain:     opts.domain,
		NodeIP:            opts.nodeIP,
		PodCIDR:           res.PodCIDR,
		MeshEgressIP:      res.MeshIP,
		PeerMeshEgressIPs: peerMeshEgressIPs(res.Peers),
		// M11.3-d3a: vmCapable alone arms the NetworkPolicy table's fail-closed
		// unknown-vm-source branch. The segment is passed unconditionally because it
		// is a host fact, not a decision — vmnetPolicyPrefix ANDs the two, so a
		// worker with no vm backend keeps the byte-identical plain table.
		VMBackend:   vmCapable,
		VMNetSubnet: netserve.DefaultVMNetSubnet,
		NetdSocket:  mode.Socket,
		Disabled:    !mode.DataPath(),
		Logger:      logger,
	}
}

// peerMeshEgressIPs extracts each join-snapshot peer's mesh-egress /32: the
// declared Spec.MeshIP, falling back to the canonical .1-of-the-pod-/24
// derivation (podnet.MeshEgressIP — the one derivation the mesh and proxy share)
// when unset. These seed the NetworkPolicy table's always-allow source set
// (M10.4): a peer's Service proxy re-originates cross-node traffic from its
// mesh-egress /32, and those node-origin dials must never be denied by a pod
// policy. A peer that enrolls AFTER this snapshot is the documented fail-open
// gap (netserve.Config.PeerMeshEgressIPs); an unparsable peer is skipped — its
// dials fail open at the table, never mis-deny.
func peerMeshEgressIPs(peers []netv1.MeshPeerSpec) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p.MeshIP != "" {
			out = append(out, p.MeshIP)
			continue
		}
		pfx, err := netip.ParsePrefix(p.PodCIDR)
		if err != nil {
			continue
		}
		a, err := podnet.MeshEgressIP(pfx)
		if err != nil {
			continue
		}
		out = append(out, a.String())
	}
	return out
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

// workerAPIServerURL derives the apiserver URL a joined worker targets: the base
// of its node kubeconfig, and so of every client the worker builds off it (the
// MeshPeer watcher, the Service proxy + kube-dns ensure, the VK node
// registration).
//
// The HOST is the control plane's OWN advertised apiserver endpoint
// (bootstrap.JoinResult.APIServers) whenever the join carried one, because a
// multi-node server binds its apiserver on the mesh interface and NOTHING else
// (`k3sm server --mesh-ip` sets BindAddress to the mesh IP), so the only address
// that answers is reachable through the wireguard tunnel. serverHost — the
// agent's `--server` — cannot stand in for it: it is an UNDERLAY address by
// construction (the join must reach <host>:9345 before this node has any mesh),
// and dialing the apiserver there is refused by construction. That was the live
// defect: the worker wrote https://<underlay>:6444, every dial was refused, and
// the virtual-kubelet never registered.
//
// It falls back to serverHost when the join advertised no usable endpoint — a
// non-mesh server joined remotely, where the underlay address IS where the
// apiserver listens. The PORT is always apiPort: the advertised endpoint
// contributes only the host, and `--api-port` keeps its role as the port.
func workerAPIServerURL(res *bootstrap.JoinResult, serverHost string, apiPort int) string {
	host := serverHost
	if advertised := advertisedAPIServerHost(res); advertised != "" {
		host = advertised
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(apiPort))
}

// advertisedAPIServerHost returns the host of the first DIALABLE apiserver
// endpoint the join response advertised, or "" when it advertised none. An
// endpoint whose host is missing or unspecified (":6444", "0.0.0.0:6444") is not
// dialable, so it is skipped rather than turned into a dead URL — the caller then
// keeps its `--server` fallback, which is at least an address that once answered.
func advertisedAPIServerHost(res *bootstrap.JoinResult) string {
	if res == nil {
		return ""
	}
	for _, endpoint := range res.APIServers {
		host := strings.TrimSpace(endpoint)
		// A bare host (no port) fails SplitHostPort; keep it as-is then.
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			continue
		}
		if addr, err := netip.ParseAddr(host); err == nil && addr.IsUnspecified() {
			continue
		}
		return host
	}
	return ""
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
