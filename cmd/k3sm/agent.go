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
	"errors"
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
	"time"

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
	server   string // control-plane UNDERLAY host (the join target; apiserver fallback only)
	token    string // K10<caHash>::<user>:<secret>
	nodeName string
	nodeIP   string // this node's mesh InternalIP (bound into the issued certs)
	workDir  string
	podRoot  string
	// logs is the container-log flag group, passed through to the node this
	// agent brings up.
	logs      containerLogOptions
	rtName    string
	dnsShim   string
	pathShim  string // path-rebase DYLD shim dylib path (runtimed only)
	apiPort   int
	meshPort  int
	network   string // host-network backend: auto (default) | none | direct | helper
	clusterIP string // DNS VIP the per-node resolver serves on + pods resolve against
	domain    string // cluster DNS domain
}

// registerAgentFlags binds `k3sm agent`'s flags onto fs. It is a function rather
// than an inline block in runAgent so the registered surface — notably that BOTH
// pod-support shims are overridable here, as they are on `k3sm server` / `k3sm
// node` — is unit-testable without parsing argv through a live join.
func registerAgentFlags(fs *flag.FlagSet, opts *agentOptions) {
	fs.StringVar(&opts.server, "server", "", "control-plane host to join — in practice an UNDERLAY address (a LAN IP or DNS name), because the join must reach <host>:9345 before this node has any mesh to route over")
	fs.StringVar(&opts.token, "token", os.Getenv("K3SM_TOKEN"), "K10 join token (or $K3SM_TOKEN) — required for a node's FIRST join only; a node that has already joined starts from its stored credential, and a token for the same cluster is ignored")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's mesh InternalIP (required; bound into the issued certs)")
	fs.StringVar(&opts.workDir, "work-dir", "/var/lib/k3sm/agent", "agent state root (node kubeconfig, node-password, certs)")
	fs.StringVar(&opts.podRoot, "pod-root", filepath.Join(os.TempDir(), "k3sm-pods"), "directory for per-pod logs/state")
	registerContainerLogFlags(fs, &opts.logs)
	addRuntimeFlag(fs, &opts.rtName)
	fs.StringVar(&opts.dnsShim, "dns-shim", "", "getaddrinfo DNS shim dylib path (runtimed runtime only)")
	fs.StringVar(&opts.pathShim, "path-shim", "", "path-rebase DYLD shim dylib path (runtimed runtime only)")
	fs.IntVar(&opts.apiPort, "api-port", 6444, "apiserver secure port to dial on the control plane (the HOST is not this flag: it comes from the apiserver endpoint the join advertises — the server's mesh IP — falling back to --server)")
	fs.IntVar(&opts.meshPort, "mesh-port", mesh.DefaultListenPort, "UDP port this node's wireguard listens on")
	fs.StringVar(&opts.network, "network", hostnet.NetworkAuto, "host-network backend: auto (root→direct, unprivileged→netd helper +probe) | none (no mesh datapath/probe) | direct (force utun, root) | helper (force netd helper)")
	fs.StringVar(&opts.clusterIP, "dns-vip", "10.43.0.10", "cluster DNS VIP the per-node resolver serves on and pods resolve against")
	fs.StringVar(&opts.domain, "cluster-domain", dns.DefaultClusterDomain, "cluster DNS domain")
}

// agentTerminalBackoff is how long runAgent waits before returning a start
// failure that will recur identically on the next start — no credential and no
// token, an expired credential and no token, a corrupt file.
//
// It exists because of how the agent is supervised: a LaunchDaemon with
// KeepAlive restarts an exited process immediately, so a terminal fault becomes a
// spawn loop that floods the log and burns CPU while looking, from the outside,
// like an agent that is running. Backing off turns that into one line every half
// minute, which is legible and survivable. It is a fixed sleep rather than an
// escalating one deliberately: nothing here recovers by waiting longer, and an
// operator who fixes the cause should not then wait minutes for the retry.
//
// (There is no agent LaunchDaemon renderer in this repo yet; the supervisor is
// whatever the operator wrote. The backoff costs nothing when it is a shell.)
const agentTerminalBackoff = 30 * time.Second

// agentTerminalDelay is the backoff actually applied. Tests shorten it; nothing
// else writes it.
var agentTerminalDelay = agentTerminalBackoff

// agentTerminal logs a terminal start failure, waits out the backoff (or until
// the context is cancelled — a SIGTERM during the wait must still stop the
// process promptly), and returns the error unchanged.
func agentTerminal(ctx context.Context, logger *slog.Logger, err error) error {
	logger.Error("this agent cannot start", "err", err, "backoff", agentTerminalDelay)
	t := time.NewTimer(agentTerminalDelay)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
	return err
}

// runAgent brings this Mac up as a WORKER node of an existing cluster.
//
// It has two start paths, chosen by agentStartPlan from what the agent work dir
// already holds. A FIRST start runs the token join: CA-pin the server (via the
// token's cluster-CA hash), submit a node-password + CSRs, receive a node-scoped
// system:node credential (NOT the admin kubeconfig), enroll into the wireguard
// mesh, and persist the whole outcome. A RESTART presents that stored credential
// and only re-publishes this node's wireguard endpoint — no token, no re-issued
// certificates. Both paths converge on the same mesh bring-up, the same
// node-local datapath and the same Virtual Kubelet registration; the mesh
// bring-up (root utun) and the live two-Mac round-trip are the K3SM_LAB gate.
func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	opts := agentOptions{}
	registerAgentFlags(fs, &opts)
	_ = fs.Parse(args)

	// --token is deliberately NOT required. A join token is TTL-bounded, so an
	// agent that re-ran its join on every start stopped being able to start a day
	// after it was installed; a node that has already joined presents what it
	// holds instead.
	if opts.server == "" || opts.nodeIP == "" {
		return fmt.Errorf("--server and --node-ip are required")
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

	// How this start obtains its identity, decided BEFORE anything is minted or
	// joined, from what the work dir already holds. Every terminal verdict backs
	// off (agentTerminal) so a supervised agent reports it once per interval
	// instead of spawn-looping.
	store := nodeCredentialStore{dir: opts.workDir}
	status, cred, err := store.Status(time.Now())
	if err != nil {
		return agentTerminal(ctx, logger, err)
	}
	tokenPresent := strings.TrimSpace(opts.token) != ""
	tokenCAHash, storedCAHash := "", ""
	tokenParses := false
	if tokenPresent {
		if tok, perr := bootstrap.ParseToken(opts.token); perr == nil {
			tokenCAHash, tokenParses = tok.CAHash, true
		} else {
			logger.Warn("the supplied join token is not a K10 join token", "err", perr)
		}
	}
	if cred != nil {
		storedCAHash = cred.clusterCAPin
	}
	plan, err := agentStartPlan(status, tokenPresent, tokenParses, tokenCAHash, storedCAHash)
	if err != nil {
		return agentTerminal(ctx, logger, err)
	}
	logStartPlan(logger, plan, status, tokenPresent, tokenParses, tokenCAHash, storedCAHash)

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

	joinHost := net.JoinHostPort(opts.server, strconv.Itoa(bootstrapPort))

	var res *bootstrap.JoinResult
	var meshEndpoint string
	if plan == startModeReuseCredential {
		res, meshEndpoint, err = agentResumeFromCredential(ctx, opts, cred, joinHost, meshPriv, meshPub, logger)
		switch {
		case errors.Is(err, bootstrap.ErrNoMeshPeer) && tokenPresent:
			// The server no longer knows this node — its MeshPeer, and with it the
			// podCIDR assignment, is gone. The stored credential still
			// authenticates, but it describes an assignment the cluster has
			// forgotten, so the only honest recovery is a fresh join, and the
			// operator already supplied the means.
			logger.Warn("the cluster has no mesh peer for this node; falling back to a full token join", "err", err)
			plan = startModeTokenJoin
		case errors.Is(err, bootstrap.ErrNoMeshPeer):
			return agentTerminal(ctx, logger, fmt.Errorf("the cluster has no mesh peer for this node; rejoin with a fresh token (k3sm token create on the server): %w", err))
		case err != nil:
			return err
		}
	}
	if plan == startModeTokenJoin {
		res, meshEndpoint, err = agentTokenJoin(ctx, opts, password, meshPriv, joinHost, logger)
		if err != nil {
			return err
		}
	}

	// Refuse a credential that carries no kubelet SERVING keypair, BEFORE anything
	// starts. A joined worker's apiserver runs with
	// --kubelet-certificate-authority=<cluster CA>, so a self-signed fallback here
	// would leave this node's :10250 unusable (x509: unknown authority) while the node
	// registers Ready — logs/exec broken, and broken invisibly. Failing here reports
	// the real fault where it can be read, next to the join that should have carried
	// the pair.
	if err := requireJoinedServingPair(res); err != nil {
		return err
	}

	// The apiserver this worker targets is the SERVER'S MESH address, not the
	// underlay --server it just joined over (see workerAPIServerURL). Persisting
	// the credential here — before bringUpMesh — is only a file write; every dial
	// against this URL happens after the tunnel exists (the MeshPeer watcher's
	// informer starts after mesh.Start, and the datapath + node clients are built
	// later still), which is the ordering the mesh-IP URL requires.
	//
	// Both paths save: a token join persists newly issued material, a reuse start
	// rewrites the same bytes (and picks up an `--api-port` change), so there is
	// exactly one writer of the on-disk shape.
	apiserverURL := workerAPIServerURL(res, opts.server, opts.apiPort)
	kubeconfigPath := store.kubeconfigPath()
	logger.Info("apiserver target for this node", "url", apiserverURL, "advertised", res.APIServers)
	if err := store.Save(apiserverURL, opts.nodeName, res); err != nil {
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
		// The endpoint this node just published goes stale the moment its LAN
		// address changes, so the refresher carries that value forward and
		// republishes it when the derivation changes. A construction failure is
		// SURVIVABLE — the mesh is up and the endpoint published at start is
		// correct today — so it is logged with what is lost rather than failing the
		// agent.
		refresher, err := newWorkerEndpointRefresher(opts, res, joinHost, meshEndpoint, logger)
		if err != nil {
			logger.Warn("this node will not republish its wireguard endpoint if its address changes; peers would keep dialing the address it joined from until it rejoins",
				"endpoint", meshEndpoint, "err", err)
		}
		if err := bringUpMesh(ctx, meshBringUp{
			podCIDR:       res.PodCIDR,
			meshIP:        res.MeshIP,
			privateKeyB64: res.WGPrivateKeyB64,
			keyRef:        meshKeyRef,
			peers:         res.Peers,
			listenPort:    opts.meshPort,
			kubeconfig:    kubeconfigPath,
			refresher:     refresher,
		}, mode, logger); err != nil {
			return fmt.Errorf("mesh bring-up: %w", err)
		}
		// Built AFTER join+mesh: the proxy's mesh-egress source is this node's
		// assigned /32 (res.MeshIP, now an lo0 alias plumbed by mesh.Start) and the
		// routing-table locality is its assigned pod /24 (res.PodCIDR); on a restart
		// both come from the stored assignment, which is the same pair the server
		// assigned. Without this a joined worker has no Service proxy and no DNS, so
		// a pod on it can't resolve names or reach the API VIP.
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

// agentTokenJoin runs the credential-issuing join and returns the result plus the
// wireguard endpoint it published.
//
// The join client is built HERE rather than left to bootstrap.Join so its dialer
// can report which of this Mac's addresses reaches the control plane — the one
// fact the mesh endpoint has to be derived from. It is still the CA-pinned
// client; pinnedJoinClient layers only the dialer onto it.
func agentTokenJoin(ctx context.Context, opts agentOptions, password, meshPriv, joinHost string, logger *slog.Logger) (*bootstrap.JoinResult, string, error) {
	tok, err := bootstrap.ParseToken(opts.token)
	if err != nil {
		return nil, "", err
	}
	joinClient, joinDialer, err := pinnedJoinClient(tok.CAHash)
	if err != nil {
		return nil, "", err
	}
	joinDialer.probe(ctx, joinHost)

	// The advertised wireguard endpoint is an UNDERLAY address, never opts.nodeIP:
	// that flag carries this node's MESH InternalIP, and a peer must dial the
	// underlay to open the handshake that creates the mesh in the first place.
	meshEndpoint, err := underlayMeshEndpoint(joinDialer.localIP(), opts.nodeIP, opts.meshPort)
	if err != nil {
		return nil, "", err
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
		// back as exactly this value and is what bringUpMesh programs.
		WGPrivateKeyB64: meshPriv,
	})
	if err != nil {
		return nil, "", fmt.Errorf("join: %w", err)
	}
	logger.Info("joined", "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))
	return res, meshEndpoint, nil
}

// agentResumeFromCredential is the restart path: it rebuilds the join outcome
// from the stored credential and re-publishes this node's wireguard endpoint,
// without a token and without re-issuing a certificate.
//
// The endpoint is re-derived (not read back) because the address that reaches the
// control plane is exactly what a restart may have changed — a new DHCP lease, a
// move between Wi-Fi and Ethernet, a dock. It is published through the
// node-certificate-authenticated refresh verb, whose whole point is that a joined
// node can write its own endpoint with the credential it already holds; the
// TTL-bounded token is not needed and deliberately not retained.
//
// A 404 comes back as bootstrap.ErrNoMeshPeer and is returned as-is: only the
// caller knows whether a token is available to recover with.
func agentResumeFromCredential(ctx context.Context, opts agentOptions, cred *nodeCredential, joinHost, meshPriv, meshPub string, logger *slog.Logger) (*bootstrap.JoinResult, string, error) {
	if cred == nil {
		return nil, "", errors.New("resume: no stored node credential")
	}
	// A FRESH dialer, and a probe against the same destination the join used, so
	// the kernel's route lookup answers the endpoint question the same way it did
	// at join time.
	d := &localAddrDialer{dialer: net.Dialer{Timeout: 10 * time.Second}}
	d.probe(ctx, joinHost)
	meshEndpoint, err := underlayMeshEndpoint(d.localIP(), opts.nodeIP, opts.meshPort)
	if err != nil {
		return nil, "", err
	}

	client, err := bootstrap.NodeIdentityClient(cred.clusterCAPEM, cred.clientCertPEM, cred.clientKeyPEM)
	if err != nil {
		return nil, "", err
	}
	logger.Info("resuming from the stored node credential", "node", opts.nodeName,
		"meshEndpoint", meshEndpoint, "podCIDR", cred.assignment.PodCIDR,
		"clientCertExpires", cred.clientNotAfter.UTC().Format(time.RFC3339))
	if err := bootstrap.RefreshMeshEndpoint(ctx, client, "https://"+joinHost, opts.nodeName, meshEndpoint); err != nil {
		return nil, "", err
	}
	res := cred.joinResult(opts.nodeName, meshPriv, meshPub)
	logger.Info("resumed", "podCIDR", res.PodCIDR, "meshIP", res.MeshIP, "peers", len(res.Peers))
	return res, meshEndpoint, nil
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
		logs:       opts.logs,
		nodeIP:     opts.nodeIP,
		runtime:    opts.rtName,
		dnsShim:    opts.dnsShim,
		pathShim:   opts.pathShim,
		dnsVIP:     opts.clusterIP, // scope the pod Seatbelt egress to the same cluster DNS VIP the resolver binds
		domain:     opts.domain,    // SAME cluster domain the per-node resolver serves → in-pod shim search list
		podCIDR:    res.PodCIDR,    // the ENROLLED /24 (mesh AllowedIPs == pod IPAM — one source)
		netMode:    mode,           // the resolved --network backend the podnet alias plumbing follows
		serveTLS:   true,

		// The cluster's client-identity (signing) CA, received in the join
		// response — the anchor this worker's :10250 verifies the apiserver's client
		// cert against. It is the SAME CA that issued this node's own system:node
		// credential, so a worker that joined successfully always has it; an empty
		// value (a server predating the field) makes startNode refuse, which is the
		// intended failure — a worker's kubelet endpoint is LAN-reachable on the
		// wildcard bind and is never served unauthenticated.
		kubeletClientCAPEM: res.ClientCAPEM,

		// The CLUSTER-CA-issued kubelet SERVING pair, also from the join
		// response — the cert this worker presents on :10250, chaining to the CA the
		// apiserver was started with --kubelet-certificate-authority. It is the
		// counterpart of the anchor above: that one authenticates the apiserver TO this
		// node, this one authenticates this node TO the apiserver. runAgent has already
		// refused an empty pair (requireJoinedServingPair), so the self-signed fallback
		// inside kubeletServingTLS is unreachable on the mesh path.
		kubeletServingCertPEM: res.KubeletServingCertPEM,
		kubeletServingKeyPEM:  res.KubeletServingKeyPEM,

		// The worker's own Service proxy is where its vm pods' live guest leases
		// are published; nil when the worker runs no datapath.
		transportOverrides: nodeTransportOverrides(datapath, mode),
	}
}

// requireJoinedServingPair refuses a join result that carries no usable kubelet
// SERVING keypair. It is a pure function of the join result so the refusal is
// unit-testable without a live join — the same shape as the client-CA anchor's
// fail-closed construction (provider.NewKubeletEndpointAuth), one step earlier.
//
// The CERT is checked first and on its own, because the two halves have different
// origins: the KEY never crosses the wire (bootstrap.Join generates it locally with
// the serving CSR), so only the cert's absence can report "the server did not issue
// one" — the realistic failure, a server that predates the field or refused the
// serving CSR. A cert with no key is the defensive residue and is named as the
// server-side pairing fault it would have to be.
func requireJoinedServingPair(res *bootstrap.JoinResult) error {
	switch {
	case res == nil || len(res.KubeletServingCertPEM) == 0:
		return fmt.Errorf("join delivered no kubelet serving certificate: this cluster's apiserver verifies node :10250 against the cluster CA (--kubelet-certificate-authority), so serving a self-signed cert here would fail every kubectl logs/exec against this node with \"x509: certificate signed by unknown authority\" while the node still registered Ready — the SERVER issues this cert during join, so upgrade it and rejoin")
	case len(res.KubeletServingKeyPEM) == 0:
		return fmt.Errorf("join delivered a kubelet serving certificate with no private key: %w", errHalfKubeletServingPair)
	}
	return nil
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

	// The endpoint refresher, for BOTH roles. It starts after the device is up
	// because its first derivation must see the world the device made: on the
	// server that means the mesh utun exists, which is the case serverMeshEndpoint
	// now excludes rather than accidentally picks.
	if in.refresher != nil {
		go func() {
			if err := in.refresher.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Error("mesh endpoint refresher", "err", err)
			}
		}()
	}
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
		// vmCapable alone arms the NetworkPolicy table's fail-closed
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
// a peer's Service proxy re-originates cross-node traffic from its
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
	// Installed atomically (and skipped when unchanged) like every other artifact
	// of the credential store this belongs to: a restart rewrites this file, and a
	// half-written kubeconfig is a node that cannot authenticate.
	if err := writeStoreFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write node kubeconfig: %w", err)
	}
	return nil
}
