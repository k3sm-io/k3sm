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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/darwin-net/pkg/dns"
	"k3sm.io/darwin-net/pkg/mesh"
	"k3sm.io/darwin-net/pkg/podnet"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/kubeclient"
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
	tokenFile string // a file holding that token, read once at start (see applyTokenFile)
	nodeName  string
	nodeIP    string // this node's mesh InternalIP (bound into the issued certs)
	workDir   string
	podRoot   string
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
	fs.StringVar(&opts.tokenFile, "token-file", "", "a file holding the K10 join token, read once at start and preferred over --token and $K3SM_TOKEN. It must not be group- or world-readable. This is how a supervised agent is given a token: a LaunchDaemon plist is world-readable, so the daemon is told where the token is and never what it is")
	fs.StringVar(&opts.nodeName, "node-name", defaultNodeName(), "node name to register")
	fs.StringVar(&opts.nodeIP, "node-ip", "", "this node's mesh InternalIP (required; bound into the issued certs)")
	fs.StringVar(&opts.workDir, "work-dir", "/var/lib/k3sm/agent", "agent state root (node kubeconfig, node-password, certs)")
	fs.StringVar(&opts.podRoot, "pod-root", "", "runtimed on-disk root (image cache + pod dirs); empty derives <work-dir parent> so the SBPL work-dir resides under the daemon home — set this to move PVCs off /Users, which the sandbox always denies")
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

	// runtimed's on-disk root — the image cache, the pod dirs, every PVC bound on
	// this node — resolved once, here, before anything under it is touched. An
	// empty --pod-root derives the work-dir's parent (the same rule `k3sm server`
	// applies), except on a worker that already holds data under the legacy
	// temp-dir root, which is kept in place and warned about rather than migrated.
	podRoot := resolveAgentPodRoot(opts.podRoot, opts.workDir, legacyAgentPodRoot(), podRootHasData)
	opts.podRoot = podRoot.root
	logAgentPodRoot(logger, podRoot)

	// --token-file, before anything reads opts.token. A file that is there and
	// cannot be used is a terminal start failure like the others (it recurs
	// identically on the next start), so it backs off rather than letting
	// KeepAlive spawn-loop on it. A file that is simply GONE is not a failure at
	// all: the token is a first-join credential the operator is told to delete
	// once the node is Ready, so this is the steady state of a joined worker and
	// the start plan decides from the stored credential.
	tokenFileAbsent, err := applyTokenFile(&opts)
	if err != nil {
		return agentTerminal(ctx, logger, err)
	}
	if tokenFileAbsent {
		logger.Info("the join token file is not there; this start presents the stored node credential instead", "path", opts.tokenFile)
	}

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
		storedCAHash = cred.ClusterCAPin
	}
	plan, err := agentStartPlan(status, tokenPresent, tokenParses, tokenCAHash, storedCAHash)
	if err != nil {
		// The plan's refusals are about the credential and the token. When a token
		// file was named and is not there, that is the missing half, and the error
		// says so rather than leaving the operator to infer it from the argv.
		if tokenFileAbsent {
			err = missingTokenFileNote(err, opts.tokenFile)
		}
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
	// The mesh teardown handle. It is declared — and its deferred run registered —
	// BEFORE anything is brought up, so it covers a half-built bring-up too, and it
	// stays a no-op under `--network none`. Running it here rather than leaving it
	// to the watcher goroutine is what guarantees the per-peer routes and the
	// MSS-clamp anchor are gone before this process exits.
	meshDown := meshTeardown(noMeshTeardown)
	defer func() { meshTeardownOnExit(ctx, meshDown, logger) }()
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
		down, err := bringUpMesh(ctx, meshBringUp{
			podCIDR:       res.PodCIDR,
			meshIP:        res.MeshIP,
			privateKeyB64: res.WGPrivateKeyB64,
			keyRef:        meshKeyRef,
			peers:         res.Peers,
			listenPort:    opts.meshPort,
			kubeconfig:    kubeconfigPath,
			refresher:     refresher,
			// On a RESTART res.Peers is the stored credential's seed, not a list the
			// cluster just handed out, so the bring-up programs the server peer and
			// then waits for this LIST instead of trusting the snapshot. plan is the
			// path actually taken: a resume that fell back to a token join has been
			// rewritten to startModeTokenJoin above, and that join's peers are live.
			resume:    plan == startModeReuseCredential,
			listPeers: meshPeerLister(kubeconfigPath),
			// ...and the list it waits for becomes the stored seed. Without this the
			// assignment keeps the join-time snapshot for the life of the node: the
			// Save above rewrites it from the credential it was just loaded from, so
			// every restart programs its server peer and its fallback out of state
			// that only ever gets older. The join path leaves this nil — its Save
			// carried a live snapshot already.
			onLivePeers: resumeSeedWriteback(plan, store),
		}, mode, logger)
		meshDown = down
		if err != nil {
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

	client, err := bootstrap.NodeIdentityClient(cred.ClusterCAPEM, cred.ClientCertPEM, cred.ClientKeyPEM)
	if err != nil {
		return nil, "", err
	}
	logger.Info("resuming from the stored node credential", "node", opts.nodeName,
		"meshEndpoint", meshEndpoint, "podCIDR", cred.Assignment.PodCIDR,
		"clientCertExpires", cred.ClientNotAfter.UTC().Format(time.RFC3339))
	if err := bootstrap.RefreshMeshEndpoint(ctx, client, "https://"+joinHost, opts.nodeName, meshEndpoint); err != nil {
		return nil, "", err
	}
	res := joinResultFrom(cred, opts.nodeName, meshPriv, meshPub)
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

// meshDatapath is the consumer-side view of the wireguard mesh bringUpMesh
// drives — darwin-net's *mesh.Mesh in production. The interface is declared HERE,
// at the consumer, because darwin-net's device-injection option is unexported:
// without a seam on this side there is no way to exercise the bring-up/teardown
// ORDERING without a root utun, and that ordering is the whole point of the
// teardown handle below.
type meshDatapath interface {
	MeshIP() netip.Addr
	Start(ctx context.Context) error
	Reconcile(ctx context.Context, peers []netv1.MeshPeerSpec) error
	Close(ctx context.Context) error
}

// meshWatch is the consumer-side view of darwin-net's MeshPeer watcher: the
// goroutine that keeps the peer set converging after the initial program.
type meshWatch interface {
	Run(ctx context.Context) error
}

// meshTeardown releases a mesh brought up by bringUpMesh. It is darwin-net's
// Mesh.Close, whose only act is the device's Down, so what it releases is whatever
// the selected backend's Down releases:
//
//   - direct mode (WGDevice): the per-peer kernel routes are deleted, the
//     utun-scoped MSS-clamp pf anchor is flushed, the mesh-egress alias is removed
//     and the wireguard utun is closed;
//   - helper mode (netdDevice): a RemoveMesh to the root netd daemon, which owns
//     the datapath. The device is rebuilt on the next start — bringUpMesh's Start
//     is what recreates it — so a torn-down helper mesh is not a lost one.
//
// It is idempotent: Mesh.Close returns nil once the device is down (the started
// flag is cleared under the mesh's own mutex), so the caller's exit path and the
// watcher goroutine's fallback may both run it and the device comes down exactly
// once.
type meshTeardown func(ctx context.Context) error

// noMeshTeardown is the handle for a mesh that was never brought up. Every failure
// path returns it, so a caller can register its deferred teardown unconditionally.
func noMeshTeardown(context.Context) error { return nil }

// meshTeardownTimeout bounds the synchronous teardown on a node's exit path. The
// exit is normally SIGTERM, so the node ctx is already cancelled and the teardown
// runs on a detached context; without a bound, a wedged route removal would hold
// the process open — the opposite of the leak the teardown exists to prevent.
//
// 5s is a bound, not a budget: a handful of route deletes plus an anchor flush
// plus a device close (or one RemoveMesh RPC) is sub-second. It is deliberately
// small because it is SERIAL with the control plane's own 30s shutdown inside the
// server's launchd ExitTimeOut — see the ExitTimeOut comment in pkg/install.
const meshTeardownTimeout = 5 * time.Second

// meshTeardownOnExit runs a mesh teardown on the node's way out. Both roles defer
// it, so the sequence lives in one place: the exit is normally SIGTERM, which has
// already cancelled the node ctx, so the teardown runs on a DETACHED context —
// with the node ctx it would return immediately and tear nothing down — bounded by
// meshTeardownTimeout so a wedged route removal cannot hold the process open.
func meshTeardownOnExit(ctx context.Context, down meshTeardown, logger *slog.Logger) {
	downCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), meshTeardownTimeout)
	defer cancel()
	if err := down(downCtx); err != nil {
		logger.Error("mesh teardown", "err", err)
	}
}

// meshSeam is how bringUpMesh constructs its mesh and its MeshPeer watcher. The
// production values are the darwin-net constructors; tests replace it to drive the
// bring-up-then-teardown sequence with no privilege and no apiserver.
type meshSeam struct {
	newMesh  func(self netip.Prefix, opts ...mesh.Option) (meshDatapath, error)
	newWatch func(cfg *rest.Config, m meshDatapath, logger *slog.Logger) (meshWatch, error)
}

// productionMeshSeam builds the real wireguard mesh and its watcher. The watcher
// constructor takes darwin-net's concrete *mesh.Mesh, so the assertion here is the
// price of the consumer-side interface; it cannot fail for a mesh this seam built.
var productionMeshSeam = meshSeam{
	newMesh: func(self netip.Prefix, opts ...mesh.Option) (meshDatapath, error) {
		return mesh.New(self, opts...)
	},
	newWatch: func(cfg *rest.Config, m meshDatapath, logger *slog.Logger) (meshWatch, error) {
		wg, ok := m.(*mesh.Mesh)
		if !ok {
			return nil, fmt.Errorf("mesh watcher needs darwin-net's *mesh.Mesh, got %T", m)
		}
		return mesh.NewWatcher(cfg, wg, logger)
	},
}

// activeMeshSeam is the seam bringUpMesh reads. It is a variable only so a test
// can swap it; nothing in the shipped paths writes it.
var activeMeshSeam = productionMeshSeam

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
//
// The initial program depends on WHERE the peer snapshot came from. A join just
// happened, so in.peers is live and is programmed whole. A RESUME (in.resume) is
// programmed from the stored credential's seed, which is as old as this node's
// last successful live list — see the Peers field on nodecred.Assignment for that
// contract — so it is NOT programmed whole: programResumedPeers programs the
// server peer alone, waits for a live LIST, and hands that list to in.onLivePeers
// so the seed the NEXT start reads is this start's, not the original join's.
//
// It RETURNS a teardown handle, and that return is the point. Nothing used to hold
// the mesh, so the only Close was the last act of the watcher goroutine — which
// runs after ctx is already cancelled and therefore races process death: on a
// SIGTERM the process could exit with the per-peer routes and the pf anchor still
// installed. A caller now defers this handle, so the teardown completes BEFORE it
// returns; the watcher's Close remains as the fallback for a path that never
// reaches the deferred call.
func bringUpMesh(ctx context.Context, in meshBringUp, mode hostnet.Mode, logger *slog.Logger) (meshTeardown, error) {
	self, err := netip.ParsePrefix(in.podCIDR)
	if err != nil {
		return noMeshTeardown, fmt.Errorf("parse assigned podCIDR %q: %w", in.podCIDR, err)
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
	m, err := activeMeshSeam.newMesh(self, meshOpts...)
	if err != nil {
		return noMeshTeardown, fmt.Errorf("build mesh: %w", err)
	}
	// The mesh derives its own mesh-egress /32 from the self prefix. If that
	// disagrees with the /32 the enroll assigned, this node's routing locality and
	// its mesh identity have diverged — fail rather than plumb an lo0 alias the
	// proxy will never source from.
	if in.meshIP != "" && m.MeshIP().String() != in.meshIP {
		return noMeshTeardown, fmt.Errorf("mesh device derives mesh-egress %s from podCIDR %s, but the enroll assigned %s", m.MeshIP(), in.podCIDR, in.meshIP)
	}
	if err := m.Start(ctx); err != nil {
		return noMeshTeardown, fmt.Errorf("start mesh device: %w", err)
	}
	startedAt := time.Now()
	// The device is UP from here, so every remaining failure hands the caller a
	// REAL teardown rather than the no-op: a half-built bring-up still owns a utun,
	// and the caller's deferred handle is the only thing that will release it.
	teardown := meshTeardown(m.Close)

	// The watcher's REST config is loaded BEFORE the initial program because the
	// resume path needs the host the resumed kubeconfig targets to pick the server
	// peer out of the seed. Its error is CARRIED rather than returned here: on the
	// join path the initial program has always run before a bad kubeconfig ends the
	// bring-up, and that order is preserved exactly.
	restCfg, restErr := clientcmd.BuildConfigFromFlags("", in.kubeconfig)
	if in.resume {
		// The resume path reports it IMMEDIATELY. A kubeconfig that will not load is
		// a bring-up that cannot list peers and cannot start a watcher, so spending
		// the whole first-sync bound discovering that would only delay the same
		// failure — and the pre-B308 code returned it here, before any wait existed.
		if restErr != nil {
			return teardown, fmt.Errorf("load kubeconfig for mesh watch: %w", restErr)
		}
		programResumedPeers(ctx, m, in, restConfigHost(restCfg), startedAt, logger)
	} else if err := m.Reconcile(ctx, in.peers); err != nil {
		logger.Error("initial mesh reconcile", "err", err)
	}
	if restErr != nil {
		return teardown, fmt.Errorf("load kubeconfig for mesh watch: %w", restErr)
	}
	watcher, err := activeMeshSeam.newWatch(restCfg, m, logger)
	if err != nil {
		return teardown, fmt.Errorf("build mesh watcher: %w", err)
	}
	go func() {
		if err := watcher.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("mesh watcher", "err", err)
		}
		// The FALLBACK teardown, kept for a path that never reaches the caller's
		// deferred handle. After the deferred one has run this is a no-op (Close is
		// idempotent), so the device still comes down exactly once.
		_ = teardown(context.WithoutCancel(ctx))
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
	return teardown, nil
}

// meshFirstSyncTimeout bounds how long a RESUMING node waits for a live MeshPeer
// list before it falls back to programming its stored seed.
//
// It is a BOUND, not a budget: the list is one GET against an apiserver this node
// is already about to watch, and it normally answers in milliseconds. 30s is
// generous because the thing being waited for is the whole reason the wait exists
// — the apiserver may only become reachable once the server peer programmed a
// moment earlier has completed its handshake — and because the cost of waiting is
// a delayed node registration, while the cost of not waiting is programming a
// stale peer set into the kernel.
const meshFirstSyncTimeout = 30 * time.Second

// meshPeerPollInterval is the retry cadence inside that bound. One second is the
// same order as the handshake it is usually waiting on; a tighter loop would only
// spend dials on an apiserver that is not yet reachable.
const meshPeerPollInterval = time.Second

// meshPeerAttemptTimeout bounds ONE list attempt — both as the REST client's own
// request timeout (meshPeerLister) and as the per-attempt context deadline
// (listMeshPeersOnce). Without it the bound above is a promise the code cannot
// keep: the agent's signal context carries no deadline, so a connection that is
// accepted and then never answered blocks node start indefinitely, which is the
// failure shape a bound exists to convert into a retry.
//
// 5s is a bound, not a budget: this is one GET against a LAN apiserver one
// wireguard hop away, and it leaves the 30s bound room for several attempts.
const meshPeerAttemptTimeout = 5 * time.Second

// programResumedPeers performs the initial peer program on the RESUME path.
//
// The seed in the stored credential is a snapshot taken at this node's last join
// or last successful resume, so programming it whole means programming, into the
// kernel device, whatever the cluster looked like then — for the whole window
// until the MeshPeer watcher's first sync. A peer removed or re-keyed since then is
// programmed anyway, and because the enroller's free-index scan recycles a removed
// node's index (lowestFreeNodeIndex), a stale entry can name the OLD node's public
// key for a pod /24 a DIFFERENT node now owns: traffic for that /24 is encrypted to
// a key nobody holds.
//
// So the seed is used for exactly two things, both narrow:
//
//   - the SERVER peer, programmed alone, because the live list has to be fetched
//     from the apiserver and on a mesh-posture cluster that apiserver is reachable
//     only through the tunnel to the server. It is selected by serverPeerFromSeed,
//     which is a structural match (whose AllowedIPs cover the apiserver host), not
//     a name; an entry that stale would be a server that changed key, which is a
//     rejoin, not a restart. When nothing matches, nothing is programmed and the
//     apiserver is reached over the underlay.
//   - the FALLBACK, after the bound expires, because a node with a possibly-stale
//     peer set is still better than a node with none, and the watcher — started
//     immediately after this returns — replaces it on its first sync.
//
// When the live list DOES arrive it is also handed to in.onLivePeers, which
// persists it as the new seed, so both of those uses are made from progressively
// fresher state on each restart instead of from a snapshot that never moves.
//
// It does not return an error: every failure here degrades to a peer set the
// watcher will correct, and none of them is a reason to refuse a mesh that is
// already up.
func programResumedPeers(ctx context.Context, m meshDatapath, in meshBringUp, apiserverHost string, startedAt time.Time, logger *slog.Logger) {
	if server, ok := serverPeerFromSeed(in.peers, apiserverHost); ok {
		if err := m.Reconcile(ctx, []netv1.MeshPeerSpec{server}); err != nil {
			logger.Error("initial mesh reconcile of the server peer from the stored seed", "err", err)
		}
	} else {
		logger.Info("the stored peer seed names no peer covering this node's apiserver; programming no peers until the live MeshPeer list arrives",
			"apiserver", apiserverHost, "seedPeers", len(in.peers))
	}
	bound := in.firstSyncTimeout
	if bound <= 0 {
		bound = meshFirstSyncTimeout
	}
	live, err := pollMeshPeers(ctx, in.listPeers, bound)
	if err != nil {
		logger.Warn("no live MeshPeer list within the first-sync bound; programming the stored seed as the fallback until the MeshPeer watcher's first sync replaces it",
			"bound", bound, "seedPeers", len(in.peers), "err", err)
		if err := m.Reconcile(ctx, in.peers); err != nil {
			logger.Error("fallback mesh reconcile of the stored seed", "err", err)
		}
		return
	}
	if err := m.Reconcile(ctx, live); err != nil {
		logger.Error("initial mesh reconcile of the live MeshPeer list", "err", err)
	}
	// The same live list becomes the stored seed, so the NEXT start's server-peer
	// selection and its fallback are made from what the cluster looked like at
	// this start rather than at the original join. It runs after the Reconcile and
	// only on this branch: a list that was never obtained is not a seed, and a
	// device that is already correct must not be held up by a file write. The copy
	// is defensive — the slice is handed to a writer that outlives this call only
	// as bytes, but the device holds the original.
	if in.onLivePeers != nil {
		if err := in.onLivePeers(slices.Clone(live)); err != nil {
			logger.Warn("could not persist the live MeshPeer list as this node's stored seed; the mesh is correct, but the next start falls back to the older seed",
				"livePeers", len(live), "err", err)
		}
	}
	logger.Info("programmed the live MeshPeer list on resume",
		"window", time.Since(startedAt), "seedPeers", len(in.peers), "livePeers", len(live),
		"staleSeedPeers", staleSeedPeers(in.peers, live))
}

// pollMeshPeers calls list until it answers or bound elapses, retrying every
// meshPeerPollInterval.
//
// Both waits are CLAMPED to the time left. The sleep is, so a bound shorter than
// the interval still retries once at the bound rather than returning early; and
// every ATTEMPT is, because the caller's ctx is the agent's signal context and has
// no deadline of its own — a single TCP or TLS attempt against an apiserver that
// accepts and then never answers would otherwise hang here forever and hold node
// start past a bound this function's whole contract is to enforce. "The bound" must
// have one meaning: how long a resuming node runs with only its server peer
// programmed.
//
// A nil list is an immediate failure, not a nil-deref: a bring-up wired without a
// lister is one that must fall back to its seed.
func pollMeshPeers(ctx context.Context, list func(context.Context) ([]netv1.MeshPeerSpec, error), bound time.Duration) ([]netv1.MeshPeerSpec, error) {
	if list == nil {
		return nil, errors.New("no MeshPeer lister wired for this bring-up")
	}
	deadline := time.Now().Add(bound)
	var err error
	for {
		var peers []netv1.MeshPeerSpec
		if peers, err = listMeshPeersOnce(ctx, list, deadline); err == nil {
			return peers, nil
		}
		// The CALLER's cancellation is terminal — retrying it would spin until the
		// bound on a context that will never recover. A per-attempt deadline is not:
		// that is the retry this loop exists for.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, err
		}
		wait := min(remaining, meshPeerPollInterval)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// listMeshPeersOnce runs one attempt under its own deadline: meshPeerAttemptTimeout,
// or the time left until the poll's deadline when that is sooner — an attempt is
// never allowed to outlive the bound it is being made inside.
func listMeshPeersOnce(ctx context.Context, list func(context.Context) ([]netv1.MeshPeerSpec, error), deadline time.Time) ([]netv1.MeshPeerSpec, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, min(meshPeerAttemptTimeout, time.Until(deadline)))
	defer cancel()
	return list(attemptCtx)
}

// serverPeerFromSeed picks, out of a stored peer seed, the peer whose mesh
// addresses cover the apiserver this node's kubeconfig targets — the one peer a
// resuming node must program before it can ask the cluster anything.
//
// The match is on AllowedIPs (falling back to the peer's pod /24 when a spec
// carries none), because that is the routing fact in question: the peer that
// carries traffic for the apiserver's address is by definition the one whose
// tunnel the LIST must traverse. Matching on a name or an index would encode a
// convention; this encodes the route.
//
// Containment is a UNIQUE selector because mesh index 0 belongs to the
// control-plane node alone: EnrollSelf pins it (meshEnroller, enroll.go) and
// lowestFreeNodeIndex only ever hands out indices ≥ 1, so the index recycling that
// makes a stale worker entry dangerous can never produce a worker /24 overlapping
// the server's AllowedIPs. At most one seed entry can cover the apiserver's
// address.
//
// A host that is not an IP literal — a DNS name, an empty kubeconfig host — matches
// nothing, deliberately: resolving it would need the very tunnel being programmed.
func serverPeerFromSeed(peers []netv1.MeshPeerSpec, apiserverHost string) (netv1.MeshPeerSpec, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(apiserverHost))
	if err != nil {
		return netv1.MeshPeerSpec{}, false
	}
	for _, peer := range peers {
		ranges := peer.AllowedIPs
		if len(ranges) == 0 && peer.PodCIDR != "" {
			ranges = []string{peer.PodCIDR}
		}
		for _, cidr := range ranges {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			if prefix.Contains(addr) {
				return peer, true
			}
		}
	}
	return netv1.MeshPeerSpec{}, false
}

// staleSeedPeers counts the seed entries the live list does not name — the size of
// the divergence the resume path exists to avoid programming. It is reported, not
// acted on: the live list is programmed whole either way.
func staleSeedPeers(seed, live []netv1.MeshPeerSpec) int {
	current := make(map[string]struct{}, len(live))
	for _, peer := range live {
		current[peer.NodeName] = struct{}{}
	}
	stale := 0
	for _, peer := range seed {
		if _, ok := current[peer.NodeName]; !ok {
			stale++
		}
	}
	return stale
}

// restConfigHost returns the bare host of the apiserver a REST config targets,
// or "" when there is none to read. It tolerates both forms clientcmd can leave
// behind — a full URL and a bare host:port — because the caller only wants the
// address, and a parse failure here must degrade to "no server peer", never panic
// a bring-up.
func restConfigHost(cfg *rest.Config) string {
	if cfg == nil || strings.TrimSpace(cfg.Host) == "" {
		return ""
	}
	if u, err := url.Parse(cfg.Host); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	if host, _, err := net.SplitHostPort(cfg.Host); err == nil {
		return host
	}
	return cfg.Host
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
	_, cs, err := kubeclient.FromPath(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("load node kubeconfig for node-local datapath: %w", err)
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
