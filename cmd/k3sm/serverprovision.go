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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
	"k3sm.io/k3sm/pkg/install"
)

// serverPKI is the mesh path's provisioned trust material; zero single-node.
type serverPKI struct {
	// hierarchy is the CA hierarchy the mesh path ensured; nil single-node.
	hierarchy *certs.Hierarchy
	// serverSecret is the server-bootstrap secret; empty single-node.
	serverSecret string
}

// serverPlan is what provisioning decided for `k3sm server`, frozen for the
// post-bring-up phases. startControlPlane builds it BY VALUE only after the HA
// etcd member route has had its say over the executor Config (joinEtcdMember),
// and every phase helper takes the plan, never a Config: so the phases read the
// Config the executor was started with. runServer's own pre-freeze cfg and pki
// locals stay in scope after that (cfg.OnComponentExit has to be assigned in
// runServer's body), and nothing after startControlPlane reads them; that is a
// convention of runServer's body, not a guarantee the types enforce.
//
// The plan carries key material: the CA hierarchy (private keys included), the
// server-bootstrap secret, cfg.Token (the static admin token) and, in opts, the
// HA join token. It must never be logged, printed with %v, or serialized.
type serverPlan struct {
	opts serverOptions
	mode hostnet.Mode
	cfg  executor.Config
	serverPKI
}

// errServerTokenAsAdmin refuses a server-class join token on a start where it
// would become the apiserver's static admin token.
var errServerTokenAsAdmin = errors.New("a server-class join token cannot be this server's static admin token")

// refuseServerTokenAsAdmin is that refusal: any start that is not a
// --server-join loads opts.token as the static system:masters bearer token, so
// a token of the K10<hash>::server:<secret> shape there is a join credential in
// the wrong place. The message names where the token came from, never its value.
func refuseServerTokenAsAdmin(opts serverOptions) error {
	if opts.serverJoin || opts.token == "" {
		return nil
	}
	if _, err := bootstrap.ParseServerToken(opts.token); err != nil {
		return nil
	}
	from := "--token or $K3SM_TOKEN"
	if opts.tokenFile != "" {
		from = "the token file " + opts.tokenFile
	}
	return fmt.Errorf("%w (from %s): it is used only with --server-join, to add this server to an existing HA control plane; without --server-join the token here is the admin bearer token, so point --token-file at the admin token the install staged, or add --server-join if this server is joining", errServerTokenAsAdmin, from)
}

// validateServerOptions runs every refusal that touches no state: the admin
// token file, the HA flag shape, the port ranges, the node name and the
// work-dir guards. It canonicalizes opts.nodeName and resolves opts.token in
// place.
func validateServerOptions(opts *serverOptions, workDirErr error, logger *slog.Logger) error {
	// The token, from the file the installed daemon is pointed at: the static
	// admin token, or on an HA server-join the server-class JOIN token. Resolved
	// BEFORE any state is touched, because a token file that is there and cannot
	// be used (group-readable, empty, unreadable) is terminal: it names a
	// credential the operator believes is in play, and coming up past it would
	// mint a different one and leave every `kubectl` call Unauthorized.
	//
	// The two credentials cannot be swapped by this, in either direction. The
	// join path never makes its token the apiserver's static credential
	// (serverExecutorConfig), and the CA-bundle import and the etcd member route
	// accept only a server-class token, so an admin token handed to a joining
	// server fails there, by name. The reverse, a server-class token reaching a
	// start that is NOT a server-join, is refused below: there it would become
	// a system:masters bearer token, and a credential that reconstructs every
	// cluster CA must not also be one that authenticates as cluster-admin.
	//
	// An ABSENT file is not terminal, exactly as it is not for the agent: the
	// executor then generates a token and writes its own kubeconfig, which is
	// what a bare `k3sm server` has always done.
	absent, terr := resolveTokenFile(opts.tokenFile, &opts.token)
	if terr != nil {
		return terr
	}
	switch {
	case absent && opts.serverJoin:
		logger.Warn("the server-join token file is not there; with --server this server cannot fetch the cluster CAs or reach the etcd member route until it is (re-run `sudo k3sm install --server-join … --token-file <file>`)",
			"path", opts.tokenFile)
	case absent:
		logger.Warn("the admin token file is not there; this start generates a token and writes its own kubeconfig, so an admin kubeconfig written by an earlier install will not authenticate",
			"path", opts.tokenFile)
	}
	if err := refuseServerTokenAsAdmin(*opts); err != nil {
		return err
	}

	// The HA flag shape, before any state is touched: a refusal here costs nothing,
	// where the executor's own check would fire after CAs and kubeconfigs exist.
	if err := opts.validateEtcdFlags(); err != nil {
		return err
	}

	if opts.ingressHTTPPort < 0 || opts.ingressHTTPPort > 65535 {
		return fmt.Errorf("--ingress-http-port %d out of range 0-65535", opts.ingressHTTPPort)
	}
	if opts.ingressHTTPSPort < 0 || opts.ingressHTTPSPort > 65535 {
		return fmt.Errorf("--ingress-https-port %d out of range 0-65535", opts.ingressHTTPSPort)
	}
	if opts.registryPort < 0 || opts.registryPort > 65535 {
		return fmt.Errorf("--registry-port %d out of range 0-65535 (0 disables)", opts.registryPort)
	}
	// The node name is checked ONCE, here, before anything keys on it: from this
	// point opts.nodeName is canonical for the self-name guard, this node's own
	// node-password binding, its certificates and its Node object alike.
	nodeName, nerr := canonicalServerNodeName(opts.nodeName)
	if nerr != nil {
		return nerr
	}
	opts.nodeName = nodeName
	if opts.workDir == "" {
		if workDirErr != nil {
			return fmt.Errorf("resolve control-plane work-dir: %w (pass --work-dir)", workDirErr)
		}
		return fmt.Errorf("control-plane work-dir is empty (pass --work-dir)")
	}
	// Refuse a shadowed data root before touching it: writing the work-dir into
	// a declared-but-unmounted mountpoint would build a fresh, empty datastore
	// that hides the real volume's (2026-09-05).
	if err := refuseShadowedWorkDir(dataroot.OSFS{}, opts.workDir, install.DefaultDataRoot); err != nil {
		return err
	}
	// --cluster-init over an existing single-node datastore, refused before
	// anything is written: the executor checks it again at provision, but by then
	// this function has minted CAs and written kubeconfigs into the work dir.
	if err := executor.RefuseClusterInitOverSQLite(executor.Config{WorkDir: opts.workDir, Etcd: opts.etcdConfig()}); err != nil {
		return err
	}
	// Fail fast if the work-dir is not writable (the unprivileged control plane
	// must not EACCES mid-bring-up against the root-owned default).
	return executor.EnsureWorkDirWritable(opts.workDir)
}

// preflightServer validates opts (validateServerOptions), builds the crash-loop
// breaker, serves --clear-crashloop and --cluster-reset, defaults opts.podRoot,
// and resolves the one `--network` backend. done reports that this start ends
// here, with err as its result (nil after --clear-crashloop).
func preflightServer(opts *serverOptions, workDirErr error, logger *slog.Logger) (breaker *crashBreaker, mode hostnet.Mode, done bool, err error) {
	if err := validateServerOptions(opts, workDirErr, logger); err != nil {
		return nil, mode, true, err
	}
	// The crash-loop circuit breaker (k3sm#344). Every component crash below is
	// recorded under the work dir; once CrashLoopThreshold of them land inside
	// CrashLoopWindow the record is tripped and this daemon PARKS instead of
	// bringing the control plane up — resident and idle, because the server
	// plist's KeepAlive is a bare `true` and launchd would respawn any exit
	// straight back into the same failure. The park ends when an operator clears
	// the record (`k3sm server --clear-crashloop`, or deleting the file) or on a
	// stop signal. The status row names the marker and the remedy.
	breaker = newCrashBreaker(opts.workDir, logger)
	if opts.clearCrashLoop {
		if err := executor.ClearCrashRecord(breaker.path); err != nil {
			return nil, mode, true, fmt.Errorf("clear crash-loop record: %w", err)
		}
		logger.Info("crash-loop record cleared; a parked daemon will now restart itself", "path", breaker.path)
		return nil, mode, true, nil
	}
	if opts.clusterReset {
		return nil, mode, true, runClusterReset(*opts, logger)
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
	mode, err = hostnet.Resolve(opts.network)
	if err != nil {
		return nil, mode, true, err
	}
	logger.Info("host-network backend", "network", opts.network, "backend", mode.Backend.String())
	return breaker, mode, false, nil
}

// admitServerStart decides whether this start may bring a control plane up at
// all. A secrets-encryption refusal or a tripped crash-loop breaker PARKS the
// daemon (done, with the park's result as err); a failed backend probe is
// returned. Otherwise it yields the encryption provider config the executor
// starts with.
func admitServerStart(ctx context.Context, opts serverOptions, breaker *crashBreaker, mode hostnet.Mode, logger *slog.Logger) (encryptionConfig string, done bool, err error) {
	// Secrets encryption at rest, decided from the credential pair under the
	// work dir BEFORE any CA-bundle import or datastore start: a datastore
	// opened under the wrong key (or none) serves Secrets it cannot read, or
	// writes plaintext beside ciphertext. A refusal PARKS, for the crash-loop
	// park's reason: launchd would respawn an exit straight back into it.
	encryptionConfig, encErr := executor.EncryptionAtStart(executor.OSEncryptionStore{}, opts.workDir, opts.etcdPosture(), uint32(os.Geteuid()))
	if encErr != nil {
		logger.Error("refusing to start the control plane: "+encErr.Error(),
			"key-file", executor.EncryptionConfigPath(opts.workDir), "status-with", "k3sm secrets-encrypt status")
		return "", true, parkWhileEncryptionRefused(ctx, opts.workDir, opts.etcdPosture(), uint32(os.Geteuid()), crashLoopPollInterval, logger)
	}
	if rec := breaker.load(); rec.Tripped() {
		last, _ := rec.Last()
		logger.Error(parkReason(last), "path", breaker.path, "tripped-at", rec.TrippedAt.Format(time.RFC3339),
			"last-component", last.Component, "crashes-in-window", rec.Recent(time.Now()),
			"clear-with", "k3sm server --clear-crashloop")
		return "", true, parkUntilCleared(ctx, breaker.path, crashLoopPollInterval, logger)
	}

	if err := mode.Probe(ctx); err != nil {
		return "", true, err
	}
	return encryptionConfig, false, nil
}

// provisionControlPlane builds the executor Config, runs the HA server-join CA
// import, and on the mesh path ensures the CA hierarchy and the apiserver's
// mesh-bound serving posture (provisionMeshPKI). It may rewrite opts.nodeIP.
func provisionControlPlane(ctx context.Context, opts *serverOptions, encryptionConfig string, logger *slog.Logger) (cfg executor.Config, pki serverPKI, err error) {
	cfg = serverExecutorConfig(*opts, encryptionConfig, logger)
	// HA server-join: a SECOND control-plane server reconstructs the IDENTICAL
	// cluster + signing CAs from the first server's AES-256-GCM bootstrap bundle BEFORE
	// EnsureHierarchy (which then LOADS them). FAIL CLOSED — an import failure halts
	// bring-up; we never fall through to minting fresh, divergent CAs (cluster trust
	// split). Requires the server-class token (--token-file, --token or $K3SM_TOKEN). The bundle and, after it,
	// the etcd member route (joinEtcdMember) are reached at --server over the
	// underlay — the existing server's bootstrap listener serves every interface — so
	// neither needs this server's mesh, which comes up after its control plane.
	if opts.serverJoin && opts.joinServer != "" {
		if opts.token == "" {
			return cfg, pki, fmt.Errorf("--server-join with --server requires the server-class join token (--token-file, --token or $K3SM_TOKEN)")
		}
		if err := importServerCABundle(ctx, *opts, logger); err != nil {
			return cfg, pki, fmt.Errorf("HA server-join: %w", err)
		}
	}

	// Multi-node: bind the apiserver + the worker-join supervisor on the mesh
	// interface ONLY, serve a cluster-CA-signed cert, wire --client-ca-file +
	// --kubelet-certificate-authority + --anonymous-auth=false. Empty --mesh-ip keeps
	// the single-node loopback/self-signed path unchanged.
	if opts.meshIP != "" {
		pki.hierarchy, pki.serverSecret, err = provisionMeshPKI(opts, &cfg, logger)
		if err != nil {
			return cfg, serverPKI{}, err
		}
	}
	return cfg, pki, nil
}

// serverExecutorConfig is the control plane's executor Config before the mesh
// posture and the HA member route touch it.
func serverExecutorConfig(opts serverOptions, encryptionConfig string, logger *slog.Logger) executor.Config {
	cfg := opts.executorConfig(logger)
	// Packaged install: `k3sm install` stages the control-plane payload at
	// <install-dir>/bin beside the daemon binary; boot seeds the workdir from it
	// so it never shells out to gh/go (absent under launchd as _k3sm). Dev shells
	// (no bin/ sibling) keep the acquisition fallbacks.
	if dir, err := install.ExecutableDir(); err == nil {
		if fi, serr := os.Stat(filepath.Join(dir, "bin")); serr == nil && fi.IsDir() {
			cfg.PayloadBinDir = filepath.Join(dir, "bin")
		}
	}
	// HA: cfg.Etcd (from executorConfig) runs an etcd member in place of kine and
	// turns on scheduler/KCM leader election so only one server is active.
	cfg.EncryptionProviderConfig = encryptionConfig
	if encryptionConfig != "" {
		logger.Info("secrets encryption at rest is on", "provider", executor.EncryptionProviderName, "config", encryptionConfig)
	}
	if cfg.Etcd != nil {
		logger.Info("HA datastore mode: embedded etcd member; scheduler/KCM leader-elected",
			"cluster-init", opts.clusterInit, "server-join", opts.serverJoin, "member", cfg.Etcd.Name, "peer-ip", cfg.Etcd.PeerIP)
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
	return cfg
}

// provisionMeshPKI is the mesh path's half of control-plane provisioning: the CA
// hierarchy (plus the etcd CAs in HA), the server-bootstrap secret, the HA admin
// kubeconfig, the mesh nodeIP rewrite, and the apiserver's mesh-bound,
// cluster-CA-served posture written into cfg.
func provisionMeshPKI(opts *serverOptions, cfg *executor.Config, logger *slog.Logger) (*certs.Hierarchy, string, error) {
	h, err := certs.EnsureHierarchy(opts.workDir)
	if err != nil {
		return nil, "", fmt.Errorf("ensure CA hierarchy: %w", err)
	}
	// HA only: the etcd server + peer CAs ride the same bootstrap bundle (a
	// joining server's import wrote them, so this LOADS them). A non-HA mesh
	// server mints none.
	if opts.etcdPosture() {
		h.EtcdServer, h.EtcdPeer, err = certs.EnsureEtcdCAs(opts.workDir)
		if err != nil {
			return nil, "", fmt.Errorf("ensure etcd CAs: %w", err)
		}
	}
	// The server-bootstrap secret (machine-generated ≥256-bit) — minted +
	// persisted on the first server, already saved by importServerCABundle on a
	// joining server. It is the CA-bundle endpoint credential AND the bundle's KDF
	// passphrase.
	serverSecret, err := bootstrap.LoadOrCreateServerSecret(serverSecretPath(opts.workDir))
	if err != nil {
		return nil, "", fmt.Errorf("server-bootstrap secret: %w", err)
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
		return nil, "", err
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
	return h, serverSecret, nil
}

// componentExitHandler is the executor's OnComponentExit for `k3sm server`.
//
// A control-plane child that dies after bring-up must take this process with
// it. Nothing watched them before: the per-component reapers were the only
// observers, and their only readers were bring-up and teardown. So a
// kube-apiserver, kine, kube-scheduler or kube-controller-manager that died
// at hour six left `k3sm server` running, which meant launchd's KeepAlive —
// a plain bool, and therefore a restart-on-EXIT policy — never fired. The
// cluster was wedged while `k3sm status` still reported the daemon up. That
// is worst for the scheduler and the controller-manager, which unlike the
// apiserver and kine have no /readyz row: a dead scheduler shows up only as
// pods that never leave Pending, and a dead KCM never shows up at all.
//
// Exiting is the k3s-faithful minimum and the smallest correct move.
// Respawning the child in-process is the larger one and is deliberately not
// taken here: every in-process client still holds a connection to the old
// apiserver, so a respawn would leave the node talking to a corpse.
//
// The first component to exit is stored in crashed, recorded on the breaker, and
// then crashCancel tears the process's context down. runServer's deferred crash
// check reads crashed back. A crash cancels ctx, and ctx feeds everything —
// so the error that actually reaches the exit line depends on WHERE bring-up had
// got to, and most of those errors are a bare "context canceled" that names
// nothing. Rewriting it there, once, covers every return path after the
// handler is wired: exec.Start (a component that crashes while a later one is
// still coming up), the RBAC and CRD provisioning in between, and startNode —
// which returns nil on a cancelled context, right for a signal but wrong for a
// crash, since exiting 0 would tell the operator this was a clean shutdown.
// launchd restarts either way (KeepAlive is an unconditional bool), so the exit
// status is for the human; the crash-loop breaker is what bounds the restarts.
func componentExitHandler(crashed *atomic.Pointer[string], breaker *crashBreaker, crashCancel context.CancelFunc, logger *slog.Logger) func(name string, exitErr error, logPath, logTail string) {
	return func(name string, exitErr error, logPath, logTail string) {
		// First writer wins: the components die in a cascade (kine's exit takes
		// the apiserver with it), and the FIRST one names the actual cause.
		if crashed.CompareAndSwap(nil, &name) {
			// The tail is already redacted and capped by pkg/executor, because
			// launchd captures this logger into a world-readable
			// /var/log/k3sm/server.log while the component log is 0600. The path
			// is logged so the operator knows where the unredacted original is.
			logger.Error("control-plane component exited; shutting down so launchd restarts the daemon",
				"component", name, "err", exitErr, "log", logPath, "log-tail", logTail)
			if breaker.record(name, logTail) {
				logger.Error("crash-loop breaker tripped; the next start will park until an operator clears the record",
					"path", breaker.path, "threshold", executor.CrashLoopThreshold, "window", executor.CrashLoopWindow)
			}
		}
		crashCancel()
	}
}

// startControlPlane runs the HA etcd member route over cfg, freezes the result
// into the serverPlan every later phase reads, then constructs the supervised
// executor from that plan's Config and brings it up, returning once every
// component is healthy. The plan is returned BY VALUE and only after the
// member route's Config reassignment, so nothing downstream reads a stale cfg.
func startControlPlane(ctx context.Context, opts serverOptions, mode hostnet.Mode, cfg executor.Config, pki serverPKI, breaker *crashBreaker, logger *slog.Logger) (serverPlan, *executor.Supervised, error) {
	// On a joining HA server's first boot the etcd member route runs here, before the
	// executor (serveretcd.go): the member starts with the route's initial cluster.
	// A transient answer is retried in-process and never counted; a PERMANENT refusal
	// (a bad or foreign token, a refused name) is recorded as a permanent bring-up
	// failure, so the breaker parks on it instead of launchd re-asking forever. A
	// shutdown during the step is returned uncounted.
	cfg, err := joinEtcdMember(ctx, newServerEtcdJoin(opts), opts.joinServer, cfg, logger)
	if err != nil {
		noteEtcdMemberRouteFailure(breaker, logger, err)
		return serverPlan{}, nil, fmt.Errorf("HA server-join: %w", err)
	}
	plan := serverPlan{opts: opts, mode: mode, cfg: cfg, serverPKI: pki}
	exec := executor.NewSupervised(plan.cfg)
	logger.Info("bringing up k3sm control plane", "work-dir", opts.workDir, "api-port", opts.apiPort)
	if err := exec.Start(ctx); err != nil {
		// This is the place a control plane that never came up gets counted.
		// Without it the breaker saw post-mark crashes only, and a persistent
		// bring-up fault (a kine that cannot open its database, an apiserver whose
		// flags no longer parse) looped under the plist's bare KeepAlive forever.
		// OnComponentExit fires only for a component already marked supervised,
		// which for every component but etcd is the end of its bring-up; etcd is
		// supervised before its promotion and quorum waits, so a death there is
		// seen by both, and pkg/executor hands the report to exactly one of them
		// (the bring-up error wraps executor.ErrEtcdChildExited when the callback
		// took it, and noteBringUpFailure skips that). The recording happens here
		// rather than in pkg/executor because the breaker is the daemon's memory,
		// not the executor's.
		noteBringUpFailure(breaker, logger, err)
		return plan, nil, fmt.Errorf("start control plane: %w", err)
	}
	return plan, exec, nil
}
