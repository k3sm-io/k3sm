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

package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/ports"
)

// schedulerCN / controllerManagerCN are the CommonNames of the per-component client
// certs the scheduler and controller-manager authenticate with — their OWN system:
// identities (the k3s model), which the apiserver's auto-created bootstrap RBAC
// (ClusterRoleBindings system:kube-scheduler / system:kube-controller-manager) binds
// to the matching ClusterRoles. They replace the shared system:masters admin token the
// child components carried through M6.
const (
	schedulerCN         = "system:kube-scheduler"
	controllerManagerCN = "system:kube-controller-manager"
)

// kcmDisabledControllers are the node-side controllers k3sm DROPS because they
// assume real Linux kubelets / cloud providers and would fight the Virtual
// Kubelet node or churn against absent infrastructure. Names match k8s v1.36.2's
// "-controller" suffix convention (kube-controller-manager --help → "All
// controllers").
//
// The --controllers value is rendered as "*,-<each>" — enable every
// on-by-default controller, then disable just these. That is robust across kube
// versions (no brittle allow-list to keep in sync) AND keeps the
// endpointslice-controller ON, which M1.4's Service proxy reconciles off.
var kcmDisabledControllers = []string{
	"persistentvolume-attach-detach-controller", // attach-detach: no real volumes to (de)attach
	"cloud-node-lifecycle-controller",           // cloud provider lifecycle: not a cloud node
	"node-route-controller",                     // route: no cloud routes
	"service-lb-controller",                     // service load-balancer: no cloud LB
	"node-ipam-controller",                      // nodeipam: podCIDR is assigned by darwin-net, not here
}

// healthTimeout bounds how long Start waits for the apiserver to report healthz.
const healthTimeout = 90 * time.Second

// drainGrace is how long Stop waits for a component to exit after SIGTERM before
// escalating to SIGKILL.
const drainGrace = 5 * time.Second

// exitLogTailLines is how many trailing log lines an early-exit error carries —
// enough to name the fatal apiserver/kine flag or config error without dumping
// the whole (token-bearing) log into the returned error.
const exitLogTailLines = 20

// component is one supervised control-plane child process. exited is closed by
// the reaper goroutine spawnEnv starts the moment the child exits; waitErr is
// the cmd.Wait result, written strictly before exited closes and read only
// after <-exited (the channel close is the happens-before edge).
type component struct {
	name    string
	cmd     *exec.Cmd
	log     *os.File
	logPath string
	exited  chan struct{}
	waitErr error
}

// exitDetail describes an early child exit for the fail-fast bring-up error:
// the Wait error (exit status) plus the last ~20 lines of the component's 0600
// log file, so the operator sees the fatal flag/config error immediately
// instead of an opaque healthz timeout. Call only after <-c.exited.
func (c *component) exitDetail() string {
	return fmt.Sprintf("%v; last log lines (%s):\n%s", c.waitErr, c.logPath, tailFile(c.logPath, exitLogTailLines))
}

// exitedNow reports whether the child has left the RUNNING state, asked of the
// kernel synchronously rather than inferred from the exited channel. It is the
// deadline tie-break awaitHealthy needs: exited is closed by a reaper goroutine
// that may not have been scheduled yet, whereas this answer is available the
// instant the child dies. Safe to call at any time, including before the reaper
// has run — it never reaps, so it cannot race cmd.Wait.
func (c *component) exitedNow() bool {
	if c.cmd == nil || c.cmd.Process == nil {
		return false
	}
	return processExited(c.cmd.Process.Pid)
}

// Supervised is the child-process control-plane executor: it os/exec-supervises
// kine, the apiserver, the scheduler, and the controller-manager as child
// processes, each in its own process group for clean teardown.
//
// Concurrency: mu guards comps + started. The components run until Stop, which
// tears them down in reverse dependency order. No Context is stored.
type Supervised struct {
	cfg    Config
	client *http.Client

	mu      sync.Mutex
	comps   []*component // in start order; Stop walks it in reverse
	started bool
	token   string
}

// NewSupervised returns a Supervised executor for cfg, filling defaults.
func NewSupervised(cfg Config) *Supervised {
	cfg = cfg.withDefaults()
	return &Supervised{
		cfg:   cfg,
		token: cfg.Token,
		// The apiserver self-signs its serving cert in M1; skip verification on the
		// loopback healthz probe (the kubeconfig does the same).
		client: &http.Client{
			Timeout:   3 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

// Compile-time check that Supervised satisfies the Executor contract.
var _ Executor = (*Supervised)(nil)

// Kubeconfig returns the admin kubeconfig path.
func (s *Supervised) Kubeconfig() string { return kubeconfigPath(s.cfg.WorkDir) }

// RESTConfigToken returns the apiserver URL and static token.
func (s *Supervised) RESTConfigToken() (string, string) {
	return apiServerURL(s.cfg.APIServerPort), s.token
}

// Start provisions the workdir (binaries, kine, SA keys, token, kubeconfig),
// then brings the control plane up in dependency order (kine → apiserver →
// scheduler → controller-manager) and blocks until the apiserver reports healthz
// ok. On any failure it tears down whatever started.
func (s *Supervised) Start(ctx context.Context) error {
	// Split-brain guard (M6.0): fail closed if HA was requested without a shared
	// datastore — never let a 2nd server quietly form its own SQLite.
	if err := s.cfg.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if s.token == "" {
		tok, err := generateToken()
		if err != nil {
			return err
		}
		s.token = tok
	}

	if err := s.provision(ctx); err != nil {
		return err
	}

	if err := s.bringUp(ctx); err != nil {
		_ = s.Stop(context.WithoutCancel(ctx))
		return err
	}

	s.mu.Lock()
	s.started = true
	s.mu.Unlock()
	return nil
}

// provision lays down everything the components need on disk.
func (s *Supervised) provision(ctx context.Context) error {
	if err := ensureWorkDirs(s.cfg.WorkDir); err != nil {
		return err
	}
	// BEFORE anything replaces the staged kine binary or lets the new pin touch the
	// database: take the verified pre-migration snapshot if this boot moves an existing
	// datastore onto a kine pin that has not opened it before. It is a no-op on a fresh
	// node, on an unchanged pin, and on the Postgres posture (no state.db). It must sit
	// ahead of seedBinDir/ensureKine, which are exactly what would destroy the old kine
	// binary the rollback path preserves. A refusal (no space, an undrained WAL) stops
	// the boot rather than migrating unprotected.
	if s.cfg.DatastoreEndpoint == "" {
		if err := snapshotBeforeKineUpgrade(ctx, s.cfg.Logger, s.cfg.WorkDir, s.cfg.KineVersion); err != nil {
			return err
		}
	}
	// Seed the workdir bin from a staged install payload FIRST, so the ensure*
	// steps below find the binaries present and only re-sign — a launchd _k3sm
	// daemon has neither gh nor a Go toolchain to fall back on.
	if err := seedBinDir(s.cfg.WorkDir, s.cfg.PayloadBinDir, s.cfg.KineVersion); err != nil {
		return err
	}
	if err := ensureControlPlaneBinaries(ctx, s.cfg.WorkDir, s.cfg.KubeVersion); err != nil {
		return err
	}
	if err := ensureKine(ctx, s.cfg.WorkDir, s.cfg.KineVersion); err != nil {
		return err
	}
	if err := writeServiceAccountKeys(ctx, s.cfg.WorkDir); err != nil {
		return err
	}
	if err := writeTokenFile(s.cfg.WorkDir, s.token); err != nil {
		return err
	}
	if err := writeKubeconfig(s.cfg.WorkDir, s.cfg.APIServerPort, s.token); err != nil {
		return err
	}
	// M10.0 (Res.3): the audit policy + admission-control config the apiserver argv
	// references MUST exist before startAPIServer — a missing file would wedge
	// bring-up opaquely until the healthz timeout. Overwritten every boot (the
	// files track the binary).
	if err := writeConformanceConfig(s.cfg.WorkDir, s.cfg.PSAEnforceBaseline); err != nil {
		return err
	}
	if err := s.provisionComponentCerts(); err != nil {
		return err
	}
	return nil
}

// provisionComponentCerts ensures the cluster + signing CA hierarchy exists (so the
// apiserver's unconditional --client-ca-file has a CA to trust) and writes the
// per-component client-cert kubeconfigs the scheduler and controller-manager
// authenticate with — each its OWN system: identity instead of the shared system:masters
// admin token (the k3s model; closes the M4.1 component-identity divergence). The certs
// are signed by the SIGNING CA (= --client-ca-file). EnsureHierarchy is idempotent — it
// LOADS an existing hierarchy (the mesh path in cmd/k3sm/server.go creates it before
// Start), so single-node mints a fresh hierarchy and both paths re-issue the component
// kubeconfigs against the same CA on every boot. It runs in provision() (before bringUp
// starts the scheduler/KCM) so the kubeconfigs and the client-CA exist when those
// components — and the apiserver — start.
func (s *Supervised) provisionComponentCerts() error {
	h, err := certs.EnsureHierarchy(s.cfg.WorkDir)
	if err != nil {
		return fmt.Errorf("ensure CA hierarchy: %w", err)
	}
	// The apiserver presents a cluster-CA-signed serving cert only when one was supplied
	// (the mesh path sets ServingCertFile); single-node it self-signs into --cert-dir, so
	// the co-located loopback components skip server verification (matching the admin
	// kubeconfig's single-node insecure-skip posture) while still presenting their
	// client-cert identity. The identity — not the loopback server-auth — is the
	// load-bearing change.
	verifyClusterCA := s.cfg.ServingCertFile != "" && s.cfg.ServingKeyFile != ""
	if err := writeComponentKubeconfig(schedulerKubeconfigPath(s.cfg.WorkDir), s.cfg.APIServerPort, schedulerCN, h, verifyClusterCA); err != nil {
		return err
	}
	if err := writeComponentKubeconfig(controllerManagerKubeconfigPath(s.cfg.WorkDir), s.cfg.APIServerPort, controllerManagerCN, h, verifyClusterCA); err != nil {
		return err
	}
	return nil
}

// bringUp starts the components in order and waits for the apiserver to be
// healthy before starting scheduler + controller-manager. Each bring-up wait
// SELECTS on child-exit as well as readiness (M10.0, SRE fail-fast): a kine or
// apiserver that dies on a bad flag/config surfaces immediately — with its log
// tail — instead of wedging opaquely until the healthz timeout.
func (s *Supervised) bringUp(ctx context.Context) error {
	kine, err := s.startKine(ctx)
	if err != nil {
		return fmt.Errorf("start kine: %w", err)
	}
	if err := awaitHealthy(ctx, kine.name, kine.exited, kine.exitedNow, tcpReady(s.cfg.KinePort), 30*time.Second, 300*time.Millisecond, kine.exitDetail); err != nil {
		return fmt.Errorf("kine not listening: %w", err)
	}
	// kine is serving, so this pin has now genuinely opened this database — stamp it.
	// Stamping here (not at provision time) is what makes the pre-migration snapshot
	// survive a boot that dies before the datastore ever came up.
	if s.cfg.DatastoreEndpoint == "" {
		if err := recordKinePin(s.cfg.WorkDir, s.cfg.KineVersion); err != nil {
			return err
		}
	}
	api, err := s.startAPIServer(ctx)
	if err != nil {
		return fmt.Errorf("start apiserver: %w", err)
	}
	if err := s.waitHealthz(ctx, api); err != nil {
		return fmt.Errorf("apiserver not healthy: %w", err)
	}
	if _, err := s.startScheduler(ctx); err != nil {
		return fmt.Errorf("start scheduler: %w", err)
	}
	if _, err := s.startControllerManager(ctx); err != nil {
		return fmt.Errorf("start controller-manager: %w", err)
	}
	return nil
}

// startKine launches the kine etcd shim. The datastore is the single-node SQLite WAL
// DB (the M1–M5 default, byte-unchanged) unless cfg.DatastoreEndpoint names a Postgres
// DSN (M6.0 HA multi-writer), in which case the password is relocated off argv into a
// 0600 PGPASSFILE the kine child reads via PGPASSFILE (kineSecretEnv) and only the
// password-stripped DSN reaches --endpoint.
func (s *Supervised) startKine(ctx context.Context) (*component, error) {
	args, err := kineArgs(s.cfg)
	if err != nil {
		return nil, err
	}
	// Record WHICH kine is about to run — version AND build variant. The variant is not
	// cosmetic: the same kine tag builds two different SQLite implementations depending
	// on CGO_ENABLED, and a datastore incident that starts "which sqlite was this?"
	// should be answerable from the node's own log.
	kineVersion, kineVariant := readKineMarker(binDir(s.cfg.WorkDir))
	s.cfg.Logger.Info("starting datastore shim", "component", "kine",
		"version", kineVersion, "variant", kineVariant, "datastore", datastorePosture(s.cfg))
	env, err := s.kineSecretEnv()
	if err != nil {
		return nil, err
	}
	return s.spawnEnv(ctx, "kine", env, args...)
}

// kineSecretEnv relocates a Postgres DSN password OFF argv. For a datastore endpoint
// carrying a password it writes a 0600 PGPASSFILE in the work-dir and returns the
// PGPASSFILE env var for the kine child; kine's pgx driver (pgx.ParseConfig) reads the
// password from it as the libpq env fallback when the DSN omits it. It returns nil for
// the SQLite path or a password-less DSN. Writing here (not in the pure kineArgs) keeps
// the secret out of both argv AND the args the tests inspect.
func (s *Supervised) kineSecretEnv() ([]string, error) {
	if s.cfg.DatastoreEndpoint == "" {
		return nil, nil
	}
	_, password, err := splitDatastorePassword(s.cfg.DatastoreEndpoint)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, nil
	}
	path := pgPassPath(s.cfg.WorkDir)
	if err := os.WriteFile(path, []byte(pgPassLine(password)), 0o600); err != nil {
		return nil, fmt.Errorf("write datastore PGPASSFILE: %w", err)
	}
	return []string{"PGPASSFILE=" + path}, nil
}

// startAPIServer launches kube-apiserver against kine on the secure port. From M4.1
// it enforces --authorization-mode=Node,RBAC + the NodeRestriction admission plugin
// (the scheduler + controller-manager authenticate with their OWN per-component client
// certs — system:kube-scheduler / system:kube-controller-manager, bound by the
// apiserver's bootstrap RBAC; only the in-process VK node + post-bring-up provisioning
// + the healthz probe still carry the system:masters admin token) and sets
// --kubelet-preferred-address-types=InternalIP so kubectl logs/exec reach the node by
// IP (closing the M0.3 gap).
//
// In-pod API reachability (M2.4): the apiserver binds 127.0.0.1 and the
// auto-created kubernetes.default.svc endpoint advertises --advertise-address,
// which is NodeIP — defaulting to 127.0.0.1 for a single node (see cmd/k3sm
// --node-ip). So on a single node the endpoint resolves to the loopback the
// apiserver actually listens on, and the in-process Service proxy (same host)
// reaches it; a pod's projected SA token + the kube-root-ca.crt CA then complete
// a working in-cluster config. When NodeIP is a routable address (multi-node),
// the kubernetes endpoint must be rewritten to a node-local address per node so
// infra VIPs are not blackholed over the mesh — that is M3.3, not here.
//
// The ServiceAccount admission plugin (in the default enabled set — the M4.1
// --enable-admission-plugins=NodeRestriction is ADDITIVE, so ServiceAccount stays
// on) stamps spec.serviceAccountName and injects the projected SA volume (token +
// kube-root-ca.crt + namespace) the provider materializes; the root-ca-cert-publisher
// controller (kept by the scoped --controllers "*") publishes kube-root-ca.crt to
// every namespace.
//
// NOTE: the DESIGN's --feature-gates=ConsistentListFromCache=false (the kine#577
// watch-staleness mitigation) is NOT passed: in the pinned kwok-ci/k8s build
// (k8s v1.36.2) that gate is GA-LOCKED to true and the apiserver refuses to
// start if it is set false ("feature is locked to true"). It is left at its
// locked default; the soak is revisited if k3sm ever pins a kube version where
// the gate is still settable.
func (s *Supervised) startAPIServer(ctx context.Context) (*component, error) {
	return s.spawn(ctx, "kube-apiserver", apiServerArgs(s.cfg)...)
}

// apiServerArgs renders the kube-apiserver argv from cfg. It is a pure function so
// the M3/M4 trust posture is table-tested without booting the apiserver: the mesh
// BindAddress (never 0.0.0.0), --anonymous-auth=false, --client-ca-file (always set —
// defaulting to the signing CA so the per-component + system:node client certs
// authenticate single-node too), --kubelet-certificate-authority, the
// --authorization-mode (Node,RBAC by default, M4.1), and the NodeRestriction
// admission plugin are all asserted here. It self-defaults the bind address and the
// authorization mode (so a raw Config in a test renders the production posture); the
// M1/M2 single-node path leaves the M3 fields zero, so the binding falls back to
// NodeIP (loopback) and the kubelet-CA / anonymous-auth flags are omitted.
func apiServerArgs(cfg Config) []string {
	wd := cfg.WorkDir
	bind := cfg.BindAddress
	if bind == "" {
		bind = cfg.NodeIP
	}
	if bind == "" {
		bind = "127.0.0.1"
	}
	authzMode := cfg.AuthorizationMode
	if authzMode == "" {
		authzMode = DefaultAuthorizationMode
	}
	args := []string{
		"--etcd-servers", "http://127.0.0.1:" + strconv.Itoa(cfg.KinePort),
		"--service-cluster-ip-range", "10.43.0.0/16",
		// Pin the NodePort range to the standard 30000-32767 (the kube-apiserver
		// default). k3sm's userspace Service proxy binds *:NodePort directly and
		// in-process as the unprivileged _k3sm user (NOT via the root netd helper,
		// which rejects wildcards).
		//
		// CORRECTED (B116) — this comment used to claim a <1024 NodePort would fail
		// EACCES on the wildcard. That is the LINUX rule, and it is false on Darwin:
		// re-measured on macOS 26, `0.0.0.0:1023` binds fine as an ordinary uid while
		// `127.0.0.1:1023` returns EACCES — inverted from Linux. So the range is NOT
		// pinned for a privilege reason; it is pinned so the range k3sm's OWN wildcard
		// listeners occupy is explicit and single-sourced (pkg/ports), which is what
		// the reserved-port admission guard and the svclb bind refusal derive from.
		// The integration canary cmd/k3sm::TestWildcardPrivilegedBindPremise pins the
		// measured OS behaviour so a future XNU change is loud rather than silent.
		"--service-node-port-range", ports.NodePortRange(),
		"--service-account-key-file", saPubPath(wd),
		"--service-account-signing-key-file", saKeyPath(wd),
		"--service-account-issuer", "https://kubernetes.default.svc.cluster.local",
		"--token-auth-file", tokenFilePath(wd),
		// M4.1: enforce the Node authorizer + RBAC (default-deny) instead of
		// AlwaysAllow. The flip is pure — the VK node + provisioners carry the static
		// admin token (system:masters, RBAC-exempt), the scheduler/KCM carry their own
		// client-cert identities the apiserver's bootstrap RBAC binds, and joined
		// workers' system:node identities get a pre-provisioned datapath grant
		// (pkg/rbac.Provision) before the VK node / join supervisor start.
		"--authorization-mode", authzMode,
		// Add NodeRestriction to the default-enabled admission set (--enable-admission-
		// plugins is ADDITIVE, so the ServiceAccount plugin M2.4 relies on stays on).
		// It confines a system:node:<name> identity to mutating only its OWN Node/Pod
		// objects — the admission half of the Node authorizer. It does NOT cover CRDs,
		// so the net.k3sm.io/MeshPeer write stays guarded by bootstrap.AuthorizeMeshPeerWrite.
		"--enable-admission-plugins=NodeRestriction",
		// B76: enable the BETA MutatingAdmissionPolicy API + feature gate so the
		// EnsureDaemonSetTolerationMutation policy (which injects the provider toleration
		// into DaemonSet-owned pods) is actually evaluated. MutatingAdmissionPolicy is
		// BETA and OFF by default at the pinned k8s (v1.36.2); without BOTH of these the
		// policy is provisioned but a runtime no-op. CAUTION: an invalid feature-gate name
		// or a v1beta1 group that the pinned apiserver does not serve makes kube-apiserver
		// REFUSE to start — the gate name + v1beta1 serving MUST be lab-verified against
		// the kwok-ci v1.36.2 apiserver before a real rollout.
		"--runtime-config=admissionregistration.k8s.io/v1beta1=true",
		"--feature-gates=MutatingAdmissionPolicy=true",
		// M10.0 audit logging (Res.4): the shipped policy is structurally
		// Metadata/None-only (see auditPolicyDoc — no Secret cleartext at rest),
		// the log lands in the 0700 <workDir>/audit dir, and rotation is bounded
		// (100MiB × (3 backups + 1 live) ≈ 400MB worst case — the honest ENOSPC
		// bound, off the datastore's db/ subtree). --audit-log-mode is deliberately
		// NOT set: the upstream default is "blocking" (each event is written before
		// the response returns), and the stricter blocking-strict — which FAILS the
		// request when the audit write fails — is deliberately not used: a full
		// audit volume must degrade to dropped events, never stall serving.
		"--audit-policy-file", auditPolicyPath(wd),
		"--audit-log-path", AuditLogPath(wd),
		"--audit-log-maxsize=100",
		"--audit-log-maxbackup=3",
		"--audit-log-maxage=30",
		// M10.0 PSA cluster defaults (Res.2): the AdmissionConfiguration embedding
		// the PodSecurityConfiguration (warn=baseline + audit=restricted; enforce
		// stays privileged unless Config.PSAEnforceBaseline flips the B71 cutover).
		"--admission-control-config-file", admissionConfigPath(wd),
		"--bind-address", bind,
		"--advertise-address", cfg.NodeIP,
		"--secure-port", strconv.Itoa(cfg.APIServerPort),
		"--cert-dir", certDir(wd),
		"--kubelet-preferred-address-types", "InternalIP",
		"--allow-privileged",
	}
	// --client-ca-file is UNCONDITIONAL (the M4.1 review flagged the mesh-gating): the
	// apiserver must trust the cluster client-CA so the per-component client certs
	// (system:kube-scheduler / system:kube-controller-manager) AND joined workers'
	// system:node certs authenticate — single-node included. It defaults to the signing
	// CA under the work-dir PKI dir (which provision ensures exists); an explicit mesh
	// ClientCAFile is honored verbatim. Adding x509 client-cert auth is additive — the
	// static token auth (admin/healthz) is unaffected.
	clientCA := cfg.ClientCAFile
	if clientCA == "" {
		clientCA = certs.SigningCACertPath(wd)
	}
	args = append(args, "--client-ca-file", clientCA)
	if cfg.KubeletCAFile != "" {
		args = append(args, "--kubelet-certificate-authority", cfg.KubeletCAFile)
	}
	if cfg.AnonymousAuth != nil {
		args = append(args, fmt.Sprintf("--anonymous-auth=%t", *cfg.AnonymousAuth))
	}
	if cfg.ServingCertFile != "" && cfg.ServingKeyFile != "" {
		args = append(args, "--tls-cert-file", cfg.ServingCertFile, "--tls-private-key-file", cfg.ServingKeyFile)
	}
	return args
}

// startScheduler launches kube-scheduler against its OWN per-component kubeconfig.
func (s *Supervised) startScheduler(ctx context.Context) (*component, error) {
	return s.spawn(ctx, "kube-scheduler", schedulerArgs(s.cfg)...)
}

// schedulerArgs renders the kube-scheduler argv from cfg. The --kubeconfig /
// --authentication-kubeconfig / --authorization-kubeconfig point at the scheduler's
// OWN client-cert kubeconfig (CN=system:kube-scheduler, provisioned by
// provisionComponentCerts), NOT the system:masters admin kubeconfig — so the
// apiserver's bootstrap system:kube-scheduler ClusterRoleBinding actually constrains
// it (the k3s model). Pure so the M6.0 leader-election posture is table-tested:
// --leader-elect is false single-node (one candidate, no lease churn — the M1–M5
// default, byte-unchanged) and true in HA (Postgres multi-writer) so only ONE server's
// scheduler is active (two active schedulers double-bind pods).
func schedulerArgs(cfg Config) []string {
	kc := schedulerKubeconfigPath(cfg.WorkDir)
	return []string{
		"--kubeconfig", kc,
		"--authentication-kubeconfig", kc,
		"--authorization-kubeconfig", kc,
		"--leader-elect=" + strconv.FormatBool(cfg.leaderElect()),
		"--bind-address", "127.0.0.1",
		"--secure-port", "10259",
	}
}

// startControllerManager launches kube-controller-manager with the SCOPED
// controller set (node-side controllers dropped; endpointslice kept).
func (s *Supervised) startControllerManager(ctx context.Context) (*component, error) {
	return s.spawn(ctx, "kube-controller-manager", controllerManagerArgs(s.cfg)...)
}

// controllerManagerArgs renders the kube-controller-manager argv from cfg. The three
// kubeconfig flags point at the KCM's OWN client-cert kubeconfig
// (CN=system:kube-controller-manager, provisioned by provisionComponentCerts), NOT the
// system:masters admin kubeconfig. Because the system:kube-controller-manager
// ClusterRole is NOT a superset of the per-controller roles, the move REQUIRES
// --use-service-account-credentials=true so each controller authenticates as its own
// service account (system:controller:<name>, bound by the apiserver's bootstrap RBAC) —
// without it the deployment/endpointslice/etc. controllers would be RBAC-denied. The
// KCM signs those SA tokens locally with --service-account-private-key-file (no
// TokenRequest round-trip), so --service-account-private-key-file + --root-ca-file stay
// as-is. Pure so the M6.0 leader-election posture is table-tested alongside the scoped
// --controllers set: --leader-elect is false single-node and true in HA so only ONE
// server's KCM is active (two active KCMs double-reconcile every object).
func controllerManagerArgs(cfg Config) []string {
	wd := cfg.WorkDir
	kc := controllerManagerKubeconfigPath(wd)
	return []string{
		"--kubeconfig", kc,
		"--authentication-kubeconfig", kc,
		"--authorization-kubeconfig", kc,
		"--leader-elect=" + strconv.FormatBool(cfg.leaderElect()),
		"--use-service-account-credentials=true",
		"--service-account-private-key-file", saKeyPath(wd),
		"--root-ca-file", filepath.Join(certDir(wd), "apiserver.crt"),
		"--bind-address", "127.0.0.1",
		"--secure-port", "10257",
		"--controllers", controllersFlag(),
	}
}

// controllersFlag renders the scoped --controllers value: "*" (all on-by-default
// controllers) followed by "-<name>" for each dropped node-side controller.
func controllersFlag() string {
	out := "*"
	for _, c := range kcmDisabledControllers {
		out += ",-" + c
	}
	return out
}

// spawn starts a control-plane binary with no extra environment (the common case).
func (s *Supervised) spawn(ctx context.Context, name string, args ...string) (*component, error) {
	return s.spawnEnv(ctx, name, nil, args...)
}

// spawnEnv starts a control-plane binary from the workdir bin as a child process in
// its own process group, redirecting its output to a per-component log file, and
// records it for teardown. extraEnv is appended to the inherited environment (used to
// pass the kine child its PGPASSFILE out-of-band, keeping the Postgres secret off
// argv). It does NOT block on the child — components run until Stop — but it DOES
// start a reaper goroutine (`go cmd.Wait()`) that closes the component's exited
// channel the moment the child dies, so the bring-up waits (awaitHealthy) and
// stopComponent can select on child-exit. That goroutine's lifetime is the child's
// lifetime — typically the whole process life for a healthy component — which is
// deliberate and leak-free: it parks in wait4 and ends exactly when the child does.
//
// The log file is mode 0600 (not the umask default 0644): a component log can carry
// bearer tokens and the kine datastore endpoint, so it must not be world-readable.
func (s *Supervised) spawnEnv(ctx context.Context, name string, extraEnv []string, args ...string) (*component, error) {
	bin := filepath.Join(binDir(s.cfg.WorkDir), name)
	logPath := filepath.Join(s.cfg.WorkDir, name+".log")
	lf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s log: %w", name, err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = lf, lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	s.cfg.Logger.Info("started control-plane component", "component", name, "pid", cmd.Process.Pid, "log", logPath)

	c := &component{name: name, cmd: cmd, log: lf, logPath: logPath, exited: make(chan struct{})}
	// The single reaper: the ONLY cmd.Wait for this child (stopComponent selects on
	// exited instead of racing a second Wait). waitErr is written before the close,
	// so a reader that has observed <-exited reads it race-free.
	go func() {
		c.waitErr = cmd.Wait()
		close(c.exited)
	}()

	s.mu.Lock()
	s.comps = append(s.comps, c)
	s.mu.Unlock()
	return c, nil
}

// waitHealthz waits for the apiserver to report healthz ok, failing fast (with
// the log tail) if the apiserver child exits first. The 90s healthTimeout is
// unchanged — fail-fast only ever SHORTENS the wedge, never lengthens it.
func (s *Supervised) waitHealthz(ctx context.Context, api *component) error {
	return awaitHealthy(ctx, api.name, api.exited, api.exitedNow, s.Ready, healthTimeout, 500*time.Millisecond, api.exitDetail)
}

// awaitHealthy is the bring-up wait: it polls ready() every poll until it
// reports true, SELECTING against child-exit the whole time. It returns nil on
// ready; an early-exit error (naming the component + exitDetail's log tail) the
// moment exited closes; a timeout error after timeout; or ctx.Err(). It is a
// pure function over channels + funcs so the fail-fast contract is table-tested
// without spawning real control-plane binaries. A closed exited wins over a
// concurrently-true ready (a dead child is never "healthy").
//
// exitedNow is the tie-breaker that makes "the child died" beat "the deadline
// expired" DETERMINISTICALLY. The exited channel is closed by a reaper goroutine,
// so a child can be long dead while the close has not been SCHEDULED yet — under
// full-suite parallel load that lag was measured in seconds, which is exactly how
// a dead child came back as an opaque "not healthy within 10s". So the deadline
// is not allowed to author its error until exitedNow — an authoritative,
// synchronous kernel probe running on THIS goroutine — has confirmed the child is
// still alive. When it says the child has exited, the wait blocks for the close
// (imminent by construction: the kernel has already released the child, so the
// reaper only needs a scheduling slot) and returns the exit-shaped error instead.
// A nil exitedNow disables the tie-break, leaving the deadline unqualified.
//
// The probe is consulted ONLY at deadline expiry — one syscall per bring-up wait,
// not one per poll — because that is the only place a wrong error shape is built.
func awaitHealthy(ctx context.Context, name string, exited <-chan struct{}, exitedNow func() bool, ready func(context.Context) bool, timeout, poll time.Duration, exitDetail func() string) error {
	deadline := time.Now().Add(timeout)
	for {
		select {
		case <-exited:
			return fmt.Errorf("%s exited during bring-up: %s", name, exitDetail())
		default:
		}
		if ready(ctx) {
			return nil
		}
		if time.Now().After(deadline) {
			if exitedNow != nil && exitedNow() {
				select {
				case <-exited:
					return fmt.Errorf("%s exited during bring-up: %s", name, exitDetail())
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return fmt.Errorf("%s not healthy within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-exited:
			return fmt.Errorf("%s exited during bring-up: %s", name, exitDetail())
		case <-time.After(poll):
		}
	}
}

// tailFile returns the last n lines of the file at path (best-effort: an
// unreadable file yields a placeholder so the caller's error stays actionable).
func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("<unreadable log: %v>", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Ready reports whether the apiserver /healthz returns "ok".
func (s *Supervised) Ready(ctx context.Context) bool {
	url := apiServerURL(s.cfg.APIServerPort) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	buf := make([]byte, 2)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode == http.StatusOK && string(buf[:n]) == "ok"
}

// Stop tears the control plane down in REVERSE dependency order: the components
// were appended in start order (kine, apiserver, scheduler, controller-manager),
// so walking the slice in reverse stops the apiserver and the controllers first
// and kine LAST, after which the SQLite DB is no longer in use. Idempotent.
func (s *Supervised) Stop(ctx context.Context) error {
	s.mu.Lock()
	comps := s.comps
	s.comps = nil
	s.started = false
	s.mu.Unlock()

	// Reverse start order = correct shutdown order, but kine (index 0) must die
	// LAST. Build the explicit order: apiserver, scheduler, controller-manager,
	// then kine.
	for _, c := range shutdownOrder(comps) {
		s.stopComponent(c)
	}
	return nil
}

// shutdownOrder returns comps ordered for a clean teardown: the apiserver drains
// FIRST (it stops writing), then scheduler + controller-manager, then kine LAST
// (so no component loses its datastore mid-shutdown). Components arrive in start
// order [kine, apiserver, scheduler, controller-manager]; this pulls kine to the
// end and keeps the rest in start order (apiserver before the controllers).
func shutdownOrder(comps []*component) []*component {
	var kine *component
	out := make([]*component, 0, len(comps))
	for _, c := range comps {
		if c.name == "kine" {
			kine = c
			continue
		}
		out = append(out, c)
	}
	if kine != nil {
		out = append(out, kine)
	}
	return out
}

// stopComponent SIGTERMs a component's process group, waits drainGrace for the
// reaper goroutine (the single cmd.Wait, started by spawnEnv) to observe the
// exit, then SIGKILLs if it has not, and closes its log file. An
// already-exited child (the fail-fast path) makes this a no-op signal + an
// immediate return on the closed exited channel.
func (s *Supervised) stopComponent(c *component) {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	pid := c.cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	select {
	case <-c.exited:
	case <-time.After(drainGrace):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-c.exited
	}
	if c.log != nil {
		_ = c.log.Close()
	}
	s.cfg.Logger.Info("stopped control-plane component", "component", c.name)
}

// tcpReady returns a bring-up ready func (for awaitHealthy) reporting whether
// 127.0.0.1:port currently accepts a TCP connection.
func tcpReady(port int) func(context.Context) bool {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	d := &net.Dialer{Timeout: time.Second}
	return func(ctx context.Context) bool {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}
