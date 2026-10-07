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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"k3sm.io/k3sm/pkg/certs"
)

// Executor brings up and tears down the k3sm control plane. Start blocks until
// the control plane is healthy (or ctx ends); Ready reports liveness; Stop
// shuts every component down cleanly in reverse dependency order.
type Executor interface {
	// Start brings the control plane up and blocks until it is healthy, then
	// returns nil (the components keep running until Stop). It returns an error if
	// any component fails to come up before the deadline or ctx is cancelled.
	Start(ctx context.Context) error
	// Ready reports whether the control plane is currently serving (apiserver
	// healthz ok). It is cheap to call repeatedly.
	Ready(ctx context.Context) bool
	// Stop tears the control plane down in reverse dependency order (apiserver →
	// scheduler/controller-manager → kine → close DB). It is idempotent.
	Stop(ctx context.Context) error
	// Kubeconfig returns the path to the admin kubeconfig the executor wrote, for
	// the in-process node and kubectl to use.
	Kubeconfig() string
	// RESTConfigToken returns the static bearer token and apiserver URL the
	// in-process clients use to reach the control plane.
	RESTConfigToken() (server, token string)
}

// ErrEmbeddedNotImplemented is returned by the Embedded strategy: from-source
// in-process embedding of the control plane is deferred to a future milestone
// (Wave-0 confirmed the k3s-io/kubernetes monorepo import is infeasible today).
var ErrEmbeddedNotImplemented = errors.New("executor: from-source in-process embedding is not implemented yet (deferred milestone); use the Supervised strategy")

// Config configures an Executor. Zero values get sensible defaults in New*.
type Config struct {
	// WorkDir is the control-plane state root: binaries, certs, SA keys, the
	// kine SQLite DB, the kubeconfig, and component logs. Defaults to
	// /var/lib/k3sm/server when empty.
	WorkDir string
	// APIServerPort is the apiserver secure port. Defaults to 6444 (NOT 6443 —
	// Docker Desktop's Kubernetes squats there).
	APIServerPort int
	// KinePort is the kine (etcd shim) listen port. Defaults to 2379.
	KinePort int
	// SchedulerPort is the kube-scheduler secure-serving port. Defaults to 10259.
	// Per-SERVER, not per-host: it is a singleton listener, so a second control
	// plane on one Mac whose scheduler keeps the default loses the bind.
	SchedulerPort int
	// ControllerManagerPort is the kube-controller-manager secure-serving port.
	// Defaults to 10257, per-server for the same reason as SchedulerPort.
	ControllerManagerPort int
	// KubeVersion is the kwok-ci/k8s control-plane release (darwin-arm64).
	// Defaults to DefaultKubeVersion.
	KubeVersion string
	// KineVersion is the kine module version to go install. Defaults to
	// DefaultKineVersion.
	KineVersion string
	// PayloadBinDir, when non-empty, is a directory of pre-staged control-plane
	// binaries (PayloadBinaries: kube-apiserver/scheduler/controller-manager/
	// kubectl + kine) the boot seeds the workdir bin from BEFORE the gh/go
	// acquisition fallbacks — the packaged-install path (`k3sm install` stages it
	// beside the daemon), where a launchd _k3sm daemon has neither gh nor a Go
	// toolchain. Empty (dev shells) keeps the acquisition fallbacks.
	PayloadBinDir string
	// Token is the static bearer token written to the token file + kubeconfig.
	// Defaults to a generated token when empty.
	Token string
	// NodeIP is the node InternalIP; the apiserver advertises it and the kubelet
	// preferred-address-types is set to InternalIP so logs/exec reach the node.
	NodeIP string
	// BindAddress is the address the apiserver binds. For a MULTI-NODE cluster it is
	// the node's wireguard mesh IP so a joining node can reach the apiserver and the
	// AlwaysAllow+token surface is NOT exposed on 0.0.0.0 or the LAN (bind the mesh
	// interface ONLY). Empty falls back to NodeIP (loopback for the
	// single-node dev path).
	BindAddress string
	// ClientCAFile is the apiserver --client-ca-file: the client-CA the apiserver trusts
	// so client certs authenticate (node certs CN=system:node:<name> and the per-component
	// certs CN=system:kube-scheduler / system:kube-controller-manager, all signed by the
	// signing CA). It is now wired UNCONDITIONALLY — when empty, apiServerArgs defaults it
	// to the signing CA under the work-dir PKI dir (certs.SigningCACertPath), so the
	// single-node path gets it too — it is never mesh-gated. An explicit value (the
	// mesh path) is honored verbatim. It was wired while the authorizer was still
	// AlwaysAllow, so the Node,RBAC flip was a pure authorizer switch.
	ClientCAFile string
	// KubeletCAFile, when set, is passed as --kubelet-certificate-authority so the
	// apiserver verifies the kubelet-serving cert and remote exec/logs are not
	// MITM-able.
	KubeletCAFile string
	// AnonymousAuth, when non-nil, sets --anonymous-auth explicitly. withDefaults
	// fills a nil pointer with FALSE: under Node,RBAC anonymous requests map to
	// system:anonymous and RBAC default-denies them, but closing the surface outright
	// is defense-in-depth — it keeps an unauthenticated caller from probing the
	// apiserver at all (and under the old AlwaysAllow posture it was the only thing stopping
	// anonymous cluster-admin). The static bearer token (scheduler/CM/kubectl/healthz
	// all carry it) is unaffected; only credential-less requests are rejected. The pure
	// apiServerArgs still omits the flag for a nil pointer, so the multi-node path
	// (explicit false) and the arg-rendering tests are unchanged.
	AnonymousAuth *bool
	// ServingCertFile / ServingKeyFile, when both set, are passed as
	// --tls-cert-file / --tls-private-key-file so the apiserver presents a cluster-CA
	// -signed serving cert (instead of self-signing into --cert-dir). A joining node
	// that pinned the cluster CA then verifies the apiserver via its kubeconfig
	// certificate-authority-data. Empty keeps the self-signed single-node path.
	ServingCertFile string
	ServingKeyFile  string
	// RootCAFile is the CA the kube-controller-manager's root-ca-cert-publisher
	// republishes into every namespace's kube-root-ca.crt ConfigMap — the trust
	// anchor every Pod uses to verify the apiserver. It MUST anchor the serving cert
	// the apiserver actually presents, so it is meaningful ONLY on the mesh path
	// (where ServingCertFile names a cluster-CA-issued leaf); single-node the
	// apiserver self-signs into its own --cert-dir and that file is the only possible
	// anchor. Empty on the mesh path defaults to the cluster CA under the work-dir PKI
	// dir; setting it WITHOUT a serving cert is a misconfiguration Validate rejects.
	//
	// It is never read directly: rootCAFile resolves it off the SAME predicate that
	// gates --tls-cert-file (meshServingCert), so --root-ca-file and --tls-cert-file
	// cannot name CAs from different postures.
	RootCAFile string
	// AuthorizationMode is the apiserver --authorization-mode. Empty defaults to
	// DefaultAuthorizationMode (Node,RBAC) — the hard-cut flip from AlwaysAllow.
	// The flip is pure because no in-process component is left unauthorized: the VK node
	// + provisioners carry the static admin token (mapped to system:masters, which
	// bypasses RBAC), the scheduler/KCM carry their own client-cert identities the
	// apiserver's bootstrap RBAC already binds, and joined workers' system:node
	// identities get a pre-provisioned datapath grant (pkg/rbac); set it
	// to "AlwaysAllow" only for a deliberate diagnostic bring-up.
	AuthorizationMode string
	// Etcd, when non-nil, selects the embedded-etcd HA posture: this server runs one
	// etcd member as a supervised child (instead of kine) and its apiserver talks to
	// that local member over mutual TLS. Nil is the kine posture (single-node SQLite),
	// which nothing about this field changes. See EtcdConfig.
	Etcd *EtcdConfig
	// PSAEnforceBaseline, when true, flips the cluster-wide Pod Security Admission
	// default ENFORCE level from privileged to baseline in the provisioned
	// PodSecurityConfiguration (see admissionConfigYAML — the SINGLE authority for
	// the PSA level tuple). The SHIPPED default is false — baseline-WARN only
	// (warn=baseline + audit=restricted, zero rejection).
	// This field is the documented, reversible cutover MECHANISM: flip it (via
	// `k3sm server --psa-enforce-baseline`) only after a pre-flight scan proves the
	// cluster clean; reverting the flag reverts the posture on the next boot. PSA
	// here is conformance-surface + defense-in-depth, NOT the privilege boundary
	// (the foreign-uid VAP + Seatbelt stay that).
	PSAEnforceBaseline bool
	// EncryptionProviderConfig, when non-empty, is the path of the apiserver
	// EncryptionConfiguration, passed as --encryption-provider-config so Secrets
	// are encrypted at rest. The caller sets it only after EncryptionAtStart has
	// accepted the credential pair under the work dir. It is a single-server
	// option: Validate refuses it in the etcd HA posture, because every server of an
	// HA control plane would need the same key and nothing distributes one.
	EncryptionProviderConfig string
	// LeaderElect, when non-nil, forces the scheduler + controller-manager --leader-elect
	// setting. A nil pointer DERIVES it from the datastore posture: ON in HA (the etcd
	// posture, every server sharing one cluster — so only one server's scheduler/KCM is active; two active
	// schedulers double-bind pods, two KCMs double-reconcile) and OFF single-node (one
	// candidate, no lease churn — the single-node default). Only the apiserver is active/active
	// in HA. The leader-election Leases are authorized by the apiserver's auto-created
	// system:kube-scheduler / system:kube-controller-manager bootstrap RBAC, which binds
	// the components' OWN per-component identities — no pkg/rbac object is needed.
	LeaderElect *bool
	// OnComponentExit, when non-nil, is called from a component's reaper goroutine
	// when that component exits after passing ITS OWN readiness gate — i.e. it
	// crashed. It is never called for a bring-up failure of that same component
	// (supervisedBringUp reports those, with the name and log tail) nor for a
	// component Stop deliberately killed. A component that has come up DOES fire
	// while later components are still coming up: that window is a real crash
	// window, not a bring-up failure (see Supervised.markSupervised).
	//
	// It receives the component name, cmd.Wait's error, the path of that
	// component's 0600 log, and a REDACTED, byte-capped tail of it. The tail is
	// safe for a less-protected sink — a daemon logger launchd captures into a
	// world-readable file — and the path is where the operator gets the
	// unredacted original. Do not read the log yourself to "improve" the tail:
	// that is what the redaction is for.
	//
	// It runs ON the reaper goroutine, so it must return promptly and MUST NOT
	// call Stop — Stop tears down the remaining components and would run
	// concurrently with the caller's own deferred Stop, and it waits for the
	// reapers, so calling it from one deadlocks. The intended implementation
	// cancels the server's root context and returns, which lets the ordinary
	// shutdown path run every deferred teardown exactly once, in order.
	OnComponentExit func(name string, err error, logPath, logTail string)
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// EtcdRole is how this server's etcd member enters the cluster on its first boot.
type EtcdRole int

const (
	// EtcdInit forms a new single-member cluster (`k3sm server --cluster-init`).
	EtcdInit EtcdRole = iota + 1
	// EtcdJoin joins an existing cluster as a learner that is then promoted
	// (`k3sm server --server-join`).
	EtcdJoin
)

// String names the role for logs.
func (r EtcdRole) String() string {
	switch r {
	case EtcdInit:
		return "init"
	case EtcdJoin:
		return "join"
	}
	return "unknown"
}

// EtcdConfig configures the embedded-etcd HA posture (Config.Etcd).
//
// The role matters only on a member's FIRST boot: once <WorkDir>/etcd/member exists
// the member restarts from its own data dir, both roles behave identically, and the
// initial-cluster fields are ignored (a restart never re-adds or re-promotes).
type EtcdConfig struct {
	// Role is EtcdInit or EtcdJoin.
	Role EtcdRole
	// Name is the member name (the node name). It must be unique in the cluster.
	Name string
	// PeerIP is the address the member's peer listener binds and advertises: the
	// server's LAN address (`k3sm server --etcd-peer-ip`, never the node's
	// advertised --node-ip). Peers reach each other directly on it under the
	// etcd peer CA's mutual TLS; the wireguard mesh carries pod traffic only. It must
	// be a parseable, non-loopback IP (Validate: ErrEtcdNeedsNodeIP).
	PeerIP string
	// PeerPort is the peer listener port. Defaults to DefaultEtcdPeerPort.
	PeerPort int
	// MetricsPort is the loopback-only plain-HTTP metrics listener. Defaults to
	// DefaultEtcdMetricsPort.
	MetricsPort int
	// InitialCluster is the `name=https://ip:port,...` set a JOINING member starts
	// with on its first boot, as the existing server's member route returned it
	// (every current member plus this one). Unused for EtcdInit and on a restart.
	InitialCluster string
	// Reset starts the member with --force-new-cluster. Only ClusterReset sets it.
	Reset bool
	// Promote, for an EtcdJoin member, asks an existing server to promote this
	// learner to a voting member (a learner cannot serve that RPC itself). On every
	// boot of a joining member, first or restart, the executor asks its own member
	// whether it is still a learner once the client port accepts; if it is, Promote is
	// retried every etcdPromoteInterval with no expiry until it returns nil (a failure
	// is logged and is never a crash). A learner with a nil Promote cannot leave that
	// state on its own: bring-up logs the remedy at ERROR and keeps waiting.
	Promote func(ctx context.Context) error
}

// Pinned defaults — the versions VALIDATED by the bring-up spike.
const (
	// DefaultKubeVersion is the kwok-ci/k8s darwin-arm64 control-plane release.
	DefaultKubeVersion = "v1.36.5"
	// DefaultKineVersion is THE kine module version for the single-node SQLite
	// posture, built CGO_ENABLED=0 against kine's pure-Go modernc.org/sqlite backend
	// (kineBuildVariant).
	//
	// It replaces the former v1.14.2 SQLite pin, which had no corresponding upstream
	// tag — it resolves only from a warmed module proxy, so a cold GOPROXY=direct build
	// of the datastore could not be reproduced at all — and which predated the kine#577
	// watch-progress-notify fix. v0.17.x is what k3s itself pins (v0.17.1 since the bump
	// off v0.17.0: bugfixes and dependency patches only, no schema or encoding change);
	// it defaults --watch-progress-notify-interval to 5s and --emulated-etcd-version to
	// 3.6.11, so the apiserver's watch cache stays fresh, and its no-cgo build is a
	// real, supported variant (pkg/drivers/sqlite/sqlite_nocgo.go, //go:build !cgo)
	// rather than the SQLite-disabled stub the spike measured on the old pin.
	//
	// Moving an EXISTING single-node state.db onto this pin is a one-way datastore
	// migration; snapshotBeforeKineUpgrade takes the verified pre-migration backup
	// (and preserves the old kine binary) before the new pin ever opens the db.
	DefaultKineVersion = "v0.17.1"
	// DefaultEtcdVersion is the etcd server module version (go.etcd.io/etcd/server/v3)
	// the executor builds CGO_ENABLED=0 from the embedded wrapper module
	// (pkg/executor/etcdchild). It must equal the wrapper's go.mod.txt require; a bump
	// is `hack/etcd-wrapper.sh regen <version>` plus this line, in one commit. 3.6 is
	// the line the pinned kube-apiserver and k3sm's own etcd client are on.
	DefaultEtcdVersion = "v3.6.15"
	// DefaultAPIServerPort avoids Docker Desktop's :6443.
	DefaultAPIServerPort = 6444
	// DefaultKinePort is the kine etcd-shim listen port. In the etcd posture the etcd
	// member's loopback client listener reuses it (KinePort): kine and etcd never run
	// in the same posture, and the port is already per-server and preflight-guarded.
	DefaultKinePort = 2379
	// DefaultEtcdPeerPort is the etcd member's peer listener port (upstream's).
	DefaultEtcdPeerPort = 2380
	// DefaultEtcdMetricsPort is the etcd member's loopback metrics listener port (the
	// value k3s uses).
	DefaultEtcdMetricsPort = 2381
	// DefaultSchedulerPort is the kube-scheduler secure-serving port (the
	// upstream default), bound on loopback only.
	DefaultSchedulerPort = 10259
	// DefaultControllerManagerPort is the kube-controller-manager secure-serving
	// port (the upstream default), bound on loopback only.
	DefaultControllerManagerPort = 10257
	// DefaultRegistryPort is the loopback port `k3sm server --registry-port`
	// serves the node-local OCI ingest registry on (pkg/registrysvc).
	//
	// It is DISABLED by default — the flag's own default is 0 — so this constant
	// is the port an operator gets when they ask for the registry without naming
	// one, not a port k3sm binds unasked.
	//
	// 6450 was picked by elimination rather than convention. The obvious choices
	// are taken: 5000 and 7000 are macOS AirPlay Receiver (a bind there succeeds
	// and then answers HTTP that is not a registry, which is worse than a
	// refusal), and this process already owns 6444 (apiserver), 2379 (kine),
	// 10250 (kubelet API), 10257/10259 (controller-manager/scheduler) and the
	// whole 30000-32767 NodePort range (pkg/ports). 6450 sits clear of all of
	// them, adjacent to the apiserver's port so an operator reading `lsof` sees
	// k3sm's listeners together.
	DefaultRegistryPort = 6450
	// DefaultAuthorizationMode is the apiserver authorizer chain:
	// the Node authorizer (scopes a kubelet/VK-node to its own objects) plus RBAC
	// (default-deny). It replaced the earlier AlwaysAllow posture.
	DefaultAuthorizationMode = "Node,RBAC"
	// DefaultWorkDir is the control-plane state root for the ROOT posture
	// (explicit run-as-root mode). It is root-owned; the unprivileged _k3sm
	// control plane cannot write here and uses ResolveWorkDir instead.
	DefaultWorkDir = "/var/lib/k3sm/server"
	// workDirLeaf is the control-plane state-root directory name appended under
	// the service user's home for the unprivileged posture (so the _k3sm home
	// /var/lib/k3sm yields /var/lib/k3sm/server, mirroring DefaultWorkDir).
	workDirLeaf = "server"
)

// ErrNoServiceUserHome is returned by ResolveWorkDir when the process is
// unprivileged (euid != 0) but no home directory is set, so there is no
// _k3sm-owned location for the control-plane state root and DefaultWorkDir
// (root-owned) would EACCES.
var ErrNoServiceUserHome = errors.New("executor: unprivileged posture has no home dir for the control-plane work-dir")

// ResolveWorkDir computes the control-plane work-dir for the CURRENT process
// posture, decoupled from the DefaultWorkDir const. As root (the explicit
// run-as-root mode) it returns DefaultWorkDir (root-owned /var/lib/k3sm/server).
// Unprivileged (the _k3sm control plane, euid != 0) DefaultWorkDir is not
// writable, so it returns <home>/server under the service user's home. It is a
// pure path choice (no I/O); EnsureWorkDirWritable performs the fail-fast
// writability check once the final work-dir (default or --work-dir override) is
// known.
func ResolveWorkDir() (string, error) {
	home, _ := os.UserHomeDir()
	return resolveWorkDir(os.Geteuid(), home)
}

// resolveWorkDir is the testable core of ResolveWorkDir: euid 0 → DefaultWorkDir;
// euid != 0 → <home>/server, or ErrNoServiceUserHome when home is empty.
func resolveWorkDir(euid int, home string) (string, error) {
	if euid == 0 {
		return DefaultWorkDir, nil
	}
	if home == "" {
		return "", ErrNoServiceUserHome
	}
	return filepath.Join(home, workDirLeaf), nil
}

// RuntimeRoot returns the runtimed on-disk root (image cache + pod dirs + PV
// storage) for a given control-plane work-dir: the work-dir's PARENT, so the
// root posture's /var/lib/k3sm/server yields /var/lib/k3sm and the unprivileged
// <home>/server yields <home>. Threaded into the runtime config (RuntimedConfig
// .Root) so runtimed's SBPL Posture.WorkDir resides under the daemon home and
// its pods-root containment check (sandbox.Posture.Home) is active.
func RuntimeRoot(workDir string) string {
	return filepath.Dir(filepath.Clean(workDir))
}

// EnsureWorkDirWritable fails fast if dir cannot be created or written: it
// MkdirAll's dir (idempotent) and probes with a temp file it immediately
// removes. Called on the FINAL work-dir (ResolveWorkDir's result or a
// --work-dir override) so the unprivileged control plane reports a clear error
// up front instead of EACCES-ing mid-bring-up against the root-owned default.
func EnsureWorkDirWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create work-dir %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".k3sm-writable-probe")
	if err := os.WriteFile(probe, []byte("k3sm"), 0o600); err != nil {
		return fmt.Errorf("work-dir %s is not writable: %w", dir, err)
	}
	_ = os.Remove(probe)
	return nil
}

// ErrRootCAWithoutServingCert is returned by Validate when a RootCAFile is supplied
// without the serving keypair it is supposed to anchor. The two are one posture, not
// two knobs: on the single-node path the apiserver self-signs into its own --cert-dir,
// so a cluster CA published as kube-root-ca.crt would anchor NOTHING the apiserver
// presents and every Pod's in-cluster API TLS would fail. rootCAFile mode-locks the
// rendering so this can never reach argv; this makes the misconfiguration LOUD instead
// of silently ignored.
var ErrRootCAWithoutServingCert = errors.New("executor: RootCAFile is set without ServingCertFile/ServingKeyFile; the published kube-root-ca.crt must anchor the apiserver serving cert, and single-node the apiserver self-signs into its own --cert-dir")

// Validate checks cfg is internally consistent before bring-up. It is called at the
// top of Start so a misconfigured server fails fast with a clear error. The checks are
// the trust-anchor guard (see ErrRootCAWithoutServingCert), the single-server-only
// encryption guard (ErrEncryptionHA) and the etcd posture's own shape (ErrEtcdRole,
// ErrEtcdNeedsNodeIP). There is no split-brain guard to check: an HA role exists only
// inside Etcd, so "join without a shared datastore" has no Config value.
func (c Config) Validate() error {
	if c.RootCAFile != "" && !c.meshServingCert() {
		return ErrRootCAWithoutServingCert
	}
	if c.EncryptionProviderConfig != "" && c.isHA() {
		return ErrEncryptionHA
	}
	if c.Etcd != nil {
		if err := c.Etcd.validate(); err != nil {
			return err
		}
	}
	return nil
}

// ErrEtcdNeedsNodeIP is returned by Validate when the etcd posture has no usable peer
// address: an empty, unparseable or loopback PeerIP. The member advertises that
// address to every other member, so the single-node default 127.0.0.1 would make
// each server dial itself.
var ErrEtcdNeedsNodeIP = errors.New("executor: the etcd HA posture needs --etcd-peer-ip set to this server's LAN address (empty, unparseable or loopback addresses cannot be an etcd peer address)")

// ErrEtcdRole is returned by Validate for an EtcdConfig whose Role is neither EtcdInit
// nor EtcdJoin, or that has no member name.
var ErrEtcdRole = errors.New("executor: the etcd HA posture needs a role (init or join) and a member name")

// validate checks the etcd posture's own fields.
func (e *EtcdConfig) validate() error {
	if (e.Role != EtcdInit && e.Role != EtcdJoin) || e.Name == "" {
		return ErrEtcdRole
	}
	ip := net.ParseIP(e.PeerIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return fmt.Errorf("%w: got %q", ErrEtcdNeedsNodeIP, e.PeerIP)
	}
	return nil
}

// EtcdDataDir is the etcd member's data directory, <workDir>/etcd (mode 0700). It
// follows the work dir, so it moves with --data-volume.
func EtcdDataDir(workDir string) string { return filepath.Join(workDir, "etcd") }

// etcdMemberDir is <workDir>/etcd/member, which etcd creates on a member's first
// start and which marks every later start as a restart.
func etcdMemberDir(workDir string) string { return filepath.Join(EtcdDataDir(workDir), "member") }

// EtcdMemberExists reports whether workDir holds an initialized etcd member
// (<workDir>/etcd/member is a directory). It is the restart predicate: a member that
// exists starts from its own data dir and is never re-added (a joiner that is still
// a learner is promoted on restart; see EtcdConfig.Promote).
func EtcdMemberExists(workDir string) bool {
	fi, err := os.Stat(etcdMemberDir(workDir))
	return err == nil && fi.IsDir()
}

// meshServingCert reports whether an explicit apiserver serving keypair was supplied
// — the mesh path, where cmd/k3sm issues a CLUSTER-CA-signed leaf into the PKI dir and
// the apiserver presents it instead of self-signing into --cert-dir.
//
// It is THE posture predicate for every flag whose correct value depends on WHICH CA
// anchors the live apiserver serving cert, and it is single-sourced for exactly that
// reason: --tls-cert-file (the cert presented) and --root-ca-file (the CA republished
// to every Pod as kube-root-ca.crt) must never be able to disagree about the posture.
// The same discrimination is made, from the outside, by cmd/k3sm's
// apiServerTrustAnchor.
func (c Config) meshServingCert() bool {
	return c.ServingCertFile != "" && c.ServingKeyFile != ""
}

// rootCAFile resolves the kube-controller-manager --root-ca-file: the CA its
// root-ca-cert-publisher republishes into every namespace's kube-root-ca.crt
// ConfigMap, which is every Pod's trust anchor for the in-cluster API.
//
// It is DERIVED from meshServingCert, never read raw, so the answer is always the CA
// that anchors the serving cert the apiserver actually presents:
//
//   - mesh (a serving keypair was supplied): the configured RootCAFile, defaulting to
//     the cluster CA under the work-dir PKI dir — the CA that issued that leaf. The
//     self-signed --cert-dir file is not merely the wrong anchor here, it does not
//     exist: an apiserver given --tls-cert-file never self-signs, so pinning it fails
//     the controller-manager's own startup ("error parsing root-ca-file ... no such
//     file or directory") on a fresh mesh work dir, and publishes a stale, unrelated
//     CA on a work dir that had previously booted single-node.
//   - single-node: the apiserver's self-signed --cert-dir cert (leaf + the self-signed
//     CA that issued it), which is the ONLY anchor for what it serves. An explicit
//     RootCAFile is deliberately not honored here — Validate rejects that Config
//     outright, and the renderer stays total so a hand-built Config in a test can
//     never render a flag pair from two different postures.
func (c Config) rootCAFile() string {
	if !c.meshServingCert() {
		return filepath.Join(certDir(c.WorkDir), "apiserver.crt")
	}
	if c.RootCAFile != "" {
		return c.RootCAFile
	}
	return certs.ClusterCACertPath(c.WorkDir)
}

// isHA reports whether this server runs the HA posture: an embedded etcd member.
func (c Config) isHA() bool {
	return c.Etcd != nil
}

// CARole is the CA mint role of this server, read off the one HA role field.
func (c Config) CARole() certs.Role {
	return certs.RoleMintAuthority
}

// schedulerPort resolves the kube-scheduler secure-serving port: the configured
// value, or the upstream default when unset. Resolving through an accessor (like
// leaderElect) keeps the pure argv renderers TOTAL — a Config built by hand in a
// test renders a real port rather than `--secure-port 0`, which upstream reads as
// "pick any free port" and would make the listener unfindable.
func (c Config) schedulerPort() int {
	if c.SchedulerPort == 0 {
		return DefaultSchedulerPort
	}
	return c.SchedulerPort
}

// controllerManagerPort resolves the kube-controller-manager secure-serving port,
// same contract as schedulerPort.
func (c Config) controllerManagerPort() int {
	if c.ControllerManagerPort == 0 {
		return DefaultControllerManagerPort
	}
	return c.ControllerManagerPort
}

// leaderElect reports the scheduler + controller-manager --leader-elect setting for
// this posture (see Config.LeaderElect): an explicit pointer wins, else it derives
// from isHA — ON in HA, OFF single-node.
func (c Config) leaderElect() bool {
	if c.LeaderElect != nil {
		return *c.LeaderElect
	}
	return c.isHA()
}

// withDefaults returns a copy of cfg with empty fields filled from the pinned
// defaults.
func (c Config) withDefaults() Config {
	if c.WorkDir == "" {
		c.WorkDir = DefaultWorkDir
	}
	if c.APIServerPort == 0 {
		c.APIServerPort = DefaultAPIServerPort
	}
	if c.KinePort == 0 {
		c.KinePort = DefaultKinePort
	}
	c.SchedulerPort = c.schedulerPort()
	c.ControllerManagerPort = c.controllerManagerPort()
	if c.KubeVersion == "" {
		c.KubeVersion = DefaultKubeVersion
	}
	if c.KineVersion == "" {
		// ONE kine pin (see DefaultKineVersion). The etcd posture never runs
		// kine; it carries the field only because the default is posture-blind.
		c.KineVersion = DefaultKineVersion
	}
	if c.NodeIP == "" {
		c.NodeIP = "127.0.0.1"
	}
	if c.AuthorizationMode == "" {
		c.AuthorizationMode = DefaultAuthorizationMode
	}
	if c.AnonymousAuth == nil {
		// Close the anonymous surface by default (defense-in-depth on top of the
		// Node,RBAC default-deny): an unauthenticated caller is rejected outright
		// rather than reaching the authorizer as system:anonymous. Explicit settings
		// (the multi-node path) are preserved.
		anonOff := false
		c.AnonymousAuth = &anonOff
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Etcd != nil {
		// A copy, so filling the ports never writes through the caller's pointer.
		e := *c.Etcd
		if e.PeerPort == 0 {
			e.PeerPort = DefaultEtcdPeerPort
		}
		if e.MetricsPort == 0 {
			e.MetricsPort = DefaultEtcdMetricsPort
		}
		c.Etcd = &e
	}
	return c
}
