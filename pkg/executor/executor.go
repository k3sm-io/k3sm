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
	"os"
	"path/filepath"
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
	// single-node dev path), so M1/M2 are unchanged.
	BindAddress string
	// ClientCAFile is the apiserver --client-ca-file: the client-CA the apiserver trusts
	// so client certs authenticate (node certs CN=system:node:<name> and the per-component
	// certs CN=system:kube-scheduler / system:kube-controller-manager, all signed by the
	// signing CA). It is now wired UNCONDITIONALLY — when empty, apiServerArgs defaults it
	// to the signing CA under the work-dir PKI dir (certs.SigningCACertPath), so the
	// single-node path gets it too (the M4.1 review flagged the prior mesh-gating). An
	// explicit value (the mesh path) is honored verbatim. Originally wired in M3 (while the
	// authorizer was still AlwaysAllow) so M4.1's Node,RBAC flip is a pure authorizer switch.
	ClientCAFile string
	// KubeletCAFile, when set, is passed as --kubelet-certificate-authority so the
	// apiserver verifies the kubelet-serving cert and remote exec/logs are not
	// MITM-able.
	KubeletCAFile string
	// AnonymousAuth, when non-nil, sets --anonymous-auth explicitly. withDefaults
	// fills a nil pointer with FALSE: under Node,RBAC (M4.1) anonymous requests map to
	// system:anonymous and RBAC default-denies them, but closing the surface outright
	// is defense-in-depth — it keeps an unauthenticated caller from probing the
	// apiserver at all (and pre-M4.1, under AlwaysAllow, it was the only thing stopping
	// anonymous cluster-admin). The static bearer token (scheduler/CM/kubectl/healthz
	// all carry it) is unaffected; only credential-less requests are rejected. The pure
	// apiServerArgs still omits the flag for a nil pointer, so the M3 multi-node path
	// (explicit false) and the arg-rendering tests are unchanged.
	AnonymousAuth *bool
	// ServingCertFile / ServingKeyFile, when both set, are passed as
	// --tls-cert-file / --tls-private-key-file so the apiserver presents a cluster-CA
	// -signed serving cert (instead of self-signing into --cert-dir). A joining node
	// that pinned the cluster CA then verifies the apiserver via its kubeconfig
	// certificate-authority-data. Empty keeps the M1/M2 self-signed path.
	ServingCertFile string
	ServingKeyFile  string
	// AuthorizationMode is the apiserver --authorization-mode. Empty defaults to
	// DefaultAuthorizationMode (Node,RBAC) — the M4.1 hard-cut flip from AlwaysAllow.
	// The flip is pure because no in-process component is left unauthorized: the VK node
	// + provisioners carry the static admin token (mapped to system:masters, which
	// bypasses RBAC), the scheduler/KCM carry their own client-cert identities the
	// apiserver's bootstrap RBAC already binds, and joined workers' system:node
	// identities get a pre-provisioned datapath grant (pkg/rbac); set it
	// to "AlwaysAllow" only for a deliberate diagnostic bring-up.
	AuthorizationMode string
	// DatastoreEndpoint, when non-empty, is the kine datastore endpoint — a Postgres
	// connection URL (postgres://user[:password]@host:port/dbname?sslmode=...) for the
	// HA multi-writer posture (M6.0): 2+ control-plane servers share ONE Postgres, the
	// single source of truth (no etcd quorum). Empty keeps the single-node kine->SQLite
	// WAL default (M1–M5), byte-unchanged. The apiserver always talks to the LOCAL kine
	// (--etcd-servers 127.0.0.1:<KinePort>); each server runs its own kine against the
	// shared Postgres (the k3s topology). The DSN PASSWORD is kept off argv and out of
	// the logs — it is relocated to a 0600 PGPASSFILE handed to the kine child, and only
	// the password-stripped DSN reaches kine's --endpoint. Setting this also moves kine
	// on the shared Postgres (see KineVersion — one pin serves both postures) and
	// turns on leader election.
	DatastoreEndpoint string
	// ServerJoin marks this control-plane server as joining/forming an HA control plane
	// (a 2nd+ apiserver). It is the split-brain guard's trigger: an HA server MUST carry
	// a DatastoreEndpoint — Validate fails closed otherwise, so a 2nd server can NEVER
	// silently fall back to its own SQLite (two servers each on their own SQLite is
	// split-brain — divergent state, no single source of truth). The full HA server-join
	// bootstrap (the identical-CA bundle, DESIGN §5c) is M6.1; M6.0 consumes this only
	// for the guard + the leader-election posture.
	ServerJoin bool
	// PSAEnforceBaseline, when true, flips the cluster-wide Pod Security Admission
	// default ENFORCE level from privileged to baseline in the provisioned
	// PodSecurityConfiguration (see admissionConfigYAML — the SINGLE authority for
	// the PSA level tuple). The SHIPPED default is false — baseline-WARN only
	// (warn=baseline + audit=restricted, zero rejection).
	// This field is the documented, reversible B71 cutover MECHANISM: flip it (via
	// `k3sm server --psa-enforce-baseline`) only after a pre-flight scan proves the
	// cluster clean; reverting the flag reverts the posture on the next boot. PSA
	// here is conformance-surface + defense-in-depth, NOT the privilege boundary
	// (the foreign-uid VAP + Seatbelt stay that).
	PSAEnforceBaseline bool
	// LeaderElect, when non-nil, forces the scheduler + controller-manager --leader-elect
	// setting. A nil pointer DERIVES it from the datastore posture: ON in HA (a Postgres
	// multi-writer datastore — so only one server's scheduler/KCM is active; two active
	// schedulers double-bind pods, two KCMs double-reconcile) and OFF single-node (one
	// candidate, no lease churn — the M1–M5 default). Only the apiserver is active/active
	// in HA. The leader-election Leases are authorized by the apiserver's auto-created
	// system:kube-scheduler / system:kube-controller-manager bootstrap RBAC, which binds
	// the components' OWN per-component identities — no pkg/rbac object is needed.
	LeaderElect *bool
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// Pinned defaults — the versions VALIDATED by the M0 spike (docs/M0-spike.md).
const (
	// DefaultKubeVersion is the kwok-ci/k8s darwin-arm64 control-plane release.
	DefaultKubeVersion = "v1.36.2"
	// DefaultKineVersion is THE kine module version — one pin for BOTH datastore
	// postures (single-node SQLite and Postgres-HA), built CGO_ENABLED=0 against
	// kine's pure-Go modernc.org/sqlite backend (kineBuildVariant).
	//
	// It replaces the former two-pin split (v1.14.2 SQLite / v0.16.3 Postgres-HA).
	// The old SQLite pin had no corresponding upstream tag — it resolves only from a
	// warmed module proxy, so a cold GOPROXY=direct build of the datastore could not
	// be reproduced at all — and it predated the kine#577 watch-progress-notify fix.
	// v0.17.0 is what k3s itself pins; it defaults --watch-progress-notify-interval
	// to 5s and --emulated-etcd-version to 3.6.11, so the apiserver's watch cache
	// stays fresh on both postures, and its no-cgo build is a real, supported variant
	// (pkg/drivers/sqlite/sqlite_nocgo.go, //go:build !cgo) rather than the
	// SQLite-disabled stub the M0 spike measured on the old pin.
	//
	// Moving an EXISTING single-node state.db onto this pin is a one-way datastore
	// migration; snapshotBeforeKineUpgrade takes the verified pre-migration backup
	// (and preserves the old kine binary) before the new pin ever opens the db.
	DefaultKineVersion = "v0.17.0"
	// DefaultAPIServerPort avoids Docker Desktop's :6443.
	DefaultAPIServerPort = 6444
	// DefaultKinePort is the kine etcd-shim listen port.
	DefaultKinePort = 2379
	// DefaultAuthorizationMode is the apiserver authorizer chain from M4.1 onward:
	// the Node authorizer (scopes a kubelet/VK-node to its own objects) plus RBAC
	// (default-deny). It replaces the M0–M3 AlwaysAllow posture.
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

// ErrHARequiresDatastore is returned by Validate when an HA control-plane server
// (ServerJoin) is requested without a shared datastore endpoint. A 2nd server must
// NEVER fall back to its own SQLite — two servers each on their own single-writer
// SQLite is split-brain (divergent state, no single source of truth). The guard is
// fail-closed: bring-up halts rather than silently diverging.
var ErrHARequiresDatastore = errors.New("executor: HA server-join requires a shared datastore endpoint (a Postgres DSN); refusing to start a second server on its own SQLite (split-brain)")

// Validate checks cfg is internally consistent before bring-up. The load-bearing
// check is the split-brain guard: an HA server (ServerJoin) MUST carry a
// DatastoreEndpoint. It is called at the top of Start so a misconfigured HA server
// fails fast with a clear error instead of quietly forming a divergent cluster.
func (c Config) Validate() error {
	if c.ServerJoin && c.DatastoreEndpoint == "" {
		return ErrHARequiresDatastore
	}
	return nil
}

// isHA reports whether this server runs the HA multi-writer posture: it has a shared
// datastore endpoint, or it was told to join/form an HA control plane.
func (c Config) isHA() bool {
	return c.DatastoreEndpoint != "" || c.ServerJoin
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
	if c.KubeVersion == "" {
		c.KubeVersion = DefaultKubeVersion
	}
	if c.KineVersion == "" {
		// ONE pin for both datastore postures (see DefaultKineVersion) — the
		// SQLite/Postgres split is a driver choice inside a single kine build,
		// never a second version.
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
		// (the M3 multi-node path) are preserved.
		anonOff := false
		c.AnonymousAuth = &anonOff
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}
