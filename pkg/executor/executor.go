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
	// Token is the static bearer token written to the token file + kubeconfig.
	// Defaults to a generated token when empty.
	Token string
	// NodeIP is the node InternalIP; the apiserver advertises it and the kubelet
	// preferred-address-types is set to InternalIP so logs/exec reach the node.
	NodeIP string
	// BindAddress is the address the apiserver binds. For a MULTI-NODE cluster it is
	// the node's wireguard mesh IP so a joining node can reach the apiserver and the
	// AlwaysAllow+token surface is NOT exposed on 0.0.0.0 or the LAN (docs/m3-plan.md
	// — bind the mesh interface ONLY). Empty falls back to NodeIP (loopback for the
	// single-node dev path), so M1/M2 are unchanged.
	BindAddress string
	// ClientCAFile, when set, is passed as --client-ca-file so node client certs
	// (CN=system:node:<name>, signed by the signing CA) authenticate. Wired in M3
	// even though the authorizer stays AlwaysAllow, so M4's Node,RBAC flip is a pure
	// authorizer switch — not a node re-bootstrap.
	ClientCAFile string
	// KubeletCAFile, when set, is passed as --kubelet-certificate-authority so the
	// apiserver verifies the kubelet-serving cert and remote exec/logs are not
	// MITM-able.
	KubeletCAFile string
	// AnonymousAuth, when non-nil, sets --anonymous-auth explicitly. withDefaults
	// fills a nil pointer with FALSE: the user-space control plane runs as the
	// unprivileged _k3sm user behind an AlwaysAllow authorizer, so an open
	// anonymous surface would hand cluster-admin to any local process that can
	// reach the apiserver port. The static bearer token (scheduler/CM/kubectl/
	// healthz all carry it) is unaffected; only credential-less requests are
	// rejected. The pure apiServerArgs still omits the flag for a nil pointer, so
	// the M3 multi-node path (explicit false) and the arg-rendering tests are
	// unchanged.
	AnonymousAuth *bool
	// ServingCertFile / ServingKeyFile, when both set, are passed as
	// --tls-cert-file / --tls-private-key-file so the apiserver presents a cluster-CA
	// -signed serving cert (instead of self-signing into --cert-dir). A joining node
	// that pinned the cluster CA then verifies the apiserver via its kubeconfig
	// certificate-authority-data. Empty keeps the M1/M2 self-signed path.
	ServingCertFile string
	ServingKeyFile  string
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// Pinned defaults — the versions VALIDATED by the M0 spike (docs/M0-spike.md).
const (
	// DefaultKubeVersion is the kwok-ci/k8s darwin-arm64 control-plane release.
	DefaultKubeVersion = "v1.36.2"
	// DefaultKineVersion is the kine module version (built CGO_ENABLED=1).
	DefaultKineVersion = "v1.14.2"
	// DefaultAPIServerPort avoids Docker Desktop's :6443.
	DefaultAPIServerPort = 6444
	// DefaultKinePort is the kine etcd-shim listen port.
	DefaultKinePort = 2379
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
		c.KineVersion = DefaultKineVersion
	}
	if c.NodeIP == "" {
		c.NodeIP = "127.0.0.1"
	}
	if c.AnonymousAuth == nil {
		// The user-space posture: close the anonymous surface by default so the
		// AlwaysAllow authorizer cannot grant cluster-admin to a credential-less
		// caller. Explicit settings (the M3 multi-node path) are preserved.
		anonOff := false
		c.AnonymousAuth = &anonOff
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}
