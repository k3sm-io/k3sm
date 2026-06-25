package executor

import (
	"context"
	"errors"
	"log/slog"
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
	// DefaultWorkDir is the control-plane state root.
	DefaultWorkDir = "/var/lib/k3sm/server"
)

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
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	return c
}
