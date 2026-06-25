package executor

import "context"

// Embedded is the (future) from-source in-process control-plane executor — the
// k3s pkg/executor/embed pattern: apiserver + scheduler + controller-manager +
// kine as goroutines in THIS process, no child binaries. It is a stub: Wave-0
// confirmed importing the k3s-io/kubernetes command trees into this module is
// infeasible today, so every method returns ErrEmbeddedNotImplemented. The seam
// exists so the strategy can land in a later milestone without disturbing
// callers (which select via the Strategy flag).
type Embedded struct {
	cfg Config
}

// NewEmbedded returns the not-yet-implemented in-process executor stub.
func NewEmbedded(cfg Config) *Embedded {
	return &Embedded{cfg: cfg.withDefaults()}
}

// Compile-time check that the stub satisfies the Executor contract.
var _ Executor = (*Embedded)(nil)

// Start always returns ErrEmbeddedNotImplemented.
func (e *Embedded) Start(ctx context.Context) error { return ErrEmbeddedNotImplemented }

// Ready always returns false (the embedded plane never starts).
func (e *Embedded) Ready(ctx context.Context) bool { return false }

// Stop is a no-op (nothing was started).
func (e *Embedded) Stop(ctx context.Context) error { return nil }

// Kubeconfig returns the configured kubeconfig path (unused until implemented).
func (e *Embedded) Kubeconfig() string { return kubeconfigPath(e.cfg.WorkDir) }

// RESTConfigToken returns the apiserver URL and static token (unused until
// implemented).
func (e *Embedded) RESTConfigToken() (string, string) {
	return apiServerURL(e.cfg.APIServerPort), e.cfg.Token
}
