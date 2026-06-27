// Package netdsvc assembles the root-side k3sm-netd daemon configuration for the
// `k3sm netd` subcommand: it turns the cluster's network policy inputs (this
// node's pod /24, the cluster Service CIDR, the _k3sm service uid) and two
// fail-closed seams — a PortAuthorizer that confirms a privileged (<1024) bind
// against the authoritative Service set, and a MeshKeyResolver that reads the
// node's wireguard private key from a root-only path — into a darwin-net
// netd.Config. The pure policy and the seams are testable without root or a real
// apiserver.
package netdsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"k3sm.io/darwin-net/pkg/netd"
)

// Options are the policy inputs and seam wiring for BuildConfig.
type Options struct {
	// NodePodCIDR is this node's pod /24 (a pod-IP alias must fall within it). It
	// is required; an invalid prefix is a build error.
	NodePodCIDR netip.Prefix
	// ServiceCIDR is the cluster Service CIDR (the proxy's ClusterIP VIPs live
	// here, OUTSIDE the pod aggregate). It is REQUIRED: without it the daemon
	// denies every Service-VIP lo0 alias and the Service proxy cannot bind any
	// ClusterIP, so BuildConfig errors rather than silently shipping a daemon
	// that rejects the proxy.
	ServiceCIDR netip.Prefix
	// ServiceUID is the unprivileged _k3sm uid the daemon's peer verifier admits
	// (the only client allowed to drive privileged ops).
	ServiceUID uint32
	// Declares reports whether some Service in the authoritative set declares
	// port — the backing for the privileged-port authorizer. nil denies every
	// <1024 bind (fail safe).
	Declares func(port int) bool
	// MeshKeyDir is the root-only directory the MeshKeyResolver reads the node's
	// wireguard private key from. Empty disables ConfigureMesh (a nil resolver,
	// which fails fast — there is no embedded key).
	MeshKeyDir string
	// Logger is the structured logger threaded into the daemon; nil uses
	// slog.Default via netd.NewServer.
	Logger *slog.Logger
}

// BuildConfig validates opts and assembles the netd.Config: it pins the node pod
// /24 and the Service CIDR (so the proxy's VIP aliases are admitted), the service
// uid (peer auth), the PortAuthorizer (privileged-port confirmation against the
// Service set), and the MeshKeyResolver (root-only key path). The cluster
// aggregate and NodePort range keep their darwin-net defaults.
func BuildConfig(opts Options) (netd.Config, error) {
	if !opts.NodePodCIDR.IsValid() {
		return netd.Config{}, fmt.Errorf("netdsvc: node pod CIDR is required and must be valid, got %q", opts.NodePodCIDR)
	}
	if !opts.ServiceCIDR.IsValid() {
		return netd.Config{}, fmt.Errorf("netdsvc: service CIDR is required (else the proxy's ClusterIP VIP aliases are denied), got %q", opts.ServiceCIDR)
	}
	cfg := netd.Config{
		NodePodCIDR:    opts.NodePodCIDR,
		ServiceCIDR:    opts.ServiceCIDR,
		ServiceUID:     opts.ServiceUID,
		PortAuthorizer: PortAuthorizer(opts.Declares),
		Logger:         opts.Logger,
	}
	if opts.MeshKeyDir != "" {
		cfg.MeshKeyResolver = MeshKeyResolver(opts.MeshKeyDir)
	}
	return cfg, nil
}

// servicePortAuthorizer confirms a privileged (<1024) bind against the
// authoritative Service set via the declares seam. A nil declares denies every
// such bind (fail safe — the daemon never trusts the client to self-assert that
// a Service declares the port).
type servicePortAuthorizer struct {
	declares func(port int) bool
}

// PortAuthorizer returns a netd.PortAuthorizer that authorizes a privileged-port
// bind only when declares reports a Service declares that port. A nil declares
// yields an authorizer that denies every bind it is asked about.
func PortAuthorizer(declares func(port int) bool) netd.PortAuthorizer {
	return servicePortAuthorizer{declares: declares}
}

// Authorize rejects port unless a Service in the authoritative set declares it.
func (a servicePortAuthorizer) Authorize(_ context.Context, port int, nodeAddr string) error {
	if a.declares == nil {
		return fmt.Errorf("no service set available to authorize port %d on %s", port, nodeAddr)
	}
	if !a.declares(port) {
		return fmt.Errorf("no service declares port %d (requested on %s)", port, nodeAddr)
	}
	return nil
}

// fileMeshKeyResolver resolves a ConfigureMesh key reference to the node's
// wireguard private key by reading <dir>/<ref>, a root-only path. The ref is an
// opaque file name; a missing key is an error (never an embedded default), and a
// ref that escapes dir (a separator or .. component) is rejected.
type fileMeshKeyResolver struct {
	dir string
}

// MeshKeyResolver returns a netd.MeshKeyResolver reading private keys from the
// root-only directory dir.
func MeshKeyResolver(dir string) netd.MeshKeyResolver {
	return fileMeshKeyResolver{dir: dir}
}

// Resolve returns the base64 private key stored at <dir>/<ref>. It rejects a ref
// that is not a bare file name (path traversal) and returns an error for a
// missing key — there is no embedded-key fallback.
func (r fileMeshKeyResolver) Resolve(_ context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("mesh key ref is empty")
	}
	if ref != filepath.Base(ref) || strings.ContainsRune(ref, '/') || ref == ".." {
		return "", fmt.Errorf("mesh key ref %q must be a bare file name (no path traversal)", ref)
	}
	path := filepath.Join(r.dir, ref)
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read mesh key %s: %w", path, err)
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("mesh key %s is empty", path)
	}
	return key, nil
}
