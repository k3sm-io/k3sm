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
	// port — the backing for the Service-CIDR-VIP branch of the privileged-port
	// authorizer. nil denies every <1024 VIP bind (fail safe).
	Declares func(port int) bool
	// DeclaresLB reports whether a Service of type LoadBalancer in the
	// authoritative set declares port — the backing for the node-own-address
	// branch of the privileged-port authorizer (the M10.3 ingress/svclb
	// listener). nil denies every <1024 node-address bind (fail safe).
	DeclaresLB func(port int) bool
	// NodeIP is this node's own InternalIP — the ONLY address outside the
	// Service CIDR a privileged bind can ever be authorized on, and only when a
	// LoadBalancer Service declares the port. The zero Addr disables the
	// node-address branch entirely (deny).
	//
	// DORMANT BY CONFIGURATION, NOT BY CONSTRUCTION (B133). Since B116 the
	// ingress/svclb listeners bind the WILDCARD in-process (unprivileged on
	// Darwin at any port), so nothing asks netd for a node-address bind, and the
	// installed plist renders NO --node-ip — leaving this zero and the branch
	// denying. The branch is deliberately KEPT: it is the authorization design
	// for any future privileged specific-address bind, and B133 owns the decision
	// to either wire it back or retire it. pkg/install::TestNetdPlistXML pins the
	// absence of --node-ip, so re-adding the flag reddens rather than silently
	// re-arming the branch.
	NodeIP netip.Addr
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
		NodePodCIDR: opts.NodePodCIDR,
		ServiceCIDR: opts.ServiceCIDR,
		ServiceUID:  opts.ServiceUID,
		PortAuthorizer: PortAuthorizer(PortPolicy{
			ServiceCIDR: opts.ServiceCIDR,
			Declares:    opts.Declares,
			NodeIP:      opts.NodeIP,
			DeclaresLB:  opts.DeclaresLB,
		}),
		Logger: opts.Logger,
	}
	if opts.MeshKeyDir != "" {
		cfg.MeshKeyResolver = MeshKeyResolver(opts.MeshKeyDir)
	}
	return cfg, nil
}

// PortPolicy is the DENY-BY-DEFAULT privileged-port (<1024) bind policy the
// authorizer applies. A bind is authorized iff the requested address falls in
// exactly one of two explicitly named classes (M10.3 — an explicit policy
// decision, never allowed-by-coincidence):
//
//   - a Service-CIDR VIP whose port some Service in the authoritative set
//     declares (the proxy's infra VIPs, e.g. 10.43.0.10:53), or
//   - this node's OWN InternalIP when a Service of type LoadBalancer declares
//     the port (the ingress/svclb listener; kube-system/k3sm-ingress is the
//     canonical declaring subject for 80/443).
//
// Every other address class, an undeclared port, and a nil predicate are all
// denied — the daemon never trusts the client's self-assertion.
type PortPolicy struct {
	// ServiceCIDR classifies the VIP address class. Invalid disables it (deny).
	ServiceCIDR netip.Prefix
	// Declares reports whether some Service declares port. nil denies VIP binds.
	Declares func(port int) bool
	// NodeIP is this node's own InternalIP. Invalid disables the node-address
	// class (deny).
	NodeIP netip.Addr
	// DeclaresLB reports whether a Service of type LoadBalancer declares port.
	// nil denies node-address binds.
	DeclaresLB func(port int) bool
}

// servicePortAuthorizer confirms a privileged (<1024) bind against the
// authoritative Service set per PortPolicy.
type servicePortAuthorizer struct {
	policy PortPolicy
}

// PortAuthorizer returns the netd.PortAuthorizer enforcing policy. The zero
// PortPolicy denies every bind it is asked about (fail safe).
func PortAuthorizer(policy PortPolicy) netd.PortAuthorizer {
	return servicePortAuthorizer{policy: policy}
}

// Authorize rejects binding port on nodeAddr unless one of PortPolicy's two
// address classes admits it. See PortPolicy for the deny-by-default contract.
func (a servicePortAuthorizer) Authorize(_ context.Context, port int, nodeAddr string) error {
	addr, err := netip.ParseAddr(nodeAddr)
	if err != nil {
		return fmt.Errorf("parse bind address %q for port %d: %w", nodeAddr, port, err)
	}
	addr = addr.Unmap()
	switch {
	case a.policy.ServiceCIDR.IsValid() && a.policy.ServiceCIDR.Contains(addr):
		if a.policy.Declares == nil {
			return fmt.Errorf("no service set available to authorize port %d on %s", port, nodeAddr)
		}
		if !a.policy.Declares(port) {
			return fmt.Errorf("no service declares port %d (requested on %s)", port, nodeAddr)
		}
		return nil
	case a.policy.NodeIP.IsValid() && addr == a.policy.NodeIP:
		if a.policy.DeclaresLB == nil {
			return fmt.Errorf("no service set available to authorize port %d on node address %s", port, nodeAddr)
		}
		if !a.policy.DeclaresLB(port) {
			return fmt.Errorf("no LoadBalancer service declares port %d (requested on node address %s)", port, nodeAddr)
		}
		return nil
	}
	return fmt.Errorf("bind address %s is neither a service-CIDR VIP nor this node's own address (port %d denied)", nodeAddr, port)
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
