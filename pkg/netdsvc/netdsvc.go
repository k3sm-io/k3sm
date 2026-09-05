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
// against the authoritative Service set (and, for a bind on the node's own
// address, against ONE named canonical Service), and a MeshKeyResolver that
// reads the node's wireguard private key from a root-only path — into a
// darwin-net netd.Config. The pure policy and the seams are testable without root or a real
// apiserver.
package netdsvc

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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
	// LBDeclarers reports WHICH Services of type LoadBalancer in the
	// authoritative set declare port, by namespace+name — the backing for the
	// node-own-address branch of the privileged-port authorizer (the
	// ingress/svclb listener). nil denies every <1024 node-address bind (fail
	// safe). It yields identities rather than a bare bool because that branch is
	// an ALLOWLIST: declaring the port is necessary but NOT sufficient.
	LBDeclarers func(port int) []ServiceRef
	// NodeAddressService is the ONE Service permitted to authorize a privileged
	// bind on this node's own address — the canonical ingress LoadBalancer. The
	// assembler binds it from ingresshost.ServiceNamespace/ServiceName (the
	// single source of that identity). The zero ServiceRef denies the
	// node-address branch entirely (fail safe).
	NodeAddressService ServiceRef
	// NodeIP is this node's own InternalIP — the ONLY address outside the
	// Service CIDR a privileged bind can ever be authorized on, and only when
	// NodeAddressService itself declares the port. The zero Addr disables the
	// node-address branch entirely (deny).
	//
	// DORMANT BY CONFIGURATION, NOT BY CONSTRUCTION. The
	// ingress/svclb listeners bind the WILDCARD in-process (unprivileged on
	// Darwin at any port), so nothing asks netd for a node-address bind, and the
	// installed plist renders NO --node-ip — leaving this zero and the branch
	// denying. The branch is deliberately KEPT rather than deleted: it is the
	// authorization design for any future privileged specific-address bind, and
	// it was narrowed to the NodeAddressService allowlist so re-arming it cannot
	// hand the node's address to whichever Service happens to declare the port.
	// pkg/install::TestNetdPlistXML pins the absence of --node-ip, so re-adding
	// the flag reddens rather than silently re-arming the branch.
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
			ServiceCIDR:        opts.ServiceCIDR,
			Declares:           opts.Declares,
			NodeIP:             opts.NodeIP,
			LBDeclarers:        opts.LBDeclarers,
			NodeAddressService: opts.NodeAddressService,
		}),
		Logger: opts.Logger,
	}
	if opts.MeshKeyDir != "" {
		cfg.MeshKeyResolver = MeshKeyResolver(opts.MeshKeyDir)
	}
	return cfg, nil
}

// ServiceRef identifies a Service by namespace and name. It is the
// authorization SUBJECT of the node-address bind class: the daemon authorizes
// that class for exactly one named Service, never for a shape ("any
// LoadBalancer"). The zero ServiceRef is invalid and names nothing.
type ServiceRef struct {
	// Namespace is the Service's namespace.
	Namespace string
	// Name is the Service's name.
	Name string
}

// IsValid reports whether the ref names a Service (both parts non-empty).
func (r ServiceRef) IsValid() bool { return r.Namespace != "" && r.Name != "" }

// String renders the ref as "namespace/name" for error and log messages.
func (r ServiceRef) String() string { return r.Namespace + "/" + r.Name }

// PortPolicy is the DENY-BY-DEFAULT privileged-port (<1024) bind policy the
// authorizer applies. A bind is authorized iff the requested address falls in
// exactly one of two explicitly named classes (an explicit policy decision,
// never allowed-by-coincidence):
//
//   - a Service-CIDR VIP whose port some Service in the authoritative set
//     declares (the proxy's infra VIPs, e.g. 10.43.0.10:53), or
//   - this node's OWN InternalIP when NodeAddressService — the ONE named
//     canonical ingress LoadBalancer, kube-system/k3sm-ingress — declares the
//     port (the ingress/svclb listener).
//
// The node-address class is an ALLOWLIST keyed on namespace+name, not a
// test on the requester's shape. It used to authorize the bind for ANY Service
// of type LoadBalancer declaring the port, in any namespace — which made the
// requesting object its own authorization predicate: any tenant able to create
// a LoadBalancer Service on :80 could authorize a root-helper bind on the
// node's real address. Declaring the port is now necessary but not sufficient.
//
// Every other address class, an undeclared port, a Service outside the
// allowlist, and a nil predicate are all denied — the daemon never trusts the
// client's self-assertion. A refusal is never silent: darwin-net's bind handler
// logs the returned error at Warn ("netd: port bind rejected"), and the
// out-of-allowlist message names the Services that did declare the port.
type PortPolicy struct {
	// ServiceCIDR classifies the VIP address class. Invalid disables it (deny).
	ServiceCIDR netip.Prefix
	// Declares reports whether some Service declares port. nil denies VIP binds.
	Declares func(port int) bool
	// NodeIP is this node's own InternalIP. Invalid disables the node-address
	// class (deny).
	NodeIP netip.Addr
	// LBDeclarers reports which Services of type LoadBalancer declare port. nil
	// denies node-address binds.
	LBDeclarers func(port int) []ServiceRef
	// NodeAddressService is the only Service whose declaration authorizes a
	// node-address bind. The zero ServiceRef denies the class (deny).
	NodeAddressService ServiceRef
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
		return a.authorizeNodeAddress(port, nodeAddr)
	}
	return fmt.Errorf("bind address %s is neither a service-CIDR VIP nor this node's own address (port %d denied)", nodeAddr, port)
}

// authorizeNodeAddress applies the node-own-address allowlist: the bind is
// authorized only when the ONE canonical Service named by
// PortPolicy.NodeAddressService is itself among the LoadBalancer Services
// declaring port. A Service outside the allowlist that declares the port is
// refused with a reason that NAMES it — the refusal reaches the root daemon's
// log verbatim (darwin-net netd logs a rejected bind at Warn), so a
// misconfigured or hostile declaring Service is visible rather than a silent
// behaviour cliff for the operator.
func (a servicePortAuthorizer) authorizeNodeAddress(port int, nodeAddr string) error {
	canonical := a.policy.NodeAddressService
	if !canonical.IsValid() {
		return fmt.Errorf("no canonical load-balancer service configured to authorize port %d on node address %s", port, nodeAddr)
	}
	if a.policy.LBDeclarers == nil {
		return fmt.Errorf("no service set available to authorize port %d on node address %s", port, nodeAddr)
	}
	declarers := a.policy.LBDeclarers(port)
	for _, d := range declarers {
		if d == canonical {
			return nil
		}
	}
	if len(declarers) == 0 {
		return fmt.Errorf("the canonical load-balancer service %s does not declare port %d (requested on node address %s)", canonical, port, nodeAddr)
	}
	return fmt.Errorf("port %d on node address %s is declared by %s, not by the canonical load-balancer service %s: only that service authorizes a node-address bind", port, nodeAddr, describeDeclarers(declarers), canonical)
}

// describeDeclarers renders the declaring Services for a refusal message. It
// sorts (a deterministic log line) and caps the list, so a cluster with many
// LoadBalancer Services on one port cannot flood the root daemon's log.
func describeDeclarers(refs []ServiceRef) string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.String())
	}
	slices.Sort(names)
	names = slices.Compact(names)
	const max = 4
	if len(names) > max {
		return fmt.Sprintf("%s (+%d more)", strings.Join(names[:max], ", "), len(names)-max)
	}
	return strings.Join(names, ", ")
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
