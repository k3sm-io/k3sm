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
// address or the IPv4 wildcard, against ONE named canonical Service, and for a
// bind on a published vm pod address, against the ports that pod is relayed
// on, and for a bind on one of this Mac's own addresses, against the
// operator's LoadBalancer port list), and a MeshKeyResolver that
// reads the node's wireguard private key from a root-only path — into a
// darwin-net netd.Config. The pure policy and the seams are testable without root or a real
// apiserver.
package netdsvc

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"k3sm.io/darwin-net/pkg/netd"
	"k3sm.io/darwin-net/pkg/podnet"
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
	// node-own-address and wildcard branches of the privileged-port authorizer
	// (the ingress listener). nil denies every <1024 node-address or wildcard
	// bind (fail safe). It yields identities rather than a bare bool because
	// those branches are an ALLOWLIST: declaring the port is necessary but NOT sufficient.
	LBDeclarers func(port int) []ServiceRef
	// Synced reports whether the Service set behind Declares and LBDeclarers has
	// completed its first sync. It changes only the wording of a refusal ("not
	// yet synced" versus "no service declares"); an unsynced set still denies.
	// nil means the set is always synced.
	Synced func() bool
	// NodeAddressService is the ONE Service permitted to authorize a privileged
	// bind on this node's own address or on the IPv4 wildcard — the canonical
	// ingress LoadBalancer. The
	// assembler binds it from ingresshost.ServiceNamespace/ServiceName (the
	// single source of that identity). The zero ServiceRef denies the
	// node-address and wildcard branches entirely (fail safe).
	NodeAddressService ServiceRef
	// NodeIP is this node's own InternalIP — the ONLY address outside the
	// Service CIDR a privileged bind can ever be authorized on, and only when
	// NodeAddressService itself declares the port. The zero Addr disables the
	// node-address branch entirely (deny).
	//
	// DORMANT BY CONFIGURATION, NOT BY CONSTRUCTION. Nothing reaches this
	// branch: the ingress listeners ask netd for the WILDCARD (a separate class
	// that needs no NodeIP), and a privileged bind on one of this Mac's own
	// addresses (svclb's listed LoadBalancer ports, the ingress host's LAN-off
	// listener) goes through the host-address class (authorizeHostAddr), which
	// reads the interface addresses on every request instead of a fixed NodeIP.
	// The installed plist renders NO --node-ip, leaving this zero and the branch
	// denying. The branch is deliberately KEPT rather than deleted: it is the
	// authorization design for any future privileged specific-address bind, and
	// it was narrowed to the NodeAddressService allowlist so re-arming it cannot
	// hand the node's address to whichever Service happens to declare the port.
	// pkg/install::TestNetdPlistXML pins the absence of --node-ip, so re-adding
	// the flag reddens rather than silently re-arming the branch.
	NodeIP netip.Addr
	// VMPodPorts backs the published-vm-pod branch of the privileged-port
	// authorizer: for an address, the ports this node relays it on when it is a
	// vm pod's published address (see PortPolicy.VMPodPorts), else nil. nil
	// denies every <1024 bind on a pod address (fail safe).
	VMPodPorts func(addr netip.Addr) []uint16
	// LBPrivilegedPorts backs the LoadBalancer-port branch of the
	// privileged-port authorizer: the ports below 1024 a LoadBalancer Service
	// may be served on at one of this Mac's own addresses (`k3sm netd
	// --lb-privileged-ports`, rendered by the installer from the node's
	// recorded arguments). Empty denies the branch (fail safe).
	LBPrivilegedPorts []uint16
	// InterfaceAddrs maps each address currently assigned to this Mac's
	// interfaces to the interface's name, read on every request so an address
	// DHCP moved is never pinned. nil denies the LoadBalancer-port branch
	// (fail safe).
	InterfaceAddrs func() (map[netip.Addr]string, error)
	// MeshKeyDir is the root-only directory the MeshKeyResolver reads the node's
	// wireguard private key from. Empty disables ConfigureMesh (a nil resolver,
	// which fails fast — there is no embedded key).
	//
	// It is ALSO the home of the adopted-identity file (NodeIdentityFileName):
	// netd writes the node pod CIDR it adopted there and re-reads it at start, so
	// the identity the join handed over survives a restart the agent did not
	// drive. The two uses share one directory deliberately — it is the only
	// root-only (0700) directory the helper is given, and a root-written identity
	// file needs exactly that posture: a path an unprivileged writer could reach
	// would let it dictate the daemon's pod-alias policy boundary at the next
	// start. Empty therefore disables persistence too (BuildConfig leaves
	// netd.Config.IdentityPath empty), which is the same fail-quiet posture netd
	// applies to an unreadable file.
	MeshKeyDir string
	// ClusterCAPath is the cluster CA certificate a managed update's signer
	// must chain to (`k3sm netd --cluster-ca`): the server's own PKI copy, or a
	// worker's root-only copy. Empty makes the daemon refuse every ApplyUpdate.
	ClusterCAPath string
	// Logger is the structured logger threaded into the daemon; nil uses
	// slog.Default via netd.NewServer.
	Logger *slog.Logger
}

// BuildConfig validates opts and assembles the netd.Config: it pins the node pod
// /24 and the Service CIDR (so the proxy's VIP aliases are admitted), the service
// uid (peer auth), the PortAuthorizer (privileged-port confirmation against the
// Service set), the MeshKeyResolver (root-only key path), and the adopted-identity
// file (NodeIdentityPath) and interconnect ownership ledger
// (InterconnectStatePath) beside it. The cluster aggregate and NodePort range
// keep their darwin-net defaults.
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
			Synced:             opts.Synced,
			NodeAddressService: opts.NodeAddressService,
			NodePodCIDR:        NodePodCIDRInForce(NodeIdentityPath(opts.MeshKeyDir), opts.NodePodCIDR),
			VMPodPorts:         opts.VMPodPorts,
			LBPrivilegedPorts:  opts.LBPrivilegedPorts,
			InterfaceAddrs:     opts.InterfaceAddrs,
		}),
		ClusterCAPath: opts.ClusterCAPath,
		Logger:        opts.Logger,
	}
	if opts.MeshKeyDir != "" {
		cfg.MeshKeyResolver = MeshKeyResolver(opts.MeshKeyDir)
		cfg.IdentityPath = NodeIdentityPath(opts.MeshKeyDir)
		cfg.InterconnectStatePath = InterconnectStatePath(opts.MeshKeyDir)
	}
	return cfg, nil
}

// NodeIdentityFileName is the leaf name of the file netd persists its ADOPTED
// node pod CIDR to, inside the mesh key dir. It is named once here — rather than
// spelled at the call site — because two processes agree on it across a restart:
// the daemon that writes it after a ConfigureMesh adoption and the daemon that
// reads it back at start are the same file path or they are nothing, and a
// second spelling would silently degrade to "no persisted identity", which is
// exactly the failure the file exists to prevent.
const NodeIdentityFileName = "node-pod-cidr"

// NodePodCIDRInForce returns a function reporting the node pod /24 the daemon is
// enforcing: the identity persisted at identityPath once a join adopted one (the
// file netd itself writes, re-read on every call so an adoption after start is
// seen), else configured, the pre-adoption value the daemon started with. A
// persisted value that does not parse, or is not a subnet of the cluster pod
// aggregate, is ignored exactly as the daemon's own restore ignores it, so the
// two can only disagree for the instant between netd writing the file and this
// reading it. An empty identityPath (persistence off) always answers configured.
//
// It is read only by the published-vm-pod bind class, where it is a bound on
// the address, not the authority for it: the authority is PortPolicy.VMPodPorts.
func NodePodCIDRInForce(identityPath string, configured netip.Prefix) func() netip.Prefix {
	return func() netip.Prefix {
		if identityPath == "" {
			return configured
		}
		raw, err := os.ReadFile(identityPath)
		if err != nil {
			return configured
		}
		cidr, err := netip.ParsePrefix(strings.TrimSpace(string(raw)))
		if err != nil {
			return configured
		}
		cidr = cidr.Masked()
		agg := podnet.ClusterPodCIDR
		if !agg.Contains(cidr.Addr()) || cidr.Bits() < agg.Bits() {
			return configured
		}
		return cidr
	}
}

// NodeIdentityPath returns the adopted-identity file inside meshKeyDir, or "" for
// an empty dir (persistence off — there is no other root-only directory to put
// it in, and inventing one here would put the node's policy boundary somewhere
// the installer never made 0700).
func NodeIdentityPath(meshKeyDir string) string {
	if meshKeyDir == "" {
		return ""
	}
	return filepath.Join(meshKeyDir, NodeIdentityFileName)
}

// InterconnectStateFileName is the leaf name of the file netd persists the
// interconnect aliases it owns on bridge0 to, inside the mesh key dir. Named once
// for the reason NodeIdentityFileName is: the daemon that writes it and the
// restarted daemon that reads it back must agree on one path, and a second
// spelling would silently degrade to "owns nothing", whose startup reconcile
// removes every derived interconnect alias.
const InterconnectStateFileName = "interconnect-aliases"

// InterconnectStatePath returns the interconnect ownership ledger inside
// meshKeyDir, or "" for an empty dir: the same root-only directory contract as
// NodeIdentityPath, for the same reason (the ledger decides which reserved-half
// aliases the root helper may remove).
func InterconnectStatePath(meshKeyDir string) string {
	if meshKeyDir == "" {
		return ""
	}
	return filepath.Join(meshKeyDir, InterconnectStateFileName)
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
// exactly one of five explicitly named classes (an explicit policy decision,
// never allowed-by-coincidence):
//
//   - a Service-CIDR VIP whose port some Service in the authoritative set
//     declares (the proxy's infra VIPs, e.g. 10.43.0.10:53), or
//   - this node's OWN InternalIP when NodeAddressService — the ONE named
//     canonical ingress LoadBalancer, kube-system/k3sm-ingress — declares the
//     port, or
//   - the IPv4 WILDCARD 0.0.0.0 on a privileged port when that same canonical
//     Service declares the port (the ingress host's 80/443 listeners, bound on
//     every interface through the root helper, the k3s ServiceLB shape), or,
//     for a port the canonical Service does not declare, when any LoadBalancer
//     Service declares it, listed in LBPrivilegedPorts or not (the svclb
//     hoster's LAN-on listener, so it has the same owner as netd's own
//     Service-VIP socket on the port and as the hoster's LAN-off listener), or
//   - a PUBLISHED VM POD ADDRESS: an address inside this node's pod /24 that is
//     a vm-RuntimeClass pod's published status.podIP, on a port that pod
//     declares as a TCP containerPort or that a Service's EndpointSlice targets
//     at that address. This is the Service proxy's published-address relay
//     (darwin-net pkg/proxy podrelay.go), which listens on the pod's /32 and
//     forwards to the guest's vmnet lease, so a vm pod serving :80 or :443 (an
//     admission webhook) is reachable at its pod IP as a native pod is. The
//     address and port set come from VMPodPorts, which the assembler backs
//     with the apiserver's view of this node's pods and EndpointSlices, NEVER
//     from the request: the requester names an address and a port and the
//     daemon checks both against that set. Any other pod address (a native
//     pod's, a vm pod on another node, an unassigned one) and any port the set
//     does not list for THAT address (including a port another pod declares)
//     are refused. A native pod gets no such class: it binds its own /32
//     itself, and a privileged port there stays refused, or
//   - one of THIS MAC'S OWN ADDRESSES on a port the operator listed
//     (LBPrivilegedPorts, 80 and 443 by default) that some LoadBalancer
//     Service declares: the svclb hoster's listeners while LAN access is off,
//     when they bind the node's address instead of every interface. The
//     address must be assigned to an interface when the request arrives
//     (InterfaceAddrs, re-read every time) and be one of three shapes:
//     127.0.0.1 (no other loopback address), this node's own mesh-egress
//     address (the node address of a derived or mesh node), or an address of
//     an en* interface (an operator-chosen node address); never a Service-CIDR
//     VIP, a pod address, or an address of a utun, bridge, vmenet, feth, awdl
//     or llw interface. The port list comes from netd's own root-owned
//     launchd job, never from the request. A port the canonical ingress
//     Service declares is the ingress host's on every bind shape, so no
//     tenant LoadBalancer is served on it here; instead the same address
//     class admits it for the ingress host itself while LAN access is off,
//     whether or not the port is listed, on this node's mesh-egress address
//     or an en* address (never 127.0.0.1: the ingress host does not serve
//     loopback below 1024). netd cannot tell which local process asks, but
//     the svclb hoster never asks for an ingress-declared port (it reserves
//     them on every node), so the ingress host is the only caller for one.
//
// The node-address and wildcard classes are one ALLOWLIST keyed on namespace+name, not a
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
	// Synced reports whether the Service set has completed its first sync; it
	// only changes refusal wording. nil means always synced.
	Synced func() bool
	// NodeAddressService is the only Service whose declaration authorizes a
	// node-address or wildcard bind. The zero ServiceRef denies the class (deny).
	NodeAddressService ServiceRef
	// NodePodCIDR reports this node's pod /24 in force (NodePodCIDRInForce). It
	// bounds the published-vm-pod class: an address outside it is refused before
	// VMPodPorts is asked. nil, or an invalid prefix, denies the class.
	NodePodCIDR func() netip.Prefix
	// VMPodPorts reports the ports this node relays addr on when addr is a vm
	// pod's published address (its declared TCP container ports together with
	// every TCP port an EndpointSlice targets at addr), and nil when addr is not
	// one. nil denies the class.
	VMPodPorts func(addr netip.Addr) []uint16
	// LBPrivilegedPorts is the operator's list of LoadBalancer ports below 1024
	// the host-address class admits. Empty denies the class.
	LBPrivilegedPorts []uint16
	// InterfaceAddrs maps the addresses assigned to this Mac's interfaces now
	// to their interface names. nil denies the host-address class.
	InterfaceAddrs func() (map[netip.Addr]string, error)
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

// Authorize rejects binding port on nodeAddr unless one of PortPolicy's five
// address classes admits it. See PortPolicy for the deny-by-default contract.
func (a servicePortAuthorizer) Authorize(_ context.Context, port int, nodeAddr string) error {
	addr, err := netip.ParseAddr(nodeAddr)
	if err != nil {
		return fmt.Errorf("parse bind address %q for port %d: %w", nodeAddr, port, err)
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified():
		return a.authorizeWildcard(port, addr)
	case a.policy.ServiceCIDR.IsValid() && a.policy.ServiceCIDR.Contains(addr):
		if a.policy.Declares == nil {
			return fmt.Errorf("no service set available to authorize port %d on %s", port, nodeAddr)
		}
		if err := a.checkSynced(port, nodeAddr); err != nil {
			return err
		}
		if !a.policy.Declares(port) {
			return fmt.Errorf("no service declares port %d (requested on %s)", port, nodeAddr)
		}
		return nil
	case a.policy.NodeIP.IsValid() && addr == a.policy.NodeIP:
		return a.authorizeCanonical(port, "node address "+nodeAddr)
	case a.inNodePodCIDR(addr) && !a.isNodeEgress(addr):
		return a.authorizeVMPod(port, addr)
	}
	return a.authorizeHostAddr(port, addr)
}

// isNodeEgress reports whether addr is the mesh-egress address (.1) of this
// node's pod /24 in force: the node's own address on a derived or mesh node,
// which is never handed to a pod (podnet.MeshEgressIP).
func (a servicePortAuthorizer) isNodeEgress(addr netip.Addr) bool {
	if a.policy.NodePodCIDR == nil {
		return false
	}
	egress, err := podnet.MeshEgressIP(a.policy.NodePodCIDR())
	return err == nil && addr == egress
}

// authorizeHostAddr applies the host-address class: a LoadBalancer port the
// operator listed, on one of the addresses the svclb hoster's LAN-off set can
// hold, that a LoadBalancer Service other than the ingress host's declares;
// or a port the canonical ingress Service declares, listed or not, on the
// node's mesh-egress or an en* address, which is the ingress host's own
// LAN-off listener (see PortPolicy).
// Those addresses are exactly three shapes: 127.0.0.1; this node's own
// mesh-egress address (the node address of a derived or mesh node, an lo0
// alias); and an operator-chosen node address, which is an address on an
// Ethernet or Wi-Fi interface (a name starting with "en"). No other interface
// qualifies: not the mesh utun, not the vm bridges or their feth/vmenet legs,
// not AirDrop's awdl or llw, and not another lo0 alias. Every input is the
// daemon's own (the port list from its launchd job, the interface addresses
// read now, the Service set from the apiserver); the request contributes only
// the address and port it asks for. A refusal names the port and the reason
// so the root daemon's log says why a LoadBalancer Service went unserved.
func (a servicePortAuthorizer) authorizeHostAddr(port int, addr netip.Addr) error {
	ingress := a.ingressDeclares(port)
	if !ingress && !slices.Contains(a.policy.LBPrivilegedPorts, uint16(port)) {
		return fmt.Errorf("port %d on %s is not in the allowed LoadBalancer port list (%s); an address that is neither a service-CIDR VIP, the wildcard, nor a published vm pod address is authorized only for a listed port", port, addr, describeAllowed(a.policy.LBPrivilegedPorts))
	}
	target := fmt.Sprintf("%s port %d", addr, port)
	switch {
	case addr == loopbackV4:
		// 127.0.0.1 is this Mac's own loopback: the LAN-off set serves it,
		// and it is on lo0 by construction, so only the Service set decides.
		// The ingress host leaves loopback out below 1024, so an
		// ingress-declared port is refused here as it always was.
		return a.authorizeLBDeclared(port, addr.String())
	case addr.IsLoopback():
		return fmt.Errorf("bind on %s denied: the only loopback address authorized for a LoadBalancer port is 127.0.0.1", target)
	case !addr.Is4():
		return fmt.Errorf("bind on %s denied: only an IPv4 host address is authorized for a LoadBalancer port", target)
	case a.policy.ServiceCIDR.IsValid() && a.policy.ServiceCIDR.Contains(addr):
		return fmt.Errorf("bind on %s denied: a service-CIDR address is never a LoadBalancer host address", target)
	case podnet.ClusterPodCIDR.Contains(addr) && !a.isNodeEgress(addr):
		return fmt.Errorf("bind on %s denied: inside the cluster pod range only this node's own address is authorized", target)
	}
	if a.policy.InterfaceAddrs == nil {
		return fmt.Errorf("bind on %s denied: no host address set available", target)
	}
	ifaces, err := a.policy.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("bind on %s denied: list this Mac's addresses: %w", target, err)
	}
	name, ok := ifaces[addr]
	if !ok {
		return fmt.Errorf("bind on %s denied: the address is not assigned to this Mac", target)
	}
	if !a.isNodeEgress(addr) && !strings.HasPrefix(name, "en") {
		return fmt.Errorf("bind on %s denied: the address is on %s; a LoadBalancer port is authorized only on 127.0.0.1, this node's own address, or an address of an en* interface", target, name)
	}
	if ingress {
		// The ingress host's LAN-off listener on the node's own address.
		return nil
	}
	return a.authorizeLBDeclared(port, addr.String())
}

// ingressDeclares reports whether the canonical ingress Service is among the
// LoadBalancer Services declaring port in a synced Service set. Before the
// first sync it reports false, so the listed-port path's refusal says the set
// is not synced yet.
func (a servicePortAuthorizer) ingressDeclares(port int) bool {
	canonical := a.policy.NodeAddressService
	if !canonical.IsValid() || a.policy.LBDeclarers == nil {
		return false
	}
	if a.policy.Synced != nil && !a.policy.Synced() {
		return false
	}
	return slices.Contains(a.policy.LBDeclarers(port), canonical)
}

// loopbackV4 is the one loopback address the LoadBalancer-port class admits.
var loopbackV4 = netip.AddrFrom4([4]byte{127, 0, 0, 1})

// authorizeLBDeclared admits a listed port on target when some LoadBalancer
// Service in the authoritative set declares it and the canonical ingress
// Service does not. A port the ingress Service declares belongs to the ingress
// host on every bind shape: a tenant's root-held node-address or loopback
// socket beside the ingress host's wildcard on the same port would win the
// more-specific match and take the ingress's traffic on that address.
func (a servicePortAuthorizer) authorizeLBDeclared(port int, target string) error {
	if a.policy.LBDeclarers == nil {
		return fmt.Errorf("no service set available to authorize port %d on %s", port, target)
	}
	if err := a.checkSynced(port, target); err != nil {
		return err
	}
	declarers := a.policy.LBDeclarers(port)
	if len(declarers) == 0 {
		return fmt.Errorf("no LoadBalancer service declares port %d (requested on %s)", port, target)
	}
	if canonical := a.policy.NodeAddressService; canonical.IsValid() && slices.Contains(declarers, canonical) {
		return fmt.Errorf("port %d on %s belongs to the ingress host: the canonical ingress service %s declares it, so no other LoadBalancer service is served on it", port, target, canonical)
	}
	return nil
}

// describeAllowed renders the allowed LoadBalancer port list for a refusal.
func describeAllowed(ports []uint16) string {
	if len(ports) == 0 {
		return "empty"
	}
	return describePorts(ports)
}

// checkSynced refuses while the Service set has not completed its first sync,
// so the log says so instead of claiming no Service declares the port.
func (a servicePortAuthorizer) checkSynced(port int, target string) error {
	if a.policy.Synced != nil && !a.policy.Synced() {
		return fmt.Errorf("service set not yet synced; port %d cannot be authorized yet on %s", port, target)
	}
	return nil
}

// inNodePodCIDR reports whether addr is a host address inside this node's pod
// /24 in force. It is only the BOUND of the published-vm-pod class; whether the
// address is a vm pod's is authorizeVMPod's question.
func (a servicePortAuthorizer) inNodePodCIDR(addr netip.Addr) bool {
	if a.policy.NodePodCIDR == nil || !addr.Is4() {
		return false
	}
	cidr := a.policy.NodePodCIDR()
	return cidr.IsValid() && cidr.Contains(addr)
}

// authorizeVMPod applies the published-vm-pod class: the bind is authorized only
// when VMPodPorts lists port for addr itself. It never consults the requester
// for either value, and it never generalizes: a port listed for a different pod
// address, or an address listed with other ports, is refused, and the refusal
// names the ports that ARE relayed so a mis-declared pod is visible in the root
// daemon's log rather than a silent behaviour cliff.
func (a servicePortAuthorizer) authorizeVMPod(port int, addr netip.Addr) error {
	if a.policy.VMPodPorts == nil {
		return fmt.Errorf("no vm pod set available to authorize port %d on pod address %s", port, addr)
	}
	ports := a.policy.VMPodPorts(addr)
	if len(ports) == 0 {
		return fmt.Errorf("pod address %s is not a published vm pod address on this node (port %d denied)", addr, port)
	}
	if slices.Contains(ports, uint16(port)) {
		return nil
	}
	return fmt.Errorf("port %d is neither declared by the vm pod at %s nor targeted by a Service there (relayed ports: %s)", port, addr, describePorts(ports))
}

// describePorts renders a relayed port set for a refusal message, sorted and
// capped like describeDeclarers so a large set cannot flood the daemon's log.
func describePorts(ports []uint16) string {
	sorted := slices.Clone(ports)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	const max = 8
	names := make([]string, 0, min(len(sorted), max))
	for _, p := range sorted[:min(len(sorted), max)] {
		names = append(names, fmt.Sprint(p))
	}
	out := strings.Join(names, ", ")
	if len(sorted) > max {
		out += fmt.Sprintf(" (+%d more)", len(sorted)-max)
	}
	return out
}

// authorizeWildcard applies the wildcard class: the IPv4 unspecified address
// on a privileged port, which is how the ingress host takes 80/443 on every
// interface (the k3s ServiceLB shape). It is the SAME allowlist as the
// node-address class, keyed on the canonical Service's namespace+name, and it
// does not depend on PortPolicy.NodeIP: the wildcard names no address, so there
// is no node address to match, only a declaring subject.
//
// For a port the canonical Service does not declare, any declaring
// LoadBalancer Service admits it too, whether or not the port is in
// LBPrivilegedPorts (see PortPolicy). The listed-port rule exists to keep root
// from binding a SPECIFIC node address below 1024 for a tenant, where the
// tenant's socket would take that address from a host listener. A wildcard is
// a different trade, and the owner decides it, because Darwin checks a bind
// against the other sockets on the port by user:
//
//   - A root-owned wildcard (this arm) lets root and launchd services still
//     bind a specific address beside it, and the specific socket wins its
//     address; netd's own Service-VIP socket is one. It blocks a NON-root
//     specific bind on that port, such as a user's dev server on 127.0.0.1 or
//     an `ssh -L` forward, for as long as the Service is served.
//   - A wildcard owned by the node daemon's service user, the shape before
//     this arm, blocked the root host services instead (netd's VIP socket
//     among them: the in-process wildcard bound only when it won the race
//     against the VIP bind, and never re-bound after a LAN access swap).
//
// Root ownership is taken: the cluster's own VIP socket and the system's
// services keep working, at the cost of a non-root local listener on a tenant
// LoadBalancer port. The macOS host-service ports (pkg/ports, 22, 53, 88, 445,
// 548 and 631) are reserved from tenants for the same reason, so a root
// wildcard never keeps one of those services from binding its own wildcard
// later. A port the canonical Service declares stays its own.
//
// The IPv6 unspecified address is refused. A "[::]" socket is dual-stack and
// would publish the listener on every IPv6 address of the host, a surface no
// k3sm listener is meant to have (the ingress binds 0.0.0.0 explicitly).
// Non-privileged ports are refused too: the arm exists for the <1024 bind an
// unprivileged process cannot make, and a high-port wildcard needs no helper.
func (a servicePortAuthorizer) authorizeWildcard(port int, addr netip.Addr) error {
	if !addr.Is4() {
		return fmt.Errorf("wildcard bind on %s port %d denied: only the IPv4 wildcard 0.0.0.0 is authorized (a [::] socket is dual-stack)", addr, port)
	}
	if port >= 1024 {
		return fmt.Errorf("wildcard bind on non-privileged port %d denied: only a privileged (<1024) wildcard bind is brokered", port)
	}
	target := "the wildcard " + addr.String()
	err := a.authorizeCanonical(port, target)
	if err == nil || !a.policy.NodeAddressService.IsValid() {
		// With no canonical Service configured nothing can say the ingress
		// does not own the port, so the tenant arm stays shut (fail safe).
		return err
	}
	// Any declaring LoadBalancer Service the canonical one is not beside, so
	// the svclb hoster's wildcard has the same owner (root) as netd's VIP
	// socket on the port and as its LAN-off listener, and a LAN access swap
	// binds the new shape before it closes the old one.
	if lerr := a.authorizeLBDeclared(port, target); lerr != nil {
		return fmt.Errorf("%w; and as a LoadBalancer port: %w", err, lerr)
	}
	return nil
}

// authorizeCanonical applies the allowlist shared by the node-address and
// wildcard classes: the bind is authorized only when the ONE canonical Service
// named by PortPolicy.NodeAddressService is itself among the LoadBalancer
// Services declaring port. A Service outside the allowlist that declares the
// port is refused with a reason that NAMES it: the refusal reaches the root
// daemon's log verbatim (darwin-net netd logs a rejected bind at Warn), so a
// misconfigured or hostile declaring Service is visible rather than a silent
// behaviour cliff for the operator. target describes the requested address in
// that message.
func (a servicePortAuthorizer) authorizeCanonical(port int, target string) error {
	canonical := a.policy.NodeAddressService
	if !canonical.IsValid() {
		return fmt.Errorf("no canonical load-balancer service configured to authorize port %d on %s", port, target)
	}
	if a.policy.LBDeclarers == nil {
		return fmt.Errorf("no service set available to authorize port %d on %s", port, target)
	}
	if err := a.checkSynced(port, target); err != nil {
		return err
	}
	declarers := a.policy.LBDeclarers(port)
	for _, d := range declarers {
		if d == canonical {
			return nil
		}
	}
	if len(declarers) == 0 {
		return fmt.Errorf("the canonical load-balancer service %s does not declare port %d (requested on %s)", canonical, port, target)
	}
	return fmt.Errorf("port %d on %s is declared by %s, not by the canonical load-balancer service %s: only that service authorizes this bind", port, target, describeDeclarers(declarers), canonical)
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
	if errors.Is(err, fs.ErrNotExist) {
		// The node daemon sees this text as its ConfigureMesh failure, so it
		// names the remedy: the root installer re-provisions this copy from the
		// node's work-dir key, and never mints over an identity that exists.
		return "", fmt.Errorf("read mesh key %s: %w (run `sudo k3sm install` to re-provision it from this node's work-dir key; it never mints over an existing identity)", path, err)
	}
	if err != nil {
		return "", fmt.Errorf("read mesh key %s: %w", path, err)
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("mesh key %s is empty", path)
	}
	return key, nil
}
