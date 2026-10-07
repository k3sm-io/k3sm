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

package install

import (
	"errors"
	"fmt"
	"net/netip"

	"k3sm.io/darwin-net/pkg/podnet"
)

// ErrMeshIPNotNodeGateway is returned by MeshNodePodCIDR for a --mesh-ip that is
// not the mesh-egress address of a node pod /24 inside the cluster pod
// aggregate. Compare with errors.Is.
var ErrMeshIPNotNodeGateway = errors.New("--mesh-ip is not the mesh-egress address of a node pod range")

// MeshNodePodCIDR returns the node pod /24 a control-plane server's --mesh-ip
// names: the node range whose mesh-egress address (podnet.MeshEgressIP, the .1
// of the /24) is meshIP.
//
// A server plumbs its --mesh-ip as an lo0 alias before control-plane bring-up
// and before its own mesh enrol, and netd admits an alias only inside the node
// pod /24 it holds at that moment. So the server's netd has to START on the /24
// its mesh address lives in, rather than on the first-server default it would
// otherwise hold until an enrol adopts the real one.
//
// The derivation is the inverse of podnet.MeshEgressIP and is checked by
// running that function forward, so the ".1 of the node /24" rule stays in
// darwin-net alone; the /24 width is read off podnet.NodeCIDR's own carve. An
// address that is not IPv4, lies outside podnet.ClusterPodCIDR, or is any host
// of its /24 other than the mesh-egress one wraps ErrMeshIPNotNodeGateway.
func MeshNodePodCIDR(meshIP string) (netip.Prefix, error) {
	ip, err := netip.ParseAddr(meshIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %q is not an IP address: %w", ErrMeshIPNotNodeGateway, meshIP, err)
	}
	ip = ip.Unmap()
	if !ip.Is4() || !podnet.ClusterPodCIDR.Contains(ip) {
		return netip.Prefix{}, fmt.Errorf("%w: %s is outside the cluster pod range %s; give the first address of this node's own /%d inside it (for example %s)",
			ErrMeshIPNotNodeGateway, ip, podnet.ClusterPodCIDR, nodePodCIDRBits(), exampleMeshIP())
	}
	cidr := netip.PrefixFrom(ip, nodePodCIDRBits()).Masked()
	gw, err := podnet.MeshEgressIP(cidr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: derive the mesh-egress address of %s: %w", ErrMeshIPNotNodeGateway, cidr, err)
	}
	if gw != ip {
		return netip.Prefix{}, fmt.Errorf("%w: %s is a host inside the node pod range %s, but a server's mesh address must be that range's mesh-egress address %s; use %s, and give each control-plane Mac its own /%d",
			ErrMeshIPNotNodeGateway, ip, cidr, gw, gw, nodePodCIDRBits())
	}
	return cidr, nil
}

// nodePodCIDRBits is the width of a node's pod range, read off podnet's own
// carve of the cluster pod CIDR so it is not a second literal here.
func nodePodCIDRBits() int {
	cidr, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 0)
	if err != nil {
		// Unreachable with the pinned package constants; an invalid width makes
		// every derivation above refuse rather than invent a range.
		return -1
	}
	return cidr.Bits()
}

// exampleMeshIP is the mesh-egress address of the first node range, the
// first server's conventional --mesh-ip, used in the refusal text.
func exampleMeshIP() string {
	cidr, err := podnet.NodeCIDR(podnet.ClusterPodCIDR, 0)
	if err != nil {
		return ""
	}
	gw, err := podnet.MeshEgressIP(cidr)
	if err != nil {
		return ""
	}
	return gw.String()
}

// netdNodePodCIDR is the --node-pod-cidr the netd plist renders, or "" for none.
//
// Only a control-plane server with a --mesh-ip gets one. A worker's pod /24 is
// decided by its join and arrives through ConfigureMesh, so it keeps the
// pre-adoption default (see NetdPlist). A server without a --mesh-ip is the
// single-node posture: the default already is its range. A --mesh-ip the
// derivation refuses renders nothing here; Install refuses it earlier
// (checkServerMeshIP), so that branch is never reached by an install.
func (c Config) netdNodePodCIDR() string {
	if c.Role == RoleAgent {
		return ""
	}
	mesh := c.meshIP()
	if mesh == "" {
		return ""
	}
	cidr, err := MeshNodePodCIDR(mesh)
	if err != nil {
		return ""
	}
	return cidr.String()
}

// checkServerMeshIP refuses a control-plane install whose effective --mesh-ip
// (this install's, or the one carried from the previous install) does not name
// a node pod range, before anything is written. carried is the argument set
// preflightServerArgs read.
func checkServerMeshIP(cfg Config, carried []string) error {
	if cfg.Role == RoleAgent {
		return nil
	}
	cfg.ExtraServerArgs = carried
	mesh := cfg.meshIP()
	if mesh == "" {
		return nil
	}
	if _, err := MeshNodePodCIDR(mesh); err != nil {
		return fmt.Errorf("install: %w. Nothing has been written", err)
	}
	return nil
}
