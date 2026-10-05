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

package linkgraph

import (
	"errors"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// ErrDomainUUIDClaimed reports a port whose domain UUID another node's DirectLink
// already lists. Compare with errors.Is.
var ErrDomainUUIDClaimed = errors.New("linkgraph: domain UUID claimed by another node")

// portRef locates one port of one node's DirectLink.
type portRef struct {
	node string
	port netv1alpha1.DirectLinkPort
}

// Resolve computes the status of every DirectLink from every spec (see the package
// doc for the up rule). fresh reports whether a node's Lease is fresh. now stamps
// each port whose state changed; an unchanged port keeps its lastTransition from
// the object's current status.
//
// A domain UUID listed by two different nodes resolves nobody's cable through it:
// both ports are down until one side stops claiming it (the writer refuses the
// second claim, so this arises only from objects written around it).
func Resolve(links []netv1alpha1.DirectLink, fresh func(node string) bool, now metav1.Time) map[string]netv1alpha1.DirectLinkStatus {
	byUUID := map[string]portRef{}
	collided := map[string]bool{}
	for _, l := range links {
		node := nodeOf(l)
		for _, p := range l.Spec.Ports {
			if p.DomainUUID == "" {
				continue
			}
			if prev, ok := byUUID[p.DomainUUID]; ok && prev.node != node {
				collided[p.DomainUUID] = true
				continue
			}
			byUUID[p.DomainUUID] = portRef{node: node, port: p}
		}
	}

	out := make(map[string]netv1alpha1.DirectLinkStatus, len(links))
	for _, l := range links {
		node := nodeOf(l)
		prev := map[string]netv1alpha1.DirectLinkPortStatus{}
		for _, ps := range l.Status.Ports {
			prev[ps.Iface] = ps
		}
		st := netv1alpha1.DirectLinkStatus{ObservedSchemaVersion: l.Spec.SchemaVersion}
		for _, p := range l.Spec.Ports {
			ps := resolvePort(node, p, byUUID, collided, fresh)
			if old, ok := prev[p.Iface]; ok && old.State == ps.State && old.LastTransition != nil {
				t := *old.LastTransition
				ps.LastTransition = &t
			} else {
				t := now
				ps.LastTransition = &t
			}
			st.Ports = append(st.Ports, ps)
		}
		out[node] = st
	}
	return out
}

// resolvePort is the up rule for one port.
func resolvePort(node string, p netv1alpha1.DirectLinkPort, byUUID map[string]portRef, collided map[string]bool, fresh func(string) bool) netv1alpha1.DirectLinkPortStatus {
	ps := netv1alpha1.DirectLinkPortStatus{Iface: p.Iface, State: netv1alpha1.DirectLinkStateDown}
	if p.PeerDomainUUID == "" || collided[p.DomainUUID] || collided[p.PeerDomainUUID] {
		return ps
	}
	peer, ok := byUUID[p.PeerDomainUUID]
	if !ok {
		ps.State = netv1alpha1.DirectLinkStatePeerUnknown
		return ps
	}
	ps.PeerNodeName = peer.node
	ps.PeerIface = peer.port.Iface
	ps.PeerLinkIP = peer.port.LinkIP
	ps.PeerRDMADevice = peer.port.RDMADevice
	switch {
	case peer.node == node:
	case peer.port.PeerDomainUUID != p.DomainUUID:
	case !p.LinkUp || !peer.port.LinkUp:
	case !p.RouteReady || !peer.port.RouteReady:
	case p.TunnelOnly || peer.port.TunnelOnly:
	case p.LinkIP == "" || peer.port.LinkIP == "":
	case fresh == nil || !fresh(peer.node):
	default:
		ps.State = netv1alpha1.DirectLinkStateUp
	}
	return ps
}

// UpCount is how many ports of a status are up.
func UpCount(st netv1alpha1.DirectLinkStatus) int {
	n := 0
	for _, p := range st.Ports {
		if p.State == netv1alpha1.DirectLinkStateUp {
			n++
		}
	}
	return n
}

// CheckDomainUUIDs refuses a spec that lists a domain UUID another node's
// DirectLink already lists, naming the UUID and the node. The writer runs it
// before every spec write, so a collision is refused, never last-write-wins.
func CheckDomainUUIDs(spec netv1alpha1.DirectLinkSpec, others []netv1alpha1.DirectLink) error {
	claimed := map[string]string{}
	for _, o := range others {
		node := nodeOf(o)
		if node == spec.NodeName {
			continue
		}
		for _, p := range o.Spec.Ports {
			if p.DomainUUID != "" {
				claimed[p.DomainUUID] = node
			}
		}
	}
	seen := map[string]bool{}
	for _, p := range spec.Ports {
		if owner, ok := claimed[p.DomainUUID]; ok {
			return fmt.Errorf("%w: port %s domain %s is listed by node %q", ErrDomainUUIDClaimed, p.Iface, p.DomainUUID, owner)
		}
		if seen[p.DomainUUID] {
			return fmt.Errorf("%w: domain %s is listed twice by node %q", ErrDomainUUIDClaimed, p.DomainUUID, spec.NodeName)
		}
		seen[p.DomainUUID] = true
	}
	return nil
}

// StatusEqual reports whether two statuses say the same thing, port by port in
// order, including every lastTransition.
func StatusEqual(a, b netv1alpha1.DirectLinkStatus) bool {
	if a.ObservedSchemaVersion != b.ObservedSchemaVersion || len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		x, y := a.Ports[i], b.Ports[i]
		if x.Iface != y.Iface || x.PeerNodeName != y.PeerNodeName || x.PeerIface != y.PeerIface ||
			x.PeerLinkIP != y.PeerLinkIP || x.PeerRDMADevice != y.PeerRDMADevice || x.State != y.State {
			return false
		}
		if (x.LastTransition == nil) != (y.LastTransition == nil) {
			return false
		}
		if x.LastTransition != nil && !x.LastTransition.Equal(y.LastTransition) {
			return false
		}
	}
	return true
}

// nodeOf is the node a DirectLink belongs to: its spec's node name, else its
// object name (they are equal for every object the writer produces).
func nodeOf(l netv1alpha1.DirectLink) string {
	if l.Spec.NodeName != "" {
		return l.Spec.NodeName
	}
	return l.Name
}

// sortedNodes returns the keys of m in order.
func sortedNodes[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
