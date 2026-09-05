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

package bootstrap

import (
	"errors"
	"fmt"

	netv1 "k3sm.io/apis/net/v1"
)

// ErrForbiddenPeer is returned by AuthorizeMeshPeerWrite when a node attempts to
// write a MeshPeer it does not own. Compare with errors.Is.
var ErrForbiddenPeer = errors.New("bootstrap: a node may write only its own MeshPeer")

// AuthorizeMeshPeerWrite reports whether the authenticated node (system:node:<nodeName>)
// may write the MeshPeer named peerName. The mesh-enroll is controller-mediated: a
// node may write ONLY its own MeshPeer (peerName == nodeName). A forged peer — an
// attacker advertising AllowedIPs over a victim's podCIDR with an attacker-controlled
// endpoint — would hijack all cross-node traffic to that podCIDR.
//
// This guard is PERMANENT, not an interim stand-in. The NodeRestriction admission
// plugin covers only the core node-owned resources (Node/Pod and their status); it
// never covers a CRD, so it does not — and will not — constrain a node's write to the
// net.k3sm.io/MeshPeer object. Under the Node,RBAC authorizer the node identity
// gets meshpeers READ (via pkg/rbac's node-datapath ClusterRole) but no write verb, so
// the WRITE stays server-mediated through this check. It returns ErrForbiddenPeer
// otherwise.
func AuthorizeMeshPeerWrite(nodeName, peerName string) error {
	if nodeName == "" || peerName == "" {
		return fmt.Errorf("%w: empty node %q or peer %q", ErrForbiddenPeer, nodeName, peerName)
	}
	if nodeName != peerName {
		return fmt.Errorf("%w: node %q may not write MeshPeer %q", ErrForbiddenPeer, nodeName, peerName)
	}
	return nil
}

// BuildMeshPeer assembles the MeshPeer the server writes on a node's behalf
// (controller-mediated enroll), binding the object's name to nodeName so the
// write-guard holds. The peer carries the node's PUBLIC wireguard key + endpoint
// from req, the server-assigned podCIDR (which is also the sole AllowedIPs entry —
// the node /24 single source of truth), and the reserved mesh-egress /32. It returns
// an error if the resulting spec is not Validate-able.
func BuildMeshPeer(nodeName, podCIDR, meshIP string, req netv1.MeshEnrollRequest) (*netv1.MeshPeer, error) {
	if err := AuthorizeMeshPeerWrite(nodeName, req.NodeName); err != nil {
		return nil, err
	}
	spec := netv1.MeshPeerSpec{
		NodeName:   nodeName,
		PublicKey:  req.PublicKey,
		Endpoint:   req.Endpoint,
		PodCIDR:    podCIDR,
		AllowedIPs: []string{podCIDR},
		MeshIP:     meshIP,
	}.WithDefaults()
	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("build mesh peer for %q: %w", nodeName, err)
	}
	peer := &netv1.MeshPeer{Spec: spec}
	peer.Name = nodeName
	peer.Kind = "MeshPeer"
	peer.APIVersion = netv1.SchemeGroupVersion.String()
	return peer, nil
}
