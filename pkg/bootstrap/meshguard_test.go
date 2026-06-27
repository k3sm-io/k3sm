package bootstrap_test

import (
	"errors"
	"testing"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
)

// TestMeshPeerWriteGuardOwnNodeOnly proves the routing-integrity guard: the
// controller-mediated enroll lets a node write ONLY its own MeshPeer, so a node
// writing a MeshPeer for a DIFFERENT node is rejected (a forged peer over a victim
// podCIDR would hijack cross-node routing). The guard is permanent — NodeRestriction
// (M4.1) never covers the net.k3sm.io/MeshPeer CRD, so the write stays server-mediated.
func TestMeshPeerWriteGuardOwnNodeOnly(t *testing.T) {
	if err := bootstrap.AuthorizeMeshPeerWrite("worker-a", "worker-a"); err != nil {
		t.Errorf("a node writing its OWN MeshPeer must be allowed: %v", err)
	}
	if err := bootstrap.AuthorizeMeshPeerWrite("worker-a", "worker-b"); !errors.Is(err, bootstrap.ErrForbiddenPeer) {
		t.Errorf("a node writing ANOTHER node's MeshPeer err = %v, want ErrForbiddenPeer", err)
	}
	for _, tc := range []struct{ node, peer string }{
		{"", "worker-a"},
		{"worker-a", ""},
		{"", ""},
	} {
		if err := bootstrap.AuthorizeMeshPeerWrite(tc.node, tc.peer); !errors.Is(err, bootstrap.ErrForbiddenPeer) {
			t.Errorf("AuthorizeMeshPeerWrite(%q,%q) must be forbidden", tc.node, tc.peer)
		}
	}
}

// TestBuildMeshPeerBindsName confirms the controller-mediated enroll builds a
// MeshPeer named for the authenticated node, with AllowedIPs == the assigned podCIDR
// (the node /24 single source of truth), and refuses a request naming another node.
func TestBuildMeshPeerBindsName(t *testing.T) {
	req := netv1.MeshEnrollRequest{
		NodeName:  "worker-a",
		PublicKey: "cHVia2V5cHVia2V5cHVia2V5cHVia2V5cHVia2V5MzI=",
		Endpoint:  "192.168.1.50:51820",
	}.WithDefaults()

	peer, err := bootstrap.BuildMeshPeer("worker-a", "100.64.1.0/24", "100.64.1.1", req)
	if err != nil {
		t.Fatalf("build mesh peer: %v", err)
	}
	if peer.Name != "worker-a" || peer.Spec.NodeName != "worker-a" {
		t.Errorf("peer name/nodeName = %q/%q, want worker-a", peer.Name, peer.Spec.NodeName)
	}
	if len(peer.Spec.AllowedIPs) != 1 || peer.Spec.AllowedIPs[0] != "100.64.1.0/24" {
		t.Errorf("AllowedIPs = %v, want [100.64.1.0/24] (== podCIDR)", peer.Spec.AllowedIPs)
	}
	if peer.Spec.PodCIDR != "100.64.1.0/24" || peer.Spec.MeshIP != "100.64.1.1" {
		t.Errorf("podCIDR/meshIP = %q/%q", peer.Spec.PodCIDR, peer.Spec.MeshIP)
	}

	// A request naming a DIFFERENT node than the authenticated one is refused.
	bad := netv1.MeshEnrollRequest{NodeName: "worker-b", PublicKey: req.PublicKey, Endpoint: req.Endpoint}.WithDefaults()
	if _, err := bootstrap.BuildMeshPeer("worker-a", "100.64.1.0/24", "100.64.1.1", bad); !errors.Is(err, bootstrap.ErrForbiddenPeer) {
		t.Errorf("enroll naming another node err = %v, want ErrForbiddenPeer", err)
	}
}
