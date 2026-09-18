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
	"context"

	netv1 "k3sm.io/apis/net/v1"
)

// HTTP bootstrap endpoints the supervisor serves on its mesh-reachable TLS listener.
const (
	// CACertPath returns the cluster CA PEM (hash-pinned by the joining node).
	CACertPath = "/v1-k3sm/cacert"
	// JoinPath is the worker-join exchange (token + node-password + CSRs + mesh-enroll).
	JoinPath = "/v1-k3sm/join"
	// BundlePath serves the AES-256-GCM-sealed CA bootstrap bundle to a joining
	// control-plane SERVER (server-token-authorized via the Authorization bearer header;
	// never a worker). The joining server decrypts it to reconstruct the IDENTICAL
	// cluster + signing CAs (DESIGN §5c).
	BundlePath = "/v1-k3sm/server-bootstrap"
	// MeshEndpointPath is the endpoint-refresh verb: a node that has already
	// joined republishes the host:port its wireguard is reachable at, so a DHCP
	// lease change or a move between Wi-Fi and Ethernet does not leave every peer
	// dialing an address this node no longer owns. It is the ONLY bootstrap route
	// authenticated by the node's own client certificate rather than the join
	// token (see MeshEndpointRefreshRequest).
	MeshEndpointPath = "/v1-k3sm/mesh/endpoint"
	// DeregisterPath is the deregistration verb: a node being uninstalled asks
	// the supervisor to remove it from the cluster, so the peers it leaves
	// behind stop carrying a wireguard entry for a Mac that will never answer
	// again. It is authenticated exactly as MeshEndpointPath is — by the node's
	// own client certificate, never the join token — and it is self-scoped by
	// the same guard, so a node can deregister itself and nothing else (see
	// DeregisterRequest).
	DeregisterPath = "/v1-k3sm/mesh/deregister"
)

// JoinSchemaVersion stamps the k3sm-internal join exchange payloads (JoinRequest /
// JoinResponse). These wrap the apis net/v1 mesh-enroll payloads, which carry their
// own version stamp; both are version-stamped from day one so a node-by-node
// roll has a compatibility seam.
const JoinSchemaVersion int32 = 1

// JoinRequest is the payload a joining worker POSTs to JoinPath over the pinned-CA
// TLS connection. The bootstrap token authorizes the join; the node-password binds
// the node name; the two CSRs request the node's client + kubelet-serving certs; the
// mesh-enroll sub-payload carries the wireguard public key + endpoint.
type JoinRequest struct {
	// SchemaVersion stamps this payload (JoinSchemaVersion).
	SchemaVersion int32 `json:"schemaVersion"`
	// Token is the K10<caHash>::<user>:<secret> join token (verified server-side).
	Token string `json:"token"`
	// NodeName is the name this node claims (bound by the node-password).
	NodeName string `json:"nodeName"`
	// NodeIP is OPTIONAL, and it is an ASSERTION, not a choice: the server assigns
	// this node's mesh address itself (the mesh enroll's reuse-by-name, else the
	// lowest free index) and names THAT in the issued certificates. When this field
	// is set and differs from the assignment the join is refused before any CSR is
	// parsed; when it is empty the assignment is used. A client therefore cannot
	// obtain a certificate naming an address the allocator gave another node.
	NodeIP string `json:"nodeIP,omitempty"`
	// NodePassword is the anti-impersonation secret (stored hashed + first-write-wins
	// server-side).
	NodePassword string `json:"nodePassword"`
	// ClientCSRPEM is the PEM CSR the server signs into a CN=system:node:<name>
	// client cert (signing CA).
	ClientCSRPEM string `json:"clientCSRPEM"`
	// ServingCSRPEM is the PEM CSR the server signs into a kubelet-serving cert
	// (cluster CA); may be empty.
	ServingCSRPEM string `json:"servingCSRPEM,omitempty"`
	// Mesh is the wireguard mesh-enroll request (public key + endpoint + requested
	// podCIDR).
	Mesh netv1.MeshEnrollRequest `json:"mesh"`
}

// WithDefaults returns a copy with SchemaVersion stamped when zero and the embedded
// mesh request defaulted.
func (r JoinRequest) WithDefaults() JoinRequest {
	out := r
	if out.SchemaVersion == 0 {
		out.SchemaVersion = JoinSchemaVersion
	}
	out.Mesh = out.Mesh.WithDefaults()
	return out
}

// MeshEndpointRefreshRequest is the payload a JOINED node POSTs to
// MeshEndpointPath to republish its wireguard endpoint.
//
// It carries the endpoint and nothing else. The public key, the podCIDR and the
// AllowedIPs are NOT writable through this channel: they are the fields a forged
// peer would use to hijack another node's pod traffic, and none of them changes
// when a Mac's address does. The node name is present only so the server can
// check it against the certificate that authenticated the request — it is never
// trusted on its own (see Server.handleMeshEndpoint).
type MeshEndpointRefreshRequest struct {
	// NodeName is the node claiming the change. It MUST equal the authenticated
	// certificate's system:node:<name> identity; a mismatch is a 403.
	NodeName string `json:"nodeName"`
	// Endpoint is the host:port peers should dial to open a wireguard handshake
	// with this node — an UNDERLAY address, for the same reason the join-time
	// endpoint is one.
	Endpoint string `json:"endpoint"`
}

// DeregisterRequest is the payload a node being uninstalled POSTs to
// DeregisterPath.
//
// It carries the node name and nothing else, for the same reason the endpoint
// refresh carries one string: the name is present only so the server can check
// it against the certificate that authenticated the request, and it is never
// trusted on its own (see Server.handleDeregister). There is no field a caller
// could use to name a DIFFERENT object to delete.
type DeregisterRequest struct {
	// NodeName is the node asking to be removed. It MUST equal the
	// authenticated certificate's system:node:<name> identity; a mismatch is a
	// 403.
	NodeName string `json:"nodeName"`
}

// JoinResponse is the bootstrap endpoint's reply: the cluster CA the node now trusts
// for the apiserver, its issued certs, and the mesh-enroll snapshot it programs
// immediately.
type JoinResponse struct {
	// SchemaVersion stamps this payload (JoinSchemaVersion).
	SchemaVersion int32 `json:"schemaVersion"`
	// NodeName is the joining node's name (echoed back).
	NodeName string `json:"nodeName"`
	// NodeIP is the InternalIP the issued certificates NAME: this node's
	// server-assigned mesh address (the same value as Mesh.MeshIP, carried
	// separately because it is a statement about the certificates, not about the
	// mesh snapshot). The joining node advertises it as its Node InternalIP and
	// binds its serving endpoint to it, so the address in its certificates and the
	// address the cluster knows it by are one value. Empty only against a server
	// that predates the field, where the node's own --node-ip was that value.
	NodeIP string `json:"nodeIP,omitempty"`
	// ClusterCAPEM is the cluster CA the node embeds in its kubeconfig's
	// certificate-authority-data to verify the apiserver going forward.
	ClusterCAPEM string `json:"clusterCAPEM"`
	// ClientCAPEM is the cluster's CLIENT-IDENTITY CA (the signing CA) — the same CA
	// that issued NodeClientCertPEM below. The node needs the CERTIFICATE (never the
	// key, which stays on the server) to run its own kubelet endpoint: :10250
	// requires and verifies the apiserver's client cert against this anchor.
	//
	// A CA certificate is public material — it is world-readable 0644 on the server
	// and already implicitly trusted by this node, whose own identity chains to it —
	// so shipping it here distributes no secret and adds no trust root.
	ClientCAPEM string `json:"clientCAPEM,omitempty"`
	// NodeClientCertPEM is the issued CN=system:node:<name>, O=system:nodes client
	// cert (the node pairs it with the private key it kept).
	NodeClientCertPEM string `json:"nodeClientCertPEM"`
	// KubeletServingCertPEM is the issued kubelet-serving cert (cluster CA); may be
	// empty if no serving CSR was submitted.
	KubeletServingCertPEM string `json:"kubeletServingCertPEM,omitempty"`
	// APIServers are the control-plane apiserver endpoints (host:port) the joining
	// node's client-side load-balancer health-checks + targets, so a server death fails
	// over without re-pointing the kubeconfig. A single-server cluster carries
	// that one server; the live cross-node failover is the lab leg.
	APIServers []string `json:"apiServers,omitempty"`
	// Mesh is the mesh-enroll response (assigned podCIDR + mesh-egress IP + peer
	// snapshot).
	Mesh netv1.MeshEnrollResponse `json:"mesh"`
}

// TokenVerifier verifies a raw K10 join token (the seam the bootstrap server uses;
// *TokenStore satisfies it).
type TokenVerifier interface {
	// VerifyToken parses and verifies tok, returning nil iff it is a minted,
	// unexpired bootstrap token. ctx is checked eagerly and fails closed: a
	// cancelled request is denied, never granted.
	VerifyToken(ctx context.Context, tok string) error
}

// BundleSource yields the AES-256-GCM-sealed CA bootstrap bundle the server-bootstrap
// endpoint returns (the envelope a joining server decrypts to reconstruct the identical
// CAs). It is a seam so the production impl (seal the live hierarchy, or read the
// datastore bootstrap key) stays out of this package — keeping bootstrap free of an
// apiserver-client dependency.
type BundleSource interface {
	// SealedBundle returns the current sealed CA bundle envelope.
	SealedBundle(ctx context.Context) ([]byte, error)
}

// Allocation says what an Enroll did with the cluster's pod-CIDR index space for
// the node it enrolled: it ALLOCATED a fresh index, or it REUSED the one an
// earlier join already assigned that name.
//
// The distinction exists for exactly one caller — a join that fails on the far
// side of the enroll (see Server.releaseFresh). A fresh allocation belongs to the
// failing join and nothing else, so it is released; a reused one belongs to an
// earlier SUCCESSFUL join, and deleting it would strand a live node's pod network
// on a failure that never touched it.
type Allocation int

const (
	// AllocationReused is the node's existing assignment, carried forward. It is
	// the ZERO VALUE deliberately: an enroller that cannot tell the two apart
	// reports "reused", and a reused allocation is never reaped — so the failure
	// mode of an unconverted implementation is a leaked index, never a deleted
	// peer belonging to a running node.
	AllocationReused Allocation = iota
	// AllocationFresh is an index this Enroll carved for a name that held none.
	AllocationFresh
)

// String renders the allocation for logs.
func (a Allocation) String() string {
	if a == AllocationFresh {
		return "fresh"
	}
	return "reused"
}

// Enroller performs the controller-mediated mesh enroll: it assigns the node's
// podCIDR + mesh-egress IP, writes the node's MeshPeer (named == nodeName, so the
// write-guard holds), and returns the current peer snapshot for the node to program
// immediately. The implementation (cmd wiring) holds the apiserver client + the
// podnet allocator, keeping that dependency out of this package.
type Enroller interface {
	// Enroll assigns and writes the node's MeshPeer, reporting whether the
	// assignment was FRESH or REUSED (see Allocation). The report is part of the
	// contract rather than a detail: it is the only thing that tells a failing
	// join whether the peer it is looking at is its own to release.
	Enroll(ctx context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, Allocation, error)
	// ReleaseAllocation deletes the MeshPeer a FRESH Enroll wrote for nodeName,
	// after the join that carved it failed — freeing the pod /24 for the next node
	// instead of burning it. It is idempotent (an already-absent peer is success)
	// and it VERIFIES by list-back that the index is free again, because "the
	// delete returned nil" and "the index can be assigned again" are different
	// claims and only the second one is the point.
	//
	// It removes the MeshPeer ONLY. Unlike Deregister it never touches the Node
	// object: a join that failed at its CSR never got far enough to register one,
	// and a Node that does exist under that name belongs to some earlier join.
	//
	// It runs under the SAME lock as Enroll, so a concurrent join of another node
	// cannot be handed this index between the failure and the release.
	ReleaseAllocation(ctx context.Context, nodeName string) error
	// RefreshEndpoint updates ONLY spec.endpoint on the node's EXISTING MeshPeer.
	// It never creates one: a node whose peer is gone has lost its podCIDR
	// assignment too, and inventing a peer here would hand it an endpoint with no
	// AllowedIPs behind it. That case returns ErrNoMeshPeer, which the handler
	// maps to 404 — the signal for the agent to rejoin.
	RefreshEndpoint(ctx context.Context, nodeName, endpoint string) error
	// Deregister removes the node from the cluster: its MeshPeer FIRST, so the
	// remaining peers drop the tunnel entry for a Mac that is going away, and
	// then its Node object. An object that is already gone is not an error —
	// deregistration is idempotent, because an uninstall can be re-run and an
	// operator may have deleted one half by hand.
	//
	// It is driven by the SERVER's own privileged client, never by the node's
	// credential: a node holds no delete verb on either object, and this verb
	// deliberately does not give it one. What authenticates the request is the
	// node's certificate; what performs the write is the supervisor.
	Deregister(ctx context.Context, nodeName string) error
}
