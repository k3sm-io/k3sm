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
	// cluster + signing CAs (M6.1, DESIGN §5c).
	BundlePath = "/v1-k3sm/server-bootstrap"
)

// JoinSchemaVersion stamps the k3sm-internal join exchange payloads (JoinRequest /
// JoinResponse). These wrap the apis net/v1 mesh-enroll payloads, which carry their
// own version stamp; both are version-stamped from day one so an M4+ node-by-node
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
	// NodeIP is the node's advertised InternalIP (the only IP SAN the CSR approver
	// permits).
	NodeIP string `json:"nodeIP"`
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

// JoinResponse is the bootstrap endpoint's reply: the cluster CA the node now trusts
// for the apiserver, its issued certs, and the mesh-enroll snapshot it programs
// immediately.
type JoinResponse struct {
	// SchemaVersion stamps this payload (JoinSchemaVersion).
	SchemaVersion int32 `json:"schemaVersion"`
	// NodeName is the joining node's name (echoed back).
	NodeName string `json:"nodeName"`
	// ClusterCAPEM is the cluster CA the node embeds in its kubeconfig's
	// certificate-authority-data to verify the apiserver going forward.
	ClusterCAPEM string `json:"clusterCAPEM"`
	// NodeClientCertPEM is the issued CN=system:node:<name>, O=system:nodes client
	// cert (the node pairs it with the private key it kept).
	NodeClientCertPEM string `json:"nodeClientCertPEM"`
	// KubeletServingCertPEM is the issued kubelet-serving cert (cluster CA); may be
	// empty if no serving CSR was submitted.
	KubeletServingCertPEM string `json:"kubeletServingCertPEM,omitempty"`
	// APIServers are the control-plane apiserver endpoints (host:port) the joining
	// node's client-side load-balancer health-checks + targets, so a server death fails
	// over without re-pointing the kubeconfig (M6.1). A single-server cluster carries
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
	// unexpired bootstrap token.
	VerifyToken(tok string) error
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

// Enroller performs the controller-mediated mesh enroll: it assigns the node's
// podCIDR + mesh-egress IP, writes the node's MeshPeer (named == nodeName, so the
// write-guard holds), and returns the current peer snapshot for the node to program
// immediately. The implementation (cmd wiring) holds the apiserver client + the
// podnet allocator, keeping that dependency out of this package.
type Enroller interface {
	Enroll(ctx context.Context, nodeName string, req netv1.MeshEnrollRequest) (netv1.MeshEnrollResponse, error)
}
