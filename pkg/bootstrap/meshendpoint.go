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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// ErrNoMeshPeer reports that the node has no MeshPeer to refresh. It is the
// enroller's signal that the node must rejoin rather than retry: without a peer
// there is no podCIDR assignment and no AllowedIPs, so an endpoint alone would
// program nothing. Compare with errors.Is.
var ErrNoMeshPeer = errors.New("bootstrap: this node has no MeshPeer to refresh (rejoin the cluster)")

// ErrNoClientIdentityCA reports that the cluster's client-identity CA, against
// which the bootstrap listener verifies a node certificate, was absent or
// unparseable.
//
// It is a hard, typed failure rather than a degraded start, mirroring
// provider.ErrNoKubeletClientCA: with no pool the listener could only be built
// with no ClientCAs at all, and tls.VerifyClientCertIfGiven would then fail every
// presented certificate while still completing the handshake — the endpoint-refresh
// verb would 401 forever and look like a network fault. Compare with errors.Is.
var ErrNoClientIdentityCA = errors.New("bootstrap: no client-identity CA for the bootstrap listener")

// ClientIdentityCAPool builds the pool a node's client certificate must chain to
// on the bootstrap listener: the cluster's SIGNING CA, and nothing else. The system
// trust store is deliberately absent — any publicly-issued certificate would
// otherwise reach the endpoint-refresh verb's identity checks.
func ClientIdentityCAPool(clientCAPEM []byte) (*x509.CertPool, error) {
	if len(clientCAPEM) == 0 {
		return nil, ErrNoClientIdentityCA
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, ErrNoClientIdentityCA
	}
	return pool, nil
}

// ListenerTLSConfig returns the TLS config the bootstrap listener serves: the
// [serving-leaf, cluster-CA] chain a joining node's CA-hash pin verifies, plus
// OPTIONAL client-certificate verification against the cluster's client-identity
// CA.
//
// tls.VerifyClientCertIfGiven is the exact posture this listener needs and the
// reason the handler's checks are written the way they are. Join, /cacert and
// /server-bootstrap are reached by a node that HAS no certificate yet — requiring
// one would break every first join — so the handshake must complete without one.
// A certificate that IS presented is verified here; one that fails verification
// aborts the handshake. What this config can never express is "this route needs a
// certificate": that is Server.handleMeshEndpoint's job, and it reads
// VerifiedChains (never PeerCertificates) precisely because optional mTLS
// mistaken for enforced mTLS is how such a verb quietly becomes anonymous.
func ListenerTLSConfig(serving tls.Certificate, clientCAPEM []byte) (*tls.Config, error) {
	pool, err := ClientIdentityCAPool(clientCAPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serving},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}, nil
}

// handleMeshEndpoint serves the endpoint-refresh verb.
//
// Authentication is the NODE'S OWN CLIENT CERTIFICATE, not the join token. The
// token is TTL-bounded (24 h by default), so a refresh gated on it would stop
// working after a day and silently restore the staleness this verb exists to
// remove; the node's system:node certificate is the credential that lives as long
// as the node does. Four checks, in order, and each denies a different thing:
//
//  1. a VERIFIED chain must exist — r.TLS.VerifiedChains, never PeerCertificates,
//     so a listener refactored back to tls.RequestClientCert denies everything
//     instead of trusting an unchecked leaf (401);
//  2. the leaf must carry O=system:nodes — the group the cluster PKI mints only
//     for node identities, so the apiserver's own kubelet client (no Organization)
//     cannot drive this verb (403);
//  3. the leaf's CN must be system:node:<the node named in the body> — every
//     joined worker holds a signing-CA-issued certificate, so chain validity alone
//     would let any node move any other node's endpoint (403);
//  4. AuthorizeMeshPeerWrite, the same permanent self-scoping guard the join path
//     runs, because this is the second write path into a node's MeshPeer and the
//     guard is what makes both of them self-scoped (403).
//
// Only then is the endpoint written, and only spec.endpoint of an EXISTING peer.
func (s *Server) handleMeshEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "no-verified-client-cert", "remote", r.RemoteAddr)
		http.Error(w, "a verified node client certificate is required", http.StatusUnauthorized)
		return
	}
	leaf := r.TLS.VerifiedChains[0][0]

	var req MeshEndpointRefreshRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode mesh endpoint refresh: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !containsGroup(leaf.Subject.Organization, systemNodesGroup) {
		s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "not-a-node-identity",
			"cn", leaf.Subject.CommonName, "o", leaf.Subject.Organization)
		http.Error(w, "the presented identity is not a node", http.StatusForbidden)
		return
	}
	certNode := strings.TrimPrefix(leaf.Subject.CommonName, systemNodePrefix)
	if certNode == leaf.Subject.CommonName || certNode == "" {
		s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "not-a-node-cn", "cn", leaf.Subject.CommonName)
		http.Error(w, "the presented identity is not a node", http.StatusForbidden)
		return
	}
	if err := AuthorizeMeshPeerWrite(certNode, req.NodeName); err != nil {
		s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "mesh-peer-guard",
			"cert-node", certNode, "body-node", req.NodeName, "err", err)
		http.Error(w, "the request names a different node", http.StatusForbidden)
		return
	}
	if err := ValidateMeshEndpoint(req.Endpoint); err != nil {
		s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "endpoint-syntax",
			"node", req.NodeName, "endpoint", req.Endpoint, "err", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.cfg.Enroller.RefreshEndpoint(r.Context(), req.NodeName, req.Endpoint); err != nil {
		if errors.Is(err, ErrNoMeshPeer) {
			s.cfg.Logger.Warn("mesh endpoint refresh rejected", "reason", "no-such-peer", "node", req.NodeName)
			http.Error(w, "no MeshPeer for this node; rejoin the cluster", http.StatusNotFound)
			return
		}
		s.cfg.Logger.Error("mesh endpoint refresh failed", "node", req.NodeName, "endpoint", req.Endpoint, "err", err)
		http.Error(w, "mesh endpoint refresh failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// containsGroup reports whether groups contains want.
func containsGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}

// ValidateMeshEndpoint rejects an endpoint that is not a host:port pair with a
// port in 1–65535.
//
// It states, for a payload that carries no public key, the SAME syntax rule
// netv1.MeshEnrollRequest.Validate applies to the join path, so a malformed value
// is a 400 at the edge instead of a 500 from the write. It is not the
// authoritative check: the enroller assembles the updated MeshPeerSpec and runs
// netv1's own Validate before the PUT, which is where apis owns the rule. And it
// is SYNTAX only — no string can prove an address is reachable, routable, or
// genuinely the publishing node's; the certificate check above is what binds the
// write to a node.
func ValidateMeshEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("mesh endpoint refresh: missing endpoint")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("mesh endpoint refresh: endpoint %q is not host:port", endpoint)
	}
	if host == "" {
		return fmt.Errorf("mesh endpoint refresh: endpoint %q has an empty host", endpoint)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("mesh endpoint refresh: endpoint %q has no port in 1-65535", endpoint)
	}
	return nil
}

// NodeIdentityClient returns the HTTP client a JOINED node uses to call
// MeshEndpointPath: it presents the node's own system:node keypair, and it
// verifies the server exactly as the join did — a CA-hash pin, not the system
// trust store and not insecure-skip-tls-verify.
//
// The pin is RE-DERIVED from the cluster CA the node persisted (certs.CertPin),
// never carried over from the join token. Retaining the token to keep a pin alive
// would leave a cluster-joining credential on disk for the lifetime of the node,
// for a value that the CA certificate — public material the node already
// trusts — yields exactly.
func NodeIdentityClient(clusterCAPEM, clientCertPEM, clientKeyPEM []byte) (*http.Client, error) {
	pin, err := certs.CertPin(clusterCAPEM)
	if err != nil {
		return nil, fmt.Errorf("derive the cluster CA pin for the mesh endpoint refresh: %w", err)
	}
	pair, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load this node's client keypair for the mesh endpoint refresh: %w", err)
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{pair},
				// Disables ONLY Go's default verification; VerifyConnection below
				// re-imposes real verification against the pinned CA.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					return certs.VerifyPinnedChain(pin, cs.PeerCertificates)
				},
			},
		},
	}, nil
}

// RefreshMeshEndpoint POSTs this node's new wireguard endpoint to the supervisor.
// serverURL is the bootstrap base URL (https://<host>:9345); client must present
// the node's own certificate (NodeIdentityClient).
//
// A 404 is returned as ErrNoMeshPeer so the caller can tell "the server does not
// know this node" — rejoin — from a transient failure, which is retried on the
// next tick.
func RefreshMeshEndpoint(ctx context.Context, client *http.Client, serverURL, nodeName, endpoint string) error {
	body, err := json.Marshal(MeshEndpointRefreshRequest{NodeName: nodeName, Endpoint: endpoint})
	if err != nil {
		return fmt.Errorf("marshal mesh endpoint refresh: %w", err)
	}
	url := strings.TrimRight(serverURL, "/") + MeshEndpointPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build mesh endpoint refresh: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post mesh endpoint refresh to %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: the server has no MeshPeer for %q", ErrNoMeshPeer, nodeName)
	}
	if resp.StatusCode/100 != 2 {
		msg := make([]byte, 512)
		n, _ := resp.Body.Read(msg)
		return fmt.Errorf("mesh endpoint refresh rejected (%s): %s", resp.Status, strings.TrimSpace(string(msg[:n])))
	}
	return nil
}
