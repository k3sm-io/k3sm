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

package provider

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"

	"k3sm.io/k3sm/pkg/certs"
)

// KubeletEndpointAuth is the authn + authz posture of the VK node's kubelet HTTP
// endpoint (:10250 — /containerLogs, /exec, /attach, /portForward, /stats,
// /metrics/resource).
//
// It replaces the endpoint's previous posture, which was none: the routes were
// served behind an always-allow authorizer over a TLS listener that asked for no
// client certificate, so identity rested entirely on network reach. The bind is
// the WILDCARD on every server and agent, so that meant anyone who could route a
// packet to the port could exec into any pod on the node.
//
// The model is upstream kubelet's x509 mode (--client-ca-file +
// --authorization-mode=Webhook), with the webhook replaced by a static predicate
// because k3sm's kubelet endpoint has exactly ONE legitimate client:
//
//   - AUTHENTICATION is the TLS handshake. ServingTLS sets
//     tls.RequireAndVerifyClientCert against the cluster's own client-identity CA
//     (the SIGNING CA — the same anchor the apiserver's --client-ca-file trusts and
//     the issuer of every system:node cert), so an unauthenticated request is
//     refused at the handshake and never reaches an HTTP route at all.
//   - AUTHORIZATION is the accepted-identity predicate below. Verifying the chain
//     is NOT sufficient: every joined worker holds a signing-CA-issued
//     CN=system:node:<name> client cert, so a CA-only check would let any node in
//     the cluster exec into any other node's pods. The endpoint therefore admits
//     the ONE identity the cluster PKI mints for this purpose —
//     certs.APIServerKubeletClientCN, the CN the apiserver presents via
//     --kubelet-client-certificate — and denies every other valid holder.
//
// Both halves are load-bearing and are pinned by
// TestKubeletEndpointRequiresClientCert. Nothing here widens what an authorized
// exec may DO: an admitted request still runs through the same runtimed Exec RPC,
// which re-enters the pod's Seatbelt profile and uid/gid drop (runtimed
// pkg/runtime/exec.go, Runtime.Exec → backend.WrapCommand → k3sm-execshim →
// supervisor.RunLaunchSequence). This is an authn fix, not a capability.
type KubeletEndpointAuth struct {
	// clientCAs is the pool a presented client certificate must chain to. It holds
	// the cluster's client-identity (signing) CA and nothing else — never the system
	// trust store, which would let any publicly-issued cert reach the predicate.
	clientCAs *x509.CertPool
	// allowedCN is the single CommonName authorized to drive the endpoint.
	allowedCN string
	// log records denials. Never nil after the constructor.
	log *slog.Logger
}

// ErrNoKubeletClientCA reports that the client-identity CA a node's kubelet
// endpoint must verify against was absent or unparseable. It is deliberately a
// hard, typed failure: without a CA the endpoint can only be served open, which is
// the exact posture this type exists to remove, so every caller fails to start
// instead of degrading. Compare with errors.Is.
var ErrNoKubeletClientCA = errors.New("provider: no client-identity CA for the kubelet endpoint (on a rolling upgrade this is the expected fail-closed result of starting a new agent against a not-yet-upgraded server — upgrade the server first)")

// NewKubeletEndpointAuth builds the kubelet endpoint's auth posture from the
// PEM-encoded client-identity CA (the cluster's SIGNING CA: <workDir>/tls/signing-ca.crt
// on a server, JoinResult.ClientCAPEM on a joined worker). log may be nil (the
// default logger is used).
//
// It fails when clientCAPEM contains no parseable certificate. An empty pool would
// make tls.RequireAndVerifyClientCert reject EVERY client — including the
// apiserver — so the node would register and then serve nothing; failing here
// reports the real fault (missing PKI material) at the place it can be fixed.
func NewKubeletEndpointAuth(clientCAPEM []byte, log *slog.Logger) (*KubeletEndpointAuth, error) {
	if len(clientCAPEM) == 0 {
		return nil, ErrNoKubeletClientCA
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCAPEM) {
		return nil, ErrNoKubeletClientCA
	}
	if log == nil {
		log = slog.Default()
	}
	return &KubeletEndpointAuth{
		clientCAs: pool,
		allowedCN: certs.APIServerKubeletClientCN,
		log:       log,
	}, nil
}

// ServingTLS returns a copy of base that REQUIRES and VERIFIES a client
// certificate against the cluster's client-identity CA. base carries the node's
// serving keypair and minimum version; it is cloned, never mutated, so a caller's
// config cannot be silently re-pointed.
//
// This is the authentication half. It is enforced by the TLS stack before any
// bytes reach an HTTP handler, which is why a client with no certificate is
// rejected at the handshake rather than by a route returning 401.
func (a *KubeletEndpointAuth) ServingTLS(base *tls.Config) *tls.Config {
	cfg := base.Clone()
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = a.clientCAs
	return cfg
}

// AuthorizedIdentity reports whether cs carries the one identity permitted to
// drive the kubelet endpoint.
//
// It is the authorization half — the who-may-exec predicate — and it fails closed:
//
//   - no TLS state, or no VERIFIED chain, is a denial. It reads VerifiedChains,
//     not PeerCertificates, so the verdict is defined only when the TLS stack
//     actually verified the peer against ClientCAs; a listener misconfigured back
//     to tls.NoClientCert or tls.RequestClientCert therefore denies everything
//     instead of silently trusting an unchecked leaf.
//   - the verified leaf's CommonName must equal the CN the cluster PKI mints for
//     the apiserver's kubelet client. Chain validity alone is NOT enough: the same
//     CA issues every worker's system:node identity.
func (a *KubeletEndpointAuth) AuthorizedIdentity(cs *tls.ConnectionState) bool {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return false
	}
	return cs.VerifiedChains[0][0].Subject.CommonName == a.allowedCN
}

// Handler wraps next with the accepted-identity check, so every provider route on
// the kubelet endpoint — logs, exec, attach, port-forward, stats — goes through
// one predicate. It is the handler vkadapter.NodeConfig.AuthorizeHandler takes,
// and NewNode refuses to serve the provider routes without it.
//
// A request that authenticated (it completed the mTLS handshake) but carries an
// identity the endpoint does not admit gets 403; a request with no verified peer
// at all gets 401. The split mirrors the kubelet's own authn/authz boundary and
// keeps "you are nobody" distinguishable from "you are somebody else" in an
// operator's logs.
func (a *KubeletEndpointAuth) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			a.log.Warn("kubelet endpoint: denied an unauthenticated request",
				"path", r.URL.Path, "remote", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !a.AuthorizedIdentity(r.TLS) {
			a.log.Warn("kubelet endpoint: denied a client certificate whose identity is not the apiserver's",
				"path", r.URL.Path, "remote", r.RemoteAddr,
				"presented-cn", r.TLS.VerifiedChains[0][0].Subject.CommonName,
				"want-cn", a.allowedCN)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
