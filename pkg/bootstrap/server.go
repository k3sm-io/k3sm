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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// DefaultNodeCertTTL is how long an issued node client / kubelet-serving cert is
// valid. A year matches the kubelet client-cert lifetime; automatic rotation is
// not implemented.
const DefaultNodeCertTTL = 365 * 24 * time.Hour

// ServerConfig configures the supervisor-side bootstrap Server.
type ServerConfig struct {
	// ClusterCA is the serving anchor (the pin) and the issuer of kubelet-serving
	// certs.
	ClusterCA *certs.CA
	// SigningCA issues the system:node client certs.
	SigningCA *certs.CA
	// Tokens verifies the join token.
	Tokens TokenVerifier
	// NodePasswords binds + verifies the anti-impersonation node-password.
	NodePasswords NodePasswordStore
	// SelfNodeName is the node name of the CONTROL-PLANE PROCESS SERVING THIS
	// ENDPOINT, and a join claiming it is refused outright (handleJoin).
	//
	// It is per-process on purpose. Every control-plane process protects ITS OWN
	// name, so in HA each server carries a different value here and none of them
	// needs a cluster-wide list of server names to keep its own identity: a
	// sibling's name is protected by that sibling's binding, not by this one.
	//
	// Empty leaves the name guard OFF (NewServer says so once at start). It is
	// deliberately not a hard construction error, because a supervisor that
	// refuses to serve is a worse failure than one whose first layer is absent
	// while the node-password binding and the enroller's index guard still stand.
	SelfNodeName string
	// Enroller performs the controller-mediated mesh enroll (MeshPeer write + peer
	// snapshot).
	Enroller Enroller
	// NodeCertTTL is the issued-cert validity; DefaultNodeCertTTL when zero.
	NodeCertTTL time.Duration
	// APIServers are the control-plane apiserver endpoints advertised to a joining node
	// in the JoinResponse (for its client-side load-balancer). Optional.
	APIServers []string
	// ServerAuth authorizes the CA-bundle endpoint (BundlePath) to the SERVER-class
	// token only. When nil (single-node / non-HA), the bundle endpoint is not served.
	ServerAuth ServerAuthorizer
	// Bundle yields the sealed CA bundle the bundle endpoint returns. When nil, the
	// bundle endpoint is not served. Both ServerAuth and Bundle must be set to enable it.
	Bundle BundleSource
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
	// Now is the clock the join rate limiters (per-token and pre-auth) refill
	// against — this package's injected-clock idiom, the one NewTokenStore
	// takes. time.Now when nil; a test advances it instead of sleeping out a
	// refill window.
	Now func() time.Time
}

// Server is the supervisor-side bootstrap endpoint a joining worker hits over a
// mesh-reachable TLS listener that presents [serving-leaf, ClusterCA] (so the join
// client's CA-hash pin verifies). It authenticates the join token, binds the
// node-password, drives the controller-mediated mesh enroll — which ASSIGNS this
// node's mesh address — and signs the node's CSRs into a system:node identity bound
// to the authenticated node + that assigned address.
type Server struct {
	cfg ServerConfig
	// joins bounds how fast ONE token may drive the expensive, post-authentication
	// half of handleJoin (see joinRateLimiter).
	joins *joinRateLimiter
	// preauth bounds anonymous join volume per source address and in total,
	// ahead of the token verification's bcrypt cost (see preAuthLimiter).
	preauth *preAuthLimiter
}

// NewServer validates cfg and returns the bootstrap Server. It errors if any
// required dependency (the CAs, token verifier, node-password store, or enroller) is
// missing — fail fast, no embedded fallback.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch {
	case cfg.ClusterCA == nil:
		return nil, errors.New("bootstrap server: ClusterCA is required")
	case cfg.SigningCA == nil:
		return nil, errors.New("bootstrap server: SigningCA is required")
	case cfg.Tokens == nil:
		return nil, errors.New("bootstrap server: Tokens verifier is required")
	case cfg.NodePasswords == nil:
		return nil, errors.New("bootstrap server: NodePasswords store is required")
	case cfg.Enroller == nil:
		return nil, errors.New("bootstrap server: Enroller is required")
	}
	if cfg.NodeCertTTL <= 0 {
		cfg.NodeCertTTL = DefaultNodeCertTTL
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if strings.TrimSpace(cfg.SelfNodeName) == "" {
		// Said ONCE, at construction, rather than per request: an unconfigured
		// guard is a wiring defect that does not vary with traffic, and a
		// per-request line would bury it. Loud here beats silent everywhere.
		cfg.Logger.Warn("the bootstrap server has no SelfNodeName: a join claiming this control plane's own node name is not refused by name, leaving only the node-password binding and the enroller's index guard behind it")
	}
	return &Server{cfg: cfg, joins: newJoinRateLimiter(cfg.Now), preauth: newPreAuthLimiter(cfg.Now)}, nil
}

// Handler returns the bootstrap HTTP mux (CACertPath + JoinPath +
// MeshEndpointPath + DeregisterPath, plus the server-bootstrap CA-bundle endpoint
// when ServerAuth + Bundle are configured).
//
// The routes do NOT share an authentication scheme, and that is deliberate:
// /cacert, /join and /server-bootstrap are reached by a node that holds no cluster
// certificate yet, so they authenticate a token (or nothing, for the public CA);
// MeshEndpointPath and DeregisterPath are reached only by a node that has already
// joined, so they authenticate that node's own certificate and accept no token at
// all. Those two are the cluster's whole node-certificate-authenticated surface:
// one moves a node's endpoint, the other removes the node, and neither can name
// any node but the one the certificate identifies.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CACertPath, s.handleCACert)
	mux.HandleFunc(JoinPath, s.handleJoin)
	mux.HandleFunc(MeshEndpointPath, s.handleMeshEndpoint)
	mux.HandleFunc(DeregisterPath, s.handleDeregister)
	if s.cfg.ServerAuth != nil && s.cfg.Bundle != nil {
		mux.HandleFunc(BundlePath, s.handleBundle)
	}
	return mux
}

// handleCACert serves the cluster CA PEM (the anchor a joining node hash-verifies).
func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.cfg.ClusterCA.CertPEM)
}

// handleJoin runs the worker-join exchange. Every rejection is logged at its boundary
// with the failure category (token / node-password / enroll / node-ip-mismatch /
// csr) — the join failures otherwise present identically as "node never Ready".
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 0. PRE-AUTHENTICATION BOUND, identity-blind: per source address and in
	// total (preAuthLimiter). Step 1 pays a bcrypt compare for every well-formed
	// token, and the per-token limiter at step 1b bounds only the
	// POST-authentication work — it cannot key a request until its token is
	// verified. Without this, anonymous volume buys bcrypt CPU without limit.
	//
	// ORDERING INVARIANT: this must stay ahead of the body decode and ahead of
	// VerifyToken. A later "cheaper checks first" reorder that moves it below
	// step 1 reopens the flood cost, and one that moves it below the decode lets
	// a flood buy a 1 MiB JSON parse per request. The key is RemoteAddr only,
	// never a client-settable header. Refusals log at Debug: a flood refused
	// here must not turn into a log flood.
	if ok, retryAfter := s.preauth.allow(preAuthSourceKey(r.RemoteAddr)); !ok {
		secs := retryAfterSeconds(retryAfter)
		s.cfg.Logger.Debug("join rejected", "reason", "pre-auth-rate-limit",
			"retryAfterSeconds", secs, "remote", r.RemoteAddr)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, fmt.Sprintf("join refused: too many join requests; retry in %ds", secs),
			http.StatusTooManyRequests)
		return
	}

	var req JoinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode join request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req = req.WithDefaults()

	// 1. Bootstrap token (authorizes the join; NOT the admin identity).
	if err := s.cfg.Tokens.VerifyToken(r.Context(), req.Token); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "token", "node", req.NodeName, "err", err)
		http.Error(w, "invalid join token", http.StatusUnauthorized)
		return
	}
	if req.NodeName == "" {
		http.Error(w, "join request missing nodeName", http.StatusBadRequest)
		return
	}

	// 1a. THIS CONTROL PLANE'S OWN NAME IS NOT JOINABLE, and that is decided
	// before anything identity-bearing happens — before the node-password store
	// is consulted, before the enroll writes a MeshPeer, before a certificate is
	// signed.
	//
	// The server's node name is derived from its hostname and is not a secret, so
	// without this a holder of an ordinary worker join token could simply ask to
	// BE the control plane: nothing had ever bound the server's own name in the
	// node-password store (the server enrolls itself directly and never goes
	// through this handler), so first-write-wins would hand the binding to the
	// caller, the enroll would reuse the server's existing index-0 assignment,
	// the MeshPeer write would replace the control plane's public key and
	// endpoint with the caller's, and the handler would then sign a
	// system:node:<server> client certificate for it.
	//
	// The refusal is by NAME, so it costs nothing and cannot be raced. The other
	// two layers — the server binding its own node-password at start, and the
	// enroller refusing a join-path write over the peer that holds the
	// control-plane index — stand behind it for the cases a name cannot see: an
	// HA sibling's name, and any path that ever reaches the enroller without
	// passing here.
	if selfNameClaimed(s.cfg.SelfNodeName, req.NodeName) {
		s.cfg.Logger.Warn("join rejected", "reason", "self-node-name",
			"node", req.NodeName, "selfNodeName", s.cfg.SelfNodeName, "remote", r.RemoteAddr)
		// The body says only that the name cannot be joined. The caller already
		// knows the name it sent; it learns nothing here about which names are
		// taken, what this node is called, or how far the request got.
		http.Error(w, "join refused: that node name is not available", http.StatusForbidden)
		return
	}

	// 1b. PER-TOKEN RATE LIMIT. Everything below this line is the expensive half
	// of a join — the node-password bind, the CSR parse and policy checks, the
	// mesh enroll's index carve and the release that gives it back, and up to two
	// signatures. A holder of one valid worker token could otherwise drive that
	// round trip as fast as the network allows, enrolling and releasing without
	// bound, and every one of those requests is authenticated, so nothing above
	// would refuse it.
	//
	// The POSITION is the design, in both directions:
	//   - AFTER the token verification and the self-node-name refusal. That
	//     refusal is a string compare that costs nothing, and charging a
	//     legitimate token's budget for someone else's refused request would let
	//     the limiter be turned into the denial of service it exists to prevent.
	//   - BEFORE NodePasswords.Ensure, so a refusal can never take the
	//     first-write-wins name binding, and nothing downstream of it runs.
	//
	// The key is the token id ALONE (joinTokenID): the node name is the caller's
	// to rotate per request, so including it would hand out a fresh bucket every
	// time and limit nothing.
	tokenID := joinTokenID(req.Token)
	if ok, retryAfter := s.joins.allow(tokenID); !ok {
		secs := retryAfterSeconds(retryAfter)
		s.cfg.Logger.Warn("join rejected", "reason", "rate-limit", "node", req.NodeName,
			"token", tokenID, "retryAfterSeconds", secs, "remote", r.RemoteAddr)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, fmt.Sprintf("join refused: too many join attempts for this token; retry in %ds", secs),
			http.StatusTooManyRequests)
		return
	}

	// 2. node-password (anti-impersonation: first-write-wins name binding).
	if err := s.cfg.NodePasswords.Ensure(r.Context(), req.NodeName, req.NodePassword); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "node-password", "node", req.NodeName, "err", err)
		http.Error(w, "node-password rejected", http.StatusForbidden)
		return
	}

	// The mesh-enroll must name the same node (cross-node write-guard).
	if err := AuthorizeMeshPeerWrite(req.NodeName, req.Mesh.NodeName); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "mesh-peer-guard", "node", req.NodeName, "err", err)
		http.Error(w, "mesh enroll names a different node", http.StatusForbidden)
		return
	}

	// 3. The CSRs, as far as they can be judged WITHOUT an address: structure,
	// proof of possession, key, and the SAN policy fixed by the node's NAME
	// (CheckNodeCSR). Everything decidable here is decided HERE, before the
	// enroll, because the enroll ALLOCATES: a rejection on its far side leaves a
	// MeshPeer and a pod /24 behind, and index recycling across node deletes does
	// not exist — so a token holder could burn the cluster's index space with
	// joins that abort at a CSR it never meant to have signed. All that is left
	// after the enroll is the signer's own judgement about the assigned address.
	clientCSR, err := parseCSR(req.ClientCSRPEM)
	if err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "csr-parse", "node", req.NodeName, "err", err)
		http.Error(w, "parse client CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := CheckNodeCSR(clientCSR, req.NodeName); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "csr-denied", "node", req.NodeName, "err", err)
		http.Error(w, "client CSR denied", http.StatusForbidden)
		return
	}
	var servingCSR *x509.CertificateRequest
	if req.ServingCSRPEM != "" {
		servingCSR, err = parseCSR(req.ServingCSRPEM)
		if err != nil {
			s.cfg.Logger.Warn("join rejected", "reason", "serving-csr-parse", "node", req.NodeName, "err", err)
			http.Error(w, "parse serving CSR: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := CheckNodeCSR(servingCSR, req.NodeName); err != nil {
			s.cfg.Logger.Warn("join rejected", "reason", "serving-csr-denied", "node", req.NodeName, "err", err)
			http.Error(w, "serving CSR denied", http.StatusForbidden)
			return
		}
	}

	// 4. Controller-mediated mesh enroll (writes THIS node's MeshPeer + peer
	// snapshot). It runs BEFORE any certificate is signed because it is what
	// DECIDES this node's mesh address — reusing the assignment already held under
	// this node name, else carving the lowest free index — and that address, not
	// anything the client asked for, is the InternalIP the issued certificates
	// name. Signing first would mean signing for an address the allocator had not
	// yet agreed to.
	//
	// From here to the response, EVERY failure path releases a FRESH allocation
	// (see releaseFresh): the index this join carved is the index this join must
	// give back when it does not finish.
	meshResp, alloc, err := s.cfg.Enroller.Enroll(r.Context(), req.NodeName, req.Mesh)
	if err != nil {
		// An enroll can fail with the peer already written (its own list-back, say),
		// in which case it reports the fresh allocation it made — so this is a reap
		// site like every other one below, not a no-op.
		s.releaseFresh(r, req.NodeName, alloc, "enroll-write")
		s.cfg.Logger.Error("join rejected", "reason", "enroll-write", "node", req.NodeName, "err", err)
		http.Error(w, "mesh enroll failed", http.StatusInternalServerError)
		return
	}
	assignedIP, err := netip.ParseAddr(strings.TrimSpace(meshResp.MeshIP))
	if err != nil {
		s.releaseFresh(r, req.NodeName, alloc, "no-assigned-address")
		s.cfg.Logger.Error("join rejected", "reason", "no-assigned-address", "node", req.NodeName, "meshIP", meshResp.MeshIP, "err", err)
		http.Error(w, "mesh enroll assigned no usable node address", http.StatusInternalServerError)
		return
	}

	// 4a. The OPTIONAL equality gate on the client's declared address. The
	// assignment above is authoritative either way: this is not where the address
	// is chosen, it is where an operator's stated expectation is checked against
	// the choice. A mismatch is refused HERE — before anything is signed — so a
	// client can never obtain a certificate naming an address the allocator gave
	// some other node. The message names the two addresses in play and nothing
	// else about the allocator's state.
	if req.NodeIP != "" {
		requested, perr := netip.ParseAddr(strings.TrimSpace(req.NodeIP))
		if perr != nil {
			s.releaseFresh(r, req.NodeName, alloc, "node-ip-unparseable")
			http.Error(w, fmt.Sprintf("nodeIP %q is not an IP address", req.NodeIP), http.StatusBadRequest)
			return
		}
		if requested != assignedIP {
			s.releaseFresh(r, req.NodeName, alloc, "node-ip-mismatch")
			s.cfg.Logger.Warn("join rejected", "reason", "node-ip-mismatch", "node", req.NodeName, "requested", requested.String(), "assigned", assignedIP.String())
			http.Error(w, fmt.Sprintf(
				"join refused: this node's address is assigned by the control plane: %s was requested, but this node is assigned %s (drop --node-ip, or pass %s)",
				requested, assignedIP, assignedIP), http.StatusConflict)
			return
		}
	}

	id := NodeIdentity{NodeName: req.NodeName, InternalIP: assignedIP.String()}

	// 5. The CSRs → a system:node client cert (signing CA) and an optional
	// kubelet-serving cert (cluster CA → --kubelet-certificate-authority), both
	// SAN-bound to the assigned address. This is all that is left of the CSRs:
	// they were parsed and shape-checked in step 3, so what can still fail here is
	// the address-dependent SAN check and the signer itself.
	clientCert, err := ApproveAndSignNodeCSR(s.cfg.SigningCA, clientCSR, id, s.cfg.NodeCertTTL)
	if err != nil {
		s.releaseFresh(r, req.NodeName, alloc, "csr-denied")
		s.cfg.Logger.Warn("join rejected", "reason", "csr-denied", "node", req.NodeName, "err", err)
		http.Error(w, "client CSR denied", http.StatusForbidden)
		return
	}

	var servingCert []byte
	if servingCSR != nil {
		servingCert, err = ApproveAndSignKubeletServing(s.cfg.ClusterCA, servingCSR, id, s.cfg.NodeCertTTL)
		if err != nil {
			s.releaseFresh(r, req.NodeName, alloc, "serving-csr-denied")
			s.cfg.Logger.Warn("join rejected", "reason", "serving-csr-denied", "node", req.NodeName, "err", err)
			http.Error(w, "serving CSR denied", http.StatusForbidden)
			return
		}
	}

	resp := JoinResponse{
		SchemaVersion:         JoinSchemaVersion,
		NodeName:              req.NodeName,
		NodeIP:                assignedIP.String(),
		ClusterCAPEM:          string(s.cfg.ClusterCA.CertPEM),
		ClientCAPEM:           string(s.cfg.SigningCA.CertPEM),
		NodeClientCertPEM:     string(clientCert),
		KubeletServingCertPEM: string(servingCert),
		APIServers:            s.cfg.APIServers,
		Mesh:                  meshResp,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.cfg.Logger.Error("encode join response", "node", req.NodeName, "err", err)
		return
	}
	s.cfg.Logger.Info("node joined", "node", req.NodeName, "nodeIP", assignedIP.String(), "podCIDR", meshResp.PodCIDR)
}

// releaseTimeout bounds the reap of a failed join's mesh allocation. It is short
// because the join it belongs to has already failed and the handler is holding the
// response open; it is not zero because the delete + list-back is a real apiserver
// round trip.
const releaseTimeout = 10 * time.Second

// releaseFresh gives back the mesh index a failing join carved — and only that: a
// REUSED allocation belongs to an earlier SUCCESSFUL join, and deleting its peer
// because a later join's CSR was bad would strand a live node's pod network on a
// failure that never touched it. A reused allocation is the zero value, so an
// enroller that cannot tell the two apart leaks an index rather than deleting
// someone's peer.
//
// The whole Allocation is handed back to the enroller, not just the node name: it
// carries the id of the write this join made, which is the only thing that
// distinguishes the peer this join wrote from the one a LATER enroll of the same
// node name wrote in the meantime (see Allocation).
//
// The release runs through the enroller, under the SAME lock the assignment took,
// so a concurrent join of another node cannot be handed this index between the
// failure and the release.
//
// It deliberately does NOT inherit the request's cancellation. A client that hangs
// up the instant its CSR is refused would otherwise defeat its own reap and keep
// the index — which is precisely the burn this exists to prevent, performed on
// purpose. A reap that still fails is LOGGED and nothing more: the join is already
// failing, and the caller must see its own error, not this one.
func (s *Server) releaseFresh(r *http.Request, nodeName string, alloc Allocation, reason string) {
	if !alloc.Fresh {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), releaseTimeout)
	defer cancel()
	if err := s.cfg.Enroller.ReleaseAllocation(ctx, nodeName, alloc); err != nil {
		s.cfg.Logger.Error("the mesh allocation of a failed join was not released",
			"node", nodeName, "reason", reason, "err", err)
		return
	}
	s.cfg.Logger.Info("released the mesh allocation of a failed join", "node", nodeName, "reason", reason)
}

// handleBundle serves the AES-256-GCM-sealed CA bootstrap bundle to a joining
// control-plane SERVER. It authorizes the SERVER-class token ONLY (a worker
// token is rejected at AuthorizeServerToken — ErrNotServerToken), then returns the
// sealed envelope. A leaked worker token can therefore never reconstruct the signing
// CA. Registered only when ServerAuth + Bundle are configured (the HA supervisor).
func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" {
		http.Error(w, "missing server bootstrap token", http.StatusUnauthorized)
		return
	}
	if err := s.cfg.ServerAuth.AuthorizeServerToken(r.Context(), token); err != nil {
		s.cfg.Logger.Warn("server-bootstrap rejected", "reason", "server-token", "err", err)
		http.Error(w, "server bootstrap token rejected", http.StatusForbidden)
		return
	}
	sealed, err := s.cfg.Bundle.SealedBundle(r.Context())
	if err != nil {
		s.cfg.Logger.Error("server-bootstrap seal", "err", err)
		http.Error(w, "seal bundle failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
	s.cfg.Logger.Info("served CA bootstrap bundle to a joining server")
}

// bearerToken extracts the credential from the Authorization header, tolerating a bare
// value or a "Bearer " prefix.
func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(h, prefix))
	}
	return h
}

// selfNameClaimed reports whether a join request claims the control plane's own
// node name. An empty selfNodeName matches nothing — the guard is off, which
// NewServer has already said out loud.
//
// The comparison is trimmed and CASE-INSENSITIVE because it is a refusal, not a
// lookup: a Kubernetes node name is lowercase RFC-1123 by rule, so a request
// differing only in case is never a legitimate second node, and matching it
// exactly would leave the cheapest possible bypass of this whole guard.
func selfNameClaimed(selfNodeName, requested string) bool {
	self := strings.TrimSpace(selfNodeName)
	if self == "" {
		return false
	}
	return strings.EqualFold(self, strings.TrimSpace(requested))
}

// parseCSR decodes a PEM CERTIFICATE REQUEST and parses it.
func parseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate request: %w", err)
	}
	return csr, nil
}
