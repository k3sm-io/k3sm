package bootstrap

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// DefaultNodeCertTTL is how long an issued node client / kubelet-serving cert is
// valid. A year matches the kubelet client-cert lifetime; rotation is an M4 concern.
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
	// Enroller performs the controller-mediated mesh enroll (MeshPeer write + peer
	// snapshot).
	Enroller Enroller
	// NodeCertTTL is the issued-cert validity; DefaultNodeCertTTL when zero.
	NodeCertTTL time.Duration
	// APIServers are the control-plane apiserver endpoints advertised to a joining node
	// in the JoinResponse (for its client-side load-balancer). Optional.
	APIServers []string
	// ServerAuth authorizes the M6.1 CA-bundle endpoint (BundlePath) to the SERVER-class
	// token only. When nil (single-node / non-HA), the bundle endpoint is not served.
	ServerAuth ServerAuthorizer
	// Bundle yields the sealed CA bundle the bundle endpoint returns. When nil, the
	// bundle endpoint is not served. Both ServerAuth and Bundle must be set to enable it.
	Bundle BundleSource
	// Logger is the structured logger; a discard logger is used if nil.
	Logger *slog.Logger
}

// Server is the supervisor-side bootstrap endpoint a joining worker hits over a
// mesh-reachable TLS listener that presents [serving-leaf, ClusterCA] (so the join
// client's CA-hash pin verifies). It authenticates the join token, binds the
// node-password, signs the node's CSRs into a system:node identity bound to the
// authenticated node + InternalIP, and drives the controller-mediated mesh enroll.
type Server struct {
	cfg ServerConfig
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
	return &Server{cfg: cfg}, nil
}

// Handler returns the bootstrap HTTP mux (CACertPath + JoinPath, plus the M6.1
// server-bootstrap CA-bundle endpoint when ServerAuth + Bundle are configured).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(CACertPath, s.handleCACert)
	mux.HandleFunc(JoinPath, s.handleJoin)
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
// with the failure category (token / node-password / csr / enroll) — the four join
// failures otherwise present identically as "node never Ready" (docs/m3-plan.md).
func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req JoinRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode join request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req = req.WithDefaults()

	// 1. Bootstrap token (authorizes the join; NOT the admin identity).
	if err := s.cfg.Tokens.VerifyToken(req.Token); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "token", "node", req.NodeName, "err", err)
		http.Error(w, "invalid join token", http.StatusUnauthorized)
		return
	}
	if req.NodeName == "" || req.NodeIP == "" {
		http.Error(w, "join request missing nodeName or nodeIP", http.StatusBadRequest)
		return
	}

	// 2. node-password (anti-impersonation: first-write-wins name binding).
	if err := s.cfg.NodePasswords.Ensure(r.Context(), req.NodeName, req.NodePassword); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "node-password", "node", req.NodeName, "err", err)
		http.Error(w, "node-password rejected", http.StatusForbidden)
		return
	}

	id := NodeIdentity{NodeName: req.NodeName, InternalIP: req.NodeIP}

	// The mesh-enroll must name the same node (cross-node write-guard).
	if err := AuthorizeMeshPeerWrite(req.NodeName, req.Mesh.NodeName); err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "mesh-peer-guard", "node", req.NodeName, "err", err)
		http.Error(w, "mesh enroll names a different node", http.StatusForbidden)
		return
	}

	// 3. HTTP-CSR → system:node client cert (SAN-bound to the authenticated node).
	clientCSR, err := parseCSR(req.ClientCSRPEM)
	if err != nil {
		http.Error(w, "parse client CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	clientCert, err := ApproveAndSignNodeCSR(s.cfg.SigningCA, clientCSR, id, s.cfg.NodeCertTTL)
	if err != nil {
		s.cfg.Logger.Warn("join rejected", "reason", "csr-denied", "node", req.NodeName, "err", err)
		http.Error(w, "client CSR denied", http.StatusForbidden)
		return
	}

	// 3b. Optional kubelet-serving cert (cluster CA → --kubelet-certificate-authority).
	var servingCert []byte
	if req.ServingCSRPEM != "" {
		servingCSR, err := parseCSR(req.ServingCSRPEM)
		if err != nil {
			http.Error(w, "parse serving CSR: "+err.Error(), http.StatusBadRequest)
			return
		}
		servingCert, err = ApproveAndSignKubeletServing(s.cfg.ClusterCA, servingCSR, id, s.cfg.NodeCertTTL)
		if err != nil {
			s.cfg.Logger.Warn("join rejected", "reason", "serving-csr-denied", "node", req.NodeName, "err", err)
			http.Error(w, "serving CSR denied", http.StatusForbidden)
			return
		}
	}

	// 4. Controller-mediated mesh enroll (writes THIS node's MeshPeer + peer snapshot).
	meshResp, err := s.cfg.Enroller.Enroll(r.Context(), req.NodeName, req.Mesh)
	if err != nil {
		s.cfg.Logger.Error("join rejected", "reason", "enroll-write", "node", req.NodeName, "err", err)
		http.Error(w, "mesh enroll failed", http.StatusInternalServerError)
		return
	}

	resp := JoinResponse{
		SchemaVersion:         JoinSchemaVersion,
		NodeName:              req.NodeName,
		ClusterCAPEM:          string(s.cfg.ClusterCA.CertPEM),
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
	s.cfg.Logger.Info("node joined", "node", req.NodeName, "nodeIP", req.NodeIP, "podCIDR", meshResp.PodCIDR)
}

// handleBundle serves the AES-256-GCM-sealed CA bootstrap bundle to a joining
// control-plane SERVER (M6.1). It authorizes the SERVER-class token ONLY (a worker
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
	if err := s.cfg.ServerAuth.AuthorizeServerToken(token); err != nil {
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
