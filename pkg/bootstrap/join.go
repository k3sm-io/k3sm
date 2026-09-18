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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/certs"
)

// JoinOptions configures a worker join (the agent side of the bootstrap exchange).
type JoinOptions struct {
	// Server is the supervisor's mesh-reachable HTTPS base URL (e.g.
	// https://100.64.0.1:6444).
	Server string
	// Token is the K10<caHash>::<user>:<secret> join token; its CA hash pins the
	// server's presented chain.
	Token string
	// NodeName is the name this node claims.
	NodeName string
	// NodeIP is OPTIONAL and is an ASSERTION of the address this node expects to be
	// assigned, never a request for one: the server assigns the mesh address and
	// issues the certificates for it (see JoinRequest.NodeIP). Empty lets the
	// assignment stand, which is the shipped path; a value that differs from the
	// assignment fails the join rather than minting a certificate for an address
	// this node does not hold.
	NodeIP string
	// NodePassword is the anti-impersonation secret (the agent mints + persists it at
	// 0600 once, then reuses it so the first-write-wins binding keeps matching).
	NodePassword string
	// MeshEndpoint is the host:port the node's wireguard is reachable at (advertised
	// to peers). It must be an UNDERLAY address: a peer dials it to OPEN the
	// handshake, so an address inside the mesh is unreachable by definition. The
	// agent derives it from the source address of this join's own connection (see
	// underlayMeshEndpoint).
	MeshEndpoint string
	// RequestedPodCIDR is an optional requested pod /24; empty asks the server to
	// assign one.
	RequestedPodCIDR string
	// WGPrivateKeyB64 is this node's PERSISTED wireguard private key, whose public
	// half is enrolled. Supplying it is how a node keeps ONE mesh identity across
	// restarts: a key minted per join rotates the public key every peer has
	// programmed, so each restart blackholes this node until every peer
	// re-reconciles. Empty mints a fresh keypair (the zero value stays usable), and
	// an unusable value fails the join rather than falling through to a mint.
	WGPrivateKeyB64 string
	// HTTPClient overrides the default pinned-CA client (tests inject one). When nil,
	// Join builds a client that verifies the server's chain against the token's CA
	// hash.
	HTTPClient *http.Client
}

// JoinResult is everything a successful join yields the agent: the trust anchor, the
// issued certs paired with the private keys the node kept, the assigned pod network,
// the peer snapshot, and the node's wireguard keypair.
type JoinResult struct {
	NodeName string
	// NodeIP is the InternalIP the issued certificates name — this node's
	// server-assigned mesh address. It is the response's value, falling back to the
	// JoinOptions value only against a server that predates the field (which is
	// exactly the server that required one). Every consumer of "what address is
	// this node" takes it from here rather than from the flag, so the Node object,
	// the kubelet serving cert and the mesh datapath cannot disagree with the
	// certificate.
	NodeIP       string
	ClusterCAPEM []byte
	// ClientCAPEM is the cluster's client-identity (signing) CA certificate — the
	// anchor this node's OWN kubelet endpoint verifies the apiserver's client cert
	// against. Empty only against a server that predates the field, which a
	// worker treats as a hard failure rather than serving :10250 open.
	ClientCAPEM           []byte
	NodeClientCertPEM     []byte
	NodeClientKeyPEM      []byte
	KubeletServingCertPEM []byte
	KubeletServingKeyPEM  []byte
	PodCIDR               string
	MeshIP                string
	Peers                 []netv1.MeshPeerSpec
	WGPrivateKeyB64       string
	WGPublicKeyB64        string
	// APIServers are the control-plane apiserver endpoints (host:port) this node
	// targets. A multi-node server advertises the address its apiserver actually
	// binds — its MESH IP — so this, not the underlay --server the join travelled
	// over, is where the node's kubeconfig and its client-side load-balancer must
	// point. Empty only when the server serves no mesh (single-node), where
	// the joined-over address is the apiserver's address too.
	APIServers []string
}

// PinnedClient returns an http.Client whose TLS verification is REPLACED by a
// CA-hash pin: it disables Go's default chain-to-system-roots verification
// (InsecureSkipVerify) and re-imposes real verification of the server's presented
// chain against caHash via certs.VerifyPinnedChain. This is the credential-issuing
// connection's trust anchor before the node possesses any CA — pinned, NOT
// insecure-skip-tls-verify.
func PinnedClient(caHash string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Disables ONLY the default verification; VerifyConnection below
				// re-imposes pinned-CA verification, so this is not trust-on-nothing.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					return certs.VerifyPinnedChain(caHash, cs.PeerCertificates)
				},
			},
		},
	}
}

// Join performs the worker join: parse + pin the token's CA hash, connect to the
// supervisor, submit the node-password + a client CSR + a kubelet-serving CSR + the
// mesh-enroll request, and return the issued certs, cluster CA, and mesh snapshot.
// The node's client/serving private keys and its wireguard private key NEVER leave
// the node (only CSRs and the wireguard PUBLIC key are sent).
//
// The wireguard identity is the caller's persisted one when opts.WGPrivateKeyB64
// is set, and freshly minted otherwise — see that field for why a worker must
// supply it.
func Join(ctx context.Context, opts JoinOptions) (*JoinResult, error) {
	tok, err := ParseToken(opts.Token)
	if err != nil {
		return nil, err
	}
	if opts.NodeName == "" {
		return nil, fmt.Errorf("bootstrap join: NodeName is required")
	}
	// The CSRs carry an IP SAN only when this node ASSERTS an address. With no
	// assertion there is nothing truthful to put there — the address is the
	// server's to assign — and none is needed: the approver ignores the CSR's
	// subject and SANs and stamps the assignment itself, while an IP SAN naming
	// anything else is exactly what it refuses (csr.go checkSANs).
	var ips []net.IP
	if opts.NodeIP != "" {
		ip := net.ParseIP(opts.NodeIP)
		if ip == nil {
			return nil, fmt.Errorf("bootstrap join: NodeIP %q is not an IP", opts.NodeIP)
		}
		ips = []net.IP{ip}
	}

	clientKeyPEM, clientCSRPEM, err := generateCSR(
		pkix.Name{CommonName: systemNodePrefix + opts.NodeName, Organization: []string{systemNodesGroup}},
		[]string{opts.NodeName}, ips)
	if err != nil {
		return nil, fmt.Errorf("generate client CSR: %w", err)
	}
	servingKeyPEM, servingCSRPEM, err := generateCSR(
		pkix.Name{CommonName: opts.NodeName},
		[]string{opts.NodeName, "localhost"}, ips)
	if err != nil {
		return nil, fmt.Errorf("generate serving CSR: %w", err)
	}

	wgPriv, wgPub := opts.WGPrivateKeyB64, ""
	if wgPriv == "" {
		wgPriv, wgPub, err = GenerateWireguardKey()
		if err != nil {
			return nil, fmt.Errorf("generate wireguard key: %w", err)
		}
	} else if wgPub, err = WireguardPublicKey(wgPriv); err != nil {
		return nil, fmt.Errorf("derive the public key of this node's persisted wireguard key: %w", err)
	}

	reqBody := JoinRequest{
		Token:         opts.Token,
		NodeName:      opts.NodeName,
		NodeIP:        opts.NodeIP,
		NodePassword:  opts.NodePassword,
		ClientCSRPEM:  string(clientCSRPEM),
		ServingCSRPEM: string(servingCSRPEM),
		Mesh: netv1.MeshEnrollRequest{
			NodeName:  opts.NodeName,
			PublicKey: wgPub,
			Endpoint:  opts.MeshEndpoint,
			PodCIDR:   opts.RequestedPodCIDR,
		},
	}.WithDefaults()

	client := opts.HTTPClient
	if client == nil {
		client = PinnedClient(tok.CAHash)
	}

	resp, err := postJSON(ctx, client, strings.TrimRight(opts.Server, "/")+JoinPath, reqBody)
	if err != nil {
		return nil, err
	}

	// The address the certificates name. A server that answers with one is
	// authoritative about its own issuance; a server that predates the field
	// required opts.NodeIP, and issued for exactly that.
	nodeIP := resp.NodeIP
	if nodeIP == "" {
		nodeIP = opts.NodeIP
	}
	return &JoinResult{
		NodeName:              resp.NodeName,
		NodeIP:                nodeIP,
		ClusterCAPEM:          []byte(resp.ClusterCAPEM),
		ClientCAPEM:           []byte(resp.ClientCAPEM),
		NodeClientCertPEM:     []byte(resp.NodeClientCertPEM),
		NodeClientKeyPEM:      clientKeyPEM,
		KubeletServingCertPEM: []byte(resp.KubeletServingCertPEM),
		KubeletServingKeyPEM:  servingKeyPEM,
		PodCIDR:               resp.Mesh.PodCIDR,
		MeshIP:                resp.Mesh.MeshIP,
		Peers:                 resp.Mesh.Peers,
		WGPrivateKeyB64:       wgPriv,
		WGPublicKeyB64:        wgPub,
		APIServers:            resp.APIServers,
	}, nil
}

// postJSON marshals body, POSTs it, and decodes a JoinResponse, mapping a non-2xx
// status to an error carrying the server's reason.
func postJSON(ctx context.Context, client *http.Client, url string, body JoinRequest) (*JoinResponse, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal join request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build join request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("join %s: %w", url, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode/100 != 2 {
		msg := make([]byte, 512)
		n, _ := httpResp.Body.Read(msg)
		reason := strings.TrimSpace(string(msg[:n]))
		// A server that predates assignment-derived addresses refuses an absent
		// nodeIP with this one 400. Left as the raw refusal it reads as a malformed
		// request, and the operator's only move — supply the address by hand, or
		// upgrade the control plane — is invisible. So it is named here, once, at
		// the boundary that can still tell WHY the field was absent.
		if httpResp.StatusCode == http.StatusBadRequest && body.NodeIP == "" && strings.Contains(reason, oldServerNodeIPRefusal) {
			return nil, fmt.Errorf("%w (the server answered: %s)", ErrServerRequiresNodeIP, reason)
		}
		// A rate-limited join is NOT a rejection, and collapsing it into one
		// would fail the install it is meant to protect (see
		// JoinRateLimitedError). It is the one non-2xx this client hands back as
		// a retry-later condition carrying the wait the server named.
		if httpResp.StatusCode == http.StatusTooManyRequests {
			return nil, &JoinRateLimitedError{
				RetryAfter: parseRetryAfter(httpResp.Header.Get("Retry-After")),
				Status:     httpResp.Status,
				Reason:     reason,
			}
		}
		return nil, fmt.Errorf("join rejected (%s): %s", httpResp.Status, reason)
	}
	var resp JoinResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode join response: %w", err)
	}
	return &resp, nil
}

// ErrServerRequiresNodeIP is returned by Join when the control plane refuses a
// join that carries no nodeIP — the answer of a server built before the address
// became the control plane's to assign. It is a TERMINAL condition for this
// agent: nothing about waiting or retrying changes it, and the two ways out are
// both the operator's. Compare with errors.Is.
var ErrServerRequiresNodeIP = errors.New(
	"this control plane predates assignment-derived node addresses; pass --node-ip <mesh address> or upgrade the control plane first")

// ErrJoinRateLimited is the sentinel a rate-limited join carries. It is a
// RETRY-LATER condition, not a refusal of this node: the token is valid and the
// request was well formed, and the control plane is bounding how fast one token
// may drive the expensive half of a join (see joinRateLimiter). Compare with
// errors.Is; recover the wait with errors.As on *JoinRateLimitedError.
var ErrJoinRateLimited = errors.New("the control plane is rate-limiting joins for this token")

// JoinRateLimitedError is the 429 a join received, carrying the Retry-After the
// server named so a caller waits the amount it was asked for rather than a
// guess of its own.
//
// It exists as a DISTINCT condition because of what the caller does next. An
// agent calls Join once per process start and `k3sm install` waits one bounded
// budget for the credential that join writes, so a rate-limited attempt read as
// a rejected token fails the install — on precisely the case the limit is there
// to protect, several Macs onboarded at once against one token. A caller that
// can tell the two apart waits instead.
type JoinRateLimitedError struct {
	// RetryAfter is the wait the server named, or zero when it named none this
	// client could read. A caller that gets zero applies a wait of its own
	// rather than retrying immediately.
	RetryAfter time.Duration
	// Status is the HTTP status line; Reason is the server's message.
	Status string
	Reason string
}

func (e *JoinRateLimitedError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("join rate-limited (%s): %s (retry after %s)", e.Status, e.Reason, e.RetryAfter)
	}
	return fmt.Sprintf("join rate-limited (%s): %s", e.Status, e.Reason)
}

// Unwrap makes errors.Is(err, ErrJoinRateLimited) the way callers ask "is this
// worth waiting for", without reaching for the concrete type unless they want
// the wait.
func (e *JoinRateLimitedError) Unwrap() error { return ErrJoinRateLimited }

// parseRetryAfter reads a Retry-After header. Only the delta-seconds form is
// understood, which is the form this control plane sends; an absent, HTTP-date
// or unreadable value yields zero, which a caller reads as "the server named no
// wait I can use" and answers with its own. Erring in that direction costs one
// more request the server refuses again, never a node that waits out a number
// it was handed.
func parseRetryAfter(v string) time.Duration {
	secs, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// oldServerNodeIPRefusal is the exact 400 body such a server answers with. It is
// matched as a substring because that is the only signal on the wire: the refusal
// predates any machine-readable error shape, and inventing one here would not
// reach the servers that emit it.
const oldServerNodeIPRefusal = "missing nodeName or nodeIP"

// generateCSR mints a fresh ECDSA P-256 keypair and a PEM CSR for subject + SANs,
// returning the PEM private key (kept by the node) and the PEM CSR (sent to the
// server). The server overrides the subject; the SANs are validated against the
// authenticated identity.
func generateCSR(subject pkix.Name, dnsNames []string, ipAddrs []net.IP) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.CertificateRequest{Subject: subject, DNSNames: dnsNames, IPAddresses: ipAddrs}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return keyPEM, csrPEM, nil
}

// GenerateWireguardKey mints a Curve25519 wireguard keypair, returning the base64
// private + public keys in the form a MeshPeer carries (the private key never leaves
// the node and never appears on a MeshPeer — only the public key is enrolled).
func GenerateWireguardKey() (privB64, pubB64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", fmt.Errorf("read random: %w", err)
	}
	// Curve25519 clamping (RFC 7748).
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	privB64 = base64.StdEncoding.EncodeToString(priv[:])
	pubB64, err = WireguardPublicKey(privB64)
	if err != nil {
		return "", "", err
	}
	return privB64, pubB64, nil
}

// WireguardPublicKey derives the base64 Curve25519 public key of the base64
// private key privB64. It is the reverse-lookup a node that PERSISTS its private
// key needs: the key is minted once and reloaded on every restart, so the public
// key its MeshPeer advertises has to be re-derived rather than re-minted (a
// re-mint would rotate the identity on every launchd kickstart and strand every
// peer's AllowedIPs). It never reads or writes the key file itself.
func WireguardPublicKey(privB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return "", fmt.Errorf("decode wireguard private key: %w", err)
	}
	if len(priv) != wireguardKeyBytes {
		return "", fmt.Errorf("wireguard private key is %d bytes, want %d", len(priv), wireguardKeyBytes)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// wireguardKeyBytes is the Curve25519 scalar/point size a wireguard key carries.
const wireguardKeyBytes = 32
