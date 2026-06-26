package bootstrap_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestCAHierarchyAndPinnedJoin proves the CA-pinned join trust core: the K10 token
// embeds sha256(cluster-CA); a join client verifies a server chain rooted in that CA
// and REJECTS a chain rooted in a different CA — with NO insecure-skip-tls-verify
// (VerifyPinnedChain re-imposes real verification against the pinned anchor).
func TestCAHierarchyAndPinnedJoin(t *testing.T) {
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	if clusterCA.PinHash() == signingCA.PinHash() {
		t.Fatal("the cluster CA and signing CA must be distinct anchors")
	}
	attackerCA, err := certs.NewCA("attacker-ca")
	if err != nil {
		t.Fatalf("attacker CA: %v", err)
	}

	// The token embeds sha256(cluster-CA).
	tokStr := bootstrap.FormatToken(clusterCA.PinHash(), "boot-x", "s3cr3t")
	tok, err := bootstrap.ParseToken(tokStr)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	sum := sha256.Sum256(clusterCA.Cert.Raw)
	if tok.CAHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("token CA hash %q != sha256(cluster CA) %q", tok.CAHash, hex.EncodeToString(sum[:]))
	}

	// A server chain rooted in the cluster CA verifies against the pin.
	good, err := clusterCA.ServingChainTLS("k3sm-apiserver", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("serving chain: %v", err)
	}
	if err := certs.VerifyPinnedChain(tok.CAHash, parseTLSChain(t, good)); err != nil {
		t.Fatalf("a chain rooted in the pinned cluster CA must verify, got: %v", err)
	}

	// A chain rooted in a DIFFERENT CA is rejected (no insecure-skip).
	bad, err := attackerCA.ServingChainTLS("attacker-apiserver", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("attacker chain: %v", err)
	}
	if err := certs.VerifyPinnedChain(tok.CAHash, parseTLSChain(t, bad)); !errors.Is(err, certs.ErrPinMismatch) {
		t.Fatalf("a chain rooted in a different CA must be REJECTED with ErrPinMismatch, got: %v", err)
	}

	// Attack: present the attacker's leaf but APPEND the genuine cluster CA so the
	// hash check finds it. The leaf still does not chain to the pinned CA → reject.
	attackerLeaf := parseTLSChain(t, bad)[0]
	forged := []*x509.Certificate{attackerLeaf, clusterCA.Cert}
	if err := certs.VerifyPinnedChain(tok.CAHash, forged); err == nil {
		t.Fatal("a leaf not signed by the pinned CA must be rejected even when the genuine CA is bundled into the chain")
	}
}

// TestJoinRoundTrip exercises the full bootstrap exchange in-process over httptest
// (no root, no real mesh): the agent's Join client submits the token + node-password
// + CSRs + mesh-enroll, and the supervisor Server issues a system:node client cert,
// the cluster CA, and the mesh snapshot.
func TestJoinRoundTrip(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	tokens := bootstrap.NewTokenStore(nil)
	user, secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	res, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
		Server:       ts.URL,
		Token:        bootstrap.FormatToken(clusterCA.PinHash(), user, secret),
		NodeName:     "worker-1",
		NodeIP:       "100.64.1.1",
		NodePassword: "node-secret-1",
		MeshEndpoint: "192.168.1.50:51820",
		HTTPClient:   ts.Client(), // skip the live pin (tested in TestCAHierarchyAndPinnedJoin)
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// The agent received a node-scoped credential, NOT the admin kubeconfig.
	leaf := parseCertPEM(t, res.NodeClientCertPEM)
	if leaf.Subject.CommonName != "system:node:worker-1" {
		t.Errorf("issued CN = %q, want system:node:worker-1", leaf.Subject.CommonName)
	}
	if !containsString(leaf.Subject.Organization, "system:nodes") {
		t.Errorf("issued O = %v, want system:nodes", leaf.Subject.Organization)
	}
	if err := leaf.CheckSignatureFrom(signingCA.Cert); err != nil {
		t.Errorf("node cert must be signed by the signing CA: %v", err)
	}
	if string(res.ClusterCAPEM) != string(clusterCA.CertPEM) {
		t.Error("join did not return the cluster CA")
	}
	if res.PodCIDR != "100.64.1.0/24" {
		t.Errorf("assigned podCIDR = %q, want 100.64.1.0/24", res.PodCIDR)
	}
	if res.WGPublicKeyB64 == "" || res.WGPrivateKeyB64 == res.WGPublicKeyB64 {
		t.Error("join must mint a wireguard keypair (distinct private/public)")
	}
	// The kubelet-serving cert is issued by the cluster CA (so --kubelet-certificate-authority verifies it).
	serving := parseCertPEM(t, res.KubeletServingCertPEM)
	if err := serving.CheckSignatureFrom(clusterCA.Cert); err != nil {
		t.Errorf("kubelet-serving cert must be signed by the cluster CA: %v", err)
	}
}

// TestJoinRejectsBadToken confirms an invalid bootstrap token is refused at the
// supervisor (a join failure boundary that must not yield a credential).
func TestJoinRejectsBadToken(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")
	srv, _ := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        bootstrap.NewTokenStore(nil), // no token minted
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1", peers: []netv1.MeshPeerSpec{}},
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
		Server:       ts.URL,
		Token:        bootstrap.FormatToken(clusterCA.PinHash(), "boot-nope", "wrong"),
		NodeName:     "worker-1",
		NodeIP:       "100.64.1.1",
		NodePassword: "x",
		MeshEndpoint: "192.168.1.50:51820",
		HTTPClient:   ts.Client(),
	})
	if err == nil {
		t.Fatal("join with an unminted token must be rejected")
	}
}

// TestPinnedClientLiveTLS proves the pinned dialer end-to-end against a live TLS
// listener presenting the cluster-CA chain: the matching pin connects, a mismatched
// pin fails the handshake (the security property that makes the join non-MITM-able).
func TestPinnedClientLiveTLS(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	attackerCA, _ := certs.NewCA("attacker-ca")
	chain, err := clusterCA.ServingChainTLS("k3sm-apiserver", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("serving chain: %v", err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{chain}}
	ts.StartTLS()
	defer ts.Close()

	// Correct pin connects.
	if _, err := bootstrap.PinnedClient(clusterCA.PinHash()).Get(ts.URL); err != nil {
		t.Fatalf("matching pin must connect: %v", err)
	}
	// Wrong pin fails the handshake.
	if _, err := bootstrap.PinnedClient(attackerCA.PinHash()).Get(ts.URL); err == nil {
		t.Fatal("a mismatched pin must fail the TLS handshake")
	}
}
