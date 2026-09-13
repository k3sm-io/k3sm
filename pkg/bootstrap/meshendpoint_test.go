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

package bootstrap_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	netv1 "k3sm.io/apis/net/v1"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// meshEndpointFixture is a live TLS bootstrap listener built with the PRODUCTION
// TLS config (bootstrap.ListenerTLSConfig), so what the table below proves about
// authentication is a property of the shipped listener rather than of the test's
// own tls.Config.
type meshEndpointFixture struct {
	ts        *httptest.Server
	clusterCA *certs.CA
	signingCA *certs.CA
	enroller  *fakeEnroller
	token     string
}

// newMeshEndpointFixture stands up the supervisor over TLS with optional client
// certificate verification against the signing CA, holding one enrolled peer.
func newMeshEndpointFixture(t *testing.T) *meshEndpointFixture {
	t.Helper()
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	signingCA, err := certs.NewCA("k3sm-signing-ca")
	if err != nil {
		t.Fatalf("signing CA: %v", err)
	}
	tokens := bootstrap.NewTokenStore(nil)
	user, secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	peer := netv1.MeshPeerSpec{
		NodeName:   "worker-1",
		PublicKey:  "dGVzdC1wdWJsaWMta2V5LWJhc2U2NC0zMmJ5dGVzPT0=",
		Endpoint:   "192.0.2.206:51820",
		PodCIDR:    "100.64.1.0/24",
		AllowedIPs: []string{"100.64.1.0/24"},
		MeshIP:     "100.64.1.1",
	}.WithDefaults()
	enroller := &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1", peer: &peer}

	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        tokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      enroller,
		ServerAuth:    bootstrap.NewStaticServerSecret("server-bootstrap-secret-0123456789abcdef"),
		Bundle:        staticBundle("sealed-bundle-bytes"),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	serving, err := clusterCA.ServingChainTLS("k3sm-supervisor",
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("serving chain: %v", err)
	}
	tlsCfg, err := bootstrap.ListenerTLSConfig(serving, signingCA.CertPEM)
	if err != nil {
		t.Fatalf("listener TLS: %v", err)
	}
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = tlsCfg
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return &meshEndpointFixture{
		ts:        ts,
		clusterCA: clusterCA,
		signingCA: signingCA,
		enroller:  enroller,
		token:     bootstrap.FormatToken(clusterCA.PinHash(), user, secret),
	}
}

// staticBundle is a BundleSource returning fixed bytes, so the server-bootstrap
// route exists and row 7 can exercise it.
type staticBundle string

func (b staticBundle) SealedBundle(context.Context) ([]byte, error) { return []byte(b), nil }

// anonymousClient verifies the server against the cluster CA and presents NO
// client certificate — the posture every un-joined node has.
func (f *meshEndpointFixture) anonymousClient(t *testing.T) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.clusterCA.CertPEM) {
		t.Fatal("cluster CA PEM did not parse")
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}
}

// nodeClient issues a client certificate from ca with the given CN + O and
// returns the PRODUCTION client that presents it (bootstrap.NodeIdentityClient),
// so the rows below exercise the same code path a joined worker runs.
func (f *meshEndpointFixture) nodeClient(t *testing.T, ca *certs.CA, cn string, org []string) *http.Client {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClient(cn, org, time.Hour)
	if err != nil {
		t.Fatalf("issue client cert %q: %v", cn, err)
	}
	client, err := bootstrap.NodeIdentityClient(f.clusterCA.CertPEM, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("NodeIdentityClient: %v", err)
	}
	return client
}

// insistentClient presents a certificate from ca even though the server's
// CertificateRequest does not name that CA as acceptable.
//
// The override is the point. Go's own client filters its certificates against the
// CertificateRequest's acceptable-CA list and sends an EMPTY certificate when none
// matches — so a well-behaved client with a foreign certificate reaches the
// handler as an anonymous caller (401) and proves nothing about the server's
// verification. An attacker has no reason to be well-behaved, so this client sends
// the certificate regardless and the row then tests what it claims to: the SERVER
// refusing a chain that does not anchor in the cluster's client-identity CA.
func (f *meshEndpointFixture) insistentClient(t *testing.T, ca *certs.CA, cn string, org []string) *http.Client {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClient(cn, org, time.Hour)
	if err != nil {
		t.Fatalf("issue client cert %q: %v", cn, err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.clusterCA.CertPEM) {
		t.Fatal("cluster CA PEM did not parse")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &pair, nil
			},
		}},
	}
}

// postRefresh POSTs a raw refresh body and returns the status code, so a row can
// assert the CODE rather than only that the call failed.
func postRefresh(t *testing.T, client *http.Client, baseURL, body string, header map[string]string) (int, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		baseURL+bootstrap.MeshEndpointPath, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}

// TestMeshEndpointVerbAuthAndGuard is B283's security table for the endpoint
// refresh verb.
//
// The verb is a SECOND write path into a node's MeshPeer, reachable from the LAN
// (the bootstrap listener binds the wildcard on the mesh path), and the object it
// writes decides where every peer sends that node's pod traffic. Its whole
// authentication is the listener's optional mTLS plus the handler's own checks —
// tls.VerifyClientCertIfGiven completes the handshake with NO client certificate,
// by necessity, because join must keep working for a node that has none. Optional
// mTLS mistaken for enforced mTLS is a recurring vulnerability class, so each row
// below pins one denial, and the denial rows assert the enroller was never called:
// "the request was refused" and "the write never happened" are different claims.
func TestMeshEndpointVerbAuthAndGuard(t *testing.T) {
	const body = `{"nodeName":"worker-1","endpoint":"192.0.2.111:51820"}`

	t.Run("no client certificate is 401 and never writes", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		before, _ := f.enroller.snapshot()
		code, err := postRefresh(t, f.anonymousClient(t), f.ts.URL, body, nil)
		if err != nil {
			t.Fatalf("the handshake must succeed with no client certificate (join depends on it): %v", err)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — an anonymous caller must not reach the write", code)
		}
		after, calls := f.enroller.snapshot()
		if calls != 0 {
			t.Errorf("the enroller was called %d times for an unauthenticated request", calls)
		}
		if after.Endpoint != before.Endpoint {
			t.Errorf("endpoint moved to %q on an unauthenticated request", after.Endpoint)
		}
	})

	t.Run("a certificate from a foreign CA fails the handshake", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		attacker, err := certs.NewCA("attacker-ca")
		if err != nil {
			t.Fatalf("attacker CA: %v", err)
		}
		client := f.insistentClient(t, attacker, "system:node:worker-1", []string{"system:nodes"})
		if _, err := postRefresh(t, client, f.ts.URL, body, nil); err == nil {
			t.Fatal("a client certificate issued by a CA outside the cluster must be rejected at the handshake")
		}
		if _, calls := f.enroller.snapshot(); calls != 0 {
			t.Errorf("the enroller was called %d times for a foreign-CA certificate", calls)
		}
	})

	t.Run("a verified certificate that is not a node is 403", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		// Issued by the cluster's own signing CA, so the chain verifies — this is
		// exactly the apiserver's kubelet client, which has no Organization.
		client := f.nodeClient(t, f.signingCA, certs.APIServerKubeletClientCN, nil)
		code, err := postRefresh(t, client, f.ts.URL, body, nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — chain validity alone is not a node identity", code)
		}
		if _, calls := f.enroller.snapshot(); calls != 0 {
			t.Errorf("the enroller was called %d times for a non-node identity", calls)
		}
	})

	t.Run("a node may not move another node's endpoint", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-2", []string{"system:nodes"})
		code, err := postRefresh(t, client, f.ts.URL, body, nil) // body names worker-1
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusForbidden {
			t.Errorf("status = %d, want 403 — every joined node holds a signing-CA certificate, so the self-scoping guard is the only thing stopping a cross-node write", code)
		}
		after, calls := f.enroller.snapshot()
		if calls != 0 {
			t.Errorf("the enroller was called %d times for a cross-node write", calls)
		}
		if after.Endpoint != "192.0.2.206:51820" {
			t.Errorf("worker-1's endpoint became %q under worker-2's certificate", after.Endpoint)
		}
	})

	t.Run("a consistent node identity writes only the endpoint", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		before, _ := f.enroller.snapshot()
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		code, err := postRefresh(t, client, f.ts.URL, body, nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		after, calls := f.enroller.snapshot()
		if calls != 1 {
			t.Errorf("the enroller was called %d times, want 1", calls)
		}
		if after.Endpoint != "192.0.2.111:51820" {
			t.Errorf("endpoint = %q, want the refreshed value", after.Endpoint)
		}
		// Everything a forged peer would want to move must be untouched.
		want := before
		want.Endpoint = after.Endpoint
		if after.PublicKey != want.PublicKey || after.PodCIDR != want.PodCIDR ||
			after.MeshIP != want.MeshIP || strings.Join(after.AllowedIPs, ",") != strings.Join(want.AllowedIPs, ",") {
			t.Errorf("the refresh changed more than the endpoint: %+v, want %+v", after, want)
		}

		// The production client helper drives the same exchange end to end.
		if err := bootstrap.RefreshMeshEndpoint(context.Background(), client, f.ts.URL, "worker-1", "192.0.2.112:51820"); err != nil {
			t.Fatalf("RefreshMeshEndpoint: %v", err)
		}
		if final, _ := f.enroller.snapshot(); final.Endpoint != "192.0.2.112:51820" {
			t.Errorf("endpoint after RefreshMeshEndpoint = %q", final.Endpoint)
		}
	})

	t.Run("a valid join token without a certificate is 401", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		code, err := postRefresh(t, f.anonymousClient(t), f.ts.URL,
			`{"nodeName":"worker-1","endpoint":"192.0.2.111:51820","token":"`+f.token+`"}`,
			map[string]string{"Authorization": "Bearer " + f.token})
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401 — the join token is TTL-bounded and is deliberately NOT a credential for this verb", code)
		}
		if _, calls := f.enroller.snapshot(); calls != 0 {
			t.Errorf("the enroller was called %d times for a token-only request", calls)
		}
	})

	t.Run("join cacert and server-bootstrap still work with no certificate", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.anonymousClient(t)

		resp, err := client.Get(f.ts.URL + bootstrap.CACertPath)
		if err != nil {
			t.Fatalf("GET %s: %v", bootstrap.CACertPath, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d, want 200", bootstrap.CACertPath, resp.StatusCode)
		}

		res, err := bootstrap.Join(context.Background(), bootstrap.JoinOptions{
			Server:       f.ts.URL,
			Token:        f.token,
			NodeName:     "worker-1",
			NodeIP:       "100.64.1.1",
			NodePassword: "node-secret-1",
			MeshEndpoint: "192.0.2.206:51820",
			HTTPClient:   client,
		})
		if err != nil {
			t.Fatalf("join must still succeed with no client certificate: %v", err)
		}
		if len(res.NodeClientCertPEM) == 0 {
			t.Error("join returned no node client certificate")
		}

		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.ts.URL+bootstrap.BundlePath, nil)
		if err != nil {
			t.Fatalf("build bundle request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+bootstrap.FormatServerToken(f.clusterCA.PinHash(), "server-bootstrap-secret-0123456789abcdef"))
		bundleResp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", bootstrap.BundlePath, err)
		}
		defer bundleResp.Body.Close()
		if bundleResp.StatusCode != http.StatusOK {
			t.Errorf("%s status = %d, want 200", bootstrap.BundlePath, bundleResp.StatusCode)
		}
	})

	t.Run("a malformed endpoint is 400", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		for _, bad := range []string{`{"nodeName":"worker-1","endpoint":"192.0.2.111"}`,
			`{"nodeName":"worker-1","endpoint":"192.0.2.111:0"}`,
			`{"nodeName":"worker-1","endpoint":""}`} {
			code, err := postRefresh(t, client, f.ts.URL, bad, nil)
			if err != nil {
				t.Fatalf("post %s: %v", bad, err)
			}
			if code != http.StatusBadRequest {
				t.Errorf("status for %s = %d, want 400", bad, code)
			}
		}
		if _, calls := f.enroller.snapshot(); calls != 0 {
			t.Errorf("the enroller was called %d times for a malformed endpoint", calls)
		}
	})

	t.Run("a node with no MeshPeer is 404", func(t *testing.T) {
		f := newMeshEndpointFixture(t)
		f.enroller.peer = nil
		client := f.nodeClient(t, f.signingCA, "system:node:worker-1", []string{"system:nodes"})
		code, err := postRefresh(t, client, f.ts.URL, body, nil)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 — the agent must rejoin rather than retry forever", code)
		}
	})
}

// TestMeshEndpointListenerFailsClosedWithoutAClientCA pins the fail-closed half of
// the listener construction. With no pool tls.VerifyClientCertIfGiven would abort
// every presented certificate while still completing the handshake, so the refresh
// verb would 401 forever and the join path would keep working — a fault that reads
// as a network problem rather than as missing PKI material.
func TestMeshEndpointListenerFailsClosedWithoutAClientCA(t *testing.T) {
	clusterCA, err := certs.NewCA("k3sm-cluster-ca")
	if err != nil {
		t.Fatalf("cluster CA: %v", err)
	}
	serving, err := clusterCA.ServingChainTLS("k3sm-supervisor", []string{"localhost"}, nil, time.Hour)
	if err != nil {
		t.Fatalf("serving chain: %v", err)
	}
	for name, pem := range map[string][]byte{"empty": nil, "not a certificate": []byte("not pem")} {
		t.Run(name, func(t *testing.T) {
			if _, err := bootstrap.ListenerTLSConfig(serving, pem); err == nil {
				t.Fatal("ListenerTLSConfig accepted an unusable client-identity CA")
			}
		})
	}
}
