package bootstrap_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// fakeBundleSource returns a fixed sealed-bundle blob (the endpoint test does not
// exercise the crypto — that is bundle_test.go — only the authorization + serving).
type fakeBundleSource struct{ sealed []byte }

func (f *fakeBundleSource) SealedBundle(context.Context) ([]byte, error) { return f.sealed, nil }

// TestCABundleEndpointRejectsWorkerIdentity proves the CA-bundle endpoint authorizes the
// SERVER-class identity ONLY: a worker token is DENIED (so a leaked worker token can
// never reconstruct the signing CA — cluster takeover), while a server token with the
// matching secret is served the sealed bundle. The endpoint is also absent entirely when
// the server is not configured for HA (no ServerAuth/Bundle).
func TestCABundleEndpointRejectsWorkerIdentity(t *testing.T) {
	clusterCA, _ := certs.NewCA("k3sm-cluster-ca")
	signingCA, _ := certs.NewCA("k3sm-signing-ca")

	workerTokens := bootstrap.NewTokenStore(nil)
	wUser, wSecret, _, err := workerTokens.Create(time.Hour)
	if err != nil {
		t.Fatalf("create worker token: %v", err)
	}
	workerToken := bootstrap.FormatToken(clusterCA.PinHash(), wUser, wSecret)

	const serverSecret = "high-entropy-server-bootstrap-secret-abc123"
	sealedWant := []byte("SEALED-CA-BUNDLE")

	srv, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA:     clusterCA,
		SigningCA:     signingCA,
		Tokens:        workerTokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"},
		ServerAuth:    bootstrap.NewStaticServerSecret(serverSecret),
		Bundle:        &fakeBundleSource{sealed: sealedWant},
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func(t *testing.T, token string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, ts.URL+bootstrap.BundlePath, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatalf("GET bundle: %v", err)
		}
		return resp
	}

	// A WORKER token is denied (it is not a server-class token).
	resp := get(t, workerToken)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a WORKER token must NOT be served the CA bundle (cluster-takeover guard)")
	}

	// No credential is denied.
	resp = get(t, "")
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("an unauthenticated request must NOT be served the CA bundle")
	}

	// A SERVER token with the right secret is served the sealed bundle.
	serverToken := bootstrap.FormatServerToken(clusterCA.PinHash(), serverSecret)
	resp = get(t, serverToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a SERVER token must be served the bundle, got %s", resp.Status)
	}
	body, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(body, sealedWant) {
		t.Errorf("served bundle = %q, want %q", body, sealedWant)
	}

	// Without ServerAuth/Bundle the endpoint is not even registered (non-HA server).
	plain, err := bootstrap.NewServer(bootstrap.ServerConfig{
		ClusterCA: clusterCA, SigningCA: signingCA, Tokens: workerTokens,
		NodePasswords: bootstrap.NewMemoryNodePasswords(),
		Enroller:      &fakeEnroller{podCIDR: "100.64.1.0/24", meshIP: "100.64.1.1"},
	})
	if err != nil {
		t.Fatalf("new plain server: %v", err)
	}
	ts2 := httptest.NewServer(plain.Handler())
	defer ts2.Close()
	req, _ := http.NewRequest(http.MethodGet, ts2.URL+bootstrap.BundlePath, nil)
	req.Header.Set("Authorization", "Bearer "+serverToken)
	resp2, err := ts2.Client().Do(req)
	if err != nil {
		t.Fatalf("GET bundle (plain): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Error("a non-HA server (no ServerAuth/Bundle) must not serve the bundle endpoint")
	}
}
