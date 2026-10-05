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

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// TestNodePasswordSharedAcrossServersInHA proves the datastore-backed node-password
// store: a binding written via one server's store (over the shared datastore) is
// enforced by another server's store — so the first-write-wins anti-impersonation
// guard holds across HA servers (a name bound on A cannot be re-bound with a different
// password on B). Without this, each server's in-memory store binds independently and
// anti-impersonation is voided. The Secret stores a bcrypt HASH, never the cleartext.
func TestNodePasswordSharedAcrossServersInHA(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := fake.NewClientset() // one fake datastore, two stores (server A + server B)
	a := newSecretNodePasswords(cs, nil)
	b := newSecretNodePasswords(cs, nil)

	// A binds worker-1; B (sharing the datastore) verifies the SAME password and rejects
	// a different one.
	if err := a.Ensure(ctx, "worker-1", "pw1"); err != nil {
		t.Fatalf("A bind worker-1: %v", err)
	}
	if err := b.Ensure(ctx, "worker-1", "pw1"); err != nil {
		t.Errorf("B must see A's binding and accept the same password: %v", err)
	}
	if err := b.Ensure(ctx, "worker-1", "impersonator"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("B verify wrong password err = %v, want ErrNodePasswordMismatch (anti-impersonation across servers)", err)
	}

	// The stored password is a bcrypt hash, never the cleartext.
	sec, err := cs.CoreV1().Secrets(bootstrapStateNamespace).Get(ctx, "worker-1"+nodePasswordSecretSuffix, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node-password secret: %v", err)
	}
	stored := sec.Data[nodePasswordHashKey]
	if len(stored) == 0 || string(stored) == "pw1" {
		t.Errorf("node-password must be stored hashed, got %q", stored)
	}

	// First-write-wins works in the other direction too (B binds, A enforces).
	if err := b.Ensure(ctx, "worker-2", "pwB"); err != nil {
		t.Fatalf("B bind worker-2: %v", err)
	}
	if err := a.Ensure(ctx, "worker-2", "pwB"); err != nil {
		t.Errorf("A must see B's binding: %v", err)
	}
	if err := a.Ensure(ctx, "worker-2", "nope"); !errors.Is(err, bootstrap.ErrNodePasswordMismatch) {
		t.Errorf("A verify wrong password err = %v, want ErrNodePasswordMismatch", err)
	}
}

// TestAdminKubeconfigUsesClientCert proves the HA admin kubeconfig authenticates with a
// signing-CA-issued system:masters CLIENT CERT (reconstructible on every server) and
// verifies the apiserver against the cluster CA — NOT a per-server static token or
// insecure-skip — so kubectl works against ANY server.
func TestAdminKubeconfigUsesClientCert(t *testing.T) {
	t.Parallel()
	wd := t.TempDir()
	h, err := certs.EnsureHierarchy(wd)
	if err != nil {
		t.Fatalf("hierarchy: %v", err)
	}
	path := filepath.Join(wd, "admin.kubeconfig")
	if err := writeAdminClientCertKubeconfig(path, "https://10.0.0.1:6444", h); err != nil {
		t.Fatalf("write admin kubeconfig: %v", err)
	}

	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load admin kubeconfig: %v", err)
	}
	user := cfg.AuthInfos["k3sm-admin"]
	if user == nil {
		t.Fatal("admin kubeconfig missing the k3sm-admin user")
	}
	if len(user.ClientCertificateData) == 0 {
		t.Error("admin kubeconfig must use a client certificate, not a token")
	}
	if user.Token != "" {
		t.Error("admin kubeconfig must NOT carry a static bearer token")
	}

	// The client cert is O=system:masters and signed by the SIGNING CA.
	block, _ := pem.Decode(user.ClientCertificateData)
	if block == nil {
		t.Fatal("client-certificate-data is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	found := false
	for _, o := range leaf.Subject.Organization {
		if o == "system:masters" {
			found = true
		}
	}
	if !found {
		t.Errorf("client cert O = %v, want it to contain system:masters", leaf.Subject.Organization)
	}
	if err := leaf.CheckSignatureFrom(h.Signing.Cert); err != nil {
		t.Errorf("admin client cert must be signed by the signing CA: %v", err)
	}

	// The cluster verifies the apiserver via the cluster CA (not insecure-skip).
	cl := cfg.Clusters["k3sm"]
	if cl == nil {
		t.Fatal("admin kubeconfig missing the k3sm cluster")
	}
	if cl.InsecureSkipTLSVerify {
		t.Error("admin kubeconfig must NOT skip TLS verification")
	}
	if len(cl.CertificateAuthorityData) == 0 {
		t.Error("admin kubeconfig must embed the cluster CA for server verification")
	}
	if string(cl.CertificateAuthorityData) != string(h.Cluster.CertPEM) {
		t.Error("admin kubeconfig CA must be the cluster CA")
	}
}

// countingBundleTransport is an http.RoundTripper standing in for the existing
// server's bootstrap listener: it serves sealed at bootstrap.BundlePath (404 for any
// other path), counts the bundle requests, answers 500 while failing is set, and
// records whether secretPath already existed when each request arrived. No network.
type countingBundleTransport struct {
	mu         sync.Mutex
	sealed     []byte
	failing    bool
	calls      int
	secretPath string
	secretSeen []bool
}

func (c *countingBundleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := func(code int, body []byte) *http.Response {
		return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)),
			Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}, Request: req}
	}
	if req.URL.Path != bootstrap.BundlePath {
		return resp(http.StatusNotFound, nil), nil
	}
	c.calls++
	if c.secretPath != "" {
		_, err := os.Stat(c.secretPath)
		c.secretSeen = append(c.secretSeen, err == nil)
	}
	if c.failing {
		return resp(http.StatusInternalServerError, []byte("bundle unavailable")), nil
	}
	return resp(http.StatusOK, c.sealed), nil
}

func (c *countingBundleTransport) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingBundleTransport) setFailing(f bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failing = f
}

// serverJoinFixture is server A's sealed hierarchy and the server token that opens it.
type serverJoinFixture struct {
	h      *certs.Hierarchy
	sealed []byte
	secret string
	token  string
}

func newServerJoinFixture(t *testing.T) serverJoinFixture {
	t.Helper()
	wdA := t.TempDir()
	hA, err := certs.EnsureHierarchy(wdA)
	if err != nil {
		t.Fatalf("server A hierarchy: %v", err)
	}
	if hA.EtcdServer, hA.EtcdPeer, err = certs.EnsureEtcdCAs(wdA); err != nil {
		t.Fatalf("server A etcd CAs: %v", err)
	}
	plaintext, err := hA.Marshal()
	if err != nil {
		t.Fatalf("marshal A: %v", err)
	}
	const secret = "server-bootstrap-secret-deadbeefdeadbeefdeadbeef"
	sealed, err := bootstrap.SealBundle(secret, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return serverJoinFixture{h: hA, sealed: sealed, secret: secret,
		token: bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret)}
}

// join runs importServerCABundleVia for workDir over tr, failing the test if the log
// carries the secret or any private key.
func (f serverJoinFixture) join(t *testing.T, workDir string, tr *countingBundleTransport) error {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	opts := serverOptions{workDir: workDir, joinServer: "192.0.2.1", token: f.token}
	err := importServerCABundleVia(context.Background(), opts, &http.Client{Transport: tr}, logger)
	if strings.Contains(logs.String(), f.secret) || strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Errorf("the server-join log leaks the secret or a key:\n%s", logs.String())
	}
	return err
}

// readPKITree returns every regular file under workDir's PKI dir, by path.
func readPKITree(t *testing.T, workDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(certs.PKIDir(workDir), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[p] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read PKI tree: %v", err)
	}
	return out
}

// TestServerJoinFetchesBundleOnlyWhenCAMissing is the B435 gate: a joined server
// restarts. The bundle is fetched only while a CA is missing, a restart over a
// complete hierarchy fetches nothing and succeeds (on main it hit the import's
// refusal to overwrite its own files), a backfill leaves present CAs byte-identical,
// a failed fetch writes no CA but keeps the secret, a different recorded secret stops
// before the network, and a divergent local CA stops with nothing written.
func TestServerJoinFetchesBundleOnlyWhenCAMissing(t *testing.T) {
	fx := newServerJoinFixture(t)
	wd := t.TempDir() // the server preflight (executor.EnsureWorkDirWritable) creates it in production
	tr := &countingBundleTransport{sealed: fx.sealed}

	assertComplete := func(t *testing.T, wd string) {
		t.Helper()
		missing, err := certs.MissingOnDisk(wd)
		if err != nil || len(missing) != 0 {
			t.Fatalf("MissingOnDisk = %v, %v; want a complete hierarchy", missing, err)
		}
		h, err := certs.EnsureHierarchy(wd)
		if err != nil {
			t.Fatalf("EnsureHierarchy: %v", err)
		}
		server, peer, err := certs.EnsureEtcdCAs(wd)
		if err != nil {
			t.Fatalf("EnsureEtcdCAs: %v", err)
		}
		if h.Cluster.PinHash() != fx.h.Cluster.PinHash() || h.Signing.PinHash() != fx.h.Signing.PinHash() ||
			server.PinHash() != fx.h.EtcdServer.PinHash() || peer.PinHash() != fx.h.EtcdPeer.PinHash() {
			t.Error("the installed CAs are not the bundle's")
		}
	}
	assertSecret := func(t *testing.T, wd, want string) {
		t.Helper()
		got, err := os.ReadFile(serverSecretPath(wd))
		if err != nil || string(got) != want {
			t.Errorf("recorded secret: err %v, match %v", err, string(got) == want)
		}
	}

	t.Run("fresh dir: one fetch, four CAs, secret saved", func(t *testing.T) {
		if err := fx.join(t, wd, tr); err != nil {
			t.Fatalf("join: %v", err)
		}
		if tr.count() != 1 {
			t.Errorf("fetches = %d, want 1", tr.count())
		}
		assertComplete(t, wd)
		assertSecret(t, wd, fx.secret)
	})

	t.Run("re-run: no fetch", func(t *testing.T) {
		before := readPKITree(t, wd)
		if err := fx.join(t, wd, tr); err != nil {
			t.Fatalf("restart join: %v", err)
		}
		if tr.count() != 1 {
			t.Errorf("fetches = %d, want still 1 (a complete hierarchy fetches nothing)", tr.count())
		}
		if !reflect.DeepEqual(before, readPKITree(t, wd)) {
			t.Error("a restart changed the PKI")
		}
	})

	t.Run("etcd pair deleted: one fetch, present CAs byte-identical", func(t *testing.T) {
		ep := certs.EtcdCertPaths(wd)
		for _, p := range []string{ep.PeerCACert, ep.PeerCAKey} {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		}
		before := readPKITree(t, wd)
		if err := fx.join(t, wd, tr); err != nil {
			t.Fatalf("backfill join: %v", err)
		}
		if tr.count() != 2 {
			t.Errorf("fetches = %d, want 2", tr.count())
		}
		after := readPKITree(t, wd)
		for p, b := range before {
			if after[p] != b {
				t.Errorf("present %s changed", p)
			}
		}
		assertComplete(t, wd)
	})

	t.Run("transport 500: secret kept, no CA, a later good fetch succeeds", func(t *testing.T) {
		wd := t.TempDir()
		tr := &countingBundleTransport{sealed: fx.sealed, failing: true, secretPath: serverSecretPath(wd)}
		if err := fx.join(t, wd, tr); err == nil {
			t.Fatal("a 500 from the bundle route must fail the join")
		}
		if len(tr.secretSeen) != 1 || !tr.secretSeen[0] {
			t.Errorf("secret present at fetch time: %v, want [true]", tr.secretSeen)
		}
		assertSecret(t, wd, fx.secret)
		if got := readPKITree(t, wd); len(got) != 0 {
			t.Errorf("a failed fetch wrote %d PKI files", len(got))
		}
		tr.setFailing(false)
		if err := fx.join(t, wd, tr); err != nil {
			t.Fatalf("retry join: %v", err)
		}
		assertComplete(t, wd)
		assertSecret(t, wd, fx.secret)
	})

	t.Run("different recorded secret: mismatch, no fetch", func(t *testing.T) {
		wd := t.TempDir()
		if err := os.WriteFile(serverSecretPath(wd), []byte("another-server-secret-0000"), 0o600); err != nil {
			t.Fatal(err)
		}
		tr := &countingBundleTransport{sealed: fx.sealed}
		if err := fx.join(t, wd, tr); !errors.Is(err, bootstrap.ErrServerSecretMismatch) {
			t.Fatalf("join err = %v, want ErrServerSecretMismatch", err)
		}
		if tr.count() != 0 {
			t.Errorf("fetches = %d, want 0 (a mismatch stops before the network)", tr.count())
		}
		assertSecret(t, wd, "another-server-secret-0000")
		if got := readPKITree(t, wd); len(got) != 0 {
			t.Errorf("a refused join wrote %d PKI files", len(got))
		}
	})

	t.Run("divergent local cluster CA, etcd CAs missing: nothing written", func(t *testing.T) {
		wd := t.TempDir()
		if _, err := certs.EnsureHierarchy(wd); err != nil { // a different cluster + signing CA
			t.Fatal(err)
		}
		before := readPKITree(t, wd)
		tr := &countingBundleTransport{sealed: fx.sealed}
		if err := fx.join(t, wd, tr); !errors.Is(err, certs.ErrHierarchyDiverged) {
			t.Fatalf("join err = %v, want ErrHierarchyDiverged", err)
		}
		if !reflect.DeepEqual(before, readPKITree(t, wd)) {
			t.Error("a divergent join changed the PKI")
		}
		if _, err := os.Stat(certs.EtcdCertPaths(wd).Dir); !os.IsNotExist(err) {
			t.Errorf("a divergent join created the etcd PKI dir (stat err %v)", err)
		}
	})
}

// TestServerJoinSavesSecretBeforeFetch pins the B435 ordering: the token's secret is on
// disk before the bundle is requested, so a fetch that fails afterwards still leaves
// it recorded.
func TestServerJoinSavesSecretBeforeFetch(t *testing.T) {
	fx := newServerJoinFixture(t)
	wd := t.TempDir()
	tr := &countingBundleTransport{sealed: fx.sealed, failing: true, secretPath: serverSecretPath(wd)}
	if err := fx.join(t, wd, tr); err == nil {
		t.Fatal("a failed fetch must fail the join")
	}
	if tr.count() != 1 || len(tr.secretSeen) != 1 || !tr.secretSeen[0] {
		t.Fatalf("fetches %d, secret present at fetch time %v; want one fetch with the secret already saved", tr.count(), tr.secretSeen)
	}
	got, err := os.ReadFile(serverSecretPath(wd))
	if err != nil || string(got) != fx.secret {
		t.Errorf("after the failed fetch the secret is not recorded (err %v)", err)
	}
}
