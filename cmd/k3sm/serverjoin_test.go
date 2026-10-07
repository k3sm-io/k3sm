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
	"encoding/base64"
	"encoding/json"
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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
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
	// rhPin is server A's request-header CA pin ("" if A has none).
	rhPin string
}

func newServerJoinFixture(t *testing.T) serverJoinFixture {
	t.Helper()
	wdA := t.TempDir()
	hA, err := certs.EnsureHierarchy(wdA, certs.RoleMintAuthority, certs.PostureKine)
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
	var rhPin string
	if b, err := os.ReadFile(certs.RequestHeaderCACertPath(wdA)); err == nil {
		if rhPin, err = certs.CertPin(b); err != nil {
			t.Fatal(err)
		}
	}
	return serverJoinFixture{h: hA, sealed: sealed, secret: secret, rhPin: rhPin,
		token: bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret)}
}

// v2Sealed seals a schema-2 bundle (no request-header CA) of f's hierarchy, as a
// server one release older serves it.
func (f serverJoinFixture) v2Sealed(t *testing.T) []byte {
	t.Helper()
	h := f.h
	v2, err := json.Marshal(map[string]any{
		"schemaVersion":       2,
		"clusterCACertPEM":    h.Cluster.CertPEM,
		"clusterCAKeyPEM":     h.Cluster.KeyPEM,
		"signingCACertPEM":    h.Signing.CertPEM,
		"signingCAKeyPEM":     h.Signing.KeyPEM,
		"etcdServerCACertPEM": h.EtcdServer.CertPEM,
		"etcdServerCAKeyPEM":  h.EtcdServer.KeyPEM,
		"etcdPeerCACertPEM":   h.EtcdPeer.CertPEM,
		"etcdPeerCAKeyPEM":    h.EtcdPeer.KeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := bootstrap.SealBundle(f.secret, v2)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// join runs importServerCABundleVia for workDir over tr, failing the test if the log
// carries the secret or any private key.
func (f serverJoinFixture) join(t *testing.T, workDir string, tr http.RoundTripper) error {
	t.Helper()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	opts := serverOptions{workDir: workDir, joinServer: "192.0.2.1", token: f.token, serverJoin: true}
	err := importServerCABundleVia(context.Background(), opts, &http.Client{Transport: tr}, logger)
	f.assertNoSecrets(t, logs.String(), err)
	return err
}

// assertNoSecrets fails the test if a log or an error carries the server secret, a
// PEM block, or any of the fixture's CA private keys.
func (f serverJoinFixture) assertNoSecrets(t *testing.T, logs string, err error) {
	t.Helper()
	text := logs
	if err != nil {
		text += err.Error()
	}
	if strings.Contains(text, f.secret) || strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "-----BEGIN") {
		t.Errorf("the server-join log or error leaks the secret or a key:\n%s", text)
	}
	for _, ca := range []*certs.CA{f.h.Cluster, f.h.Signing, f.h.EtcdServer, f.h.EtcdPeer} {
		if block, _ := pem.Decode(ca.KeyPEM); block != nil && strings.Contains(text, base64.StdEncoding.EncodeToString(block.Bytes)[:24]) {
			t.Errorf("the server-join log or error carries a CA key's DER:\n%s", text)
		}
	}
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
		missing, err := certs.MissingOnDisk(wd, certs.PostureEtcd)
		if err != nil || len(missing) != 0 {
			t.Fatalf("MissingOnDisk = %v, %v; want a complete hierarchy", missing, err)
		}
		h, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine)
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
		if pin, err := certs.LoadRequestHeaderPin(wd); err != nil || pin == "" || pin != fx.rhPin {
			t.Errorf("request-header CA pin %q (err %v), want the bundle's %q", pin, err, fx.rhPin)
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

	t.Run("request-header pair deleted (an upgraded joined server): one fetch, only it written", func(t *testing.T) {
		for _, p := range []string{certs.RequestHeaderCACertPath(wd), certs.RequestHeaderCAKeyPath(wd)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
		}
		before := readPKITree(t, wd)
		calls := tr.count()
		if err := fx.join(t, wd, tr); err != nil {
			t.Fatalf("backfill join: %v", err)
		}
		if tr.count() != calls+1 {
			t.Errorf("fetches = %d, want %d", tr.count(), calls+1)
		}
		after := readPKITree(t, wd)
		for p, b := range before {
			if after[p] != b {
				t.Errorf("present %s changed", p)
			}
		}
		var added []string
		for p := range after {
			if _, ok := before[p]; !ok {
				added = append(added, p)
			}
		}
		slices.Sort(added)
		want := []string{certs.RequestHeaderCACertPath(wd), certs.RequestHeaderCAKeyPath(wd)}
		if !slices.Equal(added, want) {
			t.Errorf("the backfill wrote %v, want only %v", added, want)
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
		if _, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine); err != nil { // a different cluster + signing CA
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

// switchingBundleTransport serves before at bootstrap.BundlePath until serveAfter
// reports true, then after; it counts the fetches.
type switchingBundleTransport struct {
	mu            sync.Mutex
	before, after []byte
	serveAfter    func() bool
	calls         int
}

func (s *switchingBundleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body := s.before
	if s.serveAfter() {
		body = s.after
	}
	s.calls++
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(bytes.NewReader(body)),
		Header: http.Header{}, Request: req}, nil
}

// fakeWait is a bundleWait on a fake clock: sleep advances now by d and counts.
type fakeWait struct {
	start, now time.Time
	sleeps     int
}

func newFakeWait() *fakeWait {
	t0 := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	return &fakeWait{start: t0, now: t0}
}

func (f *fakeWait) elapsed() time.Duration { return f.now.Sub(f.start) }

func (f *fakeWait) wait() bundleWait {
	w := defaultBundleWait
	w.now = func() time.Time { return f.now }
	w.sleep = func(_ context.Context, d time.Duration) error {
		f.sleeps++
		f.now = f.now.Add(d)
		return nil
	}
	return w
}

// TestServerJoinWaitsOnOlderBundleSource pins the bounded wait on a bundle source one
// release older (a schema-2 bundle): it retries every 30 s on a fake clock, logs the
// remedy at ERROR every 5 minutes, neither returns nor writes while it waits,
// continues once the source serves the request-header CA, gives up at 30 minutes
// with errBundleSourceStale naming the remedy, and returns at once on a divergence.
// No log line or error carries the secret or key material.
func TestServerJoinWaitsOnOlderBundleSource(t *testing.T) {
	fx := newServerJoinFixture(t)
	v2 := fx.v2Sealed(t)
	run := func(t *testing.T, wd string, tr http.RoundTripper, fw *fakeWait) (string, error) {
		t.Helper()
		var logs bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&logs, nil))
		opts := serverOptions{workDir: wd, joinServer: "192.0.2.1", token: fx.token, serverJoin: true}
		err := importServerCABundleWith(context.Background(), opts, &http.Client{Transport: tr}, fw.wait(), logger)
		fx.assertNoSecrets(t, logs.String(), err)
		return logs.String(), err
	}
	remedyLines := func(logs string) int {
		n := 0
		for _, l := range strings.Split(logs, "\n") {
			if strings.Contains(l, "level=ERROR") && strings.Contains(l, "upgrade the mint-authority server first") {
				n++
			}
		}
		return n
	}

	t.Run("older source for 25 minutes, then upgraded: waits, then backfills", func(t *testing.T) {
		wd := t.TempDir()
		fw := newFakeWait()
		tr := &switchingBundleTransport{before: v2, after: fx.sealed, serveAfter: func() bool { return fw.elapsed() >= 25*time.Minute }}
		logs, err := run(t, wd, tr, fw)
		if err != nil {
			t.Fatalf("join: %v", err)
		}
		if fw.elapsed() < 25*time.Minute {
			t.Fatalf("the join returned after %s on the fake clock; it must wait for the upgraded source", fw.elapsed())
		}
		if got := remedyLines(logs); got != 5 {
			t.Errorf("remedy logged at ERROR %d times over 25 minutes, want 5 (every 5 minutes):\n%s", got, logs)
		}
		if tr.calls != 51 {
			t.Errorf("fetches = %d, want 51 (every 30 s for 25 minutes, then the good one)", tr.calls)
		}
		if pin, err := certs.LoadRequestHeaderPin(wd); err != nil || pin != fx.rhPin {
			t.Errorf("request-header pin %q (err %v), want %q", pin, err, fx.rhPin)
		}
	})

	t.Run("older source past the bound: errBundleSourceStale, nothing written", func(t *testing.T) {
		wd := t.TempDir()
		fw := newFakeWait()
		tr := &switchingBundleTransport{before: v2, after: v2, serveAfter: func() bool { return false }}
		_, err := run(t, wd, tr, fw)
		if !errors.Is(err, errBundleSourceStale) {
			t.Fatalf("err = %v, want errBundleSourceStale", err)
		}
		if fw.elapsed() < 30*time.Minute || fw.elapsed() > 31*time.Minute {
			t.Errorf("gave up after %s on the fake clock, want 30 minutes", fw.elapsed())
		}
		for _, want := range []string{"upgrade the mint-authority server first", "--cluster-reset", "never mint a CA"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not name the remedy %q", err, want)
			}
		}
		if got := readPKITree(t, wd); len(got) != 0 {
			t.Errorf("the wait wrote %d PKI files", len(got))
		}
	})

	t.Run("divergent local CA: returns at once", func(t *testing.T) {
		wd := t.TempDir()
		if _, err := certs.EnsureHierarchy(wd, certs.RoleMintAuthority, certs.PostureKine); err != nil {
			t.Fatal(err)
		}
		fw := newFakeWait()
		_, err := run(t, wd, &countingBundleTransport{sealed: fx.sealed}, fw)
		if !errors.Is(err, certs.ErrHierarchyDiverged) {
			t.Fatalf("err = %v, want ErrHierarchyDiverged", err)
		}
		if fw.sleeps != 0 {
			t.Errorf("a divergence waited %d times; it needs a human and must return at once", fw.sleeps)
		}
	})

	t.Run("different recorded secret: returns at once", func(t *testing.T) {
		wd := t.TempDir()
		if err := os.WriteFile(serverSecretPath(wd), []byte("another-server-secret-0000"), 0o600); err != nil {
			t.Fatal(err)
		}
		fw := newFakeWait()
		_, err := run(t, wd, &countingBundleTransport{sealed: v2}, fw)
		if !errors.Is(err, bootstrap.ErrServerSecretMismatch) || fw.sleeps != 0 {
			t.Fatalf("err = %v after %d sleeps, want ErrServerSecretMismatch at once", err, fw.sleeps)
		}
	})
}
