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
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/bootstrap"
	"k3sm.io/k3sm/pkg/certs"
)

// bundleTestServer stands up an httptest server that serves the sealed bundle at
// BundlePath (any other path → the given status). It returns the server + its URL.
func bundleTestServer(t *testing.T, sealed []byte, missing bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != bootstrap.BundlePath {
			http.NotFound(w, r)
			return
		}
		if missing {
			http.Error(w, "no bundle", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(sealed)
	}))
}

// TestServerJoinImportsBundleBeforeEnsureHierarchy proves the import-then-load path: a
// joining server fetches + decrypts the bundle and writes the CA PEMs, so a SUBSEQUENT
// EnsureHierarchy LOADS the IDENTICAL cluster + signing CAs (it does NOT mint fresh
// ones). This is the mechanism by which a second server reconstructs identical CAs.
func TestServerJoinImportsBundleBeforeEnsureHierarchy(t *testing.T) {
	// Server A's hierarchy (the source of truth).
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

	ts := bundleTestServer(t, sealed, false)
	defer ts.Close()

	// Server B imports — before any EnsureHierarchy on B.
	wdB := t.TempDir()
	if _, statErr := os.Stat(certs.ClusterCACertPath(wdB)); statErr == nil {
		t.Fatal("precondition: server B must have no CA before import")
	}
	if err := bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
		Server:     ts.URL,
		Token:      bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret),
		WorkDir:    wdB,
		HTTPClient: ts.Client(),
	}); err != nil {
		t.Fatalf("import: %v", err)
	}

	// The CA PEMs now exist on B (the import wrote them).
	if _, err := os.Stat(certs.ClusterCACertPath(wdB)); err != nil {
		t.Fatalf("import must write the cluster CA: %v", err)
	}

	// EnsureHierarchy on B now LOADS the imported CAs → identical pins to A.
	hB, err := certs.EnsureHierarchy(wdB, certs.RoleMintAuthority, certs.PostureKine)
	if err != nil {
		t.Fatalf("server B EnsureHierarchy: %v", err)
	}
	if hB.Cluster.PinHash() != hA.Cluster.PinHash() {
		t.Errorf("cluster pin B %q != A %q (CAs not identical)", hB.Cluster.PinHash(), hA.Cluster.PinHash())
	}
	if hB.Signing.PinHash() != hA.Signing.PinHash() {
		t.Errorf("signing pin B %q != A %q (CAs not identical)", hB.Signing.PinHash(), hA.Signing.PinHash())
	}
	eServer, ePeer, err := certs.EnsureEtcdCAs(wdB)
	if err != nil {
		t.Fatalf("server B EnsureEtcdCAs: %v", err)
	}
	if eServer.PinHash() != hA.EtcdServer.PinHash() || ePeer.PinHash() != hA.EtcdPeer.PinHash() {
		t.Error("server B must LOAD the imported etcd CAs (identical pins), not mint fresh ones")
	}
}

// TestServerJoinFailsClosedOnAbsentBundle proves the fail-closed contract: when the
// bundle is absent (404) OR sealed under a different secret, ImportCABundle ERRORS and
// writes NO CA material — so the caller must halt and NEVER fall through to minting a
// self-signed divergent CA (which would split cluster trust).
func TestServerJoinFailsClosedOnAbsentBundle(t *testing.T) {
	caHash := func() string {
		h, _ := certs.NewCA("k3sm-cluster-ca")
		return h.PinHash()
	}()

	t.Run("absent bundle (404)", func(t *testing.T) {
		ts := bundleTestServer(t, nil, true)
		defer ts.Close()
		wd := t.TempDir()
		err := bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
			Server:     ts.URL,
			Token:      bootstrap.FormatServerToken(caHash, "any-secret"),
			WorkDir:    wd,
			HTTPClient: ts.Client(),
		})
		if err == nil {
			t.Fatal("import must FAIL when the bundle is absent (no divergent CA)")
		}
		if _, statErr := os.Stat(certs.ClusterCACertPath(wd)); !os.IsNotExist(statErr) {
			t.Error("a failed import must write NO CA material (fail closed)")
		}
	})

	t.Run("wrong secret (tag fails)", func(t *testing.T) {
		wdA := t.TempDir()
		hA, _ := certs.EnsureHierarchy(wdA, certs.RoleMintAuthority, certs.PostureKine)
		hA.EtcdServer, hA.EtcdPeer, _ = certs.EnsureEtcdCAs(wdA)
		pt, err := hA.Marshal()
		if err != nil {
			t.Fatalf("marshal A: %v", err)
		}
		sealed, _ := bootstrap.SealBundle("the-real-secret-0123456789abcdef0123456789", pt)
		ts := bundleTestServer(t, sealed, false)
		defer ts.Close()

		wd := t.TempDir()
		err = bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
			Server:     ts.URL,
			Token:      bootstrap.FormatServerToken(hA.Cluster.PinHash(), "WRONG-secret-99999999999999999999"),
			WorkDir:    wd,
			HTTPClient: ts.Client(),
		})
		if err == nil {
			t.Fatal("import must FAIL when the bundle secret is wrong (GCM tag) — no divergent CA")
		}
		if _, statErr := os.Stat(filepath.Join(certs.PKIDir(wd), "cluster-ca.crt")); !os.IsNotExist(statErr) {
			t.Error("a wrong-secret import must write NO CA material (fail closed)")
		}
	})

	t.Run("worker token rejected", func(t *testing.T) {
		ts := bundleTestServer(t, []byte("ignored"), false)
		defer ts.Close()
		wd := t.TempDir()
		// A worker-style token (user boot-...) is not a server token — import refuses it.
		err := bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
			Server:     ts.URL,
			Token:      bootstrap.FormatToken(caHash, "boot-abc", "secret"),
			WorkDir:    wd,
			HTTPClient: ts.Client(),
		})
		if err == nil {
			t.Fatal("import must reject a non-server (worker) token")
		}
	})
}

// TestImportCABundleBackfillsOnlyMissingCA is the B435 bootstrap-side gate: a server
// that already imported the bundle can import it again (a restart), the second import
// installs only the CA that went missing and leaves the present ones byte-identical,
// and a half-present CA refuses the import with nothing written.
func TestImportCABundleBackfillsOnlyMissingCA(t *testing.T) {
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
	ts := bundleTestServer(t, sealed, false)
	defer ts.Close()

	wdB := t.TempDir()
	importB := func() error {
		return bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
			Server:     ts.URL,
			Token:      bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret),
			WorkDir:    wdB,
			HTTPClient: ts.Client(),
		})
	}
	if err := importB(); err != nil {
		t.Fatalf("first import: %v", err)
	}
	ep := certs.EtcdCertPaths(wdB)
	present := []string{
		certs.ClusterCACertPath(wdB), certs.ClusterCAKeyPath(wdB),
		certs.SigningCACertPath(wdB), certs.SigningCAKeyPath(wdB),
		ep.ServerCACert, ep.ServerCAKey,
	}
	read := func(paths []string) map[string]string {
		out := map[string]string{}
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			out[p] = string(b)
		}
		return out
	}

	// A restart re-imports into a complete hierarchy: a no-op, not a refusal.
	before := read(append(present, ep.PeerCACert, ep.PeerCAKey))
	if err := importB(); err != nil {
		t.Fatalf("re-import into a complete hierarchy must succeed: %v", err)
	}
	if after := read(append(present, ep.PeerCACert, ep.PeerCAKey)); !reflect.DeepEqual(before, after) {
		t.Error("a re-import changed a present CA")
	}

	// The etcd peer pair goes missing: only it is installed.
	for _, p := range []string{ep.PeerCACert, ep.PeerCAKey} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	before = read(present)
	if err := importB(); err != nil {
		t.Fatalf("backfill import: %v", err)
	}
	if after := read(present); !reflect.DeepEqual(before, after) {
		t.Error("the backfill import changed a present CA")
	}
	_, peer, err := certs.EnsureEtcdCAs(wdB)
	if err != nil {
		t.Fatalf("EnsureEtcdCAs after backfill: %v", err)
	}
	if peer.PinHash() != hA.EtcdPeer.PinHash() {
		t.Error("the backfilled etcd peer CA is not the bundle's")
	}

	// The request-header pair is what an upgraded joined server lacks: the first
	// import installed it, and once it is gone only it is installed again, with the
	// bundle's pin.
	pinA, err := certs.LoadRequestHeaderPin(wdA)
	if err != nil {
		t.Fatalf("server A request-header pin: %v", err)
	}
	for _, p := range []string{certs.RequestHeaderCACertPath(wdB), certs.RequestHeaderCAKeyPath(wdB)} {
		if err := os.Remove(p); err != nil {
			t.Fatalf("the first import did not install the request-header CA: %v", err)
		}
	}
	before = read(append(present, ep.PeerCACert, ep.PeerCAKey))
	if err := importB(); err != nil {
		t.Fatalf("request-header backfill import: %v", err)
	}
	if after := read(append(present, ep.PeerCACert, ep.PeerCAKey)); !reflect.DeepEqual(before, after) {
		t.Error("the request-header backfill changed a present CA")
	}
	if pinB, err := certs.LoadRequestHeaderPin(wdB); err != nil || pinB != pinA {
		t.Errorf("backfilled request-header pin %q (err %v), want the bundle's %q", pinB, err, pinA)
	}

	// A server holding a different cluster CA is refused as diverged, nothing written.
	wdC := t.TempDir()
	if _, err := certs.EnsureHierarchy(wdC, certs.RoleMintAuthority, certs.PostureKine); err != nil {
		t.Fatal(err)
	}
	err = bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
		Server: ts.URL, Token: bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret), WorkDir: wdC, HTTPClient: ts.Client(),
	})
	if !errors.Is(err, certs.ErrHierarchyDiverged) {
		t.Errorf("import over a different cluster CA: err = %v, want ErrHierarchyDiverged", err)
	}
	if _, err := os.Lstat(certs.EtcdCertPaths(wdC).Dir); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a diverged import created the etcd PKI dir")
	}

	// A half-present CA (the signing key gone, its cert kept) refuses the import.
	if err := os.Remove(certs.SigningCAKeyPath(wdB)); err != nil {
		t.Fatal(err)
	}
	if err := importB(); err == nil {
		t.Fatal("an import over a half-present CA must fail")
	}
	if _, err := os.Stat(certs.SigningCAKeyPath(wdB)); !os.IsNotExist(err) {
		t.Error("a refused import must not write the missing signing key")
	}
}

// TestImportCABundleRefusesBundleWithoutRequestHeaderCA pins the policy refusal of a
// schema-2 bundle (served by a server one release older): ErrBundlePredatesRequestHeaderCA,
// returned before any write, both into an empty work dir and into the upgraded joined
// server that lacks only the request-header CA.
func TestImportCABundleRefusesBundleWithoutRequestHeaderCA(t *testing.T) {
	wdA := t.TempDir()
	hA, err := certs.EnsureHierarchy(wdA, certs.RoleMintAuthority, certs.PostureKine)
	if err != nil {
		t.Fatal(err)
	}
	if hA.EtcdServer, hA.EtcdPeer, err = certs.EnsureEtcdCAs(wdA); err != nil {
		t.Fatal(err)
	}
	v2, err := json.Marshal(map[string]any{
		"schemaVersion":       2,
		"clusterCACertPEM":    hA.Cluster.CertPEM,
		"clusterCAKeyPEM":     hA.Cluster.KeyPEM,
		"signingCACertPEM":    hA.Signing.CertPEM,
		"signingCAKeyPEM":     hA.Signing.KeyPEM,
		"etcdServerCACertPEM": hA.EtcdServer.CertPEM,
		"etcdServerCAKeyPEM":  hA.EtcdServer.KeyPEM,
		"etcdPeerCACertPEM":   hA.EtcdPeer.CertPEM,
		"etcdPeerCAKeyPEM":    hA.EtcdPeer.KeyPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	const secret = "server-bootstrap-secret-deadbeefdeadbeefdeadbeef"
	sealed, err := bootstrap.SealBundle(secret, v2)
	if err != nil {
		t.Fatal(err)
	}
	ts := bundleTestServer(t, sealed, false)
	defer ts.Close()
	importInto := func(wd string) error {
		return bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
			Server: ts.URL, Token: bootstrap.FormatServerToken(hA.Cluster.PinHash(), secret), WorkDir: wd, HTTPClient: ts.Client(),
		})
	}

	t.Run("empty work dir", func(t *testing.T) {
		wd := t.TempDir()
		err := importInto(wd)
		if !errors.Is(err, bootstrap.ErrBundlePredatesRequestHeaderCA) {
			t.Fatalf("err = %v, want ErrBundlePredatesRequestHeaderCA", err)
		}
		if !strings.Contains(err.Error(), "upgrade the mint-authority server first") {
			t.Errorf("error %q does not name the remedy", err)
		}
		if _, err := os.Lstat(certs.PKIDir(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a refused import created the PKI dir (stat err %v)", err)
		}
	})

	t.Run("upgraded joined server lacking only the request-header CA", func(t *testing.T) {
		wd := t.TempDir()
		for _, p := range []struct{ src, dst string }{
			{certs.ClusterCACertPath(wdA), certs.ClusterCACertPath(wd)}, {certs.ClusterCAKeyPath(wdA), certs.ClusterCAKeyPath(wd)},
			{certs.SigningCACertPath(wdA), certs.SigningCACertPath(wd)}, {certs.SigningCAKeyPath(wdA), certs.SigningCAKeyPath(wd)},
			{certs.EtcdCertPaths(wdA).ServerCACert, certs.EtcdCertPaths(wd).ServerCACert}, {certs.EtcdCertPaths(wdA).ServerCAKey, certs.EtcdCertPaths(wd).ServerCAKey},
			{certs.EtcdCertPaths(wdA).PeerCACert, certs.EtcdCertPaths(wd).PeerCACert}, {certs.EtcdCertPaths(wdA).PeerCAKey, certs.EtcdCertPaths(wd).PeerCAKey},
		} {
			b, err := os.ReadFile(p.src)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(p.dst), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.dst, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := importInto(wd); !errors.Is(err, bootstrap.ErrBundlePredatesRequestHeaderCA) {
			t.Fatalf("err = %v, want ErrBundlePredatesRequestHeaderCA", err)
		}
		if _, err := os.Lstat(certs.RequestHeaderCACertPath(wd)); !errors.Is(err, fs.ErrNotExist) {
			t.Error("a refused import wrote a request-header CA")
		}
	})
}
