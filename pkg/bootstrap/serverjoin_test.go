package bootstrap_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	hA, err := certs.EnsureHierarchy(wdA)
	if err != nil {
		t.Fatalf("server A hierarchy: %v", err)
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
	hB, err := certs.EnsureHierarchy(wdB)
	if err != nil {
		t.Fatalf("server B EnsureHierarchy: %v", err)
	}
	if hB.Cluster.PinHash() != hA.Cluster.PinHash() {
		t.Errorf("cluster pin B %q != A %q (CAs not identical)", hB.Cluster.PinHash(), hA.Cluster.PinHash())
	}
	if hB.Signing.PinHash() != hA.Signing.PinHash() {
		t.Errorf("signing pin B %q != A %q (CAs not identical)", hB.Signing.PinHash(), hA.Signing.PinHash())
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
		hA, _ := certs.EnsureHierarchy(wdA)
		pt, _ := hA.Marshal()
		sealed, _ := bootstrap.SealBundle("the-real-secret-0123456789abcdef0123456789", pt)
		ts := bundleTestServer(t, sealed, false)
		defer ts.Close()

		wd := t.TempDir()
		err := bootstrap.ImportCABundle(context.Background(), bootstrap.ServerJoinOptions{
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
