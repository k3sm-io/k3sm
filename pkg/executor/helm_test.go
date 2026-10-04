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

package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/helmchart"
)

// helmTarball builds a gzipped tar holding each name→content member.
func helmTarball(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeHelmRelease serves body as the pinned tarball and pins its digest (or
// pin, when non-empty), counting downloads. No network.
func fakeHelmRelease(t *testing.T, body []byte, pin string) *int {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	if pin == "" {
		sum := sha256.Sum256(body)
		pin = hex.EncodeToString(sum[:])
	}
	origURL, origSum := helmTarballURL, helmTarballSHA256
	t.Cleanup(func() { helmTarballURL, helmTarballSHA256 = origURL, origSum })
	helmTarballURL, helmTarballSHA256 = srv.URL+"/"+helmchart.HelmAsset, pin
	return &calls
}

func TestStageHelm(t *testing.T) {
	good := helmTarball(t, map[string]string{
		"darwin-arm64/README.md": "readme",
		"darwin-arm64/helm":      "the-helm-binary",
	})

	t.Run("verified download is extracted under the versioned name", func(t *testing.T) {
		fakeTool(t, "gh") // a dev shell: the download gate is open
		calls := fakeHelmRelease(t, good, "")
		bd := t.TempDir()
		path, err := EnsureHelm(t.Context(), bd)
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(bd, helmchart.HelmBinaryName) {
			t.Errorf("path = %s", path)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "the-helm-binary" {
			t.Errorf("staged helm = %q, %v", got, err)
		}
		if fi, _ := os.Stat(path); fi == nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("staged helm mode = %v, want 0755", fi)
		}
		entries, _ := os.ReadDir(bd)
		if len(entries) != 1 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("bin dir holds %v, want only the helm binary (no tarball, no temp)", names)
		}
		// A staged copy is kept: the dev-shell fallback downloads only when absent.
		if _, err := EnsureHelm(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		if *calls != 1 {
			t.Errorf("downloads = %d, want 1 (a staged helm is not fetched again)", *calls)
		}
	})

	t.Run("digest mismatch fails closed and stages nothing", func(t *testing.T) {
		fakeTool(t, "gh") // a dev shell: the download gate is open
		fakeHelmRelease(t, good, strings.Repeat("0", 64))
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); !errors.Is(err, ErrHelmDigestMismatch) {
			t.Fatalf("EnsureHelm = %v, want ErrHelmDigestMismatch", err)
		}
		if fileExists(helmchart.HelmPath(bd)) {
			t.Error("unverified bytes were staged")
		}
	})

	t.Run("a tarball without the binary is an error", func(t *testing.T) {
		fakeTool(t, "gh") // a dev shell: the download gate is open
		fakeHelmRelease(t, helmTarball(t, map[string]string{"linux-arm64/helm": "wrong"}), "")
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); err == nil || !strings.Contains(err.Error(), helmchart.HelmTarballMember) {
			t.Fatalf("EnsureHelm = %v, want an error naming %s", err, helmchart.HelmTarballMember)
		}
		if fileExists(helmchart.HelmPath(bd)) {
			t.Error("a binary was staged from a tarball that has none")
		}
	})

	t.Run("a daemon without gh gets ErrHelmNotStaged and never downloads", func(t *testing.T) {
		calls := fakeHelmRelease(t, good, "")
		t.Setenv("PATH", t.TempDir()) // no gh: the launchd daemon's environment
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); !errors.Is(err, ErrHelmNotStaged) {
			t.Fatalf("EnsureHelm = %v, want ErrHelmNotStaged", err)
		}
		if *calls != 0 {
			t.Errorf("downloads = %d, want 0 (the gate is closed)", *calls)
		}
		if fileExists(helmchart.HelmPath(bd)) {
			t.Error("a helm was staged with the gate closed")
		}
	})

	t.Run("a daemon without gh still uses a staged helm", func(t *testing.T) {
		calls := fakeHelmRelease(t, good, "")
		t.Setenv("PATH", t.TempDir())
		bd := t.TempDir()
		if err := os.WriteFile(helmchart.HelmPath(bd), []byte("payload-helm"), 0o755); err != nil {
			t.Fatal(err)
		}
		if path, err := EnsureHelm(t.Context(), bd); err != nil || path != helmchart.HelmPath(bd) {
			t.Fatalf("EnsureHelm = %q, %v", path, err)
		}
		if *calls != 0 {
			t.Errorf("downloads = %d, want 0", *calls)
		}
	})

	t.Run("a body over the download bound is truncated and fails the digest", func(t *testing.T) {
		fakeTool(t, "gh")
		fakeHelmRelease(t, good, "") // the pin is the digest of the whole body
		orig := maxHelmTarballBytes
		t.Cleanup(func() { maxHelmTarballBytes = orig })
		maxHelmTarballBytes = int64(len(good)) - 1
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); !errors.Is(err, ErrHelmDigestMismatch) {
			t.Fatalf("EnsureHelm = %v, want ErrHelmDigestMismatch (the bound truncates the body)", err)
		}
		if fileExists(helmchart.HelmPath(bd)) {
			t.Error("truncated bytes were staged")
		}
	})

	t.Run("the packaging path re-downloads over a present copy", func(t *testing.T) {
		calls := fakeHelmRelease(t, good, "")
		bd := t.TempDir()
		if err := os.WriteFile(helmchart.HelmPath(bd), []byte("signed-earlier"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := stageHelm(t.Context(), bd, true); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(helmchart.HelmPath(bd)); string(got) != "the-helm-binary" || *calls != 1 {
			t.Errorf("staged = %q after %d downloads, want the verified bytes after 1", got, *calls)
		}
	})
}

// TestPayloadCarriesHelm: helm is a payload binary, so install stages it, the
// release archive requires it, and the boot seed copies it into the work dir.
func TestPayloadCarriesHelm(t *testing.T) {
	if !slices.Contains(PayloadBinaries(), helmchart.HelmBinaryName) {
		t.Fatalf("PayloadBinaries() = %v, want %s", PayloadBinaries(), helmchart.HelmBinaryName)
	}
	payload, work := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(payload, helmchart.HelmBinaryName), []byte("payload-helm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(helmchart.HelmPath(BinDir(work))); err != nil || string(got) != "payload-helm" {
		t.Errorf("seeded helm = %q, %v", got, err)
	}
}
