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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unpinnedKubeVersion has no entry in payloadDigests: a dev running a non-default
// kube version. It is newer than staleKubeVersion, so the restage path runs for it.
const unpinnedKubeVersion = "v1.98.0"

// pinFakeDigests points the pin table for version at the digests of the bytes
// fakeDownload(content) writes, for the duration of the test. The real pins would
// need a sha256 preimage.
func pinFakeDigests(t *testing.T, version, content string) {
	t.Helper()
	orig, had := payloadDigests[version]
	t.Cleanup(func() {
		if had {
			payloadDigests[version] = orig
		} else {
			delete(payloadDigests, version)
		}
	})
	pins := map[string]string{}
	for _, name := range cpBinaries {
		sum := sha256.Sum256([]byte(content + ":" + name))
		pins[name] = hex.EncodeToString(sum[:])
	}
	payloadDigests[version] = pins
}

// TestBootPathVerifiesPinnedControlPlaneDigest (B530): the boot and dev-shell paths
// that download the kwok-ci/k8s binaries verify them against the pinned digests
// whenever a pin exists for the requested version. A tampered download fails closed
// and never reaches the working set; an unpinned version is still accepted, with one
// Warn naming it; the packaging path still refuses an unpinned version outright.
func TestBootPathVerifiesPinnedControlPlaneDigest(t *testing.T) {
	type outcome int
	const (
		refused outcome = iota
		installed
		installedWithWarn
	)
	for _, tc := range []struct {
		name    string
		restage bool   // false: fresh ensureControlPlaneBinaries; true: restageFromRelease via a stale set
		version string // requested kube version
		pin     bool   // point the pin table at the fake download's bytes
		want    outcome
	}{
		{"fresh download, tampered pinned release", false, DefaultKubeVersion, false, refused},
		{"fresh download, correct pinned release", false, DefaultKubeVersion, true, installed},
		{"fresh download, unpinned version", false, unpinnedKubeVersion, false, installedWithWarn},
		{"restage, tampered pinned release", true, DefaultKubeVersion, false, refused},
		{"restage, correct pinned release", true, DefaultKubeVersion, true, installed},
		{"restage, unpinned version", true, unpinnedKubeVersion, false, installedWithWarn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeTool(t, "gh")
			calls := fakeDownload(t, "downloaded")
			if tc.pin {
				pinFakeDigests(t, tc.version, "downloaded")
			}
			work := t.TempDir()
			bd := binDir(work)
			if tc.restage {
				stageCPSet(t, bd, "old", staleKubeVersion)
			} else if err := os.MkdirAll(bd, 0o755); err != nil {
				t.Fatal(err)
			}
			logger, buf := bufLogger()
			err := ensureControlPlaneBinaries(t.Context(), logger, work, tc.version)
			out := buf.String()
			if *calls != 1 {
				t.Fatalf("downloads = %d, want 1", *calls)
			}

			switch tc.want {
			case refused:
				if tc.restage {
					// A stale set keeps serving; the refusal is reported, not fatal.
					if err != nil {
						t.Fatalf("a refused re-stage failed the boot: %v", err)
					}
					if !strings.Contains(out, ErrPayloadDigestMismatch.Error()) {
						t.Errorf("the digest mismatch was not reported:\n%s", out)
					}
					assertCPSet(t, bd, "old")
					if got := readKubeMarker(bd); got != staleKubeVersion {
						t.Errorf("marker = %q, want the untouched %q", got, staleKubeVersion)
					}
				} else {
					if !errors.Is(err, ErrPayloadDigestMismatch) {
						t.Fatalf("tampered download = %v, want ErrPayloadDigestMismatch", err)
					}
					for _, name := range cpBinaries {
						if _, err := os.Stat(filepath.Join(bd, name)); !os.IsNotExist(err) {
							t.Errorf("tampered %s was installed into the working set", name)
						}
					}
					if _, err := os.Stat(kubeMarkerPath(bd)); !os.IsNotExist(err) {
						t.Error("a refused download left a version marker")
					}
				}
			case installed, installedWithWarn:
				if err != nil {
					t.Fatalf("ensureControlPlaneBinaries = %v", err)
				}
				assertCPSet(t, bd, "downloaded")
				if !kubeSetStaged(bd, tc.version) {
					t.Errorf("marker = %q, want %s", readKubeMarker(bd), tc.version)
				}
				warns := strings.Count(out, "level=WARN")
				if tc.want == installed && warns != 0 {
					t.Errorf("a verified download warned:\n%s", out)
				}
				if tc.want == installedWithWarn {
					if warns != 1 {
						t.Errorf("WARN lines = %d, want exactly 1:\n%s", warns, out)
					}
					if !strings.Contains(out, tc.version) || !strings.Contains(out, "unpinned") {
						t.Errorf("the warn does not name the unpinned version %s:\n%s", tc.version, out)
					}
				}
			}
			entries, _ := os.ReadDir(bd)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".kube-") {
					t.Errorf("scratch dir %s left behind", e.Name())
				}
			}
		})
	}

	t.Run("packaging refuses an unpinned version", func(t *testing.T) {
		fakeDownload(t, "downloaded")
		dir := t.TempDir()
		err := ensureControlPlaneBinariesVerified(t.Context(), discardLogger(), dir, unpinnedKubeVersion, true)
		if !errors.Is(err, ErrPayloadDigestUnpinned) {
			t.Fatalf("packaging an unpinned version = %v, want ErrPayloadDigestUnpinned", err)
		}
		if kubeSetStaged(dir, unpinnedKubeVersion) {
			t.Error("a refused packaging run wrote a version marker")
		}
	})
}
