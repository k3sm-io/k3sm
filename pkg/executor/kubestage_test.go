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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The control-plane version marker (B395). The four kwok-ci/k8s binaries used to be
// provisioned on presence alone, so a binary-only upgrade that moved
// DefaultKubeVersion kept serving the previous release's apiserver with nothing in
// the log, the status report, or the crash record. These tests pin the marker
// contract that closes it: the seed re-stages a stale set from a vouching payload,
// refuses a downgrade, grandfathers an unmarked set quietly, and the boot never
// parks or fails on a stale set.

const staleKubeVersion = "v1.35.0" // older than any DefaultKubeVersion this tree pins

// stageCPSet writes the four control-plane binaries into dir with the given content
// and, when version is non-empty, a marker vouching for it.
func stageCPSet(t *testing.T, dir, content, version string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range cpBinaries {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content+":"+name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if version != "" {
		if err := os.WriteFile(kubeMarkerPath(dir), []byte(kubeMarkerContent(version)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// assertCPSet fails unless every control-plane binary in dir carries content.
func assertCPSet(t *testing.T, dir, content string) {
	t.Helper()
	for _, name := range cpBinaries {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != content+":"+name {
			t.Errorf("%s = %q (%v), want %q", name, got, err, content+":"+name)
		}
	}
}

// bufLogger returns a logger writing text records into the returned buffer.
func bufLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

// fakeTool puts an executable named name on a fresh PATH (and nothing else), so a
// LookPath preflight finds it without anything real running.
func fakeTool(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
}

// fakeDownload replaces the release download with one that writes the four binaries
// with content into the target dir, counting calls. No network.
func fakeDownload(t *testing.T, content string) *int {
	t.Helper()
	calls := 0
	orig := runControlPlaneDownload
	t.Cleanup(func() { runControlPlaneDownload = orig })
	runControlPlaneDownload = func(_ context.Context, _, dir string) ([]byte, error) {
		calls++
		for _, name := range cpBinaries {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content+":"+name), 0o644); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	return &calls
}

func TestKubeMarkerParse(t *testing.T) {
	for _, tc := range []struct {
		name, content, want string
	}{
		{"one version line", "v1.36.5\n", "v1.36.5"},
		{"no trailing newline", "v1.36.5", "v1.36.5"},
		{"empty", "", ""},
		{"whitespace only", " \n", ""},
		{"two fields is malformed", "v1.36.5 extra\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseKubeMarker([]byte(tc.content)); got != tc.want {
				t.Errorf("ParseKubeMarker(%q) = %q, want %q", tc.content, got, tc.want)
			}
		})
	}
	t.Run("round trip through the atomic write", func(t *testing.T) {
		bd := t.TempDir()
		if err := writeKubeMarker(bd, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		if got := readKubeMarker(bd); got != DefaultKubeVersion {
			t.Errorf("readKubeMarker = %q, want %q", got, DefaultKubeVersion)
		}
		if _, err := os.Stat(kubeMarkerPath(bd) + ".tmp"); !os.IsNotExist(err) {
			t.Error("the atomic write left its temp file behind")
		}
	})
	t.Run("a marker without the full set does not vouch", func(t *testing.T) {
		bd := t.TempDir()
		stageCPSet(t, bd, "x", DefaultKubeVersion)
		if err := os.Remove(filepath.Join(bd, "kube-scheduler")); err != nil {
			t.Fatal(err)
		}
		if kubeSetStaged(bd, DefaultKubeVersion) {
			t.Error("kubeSetStaged = true with kube-scheduler missing")
		}
	})
}

// TestSeedBinDirRestagesStaleControlPlaneBinaries is the B395 gate: a workdir whose
// marker names an older release, beside a payload whose marker vouches for the
// target, gets the WHOLE set from the payload and a marker vouching for the target.
func TestSeedBinDirRestagesStaleControlPlaneBinaries(t *testing.T) {
	t.Run("stale marker, vouching payload: whole set re-seeded", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, binDir(work), "old", staleKubeVersion)
		stageCPSet(t, payload, "new", DefaultKubeVersion)
		logger, buf := bufLogger()
		if err := seedBinDir(logger, work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		assertCPSet(t, binDir(work), "new")
		if !kubeSetStaged(binDir(work), DefaultKubeVersion) {
			t.Errorf("re-seed left marker %q, want %s", readKubeMarker(binDir(work)), DefaultKubeVersion)
		}
		if !strings.Contains(buf.String(), "from="+staleKubeVersion) {
			t.Errorf("the re-seed was not logged with the version it replaced:\n%s", buf)
		}
	})

	// The marker is written LAST: a re-seed that fails part-way must leave NO marker
	// (the stale one is dropped first, the new one never written), so nothing vouches
	// for a half-replaced set and the next boot re-seeds again.
	t.Run("a re-seed interrupted mid-set leaves no marker", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, binDir(work), "old", staleKubeVersion)
		stageCPSet(t, payload, "new", DefaultKubeVersion)
		// kubectl is the last of the set; a directory in its place makes its copy fail.
		if err := os.Remove(filepath.Join(binDir(work), "kubectl")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(binDir(work), "kubectl"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion); err == nil {
			t.Fatal("seedBinDir succeeded over an uncopyable kubectl")
		}
		if _, err := os.Stat(kubeMarkerPath(binDir(work))); !os.IsNotExist(err) {
			t.Errorf("a marker survived a failed re-seed (%q); it vouches for a half-replaced set", readKubeMarker(binDir(work)))
		}
	})

	t.Run("fresh workdir: seeded and marked", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, payload, "new", DefaultKubeVersion)
		if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		assertCPSet(t, binDir(work), "new")
		if !kubeSetStaged(binDir(work), DefaultKubeVersion) {
			t.Error("a fresh seed from a vouching payload left the set unmarked")
		}
	})

	t.Run("a payload that does not vouch for the target is not trusted", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, binDir(work), "old", staleKubeVersion)
		stageCPSet(t, payload, "previous-release", "v1.35.9")
		if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		assertCPSet(t, binDir(work), "old")
		if got := readKubeMarker(binDir(work)); got != staleKubeVersion {
			t.Errorf("marker = %q, want the untouched %q", got, staleKubeVersion)
		}
	})
}

// TestSeedBinDirRefusesControlPlaneDowngrade: a payload vouching for a version OLDER
// than the workdir's marker is refused loudly, and the present set stays.
func TestSeedBinDirRefusesControlPlaneDowngrade(t *testing.T) {
	const newer = "v1.99.0"
	payload, work := t.TempDir(), t.TempDir()
	stageCPSet(t, binDir(work), "newer", newer)
	stageCPSet(t, payload, "older", DefaultKubeVersion)
	logger, buf := bufLogger()
	if err := seedBinDir(logger, work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
		t.Fatalf("a refused downgrade must not fail the boot: %v", err)
	}
	assertCPSet(t, binDir(work), "newer")
	if got := readKubeMarker(binDir(work)); got != newer {
		t.Errorf("marker = %q, want the untouched %q", got, newer)
	}
	out := buf.String()
	for _, want := range []string{"level=ERROR", "refusing to re-seed", newer, DefaultKubeVersion} {
		if !strings.Contains(out, want) {
			t.Errorf("downgrade refusal log lacks %q:\n%s", want, out)
		}
	}
}

// TestSeedBinDirGrandfathersUnmarkedControlPlane: every install before this change
// has an unmarked set. It must boot exactly as before, with no alarm, and converge
// onto a marker as soon as a vouching payload is staged.
func TestSeedBinDirGrandfathersUnmarkedControlPlane(t *testing.T) {
	t.Run("unmarked set, unmarked payload: untouched, quiet boot", func(t *testing.T) {
		fakeTool(t) // no gh: nothing may try to download
		calls := fakeDownload(t, "downloaded")
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, binDir(work), "existing", "")
		stageCPSet(t, payload, "payload", "")
		logger, buf := bufLogger()
		if err := seedBinDir(logger, work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		if err := ensureControlPlaneBinaries(t.Context(), logger, work, DefaultKubeVersion); err != nil {
			t.Fatalf("an unmarked set failed the boot: %v", err)
		}
		assertCPSet(t, binDir(work), "existing")
		if _, err := os.Stat(kubeMarkerPath(binDir(work))); !os.IsNotExist(err) {
			t.Error("stamped a marker onto a set nothing vouched for")
		}
		if *calls != 0 {
			t.Errorf("an unmarked set triggered %d downloads", *calls)
		}
		out := buf.String()
		if strings.Contains(out, "level=ERROR") || strings.Contains(out, "level=WARN") {
			t.Errorf("an unmarked set raised an alarm:\n%s", out)
		}
		if !strings.Contains(out, "unvouched") {
			t.Errorf("the unmarked set's info line is missing:\n%s", out)
		}
	})

	t.Run("unmarked set, vouching payload: converges onto the marker", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		stageCPSet(t, binDir(work), "existing", "")
		stageCPSet(t, payload, "payload", DefaultKubeVersion)
		if err := seedBinDir(discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		assertCPSet(t, binDir(work), "payload")
		if !kubeSetStaged(binDir(work), DefaultKubeVersion) {
			t.Error("the seed did not write the marker, so the unmarked state never converges")
		}
	})
}

// TestEnsureControlPlaneBinariesReportsStagedVersion: the boot-time check on a present
// set. It never fails the boot and never parks; it says what it found.
func TestEnsureControlPlaneBinariesReportsStagedVersion(t *testing.T) {
	t.Run("vouching marker: one verified info line", func(t *testing.T) {
		work := t.TempDir()
		stageCPSet(t, binDir(work), "current", DefaultKubeVersion)
		logger, buf := bufLogger()
		if err := ensureControlPlaneBinaries(t.Context(), logger, work, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "control-plane binaries verified "+DefaultKubeVersion) {
			t.Errorf("no verified line:\n%s", buf)
		}
	})

	t.Run("stale marker, no gh: loud, continues, no download", func(t *testing.T) {
		fakeTool(t) // a PATH that exists and holds no gh
		calls := fakeDownload(t, "downloaded")
		work := t.TempDir()
		stageCPSet(t, binDir(work), "old", staleKubeVersion)
		logger, buf := bufLogger()
		if err := ensureControlPlaneBinaries(t.Context(), logger, work, DefaultKubeVersion); err != nil {
			t.Fatalf("a stale set failed the boot (serving beats down): %v", err)
		}
		assertCPSet(t, binDir(work), "old")
		if *calls != 0 {
			t.Errorf("attempted %d downloads with no gh on PATH", *calls)
		}
		out := buf.String()
		for _, want := range []string{"level=ERROR", "STALE", staleKubeVersion, DefaultKubeVersion, "sudo k3sm install"} {
			if !strings.Contains(out, want) {
				t.Errorf("stale-set log lacks %q:\n%s", want, out)
			}
		}
	})

	t.Run("stale marker, gh present: dev fallback re-stages the set", func(t *testing.T) {
		fakeTool(t, "gh")
		calls := fakeDownload(t, "downloaded")
		work := t.TempDir()
		stageCPSet(t, binDir(work), "old", staleKubeVersion)
		if err := ensureControlPlaneBinaries(t.Context(), discardLogger(), work, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		if *calls != 1 {
			t.Errorf("downloads = %d, want 1", *calls)
		}
		assertCPSet(t, binDir(work), "downloaded")
		if !kubeSetStaged(binDir(work), DefaultKubeVersion) {
			t.Error("the dev fallback did not mark the re-staged set")
		}
		entries, _ := os.ReadDir(binDir(work))
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".kube-restage-") {
				t.Errorf("scratch dir %s left behind", e.Name())
			}
		}
	})

	t.Run("newer marker: loud, continues, never downloads the older release", func(t *testing.T) {
		fakeTool(t, "gh")
		calls := fakeDownload(t, "downloaded")
		work := t.TempDir()
		stageCPSet(t, binDir(work), "newer", "v1.99.0")
		logger, buf := bufLogger()
		if err := ensureControlPlaneBinaries(t.Context(), logger, work, DefaultKubeVersion); err != nil {
			t.Fatal(err)
		}
		if *calls != 0 {
			t.Errorf("downloaded the older release over a newer set (%d calls)", *calls)
		}
		assertCPSet(t, binDir(work), "newer")
		if !strings.Contains(buf.String(), "level=ERROR") {
			t.Errorf("a newer staged set was not reported:\n%s", buf)
		}
	})
}

// TestStagePayloadWritesKubeMarker is the end-to-end producer check: StagePayload's
// output carries both markers and passes VerifyPayloadSet, which it runs last. Both
// tools are faked, and the pin table is pointed at the fake bytes' digests for the
// duration — the real digests would need a sha256 preimage.
func TestStagePayloadWritesKubeMarker(t *testing.T) {
	fakeTool(t, "go")
	fakeDownload(t, "release")
	origPins := payloadDigests[DefaultKubeVersion]
	t.Cleanup(func() { payloadDigests[DefaultKubeVersion] = origPins })
	pins := map[string]string{}
	for _, name := range cpBinaries {
		sum := sha256.Sum256([]byte("release:" + name))
		pins[name] = hex.EncodeToString(sum[:])
	}
	payloadDigests[DefaultKubeVersion] = pins

	origCache, origBuild := kineModuleCacheDir, runKineBuild
	t.Cleanup(func() { kineModuleCacheDir, runKineBuild = origCache, origBuild })
	cache := t.TempDir()
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	runKineBuild = func(_ context.Context, _, gopath, _ string) ([]byte, error) {
		if err := os.MkdirAll(filepath.Join(gopath, "bin"), 0o755); err != nil {
			return nil, err
		}
		return nil, os.WriteFile(filepath.Join(gopath, "bin", "kine"), []byte("pretend-kine"), 0o755)
	}

	dest := filepath.Join(t.TempDir(), "payload")
	if err := StagePayload(t.Context(), dest); err != nil {
		t.Fatalf("StagePayload = %v, want the staged dir to pass VerifyPayloadSet", err)
	}
	if !kubeSetStaged(dest, DefaultKubeVersion) {
		t.Errorf("payload control-plane marker = %q, want %s", readKubeMarker(dest), DefaultKubeVersion)
	}
	if !kineStaged(dest, DefaultKineVersion) {
		t.Error("payload kine marker missing")
	}
	if err := VerifyPayloadSet(dest); err != nil {
		t.Errorf("VerifyPayloadSet(staged payload) = %v", err)
	}
}
