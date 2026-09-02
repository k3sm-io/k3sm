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

package registrysvc

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestZotStaged pins the marker predicate, which is the thing that makes a pin
// bump reach a machine that has already booted once. A presence-only check would
// pass every one of the "wrong" rows below.
func TestZotStaged(t *testing.T) {
	cases := []struct {
		name       string
		binary     bool
		marker     string
		wantStaged bool
	}{
		{name: "binary and matching marker", binary: true, marker: DefaultZotVersion + " " + zotBuildVariant, wantStaged: true},
		{name: "trailing newline is tolerated", binary: true, marker: DefaultZotVersion + " " + zotBuildVariant + "\n", wantStaged: true},
		{name: "no binary", binary: false, marker: DefaultZotVersion + " " + zotBuildVariant},
		{name: "no marker at all", binary: true, marker: ""},
		{name: "an earlier release's version", binary: true, marker: "v2.1.19 " + zotBuildVariant},
		{name: "the right version, the wrong build variant", binary: true, marker: DefaultZotVersion + " extended"},
		{name: "a version with no variant", binary: true, marker: DefaultZotVersion},
		{name: "an empty marker", binary: true, marker: " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bd := t.TempDir()
			if tc.binary {
				if err := os.WriteFile(ZotPath(bd), []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatalf("stage a binary: %v", err)
				}
			}
			if tc.marker != "" {
				if err := os.WriteFile(zotMarkerPath(bd), []byte(tc.marker), 0o644); err != nil {
					t.Fatalf("write a marker: %v", err)
				}
			}
			if got := zotStaged(bd, DefaultZotVersion); got != tc.wantStaged {
				t.Errorf("zotStaged = %v, want %v", got, tc.wantStaged)
			}
		})
	}
}

// TestWriteZotMarker pins the marker's content, because seedZot on ANOTHER
// machine reads exactly these bytes to decide whether a payload may be trusted.
func TestWriteZotMarker(t *testing.T) {
	bd := t.TempDir()
	if err := writeZotMarker(bd, DefaultZotVersion); err != nil {
		t.Fatalf("writeZotMarker: %v", err)
	}
	b, err := os.ReadFile(zotMarkerPath(bd))
	if err != nil {
		t.Fatalf("read the marker: %v", err)
	}
	if want := DefaultZotVersion + " " + zotBuildVariant + "\n"; string(b) != want {
		t.Errorf("marker = %q, want %q", b, want)
	}
	if _, err := os.Stat(zotMarkerPath(bd) + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("the temp marker survived the rename; an interrupted boot would find two markers")
	}
	v, variant := readZotMarker(bd)
	if v != DefaultZotVersion || variant != zotBuildVariant {
		t.Errorf("readZotMarker = (%q,%q), want (%q,%q)", v, variant, DefaultZotVersion, zotBuildVariant)
	}
}

// TestEnsureZotBuildsThenIsANoOp drives EnsureZot with the go-install seam faked,
// so the staging contract is provable without a toolchain, a network, or a
// hundred-megabyte download.
func TestEnsureZotBuildsThenIsANoOp(t *testing.T) {
	bd := filepath.Join(t.TempDir(), "bin")
	builds := 0
	restore := fakeBuild(t, func(version, gopath string) error {
		builds++
		return writeFakeBinary(filepath.Join(gopath, "bin", ZotBinaryName), version)
	})
	defer restore()

	if err := EnsureZot(t.Context(), bd, "", DefaultZotVersion); err != nil {
		t.Fatalf("EnsureZot: %v", err)
	}
	if builds != 1 {
		t.Fatalf("builds = %d after the first ensure, want 1", builds)
	}
	if !zotStaged(bd, DefaultZotVersion) {
		t.Fatal("the binary is not marked as staged after a successful build")
	}

	t.Run("a second ensure at the same pin does not rebuild", func(t *testing.T) {
		if err := EnsureZot(t.Context(), bd, "", DefaultZotVersion); err != nil {
			t.Fatalf("EnsureZot: %v", err)
		}
		if builds != 1 {
			t.Errorf("builds = %d, want 1 — a marked binary must not be rebuilt", builds)
		}
	})

	t.Run("a pin bump rebuilds over the staged binary", func(t *testing.T) {
		if err := EnsureZot(t.Context(), bd, "", "v2.1.21"); err != nil {
			t.Fatalf("EnsureZot: %v", err)
		}
		if builds != 2 {
			t.Errorf("builds = %d, want 2 — a pin bump must reach a machine that already booted", builds)
		}
		if !zotStaged(bd, "v2.1.21") {
			t.Error("the marker does not vouch for the new pin")
		}
		b, err := os.ReadFile(ZotPath(bd))
		if err != nil {
			t.Fatalf("read the staged binary: %v", err)
		}
		if !strings.Contains(string(b), "v2.1.21") {
			t.Errorf("the staged bytes are %q, still the previous pin's", b)
		}
	})
}

// TestEnsureZotFailureLeavesNoMarker pins the ordering that keeps the marker
// honest: a failed build must leave nothing vouching for bytes that were never
// written, so the next boot re-stages instead of trusting a lie.
func TestEnsureZotFailureLeavesNoMarker(t *testing.T) {
	bd := filepath.Join(t.TempDir(), "bin")
	restore := fakeBuild(t, func(string, string) error { return errNoToolchain })
	defer restore()

	err := EnsureZot(t.Context(), bd, "", DefaultZotVersion)
	if err == nil {
		t.Fatal("EnsureZot = nil after a failed build, want an error")
	}
	if !strings.Contains(err.Error(), "k3sm install") {
		t.Errorf("the build failure %q does not tell the operator what to do about it", err)
	}
	if zotStaged(bd, DefaultZotVersion) {
		t.Error("a failed build left a marker vouching for the pin")
	}
}

// TestEnsureZotSeedsFromAPayload pins the packaged-install path: a launchd daemon
// has no Go toolchain, so a marked payload must be COPIED rather than built.
func TestEnsureZotSeedsFromAPayload(t *testing.T) {
	payload := t.TempDir()
	if err := writeFakeBinary(ZotPath(payload), DefaultZotVersion); err != nil {
		t.Fatalf("stage the payload binary: %v", err)
	}
	if err := writeZotMarker(payload, DefaultZotVersion); err != nil {
		t.Fatalf("mark the payload: %v", err)
	}

	t.Run("a marked payload is copied, never built", func(t *testing.T) {
		bd := filepath.Join(t.TempDir(), "bin")
		builds := 0
		restore := fakeBuild(t, func(string, string) error { builds++; return errNoToolchain })
		defer restore()

		if err := EnsureZot(t.Context(), bd, payload, DefaultZotVersion); err != nil {
			t.Fatalf("EnsureZot: %v", err)
		}
		if builds != 0 {
			t.Errorf("builds = %d, want 0 — a packaged install has no toolchain to build with", builds)
		}
		if !zotStaged(bd, DefaultZotVersion) {
			t.Error("the seeded binary is not marked as staged")
		}
	})

	t.Run("an UNMARKED payload is not trusted", func(t *testing.T) {
		unmarked := t.TempDir()
		if err := writeFakeBinary(ZotPath(unmarked), "who-knows"); err != nil {
			t.Fatalf("stage: %v", err)
		}
		bd := filepath.Join(t.TempDir(), "bin")
		builds := 0
		restore := fakeBuild(t, func(version, gopath string) error {
			builds++
			return writeFakeBinary(filepath.Join(gopath, "bin", ZotBinaryName), version)
		})
		defer restore()

		if err := EnsureZot(t.Context(), bd, unmarked, DefaultZotVersion); err != nil {
			t.Fatalf("EnsureZot: %v", err)
		}
		if builds != 1 {
			t.Errorf("builds = %d, want 1 — an unmarked payload must never be stamped with a pin nobody verified", builds)
		}
	})

	t.Run("a payload marked for a DIFFERENT pin is not trusted", func(t *testing.T) {
		bd := filepath.Join(t.TempDir(), "bin")
		builds := 0
		restore := fakeBuild(t, func(version, gopath string) error {
			builds++
			return writeFakeBinary(filepath.Join(gopath, "bin", ZotBinaryName), version)
		})
		defer restore()

		if err := EnsureZot(t.Context(), bd, payload, "v2.1.21"); err != nil {
			t.Fatalf("EnsureZot: %v", err)
		}
		if builds != 1 {
			t.Errorf("builds = %d, want 1 — the payload carries the previous release's pin", builds)
		}
	})
}

// TestZotBuildEnv pins the environment the out-of-module install runs under. Each
// entry is load bearing and each has its own failure mode: CGO_ENABLED=0 keeps a
// C toolchain out of every artifact, GOWORK=off keeps the workspace out of an
// out-of-module install, the cleared GOBIN avoids `go install`'s cross-compile
// refusal, and the pinned GOMODCACHE keeps the dependency tree off the per-boot
// scratch dir it would otherwise be re-downloaded into every boot.
func TestZotBuildEnv(t *testing.T) {
	env := zotBuildEnv("/scratch/gopath", "/stable/modcache")
	for _, want := range []string{
		"CGO_ENABLED=0",
		"GOWORK=off",
		"GOBIN=",
		"GOPATH=/scratch/gopath",
		"GOMODCACHE=/stable/modcache",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("the build env lacks %q", want)
		}
	}
	if slices.Contains(env, "GOMODCACHE=/scratch/gopath/pkg/mod") {
		t.Error("the module cache is inside the scratch GOPATH; zot's whole dependency tree would be re-downloaded on every boot")
	}
}

// TestPayloadBinaries pins the packaging set, so `k3sm install` and the release
// archive stage exactly the binary the boot path expects to find.
func TestPayloadBinaries(t *testing.T) {
	if got := PayloadBinaries(); len(got) != 1 || got[0] != ZotBinaryName {
		t.Errorf("PayloadBinaries() = %v, want [%q]", got, ZotBinaryName)
	}
}

// errNoToolchain stands in for the `go install` failure a packaged host produces.
var errNoToolchain = os.ErrNotExist

// fakeBuild replaces the two build seams with an in-process fake and returns a
// restore func. The module-cache seam is answered from a temp dir so no real
// toolchain is consulted.
func fakeBuild(t *testing.T, build func(version, gopath string) error) func() {
	t.Helper()
	cache := t.TempDir()
	prevCache, prevBuild := zotModuleCacheDir, runZotBuild
	zotModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	runZotBuild = func(_ context.Context, version, gopath, modCache string) ([]byte, error) {
		if modCache != cache {
			t.Errorf("build ran against module cache %q, want the stable %q", modCache, cache)
		}
		if err := build(version, gopath); err != nil {
			return []byte("fake build output"), err
		}
		return nil, nil
	}
	return func() { zotModuleCacheDir, runZotBuild = prevCache, prevBuild }
}

// writeFakeBinary writes a stand-in binary whose CONTENT names the version, so a
// test can tell one staged pin from another by reading the file.
func writeFakeBinary(path, version string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("#!/bin/sh\n# zot "+version+"\n"), 0o755)
}
