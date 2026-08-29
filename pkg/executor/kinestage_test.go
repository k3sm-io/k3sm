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
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestKineStagedPredicate is the version-marker staging contract. The predicate it
// replaces was `os.Stat(kine) == nil` — presence — which cannot distinguish a correctly
// staged binary from one an EARLIER release built. Every node that has booted once has
// a kine binary, so under the old predicate a pin change reached fresh installs ONLY
// and silently never reached the installed base. Each case below is a way that could
// happen again.
func TestKineStagedPredicate(t *testing.T) {
	cases := []struct {
		name    string
		binary  bool
		marker  string // "" = write no marker at all; "\x00" = write an EMPTY marker file
		want    bool
		because string
	}{
		{"binary + matching marker", true, DefaultKineVersion + " " + kineBuildVariant, true,
			"the only state that may skip a re-stage"},
		{"binary, no marker", true, "", false,
			"every pre-marker node looks exactly like this — it MUST re-stage"},
		{"binary + older version", true, "v1.14.2 " + kineBuildVariant, false,
			"the pin moved; the staged bytes are the old pin's"},
		{"binary + same version, wrong variant", true, DefaultKineVersion + " cgo", false,
			"one tag builds two different SQLite implementations; version alone is not identity"},
		{"binary + truncated marker", true, DefaultKineVersion, false,
			"a marker without a variant vouches for nothing"},
		{"binary + empty marker file", true, "\x00", false, "an empty marker is not a marker"},
		{"marker but no binary", false, DefaultKineVersion + " " + kineBuildVariant, false,
			"a marker cannot vouch for a binary that is not there"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bd := t.TempDir()
			if tc.binary {
				if err := os.WriteFile(kinePath(bd), []byte("kine"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.marker {
			case "":
				// no marker file at all
			case "\x00":
				if err := os.WriteFile(kineMarkerPath(bd), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(kineMarkerPath(bd), []byte(tc.marker+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := kineStaged(bd, DefaultKineVersion); got != tc.want {
				t.Errorf("kineStaged = %v, want %v — %s", got, tc.want, tc.because)
			}
		})
	}
}

// TestKineMarkerRoundTrip proves the marker records the build VARIANT alongside the
// version, and that the shipped variant is the pure-Go one. "nocgo" is the whole point
// of the collapse: it is what keeps the unmaintained mattn/go-sqlite3 (and a C
// toolchain) out of every k3sm artifact.
func TestKineMarkerRoundTrip(t *testing.T) {
	bd := t.TempDir()
	if err := writeKineMarker(bd, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	v, variant := readKineMarker(bd)
	if v != DefaultKineVersion || variant != kineBuildVariant {
		t.Errorf("readKineMarker = (%q,%q), want (%q,%q)", v, variant, DefaultKineVersion, kineBuildVariant)
	}
	if kineBuildVariant != "nocgo" {
		t.Errorf("kineBuildVariant = %q, want \"nocgo\" (the pure-Go modernc.org/sqlite backend)", kineBuildVariant)
	}
	if _, err := os.Stat(kineMarkerPath(bd) + ".tmp"); !os.IsNotExist(err) {
		t.Error("the atomic marker write left its .tmp behind")
	}
}

// TestEnsureKineIntoSkipsOnMatchingMarker proves the fast path does not rebuild — a
// matching marker means the staged binary is left exactly as it is. It is the half of
// the predicate the staleness tests cannot cover: without it, every boot would shell
// out to a Go toolchain a launchd daemon does not have.
func TestEnsureKineIntoSkipsOnMatchingMarker(t *testing.T) {
	bd := t.TempDir()
	if err := os.WriteFile(kinePath(bd), []byte("pretend-kine"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeKineMarker(bd, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	if err := ensureKineInto(t.Context(), bd, DefaultKineVersion); err != nil {
		t.Fatalf("ensureKineInto on an up-to-date staging = %v, want nil", err)
	}
	got, err := os.ReadFile(kinePath(bd))
	if err != nil || string(got) != "pretend-kine" {
		t.Errorf("staged kine was replaced: %v %q", err, got)
	}
}

// TestEnsureKineBuildsWithoutCGO pins the build environment itself. The gate greps the
// source for CGO_ENABLED=0, which proves the literal is present; this proves it is the
// value the build command actually carries, and that no CGO_ENABLED=1 survives beside
// it. A cgo kine would silently re-introduce mattn/go-sqlite3 into the shipped payload.
func TestEnsureKineBuildsWithoutCGO(t *testing.T) {
	src, err := os.ReadFile("setup.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := string(src)
	start := strings.Index(fn, "func ensureKineInto(")
	if start < 0 {
		t.Fatal("ensureKineInto not found in setup.go")
	}
	body := fn[start:]
	if end := strings.Index(body, "\n// copyFile"); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `"CGO_ENABLED=0"`) {
		t.Error("ensureKineInto does not build kine with CGO_ENABLED=0")
	}
	if strings.Contains(body, `"CGO_ENABLED=1"`) {
		t.Error("ensureKineInto still carries a CGO_ENABLED=1 build env")
	}
}

// TestKineBuildReusesModuleCache is the cold-cache gate.
//
// The kine child is built into a per-build scratch GOPATH that is deleted the moment
// the build finishes. With the module cache left to derive from GOPATH it lived inside
// that scratch dir, so every boot re-downloaded kine's entire dependency tree and threw
// it away again — a network round trip on the critical path of every single bring-up,
// which is what turns a first boot into a bring-up-deadline timeout with nothing in the
// log but `go: downloading` lines. The cache must therefore be pinned OUTSIDE the
// scratch GOPATH, to a path that is the same on the next boot.
func TestKineBuildReusesModuleCache(t *testing.T) {
	envValue := func(env []string, key string) (string, bool) {
		v, ok := "", false
		for _, kv := range env { // last assignment wins, as in the child process
			if name, val, found := strings.Cut(kv, "="); found && name == key {
				v, ok = val, true
			}
		}
		return v, ok
	}

	t.Run("the build env pins GOMODCACHE outside the scratch GOPATH", func(t *testing.T) {
		gopath, cache := t.TempDir(), t.TempDir()
		env := kineBuildEnv(gopath, cache)

		got, ok := envValue(env, "GOMODCACHE")
		if !ok {
			t.Fatal("the kine build env carries no GOMODCACHE — the cache derives from the scratch GOPATH and is discarded with it, so every boot re-downloads the whole dependency tree")
		}
		if got != cache {
			t.Errorf("GOMODCACHE = %q, want the stable cache %q", got, cache)
		}
		if strings.HasPrefix(got, gopath) {
			t.Errorf("GOMODCACHE %q lives inside the per-build scratch GOPATH %q — it dies with the build", got, gopath)
		}
		// The scratch-GOPATH/cleared-GOBIN posture is what lets `go install pkg@version`
		// write a cross-compiled binary at all; pinning the cache must not disturb it.
		for _, want := range []struct{ key, val string }{
			{"GOPATH", gopath}, {"GOBIN", ""}, {"CGO_ENABLED", "0"}, {"GOWORK", "off"},
		} {
			if got, ok := envValue(env, want.key); !ok || got != want.val {
				t.Errorf("%s = %q (set=%v), want %q", want.key, got, ok, want.val)
			}
		}
	})

	t.Run("the chosen stable path is the host toolchain's own cache", func(t *testing.T) {
		dir, err := hostGoModCache(t.Context())
		if err != nil {
			t.Fatalf("hostGoModCache = %v, want the host cache", err)
		}
		if !filepath.IsAbs(dir) {
			t.Errorf("module cache %q is not an absolute path", dir)
		}
		out, err := exec.CommandContext(t.Context(), "go", "env", "GOMODCACHE").Output()
		if err != nil {
			t.Skipf("no Go toolchain to compare against: %v", err)
		}
		if want := strings.TrimSpace(string(out)); want != "" && dir != want {
			t.Errorf("module cache = %q, want the host toolchain's %q", dir, want)
		}
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("module cache %q does not exist after resolution: %v", dir, err)
		}
	})

	t.Run("a second build finds the cache warm", func(t *testing.T) {
		cache := t.TempDir()
		origCache, origBuild := kineModuleCacheDir, runKineBuild
		t.Cleanup(func() { kineModuleCacheDir, runKineBuild = origCache, origBuild })
		kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }

		// The fake stands in for `go install`: it records what it was handed, notes
		// whether the cache it was pointed at was already populated, leaves a
		// downloaded-module sentinel behind, and stages the "built" binary where
		// ensureKineInto looks for a native install.
		sentinel := filepath.Join(cache, "cache", "download", "kine-deps")
		var gopaths, caches []string
		var warm []bool
		runKineBuild = func(_ context.Context, _, gopath, modCache string) ([]byte, error) {
			gopaths, caches = append(gopaths, gopath), append(caches, modCache)
			_, err := os.Stat(filepath.Join(modCache, "cache", "download", "kine-deps"))
			warm = append(warm, err == nil)
			if err := os.MkdirAll(filepath.Dir(sentinel), 0o755); err != nil {
				return nil, err
			}
			if err := os.WriteFile(filepath.Join(modCache, "cache", "download", "kine-deps"), []byte("modules"), 0o644); err != nil {
				return nil, err
			}
			if err := os.MkdirAll(filepath.Join(gopath, "bin"), 0o755); err != nil {
				return nil, err
			}
			return nil, os.WriteFile(filepath.Join(gopath, "bin", "kine"), []byte("pretend-kine"), 0o755)
		}

		// Two staging dirs, not two calls against one: a re-stage into the SAME dir is
		// short-circuited by the version marker, whereas a second work dir (a second dev
		// instance, a payload stage) is exactly the case that used to pay a full
		// download all over again.
		for _, bd := range []string{t.TempDir(), t.TempDir()} {
			if err := ensureKineInto(t.Context(), bd, DefaultKineVersion); err != nil {
				t.Fatalf("ensureKineInto: %v", err)
			}
			if _, err := os.Stat(kinePath(bd)); err != nil {
				t.Fatalf("kine was not staged into %s: %v", bd, err)
			}
		}

		if len(caches) != 2 {
			t.Fatalf("kine was built %d time(s), want 2", len(caches))
		}
		if caches[0] != cache || caches[1] != cache {
			t.Errorf("builds used module caches %v, want both at the stable %q", caches, cache)
		}
		if gopaths[0] == gopaths[1] {
			t.Errorf("both builds used GOPATH %q — the scratch dir is meant to be per-build", gopaths[0])
		}
		for _, gopath := range gopaths {
			if _, err := os.Stat(gopath); !os.IsNotExist(err) {
				t.Errorf("scratch GOPATH %q outlived its build (%v) — the cache inside it would too", gopath, err)
			}
		}
		if want := []bool{false, true}; warm[0] != want[0] || warm[1] != want[1] {
			t.Errorf("cache warm at build start = %v, want %v — the second build re-derived a COLD cache", warm, want)
		}
		if _, err := os.Stat(sentinel); err != nil {
			t.Errorf("the downloaded modules did not survive the builds: %v", err)
		}
	})
}
