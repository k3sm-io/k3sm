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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/helmchart"
)

// fakeHelmBuild replaces the helm build with one that writes content as the
// built binary, counting builds and keeping the last command. No network, no
// compiler.
func fakeHelmBuild(t *testing.T, content string) (*int, **exec.Cmd) {
	t.Helper()
	calls := 0
	wrapper := []string{"go.mod", "go.sum"}
	var last *exec.Cmd
	cache := t.TempDir()
	origCache, origBuild := kineModuleCacheDir, runHelmBuild
	t.Cleanup(func() { kineModuleCacheDir, runHelmBuild = origCache, origBuild })
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	runHelmBuild = func(cmd *exec.Cmd) ([]byte, error) {
		calls++
		last = cmd
		// The wrapper must be fully materialized where the build runs.
		for _, f := range wrapper {
			if _, err := os.Stat(filepath.Join(cmd.Dir, f)); err != nil {
				t.Errorf("wrapper %s not materialized in the build dir: %v", f, err)
			}
		}
		return nil, os.WriteFile(cmd.Args[slices.Index(cmd.Args, "-o")+1], []byte(content), 0o755)
	}
	return &calls, &last
}

func TestStageHelm(t *testing.T) {
	t.Run("a dev shell builds the pin under the versioned name, with its marker", func(t *testing.T) {
		fakeTool(t, "gh", "go") // a dev shell: the build gate is open
		t.Setenv("GOFLAGS", "-mod=mod")
		t.Setenv("CGO_ENABLED", "1")
		t.Setenv("GOWORK", "/somewhere/go.work")
		calls, last := fakeHelmBuild(t, "the-helm-binary")
		bd := t.TempDir()
		path, err := EnsureHelm(t.Context(), bd)
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(bd, helmchart.HelmBinaryName) {
			t.Errorf("path = %s", path)
		}
		if got, err := os.ReadFile(path); err != nil || string(got) != "the-helm-binary" {
			t.Errorf("staged helm = %q, %v", got, err)
		}
		if fi, _ := os.Stat(path); fi == nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("staged helm mode = %v, want 0755", fi)
		}
		if got, _ := os.ReadFile(filepath.Join(bd, helmchart.HelmMarkerName)); string(got) != helmchart.HelmVersion+" "+helmchart.HelmBuildVariant+"\n" {
			t.Errorf("marker = %q", got)
		}
		cmd := *last
		if want := append([]string{"go"}, helmchart.HelmBuildArgs(cmd.Args[slices.Index(cmd.Args, "-o")+1])...); !slices.Equal(cmd.Args, want) {
			t.Errorf("build argv = %q, want %q", cmd.Args, want)
		}
		// The last value of a key is the one the go command sees: the pinned
		// values win over the ambient ones set above.
		final := map[string]string{}
		for _, kv := range cmd.Env {
			k, v, _ := strings.Cut(kv, "=")
			final[k] = v
		}
		for k, v := range map[string]string{"CGO_ENABLED": "0", "GOWORK": "off", "GOFLAGS": "-mod=readonly", "GOTOOLCHAIN": "local", "GOSUMDB": "sum.golang.org"} {
			if final[k] != v {
				t.Errorf("build env %s = %q, want %q", k, final[k], v)
			}
		}
		entries, _ := os.ReadDir(bd)
		if len(entries) != 2 {
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Errorf("bin dir holds %v, want only the helm binary and its marker (no temp)", names)
		}
		// A staged copy is kept: the dev-shell fallback builds only when absent.
		if _, err := EnsureHelm(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		if *calls != 1 {
			t.Errorf("builds = %d, want 1 (a staged helm is not built again)", *calls)
		}
	})

	t.Run("a failed build stages nothing", func(t *testing.T) {
		fakeTool(t, "gh", "go")
		fakeHelmBuild(t, "")
		runHelmBuild = func(*exec.Cmd) ([]byte, error) { return []byte("compile error"), errors.New("exit status 1") }
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); err == nil || !strings.Contains(err.Error(), "compile error") {
			t.Fatalf("EnsureHelm = %v, want the build's own output", err)
		}
		if fileExists(helmchart.HelmPath(bd)) || fileExists(filepath.Join(bd, helmchart.HelmMarkerName)) {
			t.Error("a failed build left a binary or a marker")
		}
	})

	t.Run("a dev shell without go is ErrNoGoToolchain", func(t *testing.T) {
		fakeTool(t, "gh")
		calls, _ := fakeHelmBuild(t, "x")
		if _, err := EnsureHelm(t.Context(), t.TempDir()); !errors.Is(err, ErrNoGoToolchain) {
			t.Fatalf("EnsureHelm = %v, want ErrNoGoToolchain", err)
		}
		if *calls != 0 {
			t.Errorf("builds = %d, want 0", *calls)
		}
	})

	t.Run("a daemon without gh gets ErrHelmNotStaged and never builds", func(t *testing.T) {
		calls, _ := fakeHelmBuild(t, "x")
		t.Setenv("PATH", t.TempDir()) // no gh: the launchd daemon's environment
		bd := t.TempDir()
		if _, err := EnsureHelm(t.Context(), bd); !errors.Is(err, ErrHelmNotStaged) {
			t.Fatalf("EnsureHelm = %v, want ErrHelmNotStaged", err)
		}
		if *calls != 0 {
			t.Errorf("builds = %d, want 0 (the gate is closed)", *calls)
		}
		if fileExists(helmchart.HelmPath(bd)) {
			t.Error("a helm was staged with the gate closed")
		}
	})

	t.Run("a daemon without gh still uses a staged helm", func(t *testing.T) {
		calls, _ := fakeHelmBuild(t, "x")
		t.Setenv("PATH", t.TempDir())
		bd := t.TempDir()
		if err := os.WriteFile(helmchart.HelmPath(bd), []byte("payload-helm"), 0o755); err != nil {
			t.Fatal(err)
		}
		if path, err := EnsureHelm(t.Context(), bd); err != nil || path != helmchart.HelmPath(bd) {
			t.Fatalf("EnsureHelm = %q, %v", path, err)
		}
		if *calls != 0 {
			t.Errorf("builds = %d, want 0", *calls)
		}
	})

	for name, marker := range map[string]string{
		"no marker (a tarball-era helm)": "",
		"another variant's marker":       helmchart.HelmVersion + " tarball\n",
	} {
		t.Run("a dev shell rebuilds a present helm with "+name, func(t *testing.T) {
			fakeTool(t, "gh", "go")
			calls, _ := fakeHelmBuild(t, "the-built-helm")
			bd := t.TempDir()
			if err := os.WriteFile(helmchart.HelmPath(bd), []byte("tarball-helm"), 0o755); err != nil {
				t.Fatal(err)
			}
			if marker != "" {
				if err := os.WriteFile(filepath.Join(bd, helmchart.HelmMarkerName), []byte(marker), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := EnsureHelm(t.Context(), bd); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(helmchart.HelmPath(bd)); string(got) != "the-built-helm" || *calls != 1 {
				t.Errorf("helm = %q after %d builds, want the built bytes after 1", got, *calls)
			}
			if !PayloadVouchesHelm(bd) {
				t.Error("the rebuilt helm's marker does not vouch for the pin")
			}
		})
	}

	t.Run("the packaging path rebuilds a copy its marker does not vouch for", func(t *testing.T) {
		fakeTool(t, "go")
		calls, _ := fakeHelmBuild(t, "the-helm-binary")
		bd := t.TempDir()
		if err := os.WriteFile(helmchart.HelmPath(bd), []byte("an-earlier-download"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := stageHelmBuild(t.Context(), bd); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(helmchart.HelmPath(bd)); string(got) != "the-helm-binary" || *calls != 1 {
			t.Errorf("staged = %q after %d builds, want the built bytes after 1", got, *calls)
		}
		if err := stageHelmBuild(t.Context(), bd); err != nil || *calls != 1 {
			t.Errorf("a vouched copy was rebuilt: %v, builds %d", err, *calls)
		}
	})
}

// TestSeedReplacesAnUnvouchedHelm: a work dir holding a helm-v4.3.0 the marker
// does not vouch for (the tarball-era download, which has no marker) is not
// current. The seed replaces it from a payload whose own marker vouches, writes
// the marker, and leaves it alone when the payload does not vouch either.
func TestSeedReplacesAnUnvouchedHelm(t *testing.T) {
	vouch := helmchart.HelmVersion + " " + helmchart.HelmBuildVariant + "\n"
	for _, tc := range []struct {
		name, payloadMarker, want string
	}{
		{"a vouching payload replaces it", vouch, "payload-helm"},
		{"an unmarked payload leaves it", "", "tarball-helm"},
		{"a payload of another variant leaves it", helmchart.HelmVersion + " tarball\n", "tarball-helm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, work := t.TempDir(), t.TempDir()
			bd := BinDir(work)
			if err := os.MkdirAll(bd, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(helmchart.HelmPath(bd), []byte("tarball-helm"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(helmchart.HelmPath(payload), []byte("payload-helm"), 0o755); err != nil {
				t.Fatal(err)
			}
			if tc.payloadMarker != "" {
				if err := os.WriteFile(filepath.Join(payload, helmchart.HelmMarkerName), []byte(tc.payloadMarker), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(helmchart.HelmPath(bd)); !strings.HasPrefix(string(got), tc.want) {
				t.Errorf("work-dir helm = %q, want %q", got, tc.want)
			}
			if vouched := PayloadVouchesHelm(bd); vouched != (tc.want == "payload-helm") {
				t.Errorf("work-dir marker vouches = %v after the seed", vouched)
			}
		})
	}
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
	if err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(helmchart.HelmPath(BinDir(work))); err != nil || string(got) != "payload-helm" {
		t.Errorf("seeded helm = %q, %v", got, err)
	}
}

// helmBuildInfo is the build info the wrapper build records in helm (dep list
// trimmed), the shape `go version -m` prints for the staged binary.
const helmBuildInfo = "go\tgo1.27.3\npath\thelm.sh/helm/v4/cmd/helm\nmod\thelm.sh/helm/v4\tv4.3.0\th1:w=\n" +
	"dep\tgolang.org/x/crypto\tv0.57.0\th1:c=\ndep\tgolang.org/x/net\tv0.60.0\th1:n=\n" +
	"build\t-trimpath=true\nbuild\tCGO_ENABLED=0\nbuild\tGOARCH=arm64\nbuild\tGOOS=darwin\n"

// parseHelmInfo parses build-info text the way buildinfo.ReadFile reads a binary:
// the leading "go" line is the toolchain (GoVersion, which debug.ParseBuildInfo
// leaves to its caller), the rest the module and build lines.
func parseHelmInfo(text string) (*debug.BuildInfo, error) {
	first, rest, _ := strings.Cut(text, "\n")
	bi, err := debug.ParseBuildInfo(rest)
	if err != nil {
		return nil, err
	}
	bi.GoVersion, _ = strings.CutPrefix(first, "go\t")
	return bi, nil
}

// TestHelmStampOf pins the release path's reading of helm's build info: only the
// wrapper build at the pin reads as (HelmVersion, HelmBuildVariant).
func TestHelmStampOf(t *testing.T) {
	parse := func(t *testing.T, text string) *debug.BuildInfo {
		t.Helper()
		bi, err := parseHelmInfo(text)
		if err != nil {
			t.Fatal(err)
		}
		return bi
	}
	if v, variant, err := helmStampOf(parse(t, helmBuildInfo)); err != nil || v != helmchart.HelmVersion || variant != helmchart.HelmBuildVariant {
		t.Fatalf("helmStampOf(the wrapper build) = %q %q %v, want %q %q", v, variant, err, helmchart.HelmVersion, helmchart.HelmBuildVariant)
	}
	if _, _, err := helmStampOf(parse(t, strings.Replace(helmBuildInfo, "go1.27.3", "go1.28.0", 1))); err != nil {
		t.Errorf("a newer toolchain was refused: %v", err)
	}
	if _, variant, _ := helmStampOf(parse(t, strings.Replace(helmBuildInfo, "CGO_ENABLED=0", "CGO_ENABLED=1", 1))); variant != "cgo" {
		t.Errorf("a cgo build reads as %q", variant)
	}
	for name, info := range map[string]string{
		"the upstream tarball's toolchain": strings.Replace(helmBuildInfo, "go1.27.3", "go1.27.1", 1),
		"helm's own x/net":                 strings.Replace(helmBuildInfo, "x/net\tv0.60.0", "x/net\tv0.57.0", 1),
		"an unreadable toolchain":          strings.Replace(helmBuildInfo, "go\tgo1.27.3", "go\tdevel", 1),
		"no x/crypto":                      strings.Replace(helmBuildInfo, "dep\tgolang.org/x/crypto\tv0.57.0\th1:c=\n", "", 1),
		"a replaced x/net":                 strings.Replace(helmBuildInfo, "h1:n=\n", "h1:n=\n=>\texample.com/fork\tv0.0.1\th1:f=\n", 1),
		"no -trimpath":                     strings.Replace(helmBuildInfo, "build\t-trimpath=true\n", "", 1),
		"another main package":             strings.Replace(helmBuildInfo, "path\thelm.sh/helm/v4/cmd/helm", "path\texample.com/helm", 1),
		"helm at another version":          strings.Replace(helmBuildInfo, "v4.3.0", "v4.2.0", 1),
	} {
		v, variant, err := helmStampOf(parse(t, info))
		if err == nil && v == helmchart.HelmVersion && variant == helmchart.HelmBuildVariant {
			t.Errorf("%s: read as the pinned build", name)
		}
	}
}

// TestReleaseSeedRefusesAMisbuiltHelm: on the release path the seed stages the
// payload's helm through ensureShipped, so a correctly signed helm-v4.3.0 whose
// build info names another toolchain or lacks the raised x/net is refused with
// ErrPayloadStamp and never reaches the work dir, while the wrapper build is
// installed and marked. The fake stamp reader parses the build-info text the
// fake binary carries through the production helmStampOf.
func TestReleaseSeedRefusesAMisbuiltHelm(t *testing.T) {
	const team = "ABCDE12345"
	devID := fakeDevIDPrefix + team
	origStamp := shippedStamp
	t.Cleanup(func() { shippedStamp = origStamp })
	shippedStamp = func(c stagedChild, path string) (string, string, error) {
		if c.name != helmchart.HelmBinaryName {
			return "", "", errors.New("only helm is staged here")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", "", err
		}
		bi, err := parseHelmInfo(strings.TrimSuffix(string(b), devID))
		if err != nil {
			return "", "", err
		}
		return helmStampOf(bi)
	}
	for name, tc := range map[string]struct {
		info   string
		refuse bool
	}{
		"the wrapper build":    {helmBuildInfo, false},
		"another toolchain":    {strings.Replace(helmBuildInfo, "go1.27.3", "go1.27.1", 1), true},
		"without raised x/net": {strings.Replace(helmBuildInfo, "x/net\tv0.60.0", "x/net\tv0.57.0", 1), true},
	} {
		t.Run(name, func(t *testing.T) {
			s := &fakeCodeSigner{}
			useFakeSigning(t, s, devID)
			work, payload := t.TempDir(), t.TempDir()
			bd := binDir(work)
			writeBin(t, helmchart.HelmPath(payload), tc.info+devID)
			err := seedBinDir(t.Context(), discardLogger(), work, payload, DefaultKineVersion, DefaultKubeVersion, false)
			if tc.refuse {
				if !errors.Is(err, ErrPayloadStamp) {
					t.Fatalf("seedBinDir = %v, want ErrPayloadStamp", err)
				}
				if fileExists(helmchart.HelmPath(bd)) {
					t.Error("a misbuilt helm was staged into the work dir")
				}
				return
			}
			if err != nil {
				t.Fatalf("seedBinDir = %v", err)
			}
			if got, _ := os.ReadFile(helmchart.HelmPath(bd)); string(got) != tc.info+devID {
				t.Errorf("work-dir helm is not the payload's bytes")
			}
			if !PayloadVouchesHelm(bd) {
				t.Error("the shipped helm's marker was not written")
			}
			if len(s.signed) != 0 {
				t.Errorf("the release path signed %v", s.signed)
			}
		})
	}
}
