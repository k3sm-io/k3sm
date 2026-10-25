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
