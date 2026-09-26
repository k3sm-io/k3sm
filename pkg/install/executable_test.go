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

package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// execDirHelperEnv makes TestExecutableDirHelper print ExecutableDir() and
// nothing else; unset, the helper is a no-op.
const execDirHelperEnv = "K3SM_TEST_PRINT_EXECUTABLE_DIR"

// evalOrFatal canonicalizes p (macOS temp dirs sit behind /var -> /private/var,
// so raw string compares of temp paths are meaningless).
func evalOrFatal(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return r
}

func touch(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func notExist(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s exists (err=%v); the link dir must not hold siblings or the symlink case collapses", p, err)
	}
}

// TestSiblingResolutionThroughSymlink is the gate for the Darwin
// os.Executable-returns-the-invoked-path bug: k3sm run through the
// /usr/local/bin/k3sm symlink must still find its siblings beside the real
// binary.
func TestSiblingResolutionThroughSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	linkDir := filepath.Join(root, "link")
	chainDir := filepath.Join(root, "chain")
	realExe := filepath.Join(realDir, "k3sm")
	touch(t, realExe)
	for _, p := range RequiredSiblings(realDir) {
		touch(t, p)
	}
	for _, d := range []string{linkDir, chainDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	linkExe := filepath.Join(linkDir, "k3sm")
	if err := os.Symlink(realExe, linkExe); err != nil {
		t.Fatal(err)
	}
	chainExe := filepath.Join(chainDir, "k3sm")
	if err := os.Symlink(linkExe, chainExe); err != nil {
		t.Fatal(err)
	}
	danglingExe := filepath.Join(linkDir, "k3sm-dangling")
	if err := os.Symlink(filepath.Join(root, "gone", "k3sm"), danglingExe); err != nil {
		t.Fatal(err)
	}

	// Non-vacuity: the invoked-path directory holds none of the siblings, so a
	// resolver that skipped EvalSymlinks would fail every symlink case below.
	notExist(t, filepath.Join(filepath.Dir(linkExe), ExecShimName))
	notExist(t, filepath.Join(filepath.Dir(chainExe), ExecShimName))

	realCanon := evalOrFatal(t, realDir)
	tests := []struct {
		name string
		exe  string
		want string // canonicalized expected dir
	}{
		{name: "direct", exe: realExe, want: realCanon},
		{name: "symlinked", exe: linkExe, want: realCanon},
		{name: "chained symlink", exe: chainExe, want: realCanon},
		{name: "dangling link falls back to the unresolved dir", exe: danglingExe, want: evalOrFatal(t, linkDir)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveExecutableDir(tc.exe)
			if g := evalOrFatal(t, got); g != tc.want {
				t.Fatalf("resolveExecutableDir(%q) = %q (canonical %q), want %q", tc.exe, got, g, tc.want)
			}
		})
	}

	t.Run("RequiredSiblings present beside the resolved dir only", func(t *testing.T) {
		resolved := resolveExecutableDir(linkExe)
		for _, p := range RequiredSiblings(resolved) {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("sibling %s missing from resolved dir: %v", p, err)
			}
		}
		for _, p := range RequiredSiblings(filepath.Dir(linkExe)) {
			notExist(t, p)
		}
	})

	t.Run("end to end through a symlinked test binary", func(t *testing.T) {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		realSelf := evalOrFatal(t, self)
		binLink := filepath.Join(t.TempDir(), "k3sm")
		if err := os.Symlink(realSelf, binLink); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binLink, "-test.run=^TestExecutableDirHelper$")
		cmd.Env = append(os.Environ(), execDirHelperEnv+"=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("re-exec through %s: %v", binLink, err)
		}
		var printed string
		for _, line := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "EXECDIR="); ok {
				printed = v
			}
		}
		if printed == "" {
			t.Fatalf("helper printed no EXECDIR line; output:\n%s", out)
		}
		want := filepath.Dir(realSelf)
		if got := evalOrFatal(t, printed); got != want {
			t.Fatalf("ExecutableDir() through symlink = %q (canonical %q), want real build dir %q", printed, got, want)
		}
	})
}

// TestExecutableDirHelper is the subprocess half of the end-to-end case: it
// runs only when re-exec'd with execDirHelperEnv set.
func TestExecutableDirHelper(t *testing.T) {
	if os.Getenv(execDirHelperEnv) != "1" {
		t.Skip("subprocess helper for TestSiblingResolutionThroughSymlink")
	}
	dir, err := ExecutableDir()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("EXECDIR=%s\n", dir)
}
