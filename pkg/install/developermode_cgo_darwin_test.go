//go:build cgo

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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestDeveloperModeMarkerJudgesAncestorsOnDisk runs the ancestor checks
// against the real filesystem, in a temp tree judged from its own root with
// the test's uid as the owner: a marker under a group-writable, an ACL'd or a
// symlinked directory is invalid, and one under clean directories is on.
func TestDeveloperModeMarkerJudgesAncestorsOnDisk(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		spoil func(t *testing.T, root, lib string)
		want  DeveloperModeState
	}{
		{name: "clean directories", spoil: func(*testing.T, string, string) {}, want: DeveloperModeMarkerOn},
		{name: "a group-writable parent", spoil: func(t *testing.T, _, lib string) { chmod(t, lib, 0o775) }, want: DeveloperModeInvalid},
		{name: "a world-writable root", spoil: func(t *testing.T, root, _ string) { chmod(t, root, 0o757) }, want: DeveloperModeInvalid},
		{name: "a parent with an ACL", spoil: func(t *testing.T, _, lib string) {
			if out, err := exec.Command("/bin/chmod", "+a", "everyone allow add_file", lib).CombinedOutput(); err != nil {
				t.Fatalf("chmod +a: %v: %s", err, out)
			}
		}, want: DeveloperModeInvalid},
		{name: "a parent that is a symlink", spoil: func(t *testing.T, root, lib string) {
			moved := filepath.Join(root, "real")
			if err := os.Rename(lib, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, lib); err != nil {
				t.Fatal(err)
			}
		}, want: DeveloperModeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			chmod(t, root, 0o755)
			lib := filepath.Join(root, "Library")
			if err := os.Mkdir(lib, 0o755); err != nil {
				t.Fatal(err)
			}
			chmod(t, lib, 0o755)
			marker := filepath.Join(lib, "k3sm.developer-mode")
			if err := os.WriteFile(marker, []byte("x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			chmod(t, marker, 0o644)
			tc.spoil(t, root, lib)
			got := developerModeState(readDeveloperModeFacts(NewDarwinSystem(), root, marker), os.Getuid())
			if got != tc.want {
				t.Errorf("state %s, want %s", got, tc.want)
			}
		})
	}
}

// chmod sets path's mode exactly, past the umask.
func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
