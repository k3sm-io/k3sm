//go:build darwin

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
	"path/filepath"
	"strings"
	"testing"
)

// The launcher-link half of the production darwin System, exercised against a
// REAL filesystem — unprivileged, in a per-case t.TempDir(). Everything these
// two functions decide is a filesystem judgement (what is at the path, what the
// parent's mode says), so a fake would be asserting the test's own model rather
// than the behaviour; and none of it needs privilege.
//
// Deliberately NOT parallel: several cases read os.Geteuid()-conditional
// branches and manipulate directory modes, and t.TempDir() cleanup of a mode-
// stripped directory is easier to reason about serially.
//
// One branch this table cannot reach: the uid-0 half of the directory-trust
// check (checkLinkDirTrust's "owned by uid N, not root"). It is gated on
// os.Geteuid()==0 precisely because an unprivileged run cannot chown a temp dir
// to root; it is covered by the live release-gate install, which runs as root
// against the real /usr/local/bin.

func TestEnsureSymlink(t *testing.T) {
	sys := darwinSystem{}

	for _, tc := range []struct {
		name string
		// setup prepares the case's temp root and returns the link path to ask
		// for and the target it must end up pointing at.
		setup func(t *testing.T, root string) (link, target string)
		// wantErr, when non-empty, is a substring the error must contain.
		wantErr string
	}{
		{
			name: "absent parent is created 0755",
			setup: func(t *testing.T, root string) (string, string) {
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "absent link is created pointing at the target",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "already-correct link is a no-op",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link, target := filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link, target
			},
		},
		{
			name: "stale link pointing elsewhere is replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				writeFile(t, filepath.Join(root, "other"))
				if err := os.Symlink(filepath.Join(root, "other"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "dangling link is replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				if err := os.Symlink(filepath.Join(root, "gone"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "a regular file at the link path is never replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				writeFile(t, link)
				return link, filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to replace non-symlink",
		},
		{
			name: "a directory at the link path is never replaced",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o755)
				link := filepath.Join(root, "bin", "k3sm")
				mkdir(t, link, 0o755)
				return link, filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to replace non-symlink",
		},
		{
			name: "a group-writable link dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o775)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link into",
		},
		{
			name: "a world-writable link dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "bin"), 0o757)
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link into",
		},
		{
			name: "a link dir that is itself a symlink to a dir is refused",
			setup: func(t *testing.T, root string) (string, string) {
				mkdir(t, filepath.Join(root, "real"), 0o755)
				if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "bin")); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(root, "bin", "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "refusing to link into",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, target := tc.setup(t, root)
			err := sys.EnsureSymlink(target, link)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("EnsureSymlink(%q, %q) = nil, want an error containing %q", target, link, tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				// A refusal must leave no temp link behind.
				assertNoTemps(t, filepath.Dir(link))
				return
			}
			if err != nil {
				t.Fatalf("EnsureSymlink(%q, %q): %v", target, link, err)
			}
			got, err := os.Readlink(link)
			if err != nil {
				t.Fatalf("readlink %s: %v", link, err)
			}
			if got != target {
				t.Errorf("link points at %q, want %q", got, target)
			}
			// The parent must be a directory at 0755 (created here or pre-made),
			// and when we are actually root it must be root-owned — the property
			// the trust check will assert on the NEXT install.
			parent := filepath.Dir(link)
			fi, err := os.Lstat(parent)
			if err != nil {
				t.Fatalf("lstat %s: %v", parent, err)
			}
			if !fi.IsDir() {
				t.Fatalf("%s is not a directory", parent)
			}
			if perm := fi.Mode().Perm(); perm&linkDirMaxMode != 0 {
				t.Errorf("link dir mode = %04o, want no group/other write", perm)
			}
			if os.Geteuid() == 0 {
				if err := checkLinkDirTrust(parent); err != nil {
					t.Errorf("link dir must satisfy the trust check after creation: %v", err)
				}
			}
			assertNoTemps(t, parent)
			// Idempotent: asking again for the same link is a no-op success.
			if err := sys.EnsureSymlink(target, link); err != nil {
				t.Errorf("second EnsureSymlink must be a no-op success, got %v", err)
			}
		})
	}
}

func TestRemoveSymlink(t *testing.T) {
	sys := darwinSystem{}

	for _, tc := range []struct {
		name string
		// setup returns the link path to ask about and the target to judge it
		// against.
		setup       func(t *testing.T, root string) (link, target string)
		wantRemoved bool
		wantErr     string
		// wantGone asserts the path is absent afterwards; otherwise it must
		// still be there, untouched.
		wantGone bool
	}{
		{
			name: "a link pointing at our target is removed",
			setup: func(t *testing.T, root string) (string, string) {
				target := filepath.Join(root, "Library", "k3sm")
				link := filepath.Join(root, "k3sm")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				return link, target
			},
			wantRemoved: true,
			wantGone:    true,
		},
		{
			name: "a link pointing somewhere else is kept",
			setup: func(t *testing.T, root string) (string, string) {
				link := filepath.Join(root, "k3sm")
				if err := os.Symlink(filepath.Join(root, "somebody-else"), link); err != nil {
					t.Fatal(err)
				}
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "a regular file is never removed",
			setup: func(t *testing.T, root string) (string, string) {
				link := filepath.Join(root, "k3sm")
				writeFile(t, link)
				return link, filepath.Join(root, "Library", "k3sm")
			},
		},
		{
			name: "an absent link is a quiet no-op",
			setup: func(t *testing.T, root string) (string, string) {
				return filepath.Join(root, "k3sm"), filepath.Join(root, "Library", "k3sm")
			},
			wantGone: true,
		},
		{
			name: "a relative link path is refused",
			setup: func(t *testing.T, root string) (string, string) {
				return "usr/local/bin/k3sm", filepath.Join(root, "Library", "k3sm")
			},
			wantErr: "non-absolute",
			// Nothing was ever created at a relative path.
			wantGone: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			link, target := tc.setup(t, root)
			removed, err := sys.RemoveSymlink(link, target)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("RemoveSymlink(%q, %q) error = %v, want it to contain %q", link, target, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("RemoveSymlink(%q, %q): %v", link, target, err)
			}
			if removed != tc.wantRemoved {
				t.Errorf("removed = %v, want %v", removed, tc.wantRemoved)
			}
			_, statErr := os.Lstat(link)
			if tc.wantGone && statErr == nil {
				t.Errorf("%s must be gone", link)
			}
			if !tc.wantGone && statErr != nil {
				t.Errorf("%s must be left in place, got %v", link, statErr)
			}
		})
	}
}

// mkdir creates dir with an explicit mode. MkdirAll applies the process umask, so
// the mode is re-applied with Chmod — the group-writable cases depend on the bits
// actually landing.
func mkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a symlink\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// assertNoTemps proves the atomic-replacement temp link never survives a run —
// a leaked `k3sm.k3sm-tmp-<pid>` in /usr/local/bin would be litter in a directory
// k3sm was trusted with.
func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // the case never created the directory
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".k3sm-tmp-") {
			t.Errorf("leaked temp link %s in %s", e.Name(), dir)
		}
	}
}
