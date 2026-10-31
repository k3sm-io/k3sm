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

package main

import (
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/k3sm/pkg/updater/layout"
)

// TestPodPathsResolveIntoTheVersionDir pins that the shadow directory and the
// DYLD shims a node hands its pods name the real files inside versions/<v>/
// when the daemon is reached through a symlinked install tree (current, or the
// flat compatibility link), and the flat files on today's layout. Seatbelt
// matches resolved paths, so a grant through current would match nothing, and a
// shim path through current would change under a running pod at a flip. The
// directory passed in is the executable's directory with every symlink
// resolved, which is what install.ExecutableDir returns.
func TestPodPathsResolveIntoTheVersionDir(t *testing.T) {
	mkfile := func(t *testing.T, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	populate := func(t *testing.T, dir string) {
		t.Helper()
		mkfile(t, filepath.Join(dir, "k3sm"))
		mkfile(t, filepath.Join(dir, install.PathShimName))
		mkfile(t, filepath.Join(dir, install.DNSShimName))
		if err := os.Mkdir(filepath.Join(dir, shadow.DirName), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	resolvedDir := func(t *testing.T, exe string) string {
		t.Helper()
		real, err := filepath.EvalSymlinks(exe)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.Dir(real)
	}
	tmp := func(t *testing.T) string {
		t.Helper()
		d, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	check := func(t *testing.T, dir, want string) {
		t.Helper()
		if got := shadowDirIn(dir); got != filepath.Join(want, shadow.DirName) {
			t.Errorf("shadow dir = %q, want %q", got, filepath.Join(want, shadow.DirName))
		}
		for _, name := range []string{install.PathShimName, install.DNSShimName} {
			if got := siblingDylibIn(dir, name); got != filepath.Join(want, name) {
				t.Errorf("%s = %q, want %q", name, got, filepath.Join(want, name))
			}
		}
	}

	t.Run("flat layout", func(t *testing.T) {
		root := tmp(t)
		populate(t, root)
		check(t, resolvedDir(t, filepath.Join(root, "k3sm")), root)
	})

	for _, via := range []string{"current", "compat"} {
		t.Run("versioned layout through "+via, func(t *testing.T) {
			root := tmp(t)
			tree := layout.New(root)
			ver, err := tree.VersionDir("0.3.0")
			if err != nil {
				t.Fatal(err)
			}
			populate(t, ver)
			if err := os.Symlink(filepath.Join(layout.VersionsName, "0.3.0"), tree.Current()); err != nil {
				t.Fatal(err)
			}
			compat, _ := tree.CompatLink("k3sm")
			if err := os.Symlink(filepath.Join(layout.CurrentName, "k3sm"), compat); err != nil {
				t.Fatal(err)
			}
			exe, _ := tree.Binary("k3sm")
			if via == "compat" {
				exe = compat
			}
			check(t, resolvedDir(t, exe), ver)
		})
	}

	t.Run("a symlinked shadow entry is refused", func(t *testing.T) {
		root := tmp(t)
		real := filepath.Join(root, "elsewhere")
		if err := os.Mkdir(real, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(root, shadow.DirName)); err != nil {
			t.Fatal(err)
		}
		if got := shadowDirIn(root); got != "" {
			t.Errorf("shadow dir = %q, want none for a symlinked entry", got)
		}
	})
}
