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

	"k3sm.io/k3sm/pkg/updater/layout"
)

// TestPodShimPathSurvivesAFlip pins how a running pod keeps its mapped shims
// across a flip of current. The node daemon resolves the DYLD shims beside its
// own executable with every symlink followed (resolveExecutableDir), and the
// pod is started with those paths in its environment. So:
//
//   - on the flat layout the captured path is the flat file, as today;
//   - on the versioned layout, whether the daemon was exec'd through current
//     or through the flat compatibility link, the captured path names the
//     version directory itself, never current;
//   - after current flips to a new version the captured path is unchanged and
//     still names a file, because the old version is retained as previous; a
//     daemon resolving afresh after the flip gets the new version's shim.
//
// A path through current would be wrong: after the flip it would name the new
// version's shim, which a process the pod spawns would load in place of the
// one the pod started with.
func TestPodShimPathSurvivesAFlip(t *testing.T) {
	shims := []string{PathShimName, DNSShimName, ExecShimName}
	write := func(t *testing.T, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(path), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	capture := func(exe string) map[string]string {
		dir := resolveExecutableDir(exe)
		out := map[string]string{}
		for _, s := range shims {
			out[s] = filepath.Join(dir, s)
		}
		return out
	}
	applyFlip := func(t *testing.T, tree layout.Layout, from, to string) {
		t.Helper()
		steps, err := tree.PlanFlip(from, to)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range steps {
			switch st.Op {
			case layout.OpRemoveStale:
				_ = os.Remove(st.Path) // absent is the normal case
			case layout.OpSymlink:
				if err := os.Symlink(st.Target, st.Path); err != nil {
					t.Fatal(err)
				}
			case layout.OpRename:
				if err := os.Rename(st.Path, st.Target); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	t.Run("flat layout", func(t *testing.T) {
		root := evalOrFatal(t, t.TempDir())
		write(t, filepath.Join(root, "k3sm"))
		for _, s := range shims {
			write(t, filepath.Join(root, s))
		}
		for s, p := range capture(filepath.Join(root, "k3sm")) {
			if p != filepath.Join(root, s) {
				t.Errorf("%s captured as %s, want the flat %s", s, p, filepath.Join(root, s))
			}
		}
	})

	for _, invoked := range []string{"current", "compat"} {
		t.Run("versioned layout, exec'd through "+invoked, func(t *testing.T) {
			root := evalOrFatal(t, t.TempDir())
			tree := layout.New(root)
			for _, v := range []string{"0.3.0", "0.3.1"} {
				dir, err := tree.VersionDir(v)
				if err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(dir, "k3sm"))
				for _, s := range shims {
					write(t, filepath.Join(dir, s))
				}
			}
			applyFlip(t, tree, "", "0.3.0")
			bin, _ := tree.Binary("k3sm")
			compat, _ := tree.CompatLink("k3sm")
			if err := os.Symlink(filepath.Join(layout.CurrentName, "k3sm"), compat); err != nil {
				t.Fatal(err)
			}
			exe := bin
			if invoked == "compat" {
				exe = compat
			}

			old, _ := tree.VersionDir("0.3.0")
			captured := capture(exe)
			for s, p := range captured {
				if p != filepath.Join(old, s) {
					t.Errorf("%s captured as %s, want the resolved %s", s, p, filepath.Join(old, s))
				}
				if strings.Contains(p, string(filepath.Separator)+layout.CurrentName+string(filepath.Separator)) {
					t.Errorf("%s captured through current: %s", s, p)
				}
			}

			applyFlip(t, tree, "0.3.0", "0.3.1")
			if v, err := tree.ResolvePrevious(os.Readlink); err != nil || v != "0.3.0" {
				t.Fatalf("previous = %q, %v; want the version flipped away from retained as previous", v, err)
			}
			for s, p := range captured {
				got, err := os.ReadFile(p)
				if err != nil {
					t.Errorf("%s at %s gone after the flip: %v", s, p, err)
					continue
				}
				if string(got) != filepath.Join(old, s) {
					t.Errorf("%s at %s now holds %q, want the pod's original file", s, p, got)
				}
			}
			next, _ := tree.VersionDir("0.3.1")
			for s, p := range capture(exe) {
				if p != filepath.Join(next, s) {
					t.Errorf("a fresh resolution after the flip gives %s for %s, want %s", p, s, filepath.Join(next, s))
				}
			}
		})
	}
}
