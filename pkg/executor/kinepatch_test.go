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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestApplyKinePatches pins the patch applier's fail-closed contract: an anchor
// that occurs exactly once is replaced, and a missing or repeated anchor is an error
// that leaves the file untouched, so a pin bump can never silently drop a fix.
func TestApplyKinePatches(t *testing.T) {
	p := kineSourcePatch{name: "demo", file: "pkg/x/x.go", old: "BUG\n", new: "FIX\n"}
	for _, tc := range []struct {
		name, content, want string
		wantErr             bool
	}{
		{name: "anchor once is replaced", content: "a\nBUG\nb\n", want: "a\nFIX\nb\n"},
		{name: "missing anchor fails", content: "a\nb\n", want: "a\nb\n", wantErr: true},
		{name: "repeated anchor fails", content: "BUG\nBUG\n", want: "BUG\nBUG\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "pkg", "x", "x.go")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			err := applyKinePatches(root, []kineSourcePatch{p})
			if (err != nil) != tc.wantErr {
				t.Fatalf("applyKinePatches = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "demo") {
				t.Errorf("error %q does not name the patch", err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.want {
				t.Errorf("file = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("missing file fails", func(t *testing.T) {
		if err := applyKinePatches(t.TempDir(), []kineSourcePatch{p}); err == nil {
			t.Fatal("applyKinePatches on a tree without the file = nil, want an error")
		}
	})
}

// TestKinePatchSetIsMarked pins the link between the carried patches and the staging
// marker: a patched build must not share a variant with the unpatched one, or nodes
// that staged the unpatched kine would never re-stage.
func TestKinePatchSetIsMarked(t *testing.T) {
	if len(kinePatches) == 0 {
		t.Fatal("no carried kine patches; if upstream fixed them, return kineBuildVariant to \"nocgo\" and delete this test")
	}
	if kineBuildVariant == "nocgo" {
		t.Errorf("kineBuildVariant = %q with %d carried patches: the unpatched builds' marker would vouch for the patched one", kineBuildVariant, len(kinePatches))
	}
	for _, p := range kinePatches {
		if p.name == "" || p.file == "" || p.old == "" || p.old == p.new {
			t.Errorf("patch %+v is incomplete or a no-op", p)
		}
	}
}

// TestKineBuildArgs pins the build argv: -mod=readonly hash-checks every module
// against kine's own go.sum, and the pin is stamped into kine's version package.
func TestKineBuildArgs(t *testing.T) {
	args := kineBuildArgs("v0.17.1", "/out/kine")
	for _, want := range []string{"build", "-mod=readonly", "-X github.com/k3s-io/kine/pkg/version.Version=v0.17.1", "/out/kine"} {
		if !slices.Contains(args, want) {
			t.Errorf("kineBuildArgs = %q, missing %q", args, want)
		}
	}
}
