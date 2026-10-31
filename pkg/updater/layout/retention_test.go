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

package layout

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// noLinks resolves a path to itself: the tree the table tests name does not
// exist, and holds no symlinks.
func noLinks(p string) (string, error) { return p, nil }

func mustPodVersions(t *testing.T, l Layout, paths []string) []string {
	t.Helper()
	got, err := l.PodVersions(paths, noLinks)
	if err != nil {
		t.Fatalf("PodVersions(%v) error: %v", paths, err)
	}
	return got
}

// TestPruneKeepsAVersionARunningPodUses pins that a version a running pod was
// started under survives a prune after it has moved past previous: two
// committed flips (0.3.0 -> 0.3.1 -> 0.3.2) leave 0.3.0 neither current nor
// previous, but a pod started under 0.3.0 still loads its shims from
// versions/0.3.0/, so the directory stays.
func TestPruneKeepsAVersionARunningPodUses(t *testing.T) {
	l := New("/Library/k3sm")
	podPaths := []string{
		"/Library/k3sm/versions/0.3.0/libk3sm-dns.dylib",
		"/Library/k3sm/versions/0.3.0/shadow",
	}
	r := Retained{Current: "0.3.2", Previous: "0.3.1", InUse: mustPodVersions(t, l, podPaths)}
	present := []string{"0.3.0", "0.3.1", "0.3.2"}
	if got := PlanPrune(present, r).Remove; len(got) != 0 {
		t.Errorf("PlanPrune(%v, %+v).Remove = %v, want nothing removed", present, r, got)
	}
}

// TestPruneRemovesAnUnreferencedVersion pins that a version no link, no
// journal entry and no running pod names is still removed, and that a name the
// prune does not recognise is left alone.
func TestPruneRemovesAnUnreferencedVersion(t *testing.T) {
	l := New("/Library/k3sm")
	r := Retained{
		Current:  "0.3.2",
		Previous: "0.3.1",
		InUse:    mustPodVersions(t, l, []string{"/Library/k3sm/versions/0.3.1/libk3sm-dns.dylib"}),
	}
	present := []string{"0.2.9", "0.3.0", "0.3.1", "0.3.2", "0.3.3.tmp", "notes"}
	want := []string{"0.2.9", "0.3.0"}
	if got := PlanPrune(present, r).Remove; !slices.Equal(got, want) {
		t.Errorf("PlanPrune(%v, %+v).Remove = %v, want %v", present, r, got, want)
	}
}

func TestPruneKeepsStaged(t *testing.T) {
	r := Retained{Current: "0.3.1", Previous: "0.3.0", Staged: "0.3.2"}
	if got := PlanPrune([]string{"0.3.0", "0.3.1", "0.3.2"}, r).Remove; len(got) != 0 {
		t.Errorf("PlanPrune.Remove = %v, want the staged version kept", got)
	}
}

// TestPodHeldVersionsAreReported pins that the prune plan names every version
// it keeps with every reason it keeps it, so a status surface can say why a
// version directory persists: a version held only by a running pod reads "in
// use by pods", and one that is both previous and pod-held carries both.
// Unrecognised names appear in neither list.
func TestPodHeldVersionsAreReported(t *testing.T) {
	r := Retained{Current: "0.3.2", Previous: "0.3.1", Staged: "0.3.3", InUse: []string{"0.3.0", "0.3.1"}}
	present := []string{"0.3.3", "0.2.9", "0.3.0", "0.3.1", "0.3.2", "0.3.4.tmp", "notes", "0.3.0"}
	got := PlanPrune(present, r)
	want := PrunePlan{
		Remove: []string{"0.2.9"},
		Keep: []Kept{
			{Version: "0.3.0", Reasons: []KeepReason{KeepInUse}},
			{Version: "0.3.1", Reasons: []KeepReason{KeepPrevious, KeepInUse}},
			{Version: "0.3.2", Reasons: []KeepReason{KeepCurrent}},
			{Version: "0.3.3", Reasons: []KeepReason{KeepStaging}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PlanPrune(%v, %+v) = %+v, want %+v", present, r, got, want)
	}
}

func TestCheckStage(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Retained
		ver  string
		want error
	}{
		{"nothing staged", Retained{Current: "0.3.1", Previous: "0.3.0"}, "0.3.2", nil},
		{"retry of the staged version", Retained{Current: "0.3.1", Previous: "0.3.0", Staged: "0.3.2"}, "0.3.2", nil},
		{"fourth staged version refused", Retained{Current: "0.3.1", Previous: "0.3.0", Staged: "0.3.2"}, "0.3.3", ErrStagingFull},
		{"pod-held versions do not fill staging", Retained{Current: "0.3.1", Previous: "0.3.0", InUse: []string{"0.2.8", "0.2.9"}}, "0.3.2", nil},
		{"re-stage current refused", Retained{Current: "0.3.1", Previous: "0.3.0"}, "0.3.1", ErrStageRetained},
		{"re-stage previous refused", Retained{Current: "0.3.1", Previous: "0.3.0"}, "0.3.0", ErrStageRetained},
		{"re-stage a pod-held version refused", Retained{Current: "0.3.1", Previous: "0.3.0", InUse: []string{"0.2.9"}}, "0.2.9", ErrStageRetained},
		{"re-stage current refused before staging full", Retained{Current: "0.3.1", Previous: "0.3.0", Staged: "0.3.2"}, "0.3.1", ErrStageRetained},
		{"bad name", Retained{}, "0.3.2.tmp", ErrBadVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckStage(tc.r, tc.ver)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("CheckStage(%+v, %q) = %v, want %v", tc.r, tc.ver, err, tc.want)
			}
		})
	}
}

func TestPodVersions(t *testing.T) {
	l := New("/Library/k3sm")
	got := mustPodVersions(t, l, []string{
		"/Library/k3sm/versions/0.3.0/libk3sm-dns.dylib",
		"/Library/k3sm/versions/0.3.0/shadow/sh",
		"/Library/k3sm/versions/0.3.1/libk3sm-path.dylib",
		"/library/K3SM/Versions/0.3.2/libk3sm-dns.dylib",
		"/Library/k3sm/current/libk3sm-dns.dylib",
		"/Library/k3sm/libk3sm-dns.dylib",
		"/Library/k3sm/versions/0.3.2.tmp/x",
		"/Library/k3sm/versions/../versions/0.2.0/x",
		"/Library/k3sm/versions",
		"versions/0.1.0/x",
		"/Library/k3sm-other/versions/0.4.0/x",
	})
	want := []string{"0.2.0", "0.3.0", "0.3.1", "0.3.2"}
	if !slices.Equal(got, want) {
		t.Errorf("PodVersions = %v, want %v", got, want)
	}
}

// TestPodVersionsResolvesSymlinks pins that a pod path is resolved before the
// versions-dir check, on a real tree: a path through current, a path through a
// link outside the root, and a path under the root's own resolved spelling
// (t.TempDir sits under /var, a link to /private/var) each name the version
// they lie in, where a textual prefix check would drop them and let a prune
// remove a version a pod runs from.
func TestPodVersionsResolvesSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, ver := range []string{"0.3.0", "0.3.1", "0.3.2"} {
		dir := filepath.Join(root, VersionsName, ver)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "lib.dylib"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(VersionsName, "0.3.1"), filepath.Join(root, CurrentName)); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	alias := filepath.Join(other, "alias")
	if err := os.Symlink(filepath.Join(root, VersionsName, "0.3.0"), alias); err != nil {
		t.Fatal(err)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	l := New(root)
	got, err := l.PodVersions([]string{
		filepath.Join(root, CurrentName, "lib.dylib"),
		filepath.Join(alias, "lib.dylib"),
		filepath.Join(realRoot, VersionsName, "0.3.2", "lib.dylib"),
	}, filepath.EvalSymlinks)
	if err != nil {
		t.Fatalf("PodVersions error: %v", err)
	}
	if want := []string{"0.3.0", "0.3.1", "0.3.2"}; !slices.Equal(got, want) {
		t.Errorf("PodVersions = %v, want %v", got, want)
	}
}

// TestPodVersionsReportsUnresolvedPaths pins the fail-toward-keeping rule: a
// pod path that cannot be resolved is reported as ErrUnresolvedPodPath, never
// dropped, and the versions of the other paths are still returned.
func TestPodVersionsReportsUnresolvedPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, VersionsName, "0.3.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	l := New(root)
	got, err := l.PodVersions([]string{
		filepath.Join(root, VersionsName, "0.3.0"),
		filepath.Join(root, VersionsName, "0.2.9", "gone.dylib"),
	}, filepath.EvalSymlinks)
	if !errors.Is(err, ErrUnresolvedPodPath) {
		t.Errorf("PodVersions error = %v, want ErrUnresolvedPodPath", err)
	}
	if want := []string{"0.3.0"}; !slices.Equal(got, want) {
		t.Errorf("PodVersions = %v, want %v", got, want)
	}

	if _, err := New(filepath.Join(root, "missing")).PodVersions(nil, filepath.EvalSymlinks); !errors.Is(err, ErrUnresolvedPodPath) {
		t.Errorf("PodVersions with no versions dir: error = %v, want ErrUnresolvedPodPath", err)
	}
}
