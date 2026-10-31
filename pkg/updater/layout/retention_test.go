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
	"slices"
	"testing"
)

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
	r := Retained{Current: "0.3.2", Previous: "0.3.1", InUse: l.PodVersions(podPaths)}
	present := []string{"0.3.0", "0.3.1", "0.3.2"}
	if got := PlanPrune(present, r); slices.Contains(got, "0.3.0") {
		t.Fatalf("PlanPrune(%v, %+v) = %v, removes the version a running pod uses", present, r, got)
	}
	if got := PlanPrune(present, r); len(got) != 0 {
		t.Errorf("PlanPrune = %v, want nothing removed", got)
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
		InUse:    l.PodVersions([]string{"/Library/k3sm/versions/0.3.1/libk3sm-dns.dylib"}),
	}
	present := []string{"0.2.9", "0.3.0", "0.3.1", "0.3.2", "0.3.3.tmp", "notes"}
	want := []string{"0.2.9", "0.3.0"}
	if got := PlanPrune(present, r); !slices.Equal(got, want) {
		t.Errorf("PlanPrune(%v, %+v) = %v, want %v", present, r, got, want)
	}
}

func TestPruneKeepsStaged(t *testing.T) {
	r := Retained{Current: "0.3.1", Previous: "0.3.0", Staged: "0.3.2"}
	if got := PlanPrune([]string{"0.3.0", "0.3.1", "0.3.2"}, r); len(got) != 0 {
		t.Errorf("PlanPrune = %v, want the staged version kept", got)
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
	got := l.PodVersions([]string{
		"/Library/k3sm/versions/0.3.0/libk3sm-dns.dylib",
		"/Library/k3sm/versions/0.3.0/shadow/sh",
		"/Library/k3sm/versions/0.3.1/libk3sm-path.dylib",
		"/Library/k3sm/current/libk3sm-dns.dylib",
		"/Library/k3sm/libk3sm-dns.dylib",
		"/Library/k3sm/versions/0.3.2.tmp/x",
		"/Library/k3sm/versions/../versions/0.2.0/x",
		"versions/0.1.0/x",
		"/Library/k3sm-other/versions/0.4.0/x",
	})
	want := []string{"0.2.0", "0.3.0", "0.3.1"}
	if !slices.Equal(got, want) {
		t.Errorf("PodVersions = %v, want %v", got, want)
	}
}
