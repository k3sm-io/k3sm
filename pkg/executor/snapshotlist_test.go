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
	"time"
)

// TestSelectScheduledPrune pins the one retention selection the schedule and
// `k3sm snapshot prune` share: the earlier of the name stamp and the mtime orders,
// a future-dated snapshot sorts oldest, the just-taken snapshot holds a slot and is
// never selected, and nothing but this node's scheduled snapshots is a candidate.
func TestSelectScheduledPrune(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()
	at := func(d time.Duration) time.Time { return now.Add(-d) }
	type file struct {
		name  string
		mtime time.Time
	}
	files := []file{
		{ScheduledEtcdSnapshotName("node-a", at(4*time.Hour)), at(4 * time.Hour)},
		{ScheduledEtcdSnapshotName("node-a", at(3*time.Hour)), at(3 * time.Hour)},
		// Stamped recent, but its mtime says it is older than the 4h one.
		{ScheduledEtcdSnapshotName("node-a", at(time.Minute)) + ".zip", at(5 * time.Hour)},
		{ScheduledEtcdSnapshotName("node-a", at(2*time.Hour)), at(2 * time.Hour)},
		{ScheduledEtcdSnapshotName("node-a", at(time.Hour)), at(time.Hour)},
		// Written under a clock a day ahead: sorts oldest.
		{ScheduledEtcdSnapshotName("node-a", now.Add(24*time.Hour)), now.Add(24 * time.Hour)},
		{ScheduledEtcdSnapshotName("node-b", at(10*time.Hour)), at(10 * time.Hour)},
		{"k3sm-etcd-snapshot-20200101T000000Z.db", at(100 * time.Hour)},
		{"k3sm-snapshot-20200101T000000Z.zip", at(100 * time.Hour)},
		{ScheduledEtcdSnapshotName("node-a", at(9*time.Hour)) + ".tmp", at(9 * time.Hour)},
	}
	for _, f := range files {
		p := filepath.Join(dir, f.name)
		mustWrite(t, p, []byte("x"))
		if err := os.Chtimes(p, f.mtime, f.mtime); err != nil {
			t.Fatal(err)
		}
	}
	infos, err := ListSnapshots(dir, "node-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != len(files)-1 {
		t.Fatalf("listed %d files, want %d (the .tmp is never a snapshot)", len(infos), len(files)-1)
	}
	names := func(in []SnapshotInfo) []string {
		var out []string
		for _, i := range in {
			out = append(out, i.Name)
		}
		return out
	}
	cases := []struct {
		name      string
		keep      int
		justTaken string
		want      []string
	}{
		{"keep 3, nothing just taken", 3, "", []string{files[0].name, files[2].name, files[5].name}},
		{"keep 3, the newest just taken holds a slot", 3, files[4].name, []string{files[0].name, files[2].name, files[5].name}},
		{"keep 2, the newest just taken holds a slot", 2, files[4].name, []string{files[1].name, files[0].name, files[2].name, files[5].name}},
		{"keep 3, a just-taken name absent from the listing still holds a slot", 3, ScheduledEtcdSnapshotName("node-a", now),
			[]string{files[1].name, files[0].name, files[2].name, files[5].name}},
		{"keep 3, an unsorted listing is re-sorted", 3, "", []string{files[0].name, files[2].name, files[5].name}},
		{"keep 1 just taken keeps only it", 1, files[4].name, []string{files[3].name, files[1].name, files[0].name, files[2].name, files[5].name}},
		{"keep more than exist", 10, "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := infos
			if strings.Contains(tc.name, "unsorted") {
				in = slices.Clone(infos)
				slices.Reverse(in)
			}
			if got := names(SelectScheduledPrune(in, tc.keep, tc.justTaken)); !slices.Equal(got, tc.want) {
				t.Fatalf("selected %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("kinds", func(t *testing.T) {
		want := map[string]SnapshotKind{
			files[0].name: SnapshotScheduled, files[2].name: SnapshotScheduled,
			files[6].name: SnapshotOther, files[7].name: SnapshotManual, files[8].name: SnapshotManual,
		}
		for _, in := range infos {
			if k, ok := want[in.Name]; ok && in.Kind != k {
				t.Errorf("%s kind = %s, want %s", in.Name, in.Kind, k)
			}
			if in.Name == files[5].name && !in.Created.IsZero() {
				t.Errorf("the future-dated snapshot's Created = %s, want zero (sorts oldest)", in.Created)
			}
			if in.Name == files[2].name && (!in.Compressed || !in.Created.Equal(files[2].mtime)) {
				t.Errorf("%s: compressed %v created %s, want true and the earlier mtime %s", in.Name, in.Compressed, in.Created, files[2].mtime)
			}
		}
	})
}
