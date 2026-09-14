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

package status

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// recordJSON is a data-volume record declaring dir, as it would sit on disk.
func recordJSON(t *testing.T, dir, name string, quota uint64) string {
	t.Helper()
	data, err := json.Marshal(dataroot.Record{
		Version:    dataroot.RecordVersion,
		UUID:       "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD",
		Name:       name,
		Mountpoint: dir,
		QuotaBytes: quota,
		CreatedBy:  "k3sm test",
		CreatedAt:  "2026-09-13T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("encode the record: %v", err)
	}
	return string(data)
}

// volumeFS is a mounted data volume of the given size, used fraction and quota.
func volumeFS(t *testing.T, dir, name string, quota, totalBytes, usedBytes uint64) fakeDataRootFS {
	t.Helper()
	const block = 4096
	return fakeDataRootFS{
		dir:     dir,
		mode:    0o750,
		uid:     271,
		mounted: true,
		record:  recordJSON(t, dir, name, quota),
		blocks:  totalBytes / block,
		bfree:   (totalBytes - usedBytes) / block,
		bsize:   block,
	}
}

// TestDataRootRowNamesVolume is the gate for what `k3sm status` says about a
// data root that lives on a k3sm-owned APFS volume. The old row could say only
// "apfs device disk3s7, mounted" — a device node and no bound — which is
// precisely the sentence the user docs' capacity claim rested on.
func TestDataRootRowNamesVolume(t *testing.T) {
	const dir = "/var/lib/k3sm"

	t.Run("a quota'd volume names itself, its usage and its bound", func(t *testing.T) {
		c := Collector{
			DataRoot:   volumeFS(t, dir, "k3sm", 100<<30, 100<<30, 30<<30),
			Paths:      testPaths(""),
			ServiceUID: 271,
		}
		row, rec := c.dataRootRow()
		if rec == nil {
			t.Fatal("dataRootRow did not report the record, so no datavol row would be shown")
		}
		if row.State != StateOK || row.Severity != SeverityOK {
			t.Errorf("row = %s/%v, want ok", row.State, row.Severity)
		}
		for _, want := range []string{dir, "apfs volume k3sm", "30G of 100G used", "mounted"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not contain %q", row.Detail, want)
			}
		}
		if row.Wide["volume"] != "k3sm" || row.Wide["quota"] != "100G" {
			t.Errorf("wide = %v, want volume k3sm and quota 100G", row.Wide)
		}
		if row.Wide["declared-by"] != "record" {
			t.Errorf("wide declared-by = %q, want record", row.Wide["declared-by"])
		}
	})

	t.Run("a volume with no quota never reads 'of 0'", func(t *testing.T) {
		c := Collector{
			DataRoot:   volumeFS(t, dir, "k3sm-pods", 0, 500<<30, 30<<30),
			Paths:      testPaths(""),
			ServiceUID: 271,
		}
		row, _ := c.dataRootRow()
		if !strings.Contains(row.Detail, "30G used") {
			t.Errorf("detail %q does not report the usage", row.Detail)
		}
		if strings.Contains(row.Detail, "of 0") {
			t.Errorf("detail %q claims a bound the volume does not have", row.Detail)
		}
		if row.Severity != SeverityOK {
			t.Errorf("severity = %v, want ok: a volume with no quota cannot be nearly full", row.Severity)
		}
		if row.Wide["quota"] != "none" {
			t.Errorf("wide quota = %q, want none", row.Wide["quota"])
		}
	})

	t.Run("at 90 percent of quota the row warns and says what reclaim frees", func(t *testing.T) {
		c := Collector{
			DataRoot:   volumeFS(t, dir, "k3sm", 100<<30, 100<<30, 92<<30),
			Paths:      testPaths(""),
			ServiceUID: 271,
		}
		row, _ := c.dataRootRow()
		if row.Severity != SeverityWarn {
			t.Errorf("severity = %v, want warn at 92%% of the quota", row.Severity)
		}
		// The cluster is serving. It is the trend that needs attention, not the
		// state, so the STATE stays ok and the severity carries the warning.
		if row.State != StateOK {
			t.Errorf("state = %s, want ok: a nearly full volume is still a working one", row.State)
		}
		for _, want := range []string{"nearly full", "reclaim frees images only", "storage.md"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not contain %q", row.Detail, want)
			}
		}
	})

	t.Run("a shadowed root WITH a record is mounted by name, not hunted with diskutil", func(t *testing.T) {
		fsys := fakeDataRootFS{
			dir:     dir,
			mode:    0o750,
			uid:     0,
			mounted: false,
			record:  recordJSON(t, dir, "k3sm", 100<<30),
			entries: []string{"run"},
		}
		c := Collector{DataRoot: fsys, Paths: testPaths(""), ServiceUID: 271}
		row, _ := c.dataRootRow()
		if row.State != StateNotMounted || row.Severity != SeverityFail {
			t.Fatalf("row = %s/%v, want not-mounted/fail", row.State, row.Severity)
		}
		if !strings.HasPrefix(row.Remedy, "sudo k3sm datavol mount") {
			t.Errorf("remedy = %q, want it to start with `sudo k3sm datavol mount`: the record names the volume, so nobody has to find it", row.Remedy)
		}
		if strings.Contains(row.Remedy, "diskutil") {
			t.Errorf("remedy = %q still asks for diskutil even though k3sm knows the UUID", row.Remedy)
		}
		if !strings.Contains(row.Detail, "k3sm data volume k3sm") {
			t.Errorf("detail %q does not say which declaration is talking", row.Detail)
		}
	})

	t.Run("a shadowed root with only an fstab line keeps the diskutil remedy", func(t *testing.T) {
		fsys := fakeDataRootFS{
			dir:     dir,
			mode:    0o750,
			mounted: false,
			fstab:   "UUID=DEADBEEF " + dir + " apfs rw\n",
			entries: []string{"run"},
		}
		c := Collector{DataRoot: fsys, Paths: testPaths(""), ServiceUID: RuntimeReachableUnknownUID}
		row, rec := c.dataRootRow()
		if rec != nil {
			t.Error("an fstab line is not a k3sm record")
		}
		if !strings.Contains(row.Remedy, "diskutil mount") {
			t.Errorf("remedy = %q, want the diskutil remedy: without a record k3sm does not know which volume belongs here", row.Remedy)
		}
	})

	t.Run("a pre-volume copy becomes its own warning row", func(t *testing.T) {
		preVolume := dir + ".pre-volume"
		now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
		fsys := volumeFS(t, dir, "k3sm", 100<<30, 100<<30, 30<<30)
		fsys.files = map[string]fakeFileInfo{
			preVolume: {name: ".pre-volume", mode: fs.ModeDir | 0o750, mod: now.Add(-50 * time.Hour)},
		}
		fsys.tree = map[string][]fakeFileInfo{
			preVolume:                     {{name: "server", mode: fs.ModeDir | 0o750}},
			preVolume + "/server":         {{name: "db", mode: fs.ModeDir | 0o750}},
			preVolume + "/server/db":      {{name: "state.db", size: 3 << 30}},
			preVolume + "/server/db/junk": nil,
		}
		c := Collector{DataRoot: fsys, Paths: testPaths(""), ServiceUID: 271, Now: func() time.Time { return now }}

		row, ok := c.preVolumeRow()
		if !ok {
			t.Fatal("no pre-volume row for a data root that has one")
		}
		if row.Severity != SeverityWarn || row.State != StateOK {
			t.Errorf("row = %s/%v, want ok/warn", row.State, row.Severity)
		}
		for _, want := range []string{preVolume, "pre-migration copy", "3G", "2 days ago"} {
			if !strings.Contains(row.Detail, want) {
				t.Errorf("detail %q does not contain %q", row.Detail, want)
			}
		}
		if !strings.Contains(row.Remedy, "sudo rm -r "+preVolume) {
			t.Errorf("remedy = %q does not name the directory to remove", row.Remedy)
		}
		// And it does not drag the whole report down with it: a leftover backup
		// is not a degraded cluster.
		verdict, _, _ := Aggregate([]Row{
			{Name: RowServer, State: StateRunning, Severity: SeverityOK},
			{Name: RowAPIServer, State: StateReady, Severity: SeverityOK},
			{Name: RowNode, State: StateReady, Severity: SeverityOK, Detail: "1/1 nodes ready"},
			row,
		}, true)
		if verdict != VerdictRunning {
			t.Errorf("verdict = %v, want running: a pre-volume copy is housekeeping, not a fault", verdict)
		}
	})

	t.Run("no pre-volume copy, no row", func(t *testing.T) {
		c := Collector{DataRoot: volumeFS(t, dir, "k3sm", 100<<30, 100<<30, 30<<30), Paths: testPaths(""), ServiceUID: 271}
		if _, ok := c.preVolumeRow(); ok {
			t.Error("a pre-volume row appeared for a data root that has no copy beside it")
		}
	})
}

// TestOneshotRow is the gate for the datavol daemon row. It exists because the
// row daemonRow would produce is WRONG for this job in the ordinary case: a
// oneshot that has mounted the volume and exited is healthy, and daemonRow
// would report it as a failure with a kickstart remedy.
func TestOneshotRow(t *testing.T) {
	const label = "io.k3sm.datavol"
	const logPath = "/var/log/k3sm/datavol.log"

	tests := []struct {
		name       string
		print      string
		printErr   error
		disabled   string
		wantState  RowState
		wantSev    Severity
		wantDetail string
		wantRemedy string
	}{
		{
			name:       "mounted and exited cleanly is the healthy state",
			print:      "state = not running\npid = 0\nruns = 1\nlast exit code = 0\n",
			wantState:  StateOK,
			wantSev:    SeverityOK,
			wantDetail: "last run exit 0",
		},
		{
			name:       "a non-zero exit is a failure, with the command that retries it",
			print:      "state = not running\npid = 0\nruns = 3\nlast exit code = 1\n",
			wantState:  StateFailed,
			wantSev:    SeverityFail,
			wantDetail: "last run exit 1",
			wantRemedy: "sudo k3sm datavol mount",
		},
		{
			name:       "not loaded means nothing will mount the volume at boot",
			printErr:   fmt.Errorf("could not find service"),
			wantState:  StateMissing,
			wantSev:    SeverityWarn,
			wantDetail: "not loaded",
			wantRemedy: "sudo k3sm install --data-volume",
		},
		{
			name:       "loaded and never run is waiting, not broken",
			print:      "state = not running\npid = 0\nruns = 0\nlast exit code = (never exited)\n",
			wantState:  StateOK,
			wantSev:    SeverityOK,
			wantDetail: "has not run yet",
		},
		{
			name:       "disabled needs enabling, not kickstarting",
			print:      "state = not running\npid = 0\nruns = 1\nlast exit code = 0\n",
			disabled:   "\"" + label + "\" => disabled",
			wantState:  StateDisabled,
			wantSev:    SeverityFail,
			wantDetail: "disabled",
			wantRemedy: "sudo launchctl enable system/" + label,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{
				Launchd: fakeLaunchd{
					out:      map[string][]byte{label: []byte(tc.print)},
					err:      map[string]error{label: tc.printErr},
					disabled: []byte(tc.disabled),
				},
				Paths: testPaths(""),
			}
			row := c.oneshotRow(RowDatavol, label, logPath)
			if row.State != tc.wantState || row.Severity != tc.wantSev {
				t.Errorf("row = %s/%v, want %s/%v", row.State, row.Severity, tc.wantState, tc.wantSev)
			}
			if !strings.Contains(row.Detail, tc.wantDetail) {
				t.Errorf("detail %q does not contain %q", row.Detail, tc.wantDetail)
			}
			if tc.wantRemedy != "" && !strings.Contains(row.Remedy, tc.wantRemedy) {
				t.Errorf("remedy %q does not contain %q", row.Remedy, tc.wantRemedy)
			}
			// Never the daemon remedy: kickstarting a oneshot that already did
			// its job is a command that fixes nothing.
			if tc.wantState == StateOK && row.Remedy != "" {
				t.Errorf("a healthy oneshot carries the remedy %q", row.Remedy)
			}
			if row.Wide["log-path"] != logPath {
				t.Errorf("wide log-path = %q, want %q", row.Wide["log-path"], logPath)
			}
		})
	}
}

// TestPreVolumeRowPartialWalk pins that a size the walk could not finish is
// reported as a lower bound, never as the whole: an unprivileged `k3sm status`
// against a root-owned copy sees only what it may read (540M on the rig, for a
// 1.8G tree), and printing that number bare would understate what the operator
// is about to reclaim.
func TestPreVolumeRowPartialWalk(t *testing.T) {
	const dir = "/var/lib/k3sm"
	preVolume := dir + ".pre-volume"
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		tree map[string][]fakeFileInfo
		want string
	}{
		{
			name: "an unreadable subtree makes the size a lower bound",
			tree: map[string][]fakeFileInfo{
				preVolume:             {{name: "server", mode: fs.ModeDir | 0o750}, {name: "top", size: 1 << 30}},
				preVolume + "/server": nil, // present but its children are not readable: absent from the tree
			},
			want: "at least 1G, re-run with sudo",
		},
		{
			name: "a fully readable tree is reported whole",
			tree: map[string][]fakeFileInfo{
				preVolume: {{name: "top", size: 1 << 30}},
			},
			want: "(1G, ",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := volumeFS(t, dir, "k3sm", 100<<30, 100<<30, 30<<30)
			fsys.files = map[string]fakeFileInfo{
				preVolume: {name: ".pre-volume", mode: fs.ModeDir | 0o750, mod: now.Add(-50 * time.Hour)},
			}
			// A directory listed as a child but absent from tree answers ReadDir with
			// an error, which is exactly what EACCES looks like through the seam.
			tree := map[string][]fakeFileInfo{}
			for k, v := range tc.tree {
				if v != nil {
					tree[k] = v
				}
			}
			fsys.tree = tree
			c := Collector{DataRoot: fsys, Paths: testPaths(""), ServiceUID: 271, Now: func() time.Time { return now }}
			row, ok := c.preVolumeRow()
			if !ok {
				t.Fatal("no pre-volume row")
			}
			if !strings.Contains(row.Detail, tc.want) {
				t.Errorf("detail %q does not contain %q", row.Detail, tc.want)
			}
		})
	}
}

// TestDataRootRowLegacyDevice pins the wording for a volume k3sm did not
// declare: with no record there is no label to print, only the device node, and
// the row must not call a device node a volume name.
func TestDataRootRowLegacyDevice(t *testing.T) {
	const dir = "/var/lib/k3sm"
	fsys := volumeFS(t, dir, "k3sm", 0, 100<<30, 30<<30)
	fsys.record = ""
	fsys.fstab = "UUID=6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD " + dir + " apfs rw\n"
	c := Collector{DataRoot: fsys, Paths: testPaths(""), ServiceUID: 271}
	row, rec := c.dataRootRow()
	if rec != nil {
		t.Fatal("a fstab-only data root reported a record")
	}
	if !strings.Contains(row.Detail, "apfs device disk3s7, mounted") {
		t.Errorf("detail %q does not name the device node as a device", row.Detail)
	}
	if strings.Contains(row.Detail, "volume disk3s7") {
		t.Errorf("detail %q calls a device node a volume", row.Detail)
	}
	if row.Wide["declared-by"] != "fstab" {
		t.Errorf("wide declared-by = %q, want fstab", row.Wide["declared-by"])
	}
}
