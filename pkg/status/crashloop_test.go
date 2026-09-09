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
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

func TestClassifyCrashLoop(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	path := "/var/lib/k3sm/server/crashloop.json"
	crash := func(ago time.Duration, comp string) executor.Crash {
		return executor.Crash{At: now.Add(-ago), Component: comp, Detail: "token=REDACTED secret material"}
	}
	tripped := now.Add(-time.Minute)

	tests := []struct {
		name        string
		rec         executor.CrashRecord
		err         error
		wantPosture CrashLoopPosture
		wantIn      []string
		wantNotIn   []string
	}{
		{"absent or empty is quiet", executor.CrashRecord{}, nil, PostureQuiet, nil, nil},
		{"one crash in the window is quiet (a fact for the log, not a pattern)",
			executor.CrashRecord{Crashes: []executor.Crash{crash(time.Minute, "kine")}}, nil, PostureQuiet, nil, nil},
		{"two crashes in the window is restarting",
			executor.CrashRecord{Crashes: []executor.Crash{crash(3*time.Minute, "kine"), crash(time.Minute, "kine")}}, nil,
			PostureRestarting, []string{"restarted 2 times", "kine", "trips at"}, nil},
		{"crashes outside the window do not count",
			executor.CrashRecord{Crashes: []executor.Crash{crash(2*executor.CrashLoopWindow, "kine"), crash(time.Minute, "kine")}}, nil,
			PostureQuiet, nil, nil},
		{"tripped is parked whatever the clock says now",
			executor.CrashRecord{Crashes: []executor.Crash{crash(time.Minute, "kube-apiserver")}, TrippedAt: &tripped}, nil,
			PostureParked, []string{"tripped", "kube-apiserver", "parked", "--clear-crashloop", path}, nil},
		{"permission denied is unreadable, named as the user's posture",
			executor.CrashRecord{}, os.ErrPermission, PostureUnreadable, []string{"not readable by this user"}, nil},
		{"any other read error is unreadable with the error",
			executor.CrashRecord{}, errors.New("disk on fire"), PostureUnreadable, []string{"disk on fire"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := ClassifyCrashLoop(tc.rec, tc.err, path, now)
			if v.Posture != tc.wantPosture {
				t.Fatalf("posture = %v, want %v (%+v)", v.Posture, tc.wantPosture, v)
			}
			for _, w := range tc.wantIn {
				if !strings.Contains(v.Detail+"\n"+v.Remedy, w) {
					t.Errorf("verdict lacks %q: %+v", w, v)
				}
			}
			// The record's detail field is never quoted: it is redacted, but the
			// status report is what an operator pastes into a public issue.
			if strings.Contains(v.Detail+v.Remedy, "secret material") || strings.Contains(v.Detail+v.Remedy, "REDACTED") {
				t.Errorf("verdict quotes the record's detail field: %+v", v)
			}
		})
	}
}

func TestApplyCrashLoopOnTheServerRow(t *testing.T) {
	t.Parallel()
	running := func() Row {
		return Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Detail: "pid 42", Wide: map[string]string{}}
	}
	t.Run("parked is a FAIL over a running row, with the remedy", func(t *testing.T) {
		row := running()
		applyCrashLoop(&row, CrashLoopVerdict{Posture: PostureParked, Detail: "d", Remedy: "r"})
		if row.Severity != SeverityFail || row.State != StateCrashLoop || row.Remedy != "r" || row.Wide["crash-loop"] != "tripped" {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("restarting is a WARN over a running row", func(t *testing.T) {
		row := running()
		applyCrashLoop(&row, CrashLoopVerdict{Posture: PostureRestarting, Detail: "d", Remedy: "r"})
		if row.Severity != SeverityWarn || row.State != StateCrashLoop || row.Detail != "d" {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("restarting never softens a row launchd already failed", func(t *testing.T) {
		row := Row{Name: RowServer, State: StateFailed, Severity: SeverityFail, Detail: "1 run, last exit 1", Wide: map[string]string{}}
		applyCrashLoop(&row, CrashLoopVerdict{Posture: PostureRestarting, Detail: "d"})
		if row.Severity != SeverityFail {
			t.Fatalf("severity softened: %+v", row)
		}
	})
	t.Run("unreadable is a wide note, never a severity", func(t *testing.T) {
		row := running()
		applyCrashLoop(&row, CrashLoopVerdict{Posture: PostureUnreadable, Detail: "not readable"})
		if row.Severity != SeverityOK || row.Wide["crash-loop"] != "not readable" {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("quiet changes nothing", func(t *testing.T) {
		row := running()
		applyCrashLoop(&row, CrashLoopVerdict{})
		if row.Severity != SeverityOK || len(row.Wide) != 0 {
			t.Fatalf("%+v", row)
		}
	})
}

// The collector reads the record through the FS seam: a tripped record makes
// the server row FAIL; a 0700 work dir a plain user cannot read leaves the row
// alone and notes why.
func TestCollectorServerRowReadsTheCrashRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	workDir := "/var/lib/k3sm/server"
	path := executor.CrashLoopPath(workDir)
	tripped := now.Add(-time.Minute)
	rec := executor.CrashRecord{Crashes: []executor.Crash{{At: tripped, Component: "kine"}}, TrippedAt: &tripped}
	b, _ := json.Marshal(rec)

	t.Run("tripped record fails the row", func(t *testing.T) {
		c := Collector{FS: fakeFS{contents: map[string][]byte{path: b}}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityFail || !strings.Contains(row.Detail, "kine") || !strings.Contains(row.Remedy, "--clear-crashloop") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("unreadable record is noted, not judged", func(t *testing.T) {
		c := Collector{FS: fakeFS{unreadable: map[string]bool{path: true}}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityOK || !strings.Contains(row.Wide["crash-loop"], "not readable") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("absent record changes nothing", func(t *testing.T) {
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityOK || len(row.Wide) != 0 {
			t.Fatalf("%+v", row)
		}
	})
}
