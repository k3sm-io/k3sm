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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fixture reads a testdata launchctl capture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// TestParseLaunchctlPrintFixtures drives the parser over hand-authored captures
// of every launchd posture the two k3sm daemons reach, and asserts the class each
// one classifies to. The fixtures reproduce launchctl's real layout — tab-indented
// `key = value` lines, nested sub-dictionaries that REPEAT `runs` and `pid`, and an
// arguments block — so the "first match wins" rule and the format-drift verdict are
// exercised against text shaped like the real thing rather than against a stub.
func TestParseLaunchctlPrintFixtures(t *testing.T) {
	t.Parallel()

	notLoaded := errors.New("exit status 113")
	code := func(n int) *int { return &n }

	tests := []struct {
		name      string
		file      string
		exitErr   error
		disabled  string // print-disabled fixture, empty for none
		wantClass DaemonClass
		wantState string
		wantPID   int
		wantRuns  int
		wantExit  *int
		wantKeys  int
	}{
		{
			name: "crash-looping server", file: "launchctl_server_crashloop.txt",
			wantClass: ClassCrashLooping, wantState: "spawn scheduled",
			// KeysMatched is 4, not 3: the nested spawn-statistics block carries
			// `pid = 0`, which parses — the job simply has no process.
			wantRuns: 497, wantExit: code(1), wantKeys: 4,
		},
		{
			name: "running netd", file: "launchctl_netd_running.txt",
			wantClass: ClassRunning, wantState: "running",
			wantPID: 1292, wantRuns: 1, wantKeys: 4,
		},
		{
			name: "not loaded", file: "launchctl_not_loaded.txt", exitErr: notLoaded,
			wantClass: ClassNotLoaded,
		},
		{
			name: "cleanly stopped", file: "launchctl_stopped_clean.txt",
			wantClass: ClassStopped, wantState: "not running",
			wantRuns: 3, wantExit: code(0), wantKeys: 3,
		},
		{
			name: "failed once", file: "launchctl_failed_once.txt",
			wantClass: ClassFailed, wantState: "not running",
			wantRuns: 1, wantExit: code(1), wantKeys: 3,
		},
		{
			name: "disabled", file: "launchctl_netd_running.txt", disabled: "launchctl_disabled.txt",
			wantClass: ClassDisabled, wantState: "running",
			wantPID: 1292, wantRuns: 1, wantKeys: 4,
		},
		{
			name: "format drift", file: "launchctl_format_drift.txt",
			wantClass: ClassUnknown, wantKeys: 0,
		},
		{
			name: "garbage values", file: "launchctl_garbage.txt",
			wantClass: ClassUnknown, wantKeys: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseLaunchctlPrint(fixture(t, tc.file), tc.exitErr)
			if tc.disabled != "" {
				MarkDisabled(&got, fixture(t, tc.disabled), "io.k3sm.server")
			}
			if got.State != tc.wantState {
				t.Errorf("State = %q, want %q", got.State, tc.wantState)
			}
			if got.PID != tc.wantPID {
				t.Errorf("PID = %d, want %d", got.PID, tc.wantPID)
			}
			if got.Runs != tc.wantRuns {
				t.Errorf("Runs = %d, want %d", got.Runs, tc.wantRuns)
			}
			switch {
			case tc.wantExit == nil && got.LastExit != nil:
				t.Errorf("LastExit = %d, want nil", *got.LastExit)
			case tc.wantExit != nil && got.LastExit == nil:
				t.Errorf("LastExit = nil, want %d", *tc.wantExit)
			case tc.wantExit != nil && *got.LastExit != *tc.wantExit:
				t.Errorf("LastExit = %d, want %d", *got.LastExit, *tc.wantExit)
			}
			if got.KeysMatched != tc.wantKeys {
				t.Errorf("KeysMatched = %d, want %d", got.KeysMatched, tc.wantKeys)
			}
			if cls := ClassifyDaemon(got); cls != tc.wantClass {
				t.Errorf("ClassifyDaemon = %v, want %v", cls, tc.wantClass)
			}
		})
	}
}

// TestParseLaunchctlPrintIgnoresOutputOnError pins the rule that makes the
// not-loaded verdict trustworthy: when launchctl exits non-zero its output is a
// diagnostic about the FAILURE, so parsing it would invent a state for a job that
// is not bootstrapped at all.
func TestParseLaunchctlPrintIgnoresOutputOnError(t *testing.T) {
	t.Parallel()
	got := ParseLaunchctlPrint(fixture(t, "launchctl_netd_running.txt"), errors.New("exit status 113"))
	if got.Loaded || got.State != "" || got.PID != 0 || got.KeysMatched != 0 {
		t.Fatalf("output was parsed despite an exit error: %+v", got)
	}
	if cls := ClassifyDaemon(got); cls != ClassNotLoaded {
		t.Fatalf("ClassifyDaemon = %v, want ClassNotLoaded", cls)
	}
}

// TestParseLaunchctlPrintFirstMatchWins asserts the nested sub-dictionary in the
// crash-loop fixture (which repeats `runs` and adds a `pid = 0`) does not overwrite
// the job's own values.
func TestParseLaunchctlPrintFirstMatchWins(t *testing.T) {
	t.Parallel()
	got := ParseLaunchctlPrint(fixture(t, "launchctl_server_crashloop.txt"), nil)
	if got.Runs != 497 {
		t.Errorf("Runs = %d, want 497 (the job's own value, not the spawn-statistics repeat)", got.Runs)
	}
	if got.PID != 0 {
		t.Errorf("PID = %d, want 0", got.PID)
	}
}

// TestClassifyDaemon is the exhaustive table over the classification order,
// driven by constructed DaemonInfo values rather than fixtures so every branch —
// including the ones no real capture shows — is pinned.
func TestClassifyDaemon(t *testing.T) {
	t.Parallel()
	code := func(n int) *int { return &n }

	tests := []struct {
		name string
		in   DaemonInfo
		want DaemonClass
	}{
		{"not loaded beats everything", DaemonInfo{Loaded: false, Disabled: true, State: "running", PID: 9, KeysMatched: 4}, ClassNotLoaded},
		{"disabled beats a running state", DaemonInfo{Loaded: true, Disabled: true, State: "running", PID: 9, KeysMatched: 4}, ClassDisabled},
		{"no keys matched is unknown", DaemonInfo{Loaded: true, KeysMatched: 0}, ClassUnknown},
		{"running needs a pid", DaemonInfo{Loaded: true, State: "running", PID: 0, KeysMatched: 1}, ClassUnknown},
		{"running with a pid", DaemonInfo{Loaded: true, State: "running", PID: 1292, KeysMatched: 4}, ClassRunning},
		{"crash loop", DaemonInfo{Loaded: true, State: "spawn scheduled", Runs: 497, LastExit: code(1), KeysMatched: 3}, ClassCrashLooping},
		{"single failure", DaemonInfo{Loaded: true, State: "not running", Runs: 1, LastExit: code(1), KeysMatched: 3}, ClassFailed},
		{"zero runs with a failure is a single failure", DaemonInfo{Loaded: true, State: "not running", Runs: 0, LastExit: code(2), KeysMatched: 3}, ClassFailed},
		{"stopped cleanly", DaemonInfo{Loaded: true, State: "not running", Runs: 3, LastExit: code(0), KeysMatched: 3}, ClassStopped},
		{"never exited and idle", DaemonInfo{Loaded: true, State: "not running", KeysMatched: 2}, ClassStopped},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ClassifyDaemon(tc.in); got != tc.want {
				t.Fatalf("ClassifyDaemon(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestClassifyDaemonSeverity pins that every non-running, readable class is a
// FAIL: the k3sm daemons are KeepAlive jobs, so "loaded and idle" is a cluster
// that is not serving, not a benign posture.
func TestClassifyDaemonSeverity(t *testing.T) {
	t.Parallel()
	want := map[DaemonClass]Severity{
		ClassRunning:      SeverityOK,
		ClassCrashLooping: SeverityFail,
		ClassFailed:       SeverityFail,
		ClassStopped:      SeverityFail,
		ClassNotLoaded:    SeverityFail,
		ClassDisabled:     SeverityFail,
		ClassUnknown:      SeverityUnknown,
	}
	for cls, sev := range want {
		if got := cls.Severity(); got != sev {
			t.Errorf("%v.Severity() = %v, want %v", cls, got, sev)
		}
	}
}

// TestMarkDisabled asserts the disabled marker is matched on the EXACT quoted
// label, so a different job's disabled entry never disables ours.
func TestMarkDisabled(t *testing.T) {
	t.Parallel()
	out := fixture(t, "launchctl_disabled.txt")

	tests := []struct {
		name  string
		label string
		want  bool
	}{
		{"our label is disabled", "io.k3sm.server", true},
		{"another k3sm label is not", "io.k3sm.netd", false},
		{"a substring of a disabled label does not match", "io.k3sm.serv", false},
		{"an unrelated job does not leak", "com.apple.some.other.job", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d := DaemonInfo{Loaded: true, State: "running", PID: 1, KeysMatched: 2}
			MarkDisabled(&d, out, tc.label)
			if d.Disabled != tc.want {
				t.Fatalf("Disabled = %v, want %v for label %q", d.Disabled, tc.want, tc.label)
			}
		})
	}
	MarkDisabled(nil, out, "io.k3sm.server") // must not panic
}
