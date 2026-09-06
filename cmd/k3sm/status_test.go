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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/status"
)

// reportOf builds a minimal report carrying a verdict, which is all the exit-code
// and rendering paths read.
func reportOf(v status.Verdict) status.Report {
	return status.Report{
		Verdict: v,
		Summary: "a summary",
		Rows: []status.Row{
			{Name: status.RowInstall, State: status.StateOK, Severity: status.SeverityOK, Detail: "installed"},
		},
	}
}

// failWriter fails every write, standing in for a full disk or a closed pipe.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// countingSleep is a fake clock: it permits n waits and then reports the deadline
// has passed, which is how both --wait's timeout and --watch's stop arrive.
type countingSleep struct {
	allow int
	calls int
}

func (c *countingSleep) sleep(context.Context, time.Duration) bool {
	c.calls++
	return c.calls <= c.allow
}

// testRunner is a statusRunner with every seam faked and output captured.
func testRunner(out, errOut io.Writer, collect func(context.Context) status.Report) statusRunner {
	return statusRunner{
		out:     out,
		errOut:  errOut,
		collect: collect,
		sleep:   func(context.Context, time.Duration) bool { return false },
		readLog: func(string, int) ([]string, error) { return nil, nil },
		logPaths: map[string]string{
			"netd":   "/var/log/k3sm/netd.log",
			"server": "/var/log/k3sm/server.log",
		},
	}
}

// TestStatusExitCodes pins every code in the table `k3sm status --help` prints —
// the five verdicts, plus the two that are NOT verdicts. The unknown case is
// listed alongside the internal-error case on purpose: "I could not tell" and
// "the tool broke" must never share a number.
func TestStatusExitCodes(t *testing.T) {
	t.Parallel()

	verdicts := []struct {
		verdict status.Verdict
		want    int
	}{
		{status.VerdictRunning, 0},
		{status.VerdictStopped, 3},
		{status.VerdictDegraded, 4},
		{status.VerdictNotInstalled, 5},
		{status.VerdictUnknown, 6},
	}
	for _, tc := range verdicts {
		t.Run("verdict "+tc.verdict.String(), func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(tc.verdict) })
			if got := r.run(context.Background(), statusOptions{format: "text"}); got != tc.want {
				t.Fatalf("exit = %d, want %d", got, tc.want)
			}
			if !strings.Contains(out.String(), "k3sm "+tc.verdict.String()) {
				t.Errorf("screen does not lead with the verdict:\n%s", out.String())
			}
		})
	}

	t.Run("2 — a bad flag is usage, not a verdict", func(t *testing.T) {
		t.Parallel()
		if got := runStatus([]string{"--nonesuch"}); got != exitUsage {
			t.Fatalf("exit = %d, want %d", got, exitUsage)
		}
	})

	t.Run("2 — an unknown view is usage", func(t *testing.T) {
		t.Parallel()
		if got := runStatus([]string{"cluser"}); got != exitUsage {
			t.Fatalf("exit = %d, want %d", got, exitUsage)
		}
	})

	t.Run("2 — --watch without a terminal", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		if got := r.run(context.Background(), statusOptions{format: "text", watch: time.Second}); got != exitUsage {
			t.Fatalf("exit = %d, want %d", got, exitUsage)
		}
		if !strings.Contains(errOut.String(), "needs a terminal") {
			t.Errorf("stderr does not say why: %q", errOut.String())
		}
		if out.String() != "" {
			t.Errorf("a refused --watch wrote to stdout: %q", out.String())
		}
	})

	t.Run("1 — a write failure is an internal error, not a verdict", func(t *testing.T) {
		t.Parallel()
		var errOut bytes.Buffer
		r := testRunner(failWriter{}, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		if got := r.run(context.Background(), statusOptions{format: "text"}); got != exitInternalError {
			t.Fatalf("exit = %d, want %d", got, exitInternalError)
		}
		if got := r.run(context.Background(), statusOptions{format: "json"}); got != exitInternalError {
			t.Fatalf("json exit = %d, want %d", got, exitInternalError)
		}
	})

	t.Run("0 — --help is not an error", func(t *testing.T) {
		t.Parallel()
		if got := runStatus([]string{"--help"}); got != 0 {
			t.Fatalf("--help exit = %d, want 0", got)
		}
	})
}

// TestStatusUsageDocumentsExitCodes asserts the help text IS the exit-code
// contract: every code the command can return is named there, so the table has
// exactly one home.
func TestStatusUsageDocumentsExitCodes(t *testing.T) {
	t.Parallel()
	for _, must := range []string{
		"0  running", "1  internal error", "2  usage",
		"3  stopped", "4  degraded", "5  not installed", "6  unknown",
		"ADDITIVE ONLY",
	} {
		if !strings.Contains(statusUsage, must) {
			t.Errorf("statusUsage does not document %q", must)
		}
	}
}

// TestStatusJSONIsTheOnlyThingOnStdout pins the machine interface: -o json emits
// parseable JSON and nothing else.
func TestStatusJSONIsTheOnlyThingOnStdout(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictDegraded) })
	if got := r.run(context.Background(), statusOptions{format: "json"}); got != 4 {
		t.Fatalf("exit = %d, want 4", got)
	}
	var back status.Report
	if err := json.Unmarshal(out.Bytes(), &back); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, out.String())
	}
	if back.Verdict != status.VerdictDegraded {
		t.Errorf("verdict round-tripped as %v", back.Verdict)
	}
}

// TestStatusWaitPolls drives --wait on a fake clock: the collector reports
// stopped twice and then running, and the command must poll exactly three times
// and exit 0. The timeout case must exit with the LAST verdict's code — not with
// a timeout code of its own, because the answer to "what is the cluster doing"
// does not change just because we stopped waiting.
func TestStatusWaitPolls(t *testing.T) {
	t.Parallel()

	t.Run("flips to running on the third poll", func(t *testing.T) {
		t.Parallel()
		calls := 0
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report {
			calls++
			if calls >= 3 {
				return reportOf(status.VerdictRunning)
			}
			return reportOf(status.VerdictStopped)
		})
		clock := &countingSleep{allow: 10}
		r.sleep = clock.sleep

		if got := r.run(context.Background(), statusOptions{format: "text", wait: true}); got != 0 {
			t.Fatalf("exit = %d, want 0", got)
		}
		if calls != 3 {
			t.Errorf("collected %d times, want 3", calls)
		}
		if clock.calls != 2 {
			t.Errorf("slept %d times, want 2 (one between each pair of polls)", clock.calls)
		}
		if strings.Contains(out.String(), ".") && !strings.Contains(out.String(), "k3sm running") {
			t.Errorf("progress leaked onto stdout: %q", out.String())
		}
	})

	t.Run("a timeout exits with the last verdict's code", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictStopped) })
		clock := &countingSleep{allow: 2}
		r.sleep = clock.sleep

		if got := r.run(context.Background(), statusOptions{format: "text", wait: true}); got != 3 {
			t.Fatalf("exit = %d, want 3 (the stopped verdict)", got)
		}
		if !strings.Contains(out.String(), "k3sm stopped") {
			t.Errorf("the last report was not printed:\n%s", out.String())
		}
	})

	t.Run("progress dots go to stderr, and only for a human", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictStopped) })
		r.stderrTTY = true
		clock := &countingSleep{allow: 2}
		r.sleep = clock.sleep

		_ = r.run(context.Background(), statusOptions{format: "text", wait: true})
		if !strings.HasPrefix(errOut.String(), "...") {
			t.Errorf("stderr does not carry one dot per poll: %q", errOut.String())
		}
		if strings.Contains(out.String(), "...") {
			t.Errorf("progress dots reached stdout: %q", out.String())
		}
	})
}

// TestStatusWatchRenders drives --watch on a fake clock and a fake terminal: it
// must clear the screen and re-render once per frame, and stop when the clock
// says the context ended.
func TestStatusWatchRenders(t *testing.T) {
	t.Parallel()
	frames := 0
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, func(context.Context) status.Report {
		frames++
		return reportOf(status.VerdictRunning)
	})
	r.stdoutTTY = true
	clock := &countingSleep{allow: 2}
	r.sleep = clock.sleep

	if got := r.run(context.Background(), statusOptions{format: "text", watch: 2 * time.Second}); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	if frames != 3 {
		t.Fatalf("rendered %d frames, want 3", frames)
	}
	if n := strings.Count(out.String(), clearScreen); n != 3 {
		t.Errorf("cleared the screen %d times, want 3", n)
	}
	if n := strings.Count(out.String(), "k3sm running"); n != 3 {
		t.Errorf("printed the report %d times, want 3", n)
	}
}

// TestStatusWatchRefusesNonTTY pins the refusal: escape sequences written into a
// file or a pipe are never what the caller meant, so --watch stops rather than
// corrupting the output.
func TestStatusWatchRefusesNonTTY(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
	r.stdoutTTY = false

	if got := r.run(context.Background(), statusOptions{format: "text", watch: time.Second}); got != exitUsage {
		t.Fatalf("exit = %d, want %d", got, exitUsage)
	}
	if strings.Contains(out.String(), clearScreen) {
		t.Error("a refused --watch still emitted a clear-screen escape")
	}
	if !strings.Contains(errOut.String(), "--wait") {
		t.Errorf("the refusal does not point at the scriptable alternative: %q", errOut.String())
	}
}

// TestStatusLogsPermissionDenied pins the unreadable-log path: the exit code is
// the UNKNOWN verdict's, because a log this account cannot read is a fact that
// could not be determined — not a broken tool — and the message names the
// command that would work.
func TestStatusLogsPermissionDenied(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
	r.readLog = func(path string, _ int) ([]string, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	}

	got := r.run(context.Background(), statusOptions{format: "text", view: "logs", target: "server", lines: 10})
	if want := status.VerdictUnknown.ExitCode(); got != want {
		t.Fatalf("exit = %d, want %d", got, want)
	}
	if !strings.Contains(errOut.String(), "sudo k3sm status logs server") {
		t.Errorf("stderr does not name the command that would work: %q", errOut.String())
	}
	if out.String() != "" {
		t.Errorf("stdout carried something other than log lines: %q", out.String())
	}
}

// TestStatusLogsRedactsAndSeparates asserts the log view prints redacted lines to
// stdout and the file headers to stderr, so a redirected stdout holds log lines
// and nothing else.
func TestStatusLogsRedactsAndSeparates(t *testing.T) {
	t.Parallel()
	const token = "k3sm-DEADBEEFfake0token0for0tests0only"
	var out, errOut bytes.Buffer
	r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
	r.readLog = func(path string, _ int) ([]string, error) {
		return []string{"starting " + filepath.Base(path), "argv --token " + token}, nil
	}

	if got := r.run(context.Background(), statusOptions{format: "text", view: "logs", lines: 10}); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	if strings.Contains(out.String(), token) {
		t.Errorf("the log view leaked a token:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "<redacted>") {
		t.Errorf("the token line was not redacted:\n%s", out.String())
	}
	for _, name := range []string{"netd.log", "server.log"} {
		if !strings.Contains(errOut.String(), name) {
			t.Errorf("stderr is missing the %s header: %q", name, errOut.String())
		}
		if strings.Contains(out.String(), "==> ") {
			t.Errorf("a file header reached stdout:\n%s", out.String())
		}
	}
}

// TestParseStatusArgs pins the command line, including the two orders a caller
// naturally types the view and its flags in.
func TestParseStatusArgs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    []string
		want    statusOptions
		wantErr bool
	}{
		{"bare", nil, statusOptions{format: "text", timeout: defaultWaitTimeout, lines: defaultLogLines}, false},
		{"view then flags", []string{"daemons", "-o", "json"},
			statusOptions{view: "daemons", format: "json", timeout: defaultWaitTimeout, lines: defaultLogLines}, false},
		{"flags then view", []string{"-o", "json", "cluster"},
			statusOptions{view: "cluster", format: "json", timeout: defaultWaitTimeout, lines: defaultLogLines}, false},
		{"logs with a target and a line count", []string{"logs", "server", "--lines", "5"},
			statusOptions{view: "logs", target: "server", format: "text", timeout: defaultWaitTimeout, lines: 5}, false},
		{"bare --watch takes the default interval", []string{"--watch"},
			statusOptions{format: "text", timeout: defaultWaitTimeout, lines: defaultLogLines, watch: defaultWatchInterval}, false},
		{"--watch= takes an interval", []string{"--watch=5s"},
			statusOptions{format: "text", timeout: defaultWaitTimeout, lines: defaultLogLines, watch: 5 * time.Second}, false},
		{"--wait with a timeout", []string{"--wait", "--timeout", "10s"},
			statusOptions{format: "text", wait: true, timeout: 10 * time.Second, lines: defaultLogLines}, false},
		{"wide", []string{"-o", "wide"},
			statusOptions{format: "wide", timeout: defaultWaitTimeout, lines: defaultLogLines}, false},
		{"an unknown view", []string{"clusters"}, statusOptions{}, true},
		{"an unknown format", []string{"-o", "yaml"}, statusOptions{}, true},
		{"a log target on the wrong view", []string{"daemons", "server"}, statusOptions{}, true},
		{"an unknown log", []string{"logs", "kine"}, statusOptions{}, true},
		{"too many arguments", []string{"logs", "server", "extra"}, statusOptions{}, true},
		{"a non-positive --lines", []string{"--lines", "0"}, statusOptions{}, true},
		{"an unparseable --watch interval", []string{"--watch=soon"}, statusOptions{}, true},
		{"a non-positive --watch interval", []string{"--watch=0s"}, statusOptions{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseStatusArgs(tc.args, io.Discard)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseStatusArgs(%q) = %+v, want an error", tc.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStatusArgs(%q): %v", tc.args, err)
			}
			if got != tc.want {
				t.Fatalf("parseStatusArgs(%q) = %+v, want %+v", tc.args, got, tc.want)
			}
		})
	}
}

// TestRuntimedForRefusesUnprivileged pins the adapter half of the owner-only
// socket decision: an ordinary account gets NO seam at all, so nothing can dial.
func TestRuntimedForRefusesUnprivileged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name             string
		euid, serviceUID int
		wantSeam         bool
	}{
		{"root gets a seam", 0, 250, true},
		{"the service user gets a seam", 250, 250, true},
		{"an ordinary account gets none", 501, 250, false},
		{"an unresolved service user gets none", 501, status.RuntimeReachableUnknownUID, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runtimedFor(tc.euid, tc.serviceUID, "/var/lib/k3sm/run/runtimed.sock")
			if (got != nil) != tc.wantSeam {
				t.Fatalf("runtimedFor(%d, %d) seam = %v, want %v", tc.euid, tc.serviceUID, got != nil, tc.wantSeam)
			}
		})
	}
}

// TestStatusWorkDirIsTheInstalledOne pins that an ordinary account reports on the
// INSTALLED cluster's work dir, not on a directory in its own home that no
// control plane has ever written to.
func TestStatusWorkDirIsTheInstalledOne(t *testing.T) {
	t.Setenv("K3SM_WORK_DIR", "")
	if got := statusWorkDir(501, 250); got != executor.DefaultWorkDir {
		t.Fatalf("statusWorkDir(501, 250) = %q, want %q", got, executor.DefaultWorkDir)
	}
	t.Setenv("K3SM_WORK_DIR", "/tmp/pinned")
	if got := statusWorkDir(501, 250); got != "/tmp/pinned" {
		t.Fatalf("K3SM_WORK_DIR was ignored: %q", got)
	}
	if runsAsControlPlane(501, 250) {
		t.Error("an ordinary account was treated as the control plane's identity")
	}
	if !runsAsControlPlane(0, 250) || !runsAsControlPlane(250, 250) {
		t.Error("root or the service user was not treated as the control plane's identity")
	}
}

// TestNormalizeMountPoint pins the /var → /private/var compensation: statfs
// answers about the resolved path, and without the rewrite an installed, mounted
// data root reads as the shadow posture — a hard failure on a healthy Mac.
func TestNormalizeMountPoint(t *testing.T) {
	t.Parallel()

	statfsOn := func(on string) *unix.Statfs_t {
		var st unix.Statfs_t
		copy(st.Mntonname[:], on)
		return &st
	}
	resolveTo := func(target string) func(string) (string, error) {
		return func(string) (string, error) { return target, nil }
	}

	tests := []struct {
		name    string
		path    string
		on      string
		resolve func(string) (string, error)
		want    string
	}{
		{"the symlinked mount point is rewritten back", "/var/lib/k3sm", "/private/var/lib/k3sm",
			resolveTo("/private/var/lib/k3sm"), "/var/lib/k3sm"},
		{"an already-matching mount point is untouched", "/var/lib/k3sm", "/var/lib/k3sm",
			resolveTo("/var/lib/k3sm"), "/var/lib/k3sm"},
		{"a genuine shadow is left alone — the ancestor is not this path", "/var/lib/k3sm", "/",
			resolveTo("/private/var/lib/k3sm"), "/"},
		{"an unresolvable path is left alone", "/var/lib/k3sm", "/private/var/lib/k3sm",
			func(string) (string, error) { return "", errors.New("no such file") }, "/private/var/lib/k3sm"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := statfsOn(tc.on)
			normalizeMountPoint(tc.path, st, tc.resolve)
			if got := cstring(st.Mntonname[:]); got != tc.want {
				t.Fatalf("mount point = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReadTail pins the bounded log reader: it returns the LAST n lines, and it
// never reads the whole of a file bigger than its budget.
func TestReadTail(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	small := filepath.Join(dir, "small.log")
	if err := os.WriteFile(small, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines, err := readTail(small, 2)
	if err != nil {
		t.Fatalf("readTail: %v", err)
	}
	if len(lines) != 2 || lines[0] != "two" || lines[1] != "three" {
		t.Fatalf("readTail = %q, want the last two lines", lines)
	}

	big := filepath.Join(dir, "big.log")
	var b bytes.Buffer
	for i := 0; b.Len() < logTailBudget*2; i++ {
		b.WriteString(strings.Repeat("x", 120))
		b.WriteString("\n")
	}
	b.WriteString("the last line\n")
	if err := os.WriteFile(big, b.Bytes(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines, err = readTail(big, 3)
	if err != nil {
		t.Fatalf("readTail: %v", err)
	}
	if len(lines) != 3 || lines[2] != "the last line" {
		t.Fatalf("readTail on a big file = %d lines ending %q", len(lines), lines[len(lines)-1])
	}

	if _, err := readTail(filepath.Join(dir, "absent.log"), 5); err == nil {
		t.Fatal("readTail on an absent file returned no error")
	}
}
