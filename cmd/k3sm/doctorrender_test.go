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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/status"
	"k3sm.io/k3sm/pkg/version"
)

// doctorTestVersion is the provenance a rendered test report carries. It is a
// literal rather than version.Get() so the screen a test asserts on does not
// change with the build stamp.
var doctorTestVersion = version.Info{Version: "v0.0.0-test", KubeVersion: "v1.36.2"}

// doctorTestTime is a fixed clock, for the same reason.
var doctorTestTime = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

// reportFor runs the preflight checks against a fake env and returns the
// report, the plain screen, and the exit code the process would use.
func reportFor(t *testing.T, env doctorEnv) (status.Report, string, int) {
	t.Helper()
	rep := doctorReport(env, doctorTestVersion, doctorTestTime)
	return rep, status.RenderRows(rep, status.Style{}), doctorExitCode(rep)
}

// nextBlock returns the `Next:` block of a rendered screen, and whether there
// was one at all.
func nextBlock(screen string) (string, bool) {
	_, block, ok := strings.Cut(screen, "\nNext: ")
	return block, ok
}

// TestDoctorRendersRemedies is the B252 gate: `k3sm doctor` renders its
// preflight checks as status rows, with a real remedy for every non-pass in the
// Next block, and an exit code that keeps its own 0/1 contract while borrowing
// status's code for a WARN-only run.
func TestDoctorRendersRemedies(t *testing.T) {
	t.Parallel()

	// (a) A failing check is a FAIL row, its remedy is in the Next block, and
	// the process exits 1 — the code doctor has always returned for this.
	t.Run("a-failing-check-fails-the-row-and-the-exit-code", func(t *testing.T) {
		t.Parallel()
		env := healthyDoctorEnv()
		env.goarch = "amd64"
		rep, screen, code := reportFor(t, env)

		row, ok := rep.Row("arch")
		if !ok {
			t.Fatalf("no arch row in the report:\n%s", screen)
		}
		if row.Severity != status.SeverityFail {
			t.Errorf("arch severity = %v, want fail", row.Severity)
		}
		if row.Remedy == "" {
			t.Error("the failing row carries no remedy — a FAIL with no answer")
		}
		if !strings.Contains(screen, "arch") || !strings.Contains(screen, string(row.State)) {
			t.Errorf("the screen does not carry the arch row's name and state:\n%s", screen)
		}
		block, hasNext := nextBlock(screen)
		if !hasNext {
			t.Fatalf("a failing run rendered no Next: block:\n%s", screen)
		}
		if !strings.Contains(block, row.Remedy) {
			t.Errorf("the Next: block does not carry the arch remedy %q:\n%s", row.Remedy, screen)
		}
		if code != 1 {
			t.Errorf("exit code = %d, want 1 for a failed check", code)
		}
	})

	// (b) An all-pass run has nothing to suggest, and exits 0.
	t.Run("an-all-pass-run-has-no-next-block-and-exits-zero", func(t *testing.T) {
		t.Parallel()
		rep, screen, code := reportFor(t, healthyDoctorEnv())

		if rep.Verdict != status.VerdictRunning {
			t.Fatalf("verdict = %v, want running:\n%s", rep.Verdict, screen)
		}
		if _, hasNext := nextBlock(screen); hasNext {
			t.Errorf("an all-pass run rendered a Next: block:\n%s", screen)
		}
		if code != 0 {
			t.Errorf("exit code = %d, want 0", code)
		}
		// The summary is about the preflight, not about a control plane this
		// command never probed.
		if strings.Contains(rep.Summary, "control plane is serving") {
			t.Errorf("the clean summary claims a serving control plane doctor never checked: %q", rep.Summary)
		}
	})

	// (c) A WARN-only run is not a failure: it takes `k3sm status`'s own
	// degraded code, because it is the same verdict about the same machine.
	t.Run("a-warn-only-run-takes-the-status-degraded-code", func(t *testing.T) {
		t.Parallel()
		env := healthyDoctorEnv()
		env.brewPresent = func() bool { return false }
		rep, screen, code := reportFor(t, env)

		for _, row := range rep.Rows {
			if row.Severity == status.SeverityFail {
				t.Fatalf("row %q failed — this case must be WARN-only:\n%s", row.Name, screen)
			}
		}
		if want := status.VerdictDegraded.ExitCode(); code != want {
			t.Errorf("exit code = %d, want %d (status's degraded code)", code, want)
		}
		if code == 1 {
			t.Error("a WARN-only run exited 1 — that is the failed-check code")
		}
		block, hasNext := nextBlock(screen)
		if !hasNext {
			t.Fatalf("a warning run rendered no Next: block:\n%s", screen)
		}
		if !strings.Contains(block, "brew.sh") {
			t.Errorf("the Next: block does not carry the brew remedy:\n%s", screen)
		}
	})

	// Every non-pass row an operator can act on carries a remedy. A warning
	// with no answer is the failure mode this whole change exists to remove.
	t.Run("every-warning-and-failure-carries-a-remedy", func(t *testing.T) {
		t.Parallel()
		envs := map[string]doctorEnv{
			"broken-everything": brokenDoctorEnv(),
			"worker-never-joined": func() doctorEnv {
				e := agentEnv()
				e.agentCredential = func() (status.CredentialState, time.Time) { return status.CredentialAbsent, time.Time{} }
				return e
			}(),
			"worker-daemon-down": func() doctorEnv {
				e := agentEnv()
				e.agentState = func() (bool, bool) { return true, false }
				return e
			}(),
		}
		for name, env := range envs {
			rep, screen, _ := reportFor(t, env)
			block, _ := nextBlock(screen)
			for _, row := range rep.Rows {
				if row.Severity != status.SeverityWarn && row.Severity != status.SeverityFail {
					continue
				}
				if row.Remedy == "" {
					t.Errorf("%s: row %q is %v with no remedy", name, row.Name, row.Severity)
					continue
				}
				for _, step := range strings.Split(row.Remedy, "\n") {
					if !strings.Contains(block, strings.TrimSpace(step)) {
						t.Errorf("%s: row %q remedy step %q is not in the Next: block:\n%s", name, row.Name, step, screen)
					}
				}
			}
		}
	})

	// The rows render on the status screen's columns: same glyphs, same state
	// column, same headline. A second renderer in cmd/k3sm is exactly what the
	// shared one exists to prevent.
	t.Run("the-screen-is-the-status-screen", func(t *testing.T) {
		t.Parallel()
		env := healthyDoctorEnv()
		env.goarch = "amd64"
		rep := doctorReport(env, doctorTestVersion, doctorTestTime)
		screen := status.RenderRows(rep, status.Style{Glyphs: true})

		if !strings.HasPrefix(screen, "k3sm "+rep.Verdict.String()+": ") {
			t.Errorf("the screen does not lead with the status headline:\n%s", screen)
		}
		if !strings.Contains(screen, status.SeverityFail.Glyph()+" arch") {
			t.Errorf("the failing row is not rendered with the status fail glyph:\n%s", screen)
		}
		if !strings.Contains(screen, doctorTestVersion.Version) {
			t.Errorf("the screen drops the build provenance a bug report needs:\n%s", screen)
		}
	})

	// --json is status's own encoding of status's own struct, so a consumer
	// that parses `k3sm status -o json` parses this without a second parser.
	t.Run("json-is-the-status-report-shape", func(t *testing.T) {
		t.Parallel()
		env := healthyDoctorEnv()
		env.goarch = "amd64"
		rep := doctorReport(env, doctorTestVersion, doctorTestTime)

		var out, errOut bytes.Buffer
		code := emitDoctorReport(rep, doctorOptions{json: true}, &out, &errOut, false)
		if code != 1 {
			t.Errorf("exit code = %d, want 1 (the same code the screen returns)", code)
		}
		if errOut.Len() != 0 {
			t.Errorf("stderr = %q, want empty", errOut.String())
		}
		var decoded status.Report
		if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
			t.Fatalf("the JSON does not parse as a status.Report: %v\n%s", err, out.String())
		}
		if decoded.Verdict != rep.Verdict {
			t.Errorf("decoded verdict = %v, want %v", decoded.Verdict, rep.Verdict)
		}
		row, ok := decoded.Row("arch")
		if !ok || row.Remedy == "" {
			t.Errorf("the decoded report lost the arch row's remedy: %+v", row)
		}
	})

	// (d) --report writes a bundle whose every component has been through
	// status.Redact, and whose launchd view is the four parsed scalars and
	// nothing else — never the raw `launchctl print` text, which carries the
	// job's argv and environment.
	t.Run("report-writes-a-redacted-bundle", func(t *testing.T) {
		t.Parallel()
		// Non-vacuity first: if the seeds were not shapes Redact recognises,
		// every "the secret is absent" assertion below would pass on a bundle
		// that redacts nothing at all.
		if status.Redact(seededJoinToken) == seededJoinToken || status.Redact(seededDSN) == seededDSN {
			t.Fatal("the seeded credentials are not shapes status.Redact removes")
		}
		files := map[string]string{}
		env := bundleEnv(files)
		rep := doctorReport(env, doctorTestVersion, doctorTestTime)

		dir, written, err := writeDoctorBundle(context.Background(), env, rep, "")
		if err != nil {
			t.Fatalf("writeDoctorBundle: %v", err)
		}
		if dir != fakeBundleDir {
			t.Errorf("bundle dir = %q, want the injected %q", dir, fakeBundleDir)
		}
		for _, name := range []string{reportDoctorFile, reportStatusFile, reportLaunchdFile, reportServerLog, reportAgentLog} {
			if _, ok := files[name]; !ok {
				t.Errorf("the bundle is missing %s (wrote %v)", name, written)
			}
		}
		if len(written) != len(files) {
			t.Errorf("wrote %d names for %d files", len(written), len(files))
		}

		// Nothing in the bundle carries the seeded credentials, in any file.
		for name, body := range files {
			for _, secret := range []string{"K10", seededJoinToken, "hunter2"} {
				if strings.Contains(body, secret) {
					t.Errorf("%s carries the secret %q:\n%s", name, secret, body)
				}
			}
			// Nor anything only raw launchctl output would have.
			for _, leak := range []string{"ProgramArguments", "argv", "environment"} {
				if strings.Contains(body, leak) {
					t.Errorf("%s carries %q — the bundle must never hold raw launchctl output:\n%s", name, leak, body)
				}
			}
		}
		// The redaction is not vacuous: the seeded lines are there, minus the
		// secrets.
		if !strings.Contains(files[reportServerLog], "control plane exited") {
			t.Errorf("the log tail lost the line it was quoted for:\n%s", files[reportServerLog])
		}

		// The launchd view is exactly the four parsed keys, plus the label
		// naming which daemon they belong to.
		var view []map[string]json.RawMessage
		if err := json.Unmarshal([]byte(files[reportLaunchdFile]), &view); err != nil {
			t.Fatalf("launchd view does not parse: %v\n%s", err, files[reportLaunchdFile])
		}
		if len(view) == 0 {
			t.Fatal("the launchd view is empty")
		}
		want := map[string]bool{"label": true, "state": true, "pid": true, "runs": true, "last_exit": true}
		for _, entry := range view {
			if len(entry) != len(want) {
				t.Errorf("launchd entry has %d keys, want %d: %v", len(entry), len(want), entry)
			}
			for key := range entry {
				if !want[key] {
					t.Errorf("launchd entry carries an unexpected key %q", key)
				}
			}
		}
	})

	// (e) With no directory named, the bundle lands under the system temp dir
	// — never the working directory, which is usually a checkout.
	t.Run("report-never-writes-under-the-working-directory", func(t *testing.T) {
		t.Parallel()
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		dir, err := makeReportDir("")
		if err != nil {
			t.Fatalf("makeReportDir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		if !filepath.IsAbs(dir) {
			t.Errorf("bundle dir %q is relative — it would resolve against the caller's cwd", dir)
		}
		if strings.HasPrefix(dir, cwd+string(filepath.Separator)) || dir == cwd {
			t.Errorf("bundle dir %q is inside the working directory %q", dir, cwd)
		}
		if !strings.HasPrefix(dir, strings.TrimSuffix(os.TempDir(), string(filepath.Separator))) {
			t.Errorf("bundle dir %q is not under the system temp dir %q", dir, os.TempDir())
		}
		if !strings.Contains(filepath.Base(dir), reportDirPrefix) {
			t.Errorf("bundle dir %q is not a k3sm bundle directory", dir)
		}
	})

	// A bundle is written as root often enough that an operator-named
	// directory is a trust decision: every refusal below is a way somebody
	// else could read or replace the bundle after it lands.
	t.Run("report-refuses-a-directory-it-does-not-trust", func(t *testing.T) {
		t.Parallel()
		const me = 501
		cases := []struct {
			name       string
			facts      dirFacts
			wantRefuse string // a substring of the refusal, "" means accept
		}{
			{"missing-is-created-by-the-caller", dirFacts{}, ""},
			{"mine-and-private", dirFacts{exists: true, dir: true, uid: me, perm: 0o700}, ""},
			{"mine-and-group-readable", dirFacts{exists: true, dir: true, uid: me, perm: 0o750}, ""},
			{"symlink", dirFacts{exists: true, symlink: true, uid: me, perm: 0o777}, "is a symlink"},
			{"not-a-directory", dirFacts{exists: true, uid: me, perm: 0o600}, "is not a directory"},
			{"owned-by-another-account", dirFacts{exists: true, dir: true, uid: 0, perm: 0o700}, "owned by uid 0"},
			{"group-writable", dirFacts{exists: true, dir: true, uid: me, perm: 0o770}, "group- or other-writable"},
			{"world-writable", dirFacts{exists: true, dir: true, uid: me, perm: 0o777}, "group- or other-writable"},
		}
		for _, c := range cases {
			err := checkReportDir("/named/by/the/operator", c.facts, me)
			switch {
			case c.wantRefuse == "" && err != nil:
				t.Errorf("%s: refused a directory it should accept: %v", c.name, err)
			case c.wantRefuse != "" && err == nil:
				t.Errorf("%s: accepted a directory it must refuse", c.name)
			case c.wantRefuse != "" && !strings.Contains(err.Error(), c.wantRefuse):
				t.Errorf("%s: refusal does not name the property %q: %v", c.name, c.wantRefuse, err)
			case c.wantRefuse != "" && !strings.Contains(err.Error(), "choose a directory you own"):
				t.Errorf("%s: refusal does not carry the remedy: %v", c.name, err)
			}
		}
	})

	// The same guard against the real filesystem, where the symlink and the
	// mode bits are the ones the kernel sees rather than the ones a table says.
	t.Run("report-refuses-an-untrusted-directory-on-disk", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		// A fresh, private directory the caller owns is accepted, and a missing
		// one is created 0700.
		fresh := filepath.Join(root, "fresh")
		got, err := makeReportDir(fresh)
		if err != nil {
			t.Fatalf("refused a directory it should have created: %v", err)
		}
		if got != fresh {
			t.Errorf("dir = %q, want %q", got, fresh)
		}
		if info, err := os.Stat(fresh); err != nil {
			t.Errorf("stat the created dir: %v", err)
		} else if info.Mode().Perm() != 0o700 {
			t.Errorf("created dir mode = %04o, want 0700", info.Mode().Perm())
		}

		link := filepath.Join(root, "link")
		if err := os.Symlink(fresh, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := makeReportDir(link); err == nil {
			t.Error("a symlinked bundle directory was accepted")
		} else if !strings.Contains(err.Error(), "symlink") {
			t.Errorf("refusal does not name the symlink: %v", err)
		}

		shared := filepath.Join(root, "shared")
		if err := os.Mkdir(shared, 0o777); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(shared, 0o777); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := makeReportDir(shared); err == nil {
			t.Error("a world-writable bundle directory was accepted")
		}

		// A component never overwrites, and never follows a symlink planted
		// under the name it is about to write.
		if err := writeReportFile(fresh, reportDoctorFile, []byte("first")); err != nil {
			t.Fatalf("write the first component: %v", err)
		}
		if err := writeReportFile(fresh, reportDoctorFile, []byte("second")); err == nil {
			t.Error("a bundle component overwrote an existing file")
		} else if !strings.Contains(err.Error(), reportDoctorFile) {
			t.Errorf("the refusal does not name the file: %v", err)
		}
		if body, err := os.ReadFile(filepath.Join(fresh, reportDoctorFile)); err != nil {
			t.Errorf("read back: %v", err)
		} else if string(body) != "first" {
			t.Errorf("the existing file changed: %q", body)
		}
		target := filepath.Join(root, "elsewhere")
		if err := os.Symlink(target, filepath.Join(fresh, "planted")); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := writeReportFile(fresh, "planted", []byte("through the link")); err == nil {
			t.Error("a bundle component was written through a planted symlink")
		}
		if _, err := os.Stat(target); err == nil {
			t.Errorf("%s was created — O_NOFOLLOW did not hold", target)
		}
	})

	// The log tails are bounded by BOTH limits, and the end of the log is what
	// survives: that is the part that explains the failure.
	t.Run("the-log-tails-are-bounded", func(t *testing.T) {
		t.Parallel()
		many := make([]string, 1000)
		for i := range many {
			many[i] = fmt.Sprintf("line %d %s", i, strings.Repeat("x", 40))
		}
		out := boundTail(many, reportLogLines, reportLogBytes)
		if got := strings.Count(string(out), "\n"); got > reportLogLines {
			t.Errorf("%d lines survived, want at most %d", got, reportLogLines)
		}
		if !strings.Contains(string(out), "line 999 ") {
			t.Error("the bound dropped the END of the log")
		}

		long := []string{strings.Repeat("a", 10), strings.Repeat("b", 10), strings.Repeat("c", 10)}
		if out := boundTail(long, reportLogLines, 22); len(out) > 22 {
			t.Errorf("byte bound not applied: %d bytes for a 22-byte budget", len(out))
		} else if !strings.Contains(string(out), "cccc") {
			t.Errorf("the byte bound dropped the end of the log: %q", out)
		}
	})
}

// fakeBundleDir is the directory the injected factory hands back: a path that
// is not created and never written to, which is the point — the bundle gate
// proves CONTENT without touching the filesystem.
const fakeBundleDir = "/fake/bundle/dir"

// seededJoinToken and seededDSN are the two credential shapes a daemon log can
// echo: the CA-pinned bootstrap token and a datastore DSN's password.
const (
	seededJoinToken = "K10abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567::server:deadbeef"
	seededDSN       = "postgres://kine:hunter2@db.example:5432/k3sm"
)

// bundleEnv is a healthy Mac with the bundle seams faked: a status report and
// two log tails that BOTH carry seeded credentials, launchd scalars that stand
// in for a parsed print, and a writer that records into files.
func bundleEnv(files map[string]string) doctorEnv {
	env := healthyDoctorEnv()
	env.statusReport = func(context.Context) status.Report {
		return status.Report{
			Verdict: status.VerdictDegraded,
			Summary: "server: started with --datastore-endpoint " + seededDSN,
			Rows: []status.Row{
				{Name: "server", State: status.StateCrashLoop, Severity: status.SeverityFail,
					Detail: "497 runs, last exit 1", Remedy: "sudo launchctl kickstart -k system/io.k3sm.server"},
			},
			Version: doctorTestVersion,
		}
	}
	env.logTail = func(path string) ([]string, error) {
		return []string{
			"level=INFO msg=\"joining\" --token " + seededJoinToken,
			"level=INFO msg=\"datastore\" endpoint=" + seededDSN,
			"level=ERROR msg=\"control plane exited\" err=\"bind: address already in use\"",
		}, nil
	}
	env.daemonInfo = func(string) status.DaemonInfo {
		exit := 1
		return status.DaemonInfo{Loaded: true, State: "running", PID: 4242, Runs: 497, LastExit: &exit}
	}
	env.reportDir = func(requested string) (string, error) {
		if requested != "" {
			return requested, nil
		}
		return fakeBundleDir, nil
	}
	env.writeReport = func(_, name string, contents []byte) error {
		files[name] = string(contents)
		return nil
	}
	return env
}

// brokenDoctorEnv is a Mac where every check that can warn or fail does: the
// baseline for the "every non-pass has a remedy" property.
func brokenDoctorEnv() doctorEnv {
	e := healthyDoctorEnv()
	e.goarch = "amd64"
	e.macOSVersion = func() (string, error) { return "15.5", nil }
	e.sipEnabled = func() (bool, error) { return false, nil }
	e.helperState = func() (bool, bool) { return true, false }
	e.brewPresent = func() bool { return false }
	e.datastorePosture = func() (bool, int, string, error) { return true, 3, "rollback", nil }
	e.developerDir = func() (string, error) { return "/Library/Developer/CommandLineTools", nil }
	return e
}
