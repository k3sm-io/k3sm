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
	"encoding/json"
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
