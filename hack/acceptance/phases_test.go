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

// Package acceptance holds the integrity test for the milestone gate manifest
// (hack/acceptance/phases.json). It is intentionally test-only — there is no
// production code here; the gates themselves are the m<n>.sh scripts.
package acceptance

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// gateRow is one milestone row in hack/acceptance/phases.json: the single command
// that PROVES the milestone (Gate) with the argument vector it is invoked with (Args),
// the test Tier it runs at, the host capabilities it Requires, whether it is lab-only
// (Manual), and whether its gate is not yet the real proof (Skeleton — an
// honesty-contract placeholder). Only Gate is asserted by TestPhasesGatePathsResolve;
// Manual+Skeleton drive the honesty tests; the remaining fields document the schema and
// force every row to decode as a JSON object (a malformed bare-string row fails the
// unmarshal rather than passing silently).
//
// Args exists because TestPhasesGatePathsResolve os.Stats Gate as a PATH, so a
// mode-selecting flag cannot be appended to the gate string — "hack/lab/m11.sh --core"
// resolves to nothing. It is a first-class field rather than a _comment because the
// launch ledger's contract is that the row set is MACHINE-ENUMERABLE: a release process
// that must read prose to learn how to invoke a gate cannot run one. Two rows sharing a
// Gate and differing only in Args (M11-core vs M11-lab) are therefore genuinely
// distinct gates, and the subset relation between them is not a comment.
type gateRow struct {
	Gate     string   `json:"gate"`
	Args     []string `json:"args"`
	Tier     string   `json:"tier"`
	Requires []string `json:"requires"`
	Manual   bool     `json:"manual"`
	Skeleton bool     `json:"skeleton"`
}

// thisFileDir returns the directory containing this test's source file
// (hack/acceptance), resolved from runtime.Caller so it is independent of the
// `go test` working directory. phases.json lives beside this file.
func thisFileDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0): could not resolve this test file's path")
	}
	return filepath.Dir(file)
}

// repoRoot walks up from this test file's directory to the module root (the
// directory containing go.mod). The gate paths in phases.json are repo-root-relative
// (e.g. "hack/acceptance/m0.sh", "hack/lab/m3.sh"), so they must be resolved against
// this root — never against the `go test` working directory, which is the package
// directory hack/acceptance.
func repoRoot(t *testing.T) string {
	t.Helper()
	start := thisFileDir(t)
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("repoRoot: no go.mod found walking up from %s", start)
		}
		dir = parent
	}
}

// loadGateRows decodes phases.json into typed rows, skipping the non-row _comment
// key. It first decodes into map[string]json.RawMessage so the leading documentation
// keys (any key starting with "_") are dropped by name, then unmarshals each
// remaining value into a typed gateRow — no raw-byte or regex scraping of the
// manifest.
func loadGateRows(t *testing.T) map[string]gateRow {
	t.Helper()
	manifestPath := filepath.Join(thisFileDir(t), "phases.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read %s: %v", manifestPath, err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("decode %s: %v", manifestPath, err)
	}
	rows := make(map[string]gateRow, len(top))
	for key, val := range top {
		if strings.HasPrefix(key, "_") {
			continue // _comment and any future non-row documentation key
		}
		var row gateRow
		if err := json.Unmarshal(val, &row); err != nil {
			t.Fatalf("decode row %q in %s: %v", key, manifestPath, err)
		}
		if row.Gate == "" {
			t.Fatalf("row %q in %s has no gate path", key, manifestPath)
		}
		rows[key] = row
	}
	if len(rows) == 0 {
		t.Fatalf("%s declared no gate rows", manifestPath)
	}
	return rows
}

// TestPhasesGatePathsResolve asserts the integrity of the milestone gate manifest
// hack/acceptance/phases.json:
//
//   - Forward: every gate path it declares resolves to a file under the repo root
//     that EXISTS and is EXECUTABLE (mode&0o111 != 0) — existence alone is too weak,
//     a 0-byte or non-+x gate stats OK but cannot run.
//   - Inverse: every milestone gate script on disk (hack/acceptance/m*.sh and
//     hack/lab/m*.sh) is referenced by some manifest row, so a committed gate with
//     no row (an orphan) is caught.
//
// It asserts ONLY that the scripts exist and are runnable — it never executes a gate
// and never asserts a gate PASSES. The milestone proofs stay in the gates (and their
// lab successors B34/B35); a green here can never be mistaken for a proven milestone.
func TestPhasesGatePathsResolve(t *testing.T) {
	root := repoRoot(t)
	rows := loadGateRows(t)

	milestones := make([]string, 0, len(rows))
	for m := range rows {
		milestones = append(milestones, m)
	}
	sort.Strings(milestones)

	// Forward check: every declared gate exists and is executable. Build the set of
	// referenced (repo-root-relative, slash-normalized) gate paths as we go, for the
	// inverse orphan check below.
	referenced := make(map[string]bool, len(rows))
	for _, milestone := range milestones {
		row := rows[milestone]
		referenced[filepath.ToSlash(filepath.Clean(row.Gate))] = true
		t.Run("gate_resolves/"+milestone, func(t *testing.T) {
			abs := filepath.Join(root, filepath.FromSlash(row.Gate))
			info, err := os.Stat(abs)
			if err != nil {
				t.Fatalf("milestone %s gate %q does not resolve under repo root %s: %v", milestone, row.Gate, root, err)
			}
			if info.IsDir() {
				t.Fatalf("milestone %s gate %q is a directory, not a runnable script", milestone, row.Gate)
			}
			if info.Mode()&0o111 == 0 {
				t.Fatalf("milestone %s gate %q exists but is not executable (mode %v); chmod +x it", milestone, row.Gate, info.Mode())
			}
		})
	}

	// Inverse check: no orphan gate scripts — every milestone gate on disk is
	// referenced by some manifest row.
	t.Run("no_orphan_gate_scripts", func(t *testing.T) {
		for _, globRel := range []string{"hack/acceptance/m[0-9]*.sh", "hack/lab/m[0-9]*.sh"} {
			matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(globRel)))
			if err != nil {
				t.Fatalf("glob %s: %v", globRel, err)
			}
			for _, abs := range matches {
				rel, err := filepath.Rel(root, abs)
				if err != nil {
					t.Fatalf("rel of %s under %s: %v", abs, root, err)
				}
				rel = filepath.ToSlash(rel)
				if !referenced[rel] {
					t.Errorf("gate script %s exists on disk but is not referenced by any phases.json row (orphan)", rel)
				}
			}
		}
	})
}

// TestLabSkeletonHonesty pins the load-bearing honesty contract of the lab
// skeletons: with K3SM_LAB unset they SKIP and exit 0 ("PENDING — not a pass");
// under K3SM_LAB=1 they report not-yet-implemented and exit NON-ZERO. The release
// process runs a manual lab gate under K3SM_LAB=1 and trusts exit 0 as "milestone
// proven", so a placeholder that exited 0 there would falsely pass a milestone whose
// real proof is still owed.
//
// The skeleton set is DERIVED from phases.json — every row that is BOTH manual:true
// AND skeleton:true (Res. 1). Keying on manual:true alone would wrongly select the
// real hardware gates hack/lab/{m3,m6}.sh (manual:true WITHOUT skeleton — they run
// real conformance slices under K3SM_LAB=1, not hermetic) and, once it lands green,
// the M9 launch pre-flight; the skeleton:true discriminator keeps those out. DISTINCT
// gate paths are iterated (M4-lab and M7-lab share hack/lab/m7.sh), so a shared
// skeleton is exercised once.
func TestLabSkeletonHonesty(t *testing.T) {
	root := repoRoot(t)
	rows := loadGateRows(t)

	// Derive the distinct manual+skeleton gate paths.
	seen := make(map[string]bool)
	var skeletons []string
	for _, row := range rows {
		if !(row.Manual && row.Skeleton) {
			continue
		}
		rel := filepath.ToSlash(filepath.Clean(row.Gate))
		if seen[rel] {
			continue
		}
		seen[rel] = true
		skeletons = append(skeletons, rel)
	}
	sort.Strings(skeletons)
	if len(skeletons) == 0 {
		t.Fatal("no manual+skeleton rows found in phases.json — the honesty contract has nothing to pin (did a schema field get dropped?)")
	}

	for _, rel := range skeletons {
		path := filepath.Join(root, filepath.FromSlash(rel))
		t.Run(rel, func(t *testing.T) {
			if code := runGate(t, path, ""); code != 0 {
				t.Errorf("%s with K3SM_LAB unset: exit %d, want 0 (a skip — PENDING, NOT a pass)", rel, code)
			}
			if code := runGate(t, path, "1"); code == 0 {
				t.Errorf("%s with K3SM_LAB=1: exit 0 — a placeholder must NOT report the milestone proven (the real gate is still owed)", rel)
			}
		})
	}
}

// TestNonManualSkeletonsAlwaysRed pins the complementary honesty contract for
// manual:false skeleton gates (Res. 2). A CI-runnable gate (e.g. the M7 umbrella +
// M8) is run DIRECTLY by the release process, which trusts exit 0 as "milestone
// proven" — so a not-yet-real skeleton for such a row must exit NON-ZERO
// UNCONDITIONALLY (the hack/lab/*.sh K3SM_LAB-unset→exit-0 pattern would falsely
// pass a non-manual row).
// Each such gate carries a greppable "# K3SM-SKELETON" sentinel so the always-red
// intent is auditable; this test asserts both the sentinel's presence and the
// non-zero exit under BOTH K3SM_LAB unset and K3SM_LAB=1.
func TestNonManualSkeletonsAlwaysRed(t *testing.T) {
	root := repoRoot(t)
	rows := loadGateRows(t)

	var reds []string
	for _, row := range rows {
		if row.Manual || !row.Skeleton {
			continue
		}
		reds = append(reds, filepath.ToSlash(filepath.Clean(row.Gate)))
	}
	sort.Strings(reds)
	if len(reds) == 0 {
		t.Fatal("no manual:false skeleton rows found in phases.json — expected the M7/M8 umbrella skeletons")
	}

	for _, rel := range reds {
		path := filepath.Join(root, filepath.FromSlash(rel))
		t.Run(rel, func(t *testing.T) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if !strings.Contains(string(body), "# K3SM-SKELETON") {
				t.Errorf("%s is a manual:false skeleton row but its script carries no `# K3SM-SKELETON` sentinel", rel)
			}
			for _, lab := range []string{"", "1"} {
				if code := runGate(t, path, lab); code == 0 {
					t.Errorf("%s (K3SM_LAB=%q): exit 0 — a manual:false skeleton must exit non-zero UNCONDITIONALLY until real (Res. 2), or the release process falsely passes the milestone", rel, lab)
				}
			}
		})
	}
}

// runGate runs a lab gate script with the given K3SM_LAB value and returns its exit
// code. The skeletons are hermetic (they echo and exit before touching any hardware),
// so this stays a fast, deterministic unit check. The trailing K3SM_LAB entry wins
// over any value already in the environment.
func runGate(t *testing.T, path, k3smLab string) int {
	t.Helper()
	cmd := exec.Command("bash", path)
	cmd.Env = append(os.Environ(), "K3SM_LAB="+k3smLab)
	switch err := cmd.Run(); {
	case err == nil:
		return 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("run %s (K3SM_LAB=%q): %v", path, k3smLab, err)
		return -1
	}
}

// TestM11CoreGateDeclaresCoreMode is B230's gate: it pins, STATICALLY and hermetically,
// the three properties that make the M11-core row honest evidence.
//
// Why it must exist as its own test. Today M11-core and M11-lab are both
// manual+skeleton, so TestLabSkeletonHonesty executes hack/lab/m11.sh — but it
// deduplicates by gate PATH, so it exercises only the bare (full-ledger) invocation and
// never --core; and the moment the real script lands, the skeleton flag drops and that
// test stops covering the file at all. The honesty the flag carries has to survive that
// transition, so it is re-expressed here as assertions on the manifest and on the
// script's own text, neither of which depends on the row still being a skeleton.
//
//  1. THE MODE IS PARSED, NOT IGNORED. The two rows share one gate path, so if the
//     script ignored its arguments the launch subset and the full B109 ledger would be
//     the same run under two names — and a --core green would silently discharge a row
//     it does not satisfy. Proven behaviourally (the two invocations differ) plus by an
//     unknown flag being REJECTED, which is what distinguishes parsing from ignoring.
//  2. THE ARGS COME FROM THE MANIFEST. The invocation is read out of the M11-core row's
//     args field rather than hardcoded here, so the field is machine-consumed and cannot
//     decay into decoration.
//  3. THE RUN-LOG HEADER NAMES ALL FOUR REQUIRED FIELDS — gate, artifact sha256,
//     per-repo git SHA, and the PASS/FAIL verdict (hack/lab/runs/README.md). A lab run
//     is run by hand and then it is over; the log is the only surviving evidence, so a
//     header missing a field yields a log that cannot discharge a ledger row.
//
// Hermetic: every invocation runs with K3SM_LAB unset, where the gate prints a PENDING
// notice and exits before touching any hardware.
func TestM11CoreGateDeclaresCoreMode(t *testing.T) {
	root := repoRoot(t)
	rows := loadGateRows(t)

	core, ok := rows["M11-core"]
	if !ok {
		t.Fatal("phases.json declares no M11-core row — the launch subset of the vm path has no gate")
	}
	full, ok := rows["M11-lab"]
	if !ok {
		t.Fatal("phases.json declares no M11-lab row — the FULL B109 vm-path ledger has no gate")
	}

	// (2) The rows are distinct BY ARGS over a shared gate path, and M11-core does not
	// require signing — m11-plan R28 removed Developer-ID from this path, so a signing
	// requirement would make the launch row unrunnable on the rig that must run it.
	t.Run("manifest_rows_are_distinct_by_args", func(t *testing.T) {
		if core.Gate != full.Gate {
			t.Fatalf("M11-core gate %q and M11-lab gate %q differ; the subset relation is expressed by args over ONE script", core.Gate, full.Gate)
		}
		if len(core.Args) != 1 || core.Args[0] != "--core" {
			t.Fatalf("M11-core args = %v, want [--core] (the launch subset is selected by a parsed flag, not by prose)", core.Args)
		}
		if len(full.Args) != 0 {
			t.Errorf("M11-lab args = %v, want none: the bare invocation IS the full B109 ledger", full.Args)
		}
		for _, req := range core.Requires {
			if req == "signing" {
				t.Errorf("M11-core requires %v: it must NOT require signing — R28 removed Developer-ID from this path and the requirement would make the launch row unrunnable", core.Requires)
			}
		}
		if !core.Manual || !full.Manual {
			t.Errorf("both M11 lab rows must be manual:true (core manual=%v, lab manual=%v) — a lab gate must never auto-green in CI", core.Manual, full.Manual)
		}
	})

	gatePath := filepath.Join(root, filepath.FromSlash(core.Gate))

	// (1) The mode is PARSED: --core and the bare invocation are different runs, and a
	// near-miss flag is rejected rather than silently downgraded to the full ledger.
	t.Run("core_mode_is_parsed_not_ignored", func(t *testing.T) {
		coreCode, coreOut := runGateArgs(t, gatePath, "", core.Args...)
		if coreCode != 0 {
			t.Fatalf("%s %v with K3SM_LAB unset: exit %d, want 0 (a skip — PENDING, NOT a pass); output:\n%s", core.Gate, core.Args, coreCode, coreOut)
		}
		fullCode, fullOut := runGateArgs(t, gatePath, "", full.Args...)
		if fullCode != 0 {
			t.Fatalf("%s (bare) with K3SM_LAB unset: exit %d, want 0 (a skip — PENDING, NOT a pass); output:\n%s", full.Gate, fullCode, fullOut)
		}
		if coreOut == fullOut {
			t.Errorf("%s produces IDENTICAL output for %v and for no args — the argument is being ignored, so a --core green would silently discharge the full B109 ledger; output:\n%s", core.Gate, core.Args, coreOut)
		}
		if !strings.Contains(coreOut, "M11-core") {
			t.Errorf("the --core invocation does not name the M11-core row in its notice; a log that cannot say which row it ran discharges neither. Output:\n%s", coreOut)
		}
		if !strings.Contains(fullOut, "M11-lab") {
			t.Errorf("the bare invocation does not name the M11-lab row in its notice. Output:\n%s", fullOut)
		}
		// Parsing, not ignoring: an unknown argument must be refused.
		if code, out := runGateArgs(t, gatePath, "", "--not-a-mode"); code == 0 {
			t.Errorf("%s accepted an unknown argument (exit 0) — a typo must not be silently downgraded into a full-ledger run; output:\n%s", core.Gate, out)
		}
	})

	// (3) The run-log header emitter names all four required evidence fields. Asserted
	// against the script SOURCE so it survives the skeleton flag being dropped, and so a
	// field cannot be lost in a branch this test does not happen to execute.
	t.Run("run_log_header_names_the_four_required_fields", func(t *testing.T) {
		body, err := os.ReadFile(gatePath)
		if err != nil {
			t.Fatalf("read %s: %v", core.Gate, err)
		}
		src := string(body)
		for _, want := range []struct{ field, token string }{
			{"gate name", "gate: "},
			{"artifact sha256", "artifact_sha256: "},
			{"per-repo git SHA", "git_sha."},
			{"verdict", "result: "},
			{"verdict value PASS", "PASS"},
			{"verdict value FAIL", "FAIL"},
		} {
			if !strings.Contains(src, want.token) {
				t.Errorf("%s emits no %s field (no %q) — see hack/lab/runs/README.md; a log missing it is not evidence", core.Gate, want.field, want.token)
			}
		}
		// Per-repo means PER REPO: one binary is built from four modules, so a single
		// "the SHA" would be a lie about three of them.
		for _, repo := range []string{"apis", "runtimed", "darwin-net", "k3sm"} {
			if !strings.Contains(src, repo) {
				t.Errorf("%s never names the %s module — the run log must record a git SHA for each of the four repos the binary is built from", core.Gate, repo)
			}
		}
	})
}

// runGateArgs runs a lab gate with the given K3SM_LAB value and argument vector and
// returns its exit code together with its combined output. It is the args-aware sibling
// of runGate (which stays argument-free for the honesty tests that only need the exit
// code). The trailing K3SM_LAB entry wins over any value already in the environment.
func runGateArgs(t *testing.T, path, k3smLab string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{path}, args...)...)
	cmd.Env = append(os.Environ(), "K3SM_LAB="+k3smLab)
	out, err := cmd.CombinedOutput()
	switch {
	case err == nil:
		return 0, string(out)
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("run %s %v (K3SM_LAB=%q): %v", path, args, k3smLab, err)
		return -1, string(out)
	}
}
