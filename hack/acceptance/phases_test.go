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
// that PROVES the milestone (Gate), the test Tier it runs at, the host capabilities
// it Requires, and whether it is lab-only (Manual). Only Gate is asserted by the
// test; the remaining fields document the schema and force every row to decode as a
// JSON object (a malformed bare-string row fails the unmarshal rather than passing
// silently).
type gateRow struct {
	Gate     string   `json:"gate"`
	Tier     string   `json:"tier"`
	Requires []string `json:"requires"`
	Manual   bool     `json:"manual"`
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

// TestLabSkeletonHonesty pins the load-bearing honesty contract of the B25 lab
// skeletons (hack/lab/m4.sh, hack/lab/m5.sh): with K3SM_LAB unset they SKIP and
// exit 0 ("PENDING — not a pass"); under K3SM_LAB=1 they report not-yet-implemented
// and exit NON-ZERO. /orchestrate runs a manual lab gate under K3SM_LAB=1 and trusts
// exit 0 as "milestone proven", so a placeholder that exited 0 there would fake-green
// M4-lab/M5 whose real proof is owned by B35/B34. This test makes that contract a
// CI invariant — notably across the eventual B34/B35 handoff that replaces these
// files. Scoped to the SKELETONS only: hack/lab/{m3,m6}.sh run real conformance
// slices under K3SM_LAB=1 (not hermetic), so they are deliberately out of scope.
func TestLabSkeletonHonesty(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{"hack/lab/m4.sh", "hack/lab/m5.sh"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		t.Run(rel, func(t *testing.T) {
			if code := runGate(t, path, ""); code != 0 {
				t.Errorf("%s with K3SM_LAB unset: exit %d, want 0 (a skip — PENDING, NOT a pass)", rel, code)
			}
			if code := runGate(t, path, "1"); code == 0 {
				t.Errorf("%s with K3SM_LAB=1: exit 0 — a placeholder must NOT report the milestone proven (the real gate is B34/B35)", rel)
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
