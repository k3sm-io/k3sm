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
	"encoding/binary"
	"errors"
	"os"
	"testing"
)

// healthyDoctorEnv returns a fully-passing fake doctorEnv. Each table case
// overrides only the field under test — no real sysctl/csrutil/launchctl/sqlite
// or privilege is touched (GO-STANDARDS: fake at seams). A doctorEnv is a value
// with function fields and each subtest builds its own, so this is -race /
// t.Parallel safe.
func healthyDoctorEnv() doctorEnv {
	return doctorEnv{
		goarch:           "arm64",
		macOSVersion:     func() (string, error) { return "26.1", nil },
		sipEnabled:       func() (bool, error) { return true, nil },
		helperState:      func() (bool, bool) { return true, true },
		brewPresent:      func() bool { return true },
		datastorePosture: func() (bool, int, string, error) { return true, 3, "wal", nil },
	}
}

func TestDoctorChecksTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		fn   func(doctorEnv) checkResult
		mut  func(*doctorEnv) // mutate the healthy baseline for the field under test
		want doctorStatus
	}{
		// arch: arm64 → PASS, else → FAIL (Apple-Silicon-only).
		{"arch/pass-arm64", checkArch, func(e *doctorEnv) { e.goarch = "arm64" }, statusPass},
		{"arch/fail-amd64", checkArch, func(e *doctorEnv) { e.goarch = "amd64" }, statusFail},

		// macos: >= floor → PASS, below → FAIL, probe error → WARN.
		{"macos/pass-at-floor", checkMacOS, func(e *doctorEnv) {
			e.macOSVersion = func() (string, error) { return "26.0", nil }
		}, statusPass},
		{"macos/fail-below-floor", checkMacOS, func(e *doctorEnv) {
			e.macOSVersion = func() (string, error) { return "15.5", nil }
		}, statusFail},
		{"macos/warn-probe-error", checkMacOS, func(e *doctorEnv) {
			e.macOSVersion = func() (string, error) { return "", errors.New("no sysctl") }
		}, statusWarn},
		{"macos/warn-unparseable", checkMacOS, func(e *doctorEnv) {
			e.macOSVersion = func() (string, error) { return "nonsense", nil }
		}, statusWarn},

		// sip: enabled → PASS, disabled → WARN, probe error → WARN.
		{"sip/pass-enabled", checkSIP, func(e *doctorEnv) {
			e.sipEnabled = func() (bool, error) { return true, nil }
		}, statusPass},
		{"sip/warn-disabled", checkSIP, func(e *doctorEnv) {
			e.sipEnabled = func() (bool, error) { return false, nil }
		}, statusWarn},
		{"sip/warn-probe-error", checkSIP, func(e *doctorEnv) {
			e.sipEnabled = func() (bool, error) { return false, errors.New("no csrutil") }
		}, statusWarn},

		// netd-helper: installed+running → PASS, installed-only → WARN, absent → WARN.
		{"helper/pass-running", checkHelper, func(e *doctorEnv) {
			e.helperState = func() (bool, bool) { return true, true }
		}, statusPass},
		{"helper/warn-installed-stopped", checkHelper, func(e *doctorEnv) {
			e.helperState = func() (bool, bool) { return true, false }
		}, statusWarn},
		{"helper/warn-not-installed", checkHelper, func(e *doctorEnv) {
			e.helperState = func() (bool, bool) { return false, false }
		}, statusWarn},

		// brew: present → PASS, absent → WARN.
		{"brew/pass-present", checkBrew, func(e *doctorEnv) { e.brewPresent = func() bool { return true } }, statusPass},
		{"brew/warn-absent", checkBrew, func(e *doctorEnv) { e.brewPresent = func() bool { return false } }, statusWarn},

		// datastore: present+wal → PASS, absent → SKIP, non-wal → WARN, error → WARN.
		{"datastore/pass-present-wal", checkDatastore, func(e *doctorEnv) {
			e.datastorePosture = func() (bool, int, string, error) { return true, 3, "wal", nil }
		}, statusPass},
		{"datastore/skip-absent", checkDatastore, func(e *doctorEnv) {
			e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
		}, statusSkip},
		{"datastore/warn-non-wal", checkDatastore, func(e *doctorEnv) {
			e.datastorePosture = func() (bool, int, string, error) { return true, 3, "rollback", nil }
		}, statusWarn},
		{"datastore/warn-probe-error", checkDatastore, func(e *doctorEnv) {
			e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", errors.New("io error") }
		}, statusWarn},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := healthyDoctorEnv()
			c.mut(&e)
			got := c.fn(e)
			if got.status != c.want {
				t.Fatalf("status = %v, want %v (detail: %q)", got.status, c.want, got.detail)
			}
			if got.detail == "" {
				t.Errorf("empty detail — every check must explain its verdict")
			}
		})
	}

	// Highest-value property: an unprobed datastore (absent state.db) is SKIP and
	// is NEITHER PASS nor FAIL. A check that could not probe must not read as
	// healthy, and a fresh node is not a failure.
	t.Run("datastore/skip-is-distinct-from-pass-and-fail", func(t *testing.T) {
		t.Parallel()
		e := healthyDoctorEnv()
		e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
		got := checkDatastore(e)
		if got.status != statusSkip {
			t.Fatalf("absent state.db: status = %v, want statusSkip", got.status)
		}
		if got.status == statusPass {
			t.Fatal("SKIP must NOT read as PASS — a check that could not probe must not appear healthy")
		}
		if got.status == statusFail {
			t.Fatal("SKIP must NOT read as FAIL — a fresh node with no state.db is not a failure")
		}
	})

	// The registry the gate iterates must cover every check, and each fn must
	// return a checkResult whose name matches its registry entry (so the ladder
	// label and the result agree — a mismatch would mislabel a verdict).
	t.Run("registry/covers-all-checks-with-matching-names", func(t *testing.T) {
		t.Parallel()
		e := healthyDoctorEnv()
		seen := map[string]bool{}
		for _, dc := range doctorChecks() {
			if seen[dc.name] {
				t.Errorf("duplicate registry check name %q", dc.name)
			}
			seen[dc.name] = true
			if r := dc.fn(e); r.name != dc.name {
				t.Errorf("registry entry %q returns checkResult.name %q — must match", dc.name, r.name)
			}
		}
		for _, want := range []string{"arch", "macos", "sip", "netd-helper", "brew", "datastore"} {
			if !seen[want] {
				t.Errorf("registry missing check %q", want)
			}
		}
	})

	// statusSkip's tag is distinct from the others so the ladder surfaces it
	// distinctly (not folded into PASS).
	t.Run("status/skip-tag-is-distinct", func(t *testing.T) {
		t.Parallel()
		tags := map[string]doctorStatus{
			statusPass.String(): statusPass,
			statusWarn.String(): statusWarn,
			statusFail.String(): statusFail,
			statusSkip.String(): statusSkip,
		}
		if len(tags) != 4 {
			t.Fatalf("status tags collide: %v", tags)
		}
	})
}

// TestProbeDatastorePosture exercises the REAL read-only probe against a temp file
// to prove it (a) SKIPs an absent path with no file creation and (b) parses the
// SQLite header without a driver. It never opens a real control-plane db.
func TestProbeDatastorePosture(t *testing.T) {
	t.Parallel()

	t.Run("absent-path-skips-and-creates-nothing", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir() + "/state.db"
		present, uv, jm, err := probeDatastorePosture(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if present {
			t.Fatal("absent path reported present=true")
		}
		if uv != 0 || jm != "" {
			t.Fatalf("absent path returned uv=%d jm=%q, want 0/\"\"", uv, jm)
		}
		// The probe must NOT have created the file (forbidden side effect).
		if _, statErr := os.Stat(path); statErr == nil {
			t.Fatal("probe created the state.db file — it must be strictly read-only")
		}
	})

	t.Run("parses-wal-header", func(t *testing.T) {
		t.Parallel()
		path := t.TempDir() + "/state.db"
		writeFakeSQLiteHeader(t, path, 2 /*WAL*/, 42 /*user_version*/)
		present, uv, jm, err := probeDatastorePosture(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !present || uv != 42 || jm != "wal" {
			t.Fatalf("got present=%v uv=%d jm=%q, want true/42/wal", present, uv, jm)
		}
	})
}

// writeFakeSQLiteHeader writes a minimal 100-byte SQLite database header with the
// given write-version byte (offset 18: 1=rollback, 2=WAL) and user_version (offset
// 60, big-endian uint32) — enough for probeDatastorePosture's header parse. It is
// NOT a real database; the probe only reads the header.
func writeFakeSQLiteHeader(t *testing.T, path string, writeVersion byte, userVersion uint32) {
	t.Helper()
	var hdr [100]byte
	copy(hdr[0:16], "SQLite format 3\x00")
	hdr[18] = writeVersion
	hdr[19] = writeVersion
	binary.BigEndian.PutUint32(hdr[60:64], userVersion)
	if err := os.WriteFile(path, hdr[:], 0o600); err != nil {
		t.Fatalf("write fake header: %v", err)
	}
}
