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
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/status"
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
		developerDir:     func() (string, error) { return "/Applications/Xcode.app/Contents/Developer", nil },
		// The healthy baseline is a control plane, which is what a Mac running
		// `k3sm doctor` is unless it was installed as a worker — so the
		// agent-daemon check SKIPs here, and each agent case opts in.
		nodeRole:   func() (install.Role, bool) { return install.RoleServer, true },
		agentState: func() (bool, bool) { return true, true },
		agentCredential: func() (status.CredentialState, time.Time) {
			return status.CredentialValid, time.Now().Add(90 * 24 * time.Hour)
		},
	}
}

// agentEnv is the healthy baseline as a JOINED WORKER: the role this Mac is
// installed as, its daemon up, and a credential in date.
func agentEnv() doctorEnv {
	e := healthyDoctorEnv()
	e.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
	return e
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
		{"datastore/skip-absent-on-a-worker", checkDatastore, func(e *doctorEnv) {
			*e = agentEnv()
			e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
		}, statusSkip},

		// toolchain: the three node classes. A full Xcode developer dir is the one
		// the annotation grants; the other two grant nothing and are WARN, never
		// FAIL — a Mac with no Xcode is a normal k3sm node for anything that is not
		// a build. The verdict is sandbox.ValidateXcodeToolchainDir's, so the
		// Command Line Tools case is decided by the same predicate the daemon uses
		// rather than by this test's idea of a path shape.
		{"toolchain/pass-full-xcode", checkXcodeToolchain, func(e *doctorEnv) {
			e.developerDir = func() (string, error) { return "/Applications/Xcode.app/Contents/Developer", nil }
		}, statusPass},
		{"toolchain/warn-command-line-tools", checkXcodeToolchain, func(e *doctorEnv) {
			e.developerDir = func() (string, error) { return "/Library/Developer/CommandLineTools", nil }
		}, statusWarn},
		{"toolchain/warn-no-developer-dir", checkXcodeToolchain, func(e *doctorEnv) {
			e.developerDir = func() (string, error) { return "", errors.New("xcode-select -p: no developer tools") }
		}, statusWarn},

		// agent-daemon: SKIP on anything that is not a worker (a control plane
		// has no agent daemon and never will — a WARN there would teach an
		// operator to ignore the row). On a worker: a daemon that is not
		// running is a FAIL, and a running daemon whose credential is absent or
		// expired is a WARN, because the pid alone says nothing about whether
		// this Mac ever joined.
		{"agent-daemon/skip-on-a-server", checkAgentDaemon, func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleServer, true }
		}, statusSkip},
		{"agent-daemon/skip-when-nothing-is-installed", checkAgentDaemon, func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleServer, false }
		}, statusSkip},
		{"agent-daemon/pass-running-with-a-valid-credential", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
		}, statusPass},
		{"agent-daemon/fail-daemon-not-running", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentState = func() (bool, bool) { return true, false }
		}, statusFail},
		{"agent-daemon/fail-daemon-not-installed", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentState = func() (bool, bool) { return false, false }
		}, statusFail},
		{"agent-daemon/warn-running-but-never-joined", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentCredential = func() (status.CredentialState, time.Time) { return status.CredentialAbsent, time.Time{} }
		}, statusWarn},
		{"agent-daemon/warn-credential-expired", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentCredential = func() (status.CredentialState, time.Time) {
				return status.CredentialExpired, time.Now().Add(-24 * time.Hour)
			}
		}, statusWarn},
		{"agent-daemon/warn-credential-corrupt", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentCredential = func() (status.CredentialState, time.Time) { return status.CredentialCorrupt, time.Time{} }
		}, statusWarn},
		{"agent-daemon/skip-credential-unreadable-as-this-user", checkAgentDaemon, func(e *doctorEnv) {
			*e = agentEnv()
			e.agentCredential = func() (status.CredentialState, time.Time) { return status.CredentialUnknown, time.Time{} }
		}, statusSkip},
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

	// The highest-value agent property: a worker whose daemon is UP but has
	// never joined must not read as healthy. launchd keeps that pid alive
	// forever, so PASS there would be the report agreeing with the one fact
	// that does not matter.
	t.Run("agent-daemon/a-running-daemon-that-never-joined-is-not-a-pass", func(t *testing.T) {
		t.Parallel()
		e := agentEnv()
		e.agentCredential = func() (status.CredentialState, time.Time) { return status.CredentialAbsent, time.Time{} }
		got := checkAgentDaemon(e)
		if got.status == statusPass {
			t.Fatalf("a worker with no node credential read as PASS: %q", got.detail)
		}
		// The two-Mac repair is in the REMEDY, which is the field the report's
		// Next: block is built from; the detail states the condition. What
		// matters is that the operator is told all three, so the assertion is
		// over the pair.
		told := got.detail + "\n" + got.remedy
		for _, want := range []string{"k3sm token create", "--token-file", "agent.log"} {
			if !strings.Contains(told, want) {
				t.Errorf("neither detail nor remedy names %q — the repair spans two Macs and has to say so:\n%s", want, told)
			}
		}
	})

	// A control plane never gets a warning about a daemon it is not supposed to
	// have: the row is SKIP, and SKIP is neither PASS nor FAIL.
	t.Run("agent-daemon/a-server-is-skipped-not-warned", func(t *testing.T) {
		t.Parallel()
		got := checkAgentDaemon(healthyDoctorEnv())
		if got.status != statusSkip {
			t.Fatalf("status = %v, want SKIP on a control plane (detail: %q)", got.status, got.detail)
		}
	})

	// A worker is not a control plane that has not started yet: its datastore
	// row must not describe a wait that will never end.
	t.Run("datastore/a-worker-is-told-it-runs-no-datastore", func(t *testing.T) {
		t.Parallel()
		e := agentEnv()
		e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
		got := checkDatastore(e)
		if got.status != statusSkip {
			t.Fatalf("status = %v, want SKIP", got.status)
		}
		if strings.Contains(got.detail, "has not initialized") {
			t.Errorf("a worker is told to wait for a control plane it does not run: %q", got.detail)
		}
		if !strings.Contains(got.detail, "worker") {
			t.Errorf("detail does not say why there is no datastore here: %q", got.detail)
		}
		// And a control plane's sentence is unchanged.
		server := healthyDoctorEnv()
		server.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
		if detail := checkDatastore(server).detail; !strings.Contains(detail, "has not initialized") {
			t.Errorf("the control-plane sentence changed: %q", detail)
		}
	})

	// The two paths the agent lines quote are derived from the installer, not
	// spelled out in the doctor: the credential store is the directory the
	// install verifier watches, and the staged join token sits beside it.
	t.Run("agent-daemon/the-paths-it-names-come-from-the-installer", func(t *testing.T) {
		t.Parallel()
		want := filepath.Dir(install.AgentCredentialPath(install.DefaultDataRoot))
		if got := agentCredentialDir(); got != want {
			t.Errorf("credential dir = %q, want %q", got, want)
		}
		if got := agentStagedTokenPath(); filepath.Dir(got) != want {
			t.Errorf("staged token path = %q, want it inside %q", got, want)
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
		for _, want := range []string{"arch", "macos", "sip", "netd-helper", "brew", "datastore", "toolchain", "agent-daemon"} {
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
