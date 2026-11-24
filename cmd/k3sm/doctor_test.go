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
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/keystore"
	"k3sm.io/k3sm/pkg/keystore/socket"
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

		// keystore-logs: both logs flagged and the service user's → PASS;
		// missing → WARN naming install; refused (flag clear, wrong owner) →
		// FAIL; unreadable as an ordinary account → WARN; a worker → SKIP.
		{"keystore-logs/pass", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return nil }
		}, statusPass},
		{"keystore-logs/warn-missing", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return fmt.Errorf("no log: %w", fs.ErrNotExist) }
		}, statusWarn},
		{"keystore-logs/warn-permission", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return fmt.Errorf("open: %w", fs.ErrPermission) }
		}, statusWarn},
		{"keystore-logs/fail-unflagged", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return errors.New("the log is not flagged append-only") }
		}, statusFail},
		{"keystore-logs/pass-under-soft-cap", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return nil }
			e.keystoreLogSizes = func(context.Context) (keystore.LogSizes, error) {
				return keystore.LogSizes{UserFloor: 10, Audit: 64, SoftCap: 64, HardCap: 256}, nil
			}
		}, statusPass},
		{"keystore-logs/warn-past-soft-cap", checkKeystoreLogs, func(e *doctorEnv) {
			e.keystoreLogs = func(context.Context) error { return nil }
			e.keystoreLogSizes = func(context.Context) (keystore.LogSizes, error) {
				return keystore.LogSizes{UserFloor: 65, SoftCap: 64, HardCap: 256}, nil
			}
		}, statusWarn},
		{"keystore-logs/skip-worker", checkKeystoreLogs, func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
		}, statusSkip},

		// keystore-floor: no damage → PASS; damaged lines or a floor past
		// the reader's bounds → WARN naming floor --rebuild; a floor not
		// read (missing, permission) → SKIP, the keystore-logs row's; a
		// worker or no seam → SKIP.
		{"keystore-floor/pass", checkKeystoreFloor, func(e *doctorEnv) {
			e.keystoreFloorDamage = func(context.Context) (int, error) { return 0, nil }
		}, statusPass},
		{"keystore-floor/warn-damaged", checkKeystoreFloor, func(e *doctorEnv) {
			e.keystoreFloorDamage = func(context.Context) (int, error) { return 3, nil }
		}, statusWarn},
		{"keystore-floor/warn-past-bounds", checkKeystoreFloor, func(e *doctorEnv) {
			e.keystoreFloorDamage = func(context.Context) (int, error) {
				return 1, errors.New("the keystore append-only log is larger than the reader's bound")
			}
		}, statusWarn},
		{"keystore-floor/skip-missing", checkKeystoreFloor, func(e *doctorEnv) {
			e.keystoreFloorDamage = func(context.Context) (int, error) { return 0, fmt.Errorf("no log: %w", fs.ErrNotExist) }
		}, statusSkip},
		{"keystore-floor/skip-unprobed", checkKeystoreFloor, func(e *doctorEnv) { e.keystoreFloorDamage = nil }, statusSkip},
		{"keystore-floor/skip-worker", checkKeystoreFloor, func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
		}, statusSkip},

		// keystore-maintenance: no marker → PASS; a standing marker → WARN
		// naming its verb; a worker or no seam → SKIP.
		{"keystore-maintenance/pass", checkKeystoreMaintenance, func(e *doctorEnv) {
			e.keystoreMaintenance = func(context.Context) (string, bool, error) { return "", false, nil }
		}, statusPass},
		{"keystore-maintenance/warn-standing", checkKeystoreMaintenance, func(e *doctorEnv) {
			e.keystoreMaintenance = func(context.Context) (string, bool, error) { return "floor --rebuild", true, nil }
		}, statusWarn},
		{"keystore-maintenance/warn-unknown", checkKeystoreMaintenance, func(e *doctorEnv) {
			e.keystoreMaintenance = func(context.Context) (string, bool, error) { return "", true, nil }
		}, statusWarn},
		{"keystore-maintenance/skip-unprobed", checkKeystoreMaintenance, func(e *doctorEnv) { e.keystoreMaintenance = nil }, statusSkip},
		{"keystore-maintenance/skip-worker", checkKeystoreMaintenance, func(e *doctorEnv) {
			e.nodeRole = func() (install.Role, bool) { return install.RoleAgent, true }
		}, statusSkip},

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

		// datastore: present+wal → PASS, absent → SKIP, non-wal → WARN, error → WARN;
		// and on a worker SKIP either way — a worker runs no kine.
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
		// A state.db that IS there on a worker is the stale <DataRoot>/server
		// directory of an earlier server-era install, never this node's.
		// Nor is a posture the worker arm could even fail to read: the role is
		// consulted first, so an unreadable stale database is still a SKIP and
		// never the "sudo k3sm doctor" repair of a datastore this Mac lacks.
		{"datastore/skip-present-on-a-worker", checkDatastore, func(e *doctorEnv) {
			*e = agentEnv()
			e.datastorePosture = func() (bool, int, string, error) { return true, 3, "wal", nil }
		}, statusSkip},
		{"datastore/skip-unreadable-on-a-worker", checkDatastore, func(e *doctorEnv) {
			*e = agentEnv()
			e.datastorePosture = func() (bool, int, string, error) {
				return false, 0, "", errors.New("permission denied")
			}
		}, statusSkip},

		// datastore on an embedded etcd HA server: the member, judged by the same
		// rule as the status row, replaces "no state.db yet".
		{"datastore/pass-etcd-member-healthy", checkDatastore, func(e *doctorEnv) {
			e.datastorePosture = func() (bool, int, string, error) { return false, 0, "", nil }
			e.etcdMember = func() (bool, executor.EtcdStatus, error) {
				return true, executor.EtcdStatus{Members: 2, LeaderPresent: true}, nil
			}
		}, statusPass},
		{"datastore/fail-etcd-member-no-leader", checkDatastore, func(e *doctorEnv) {
			e.etcdMember = func() (bool, executor.EtcdStatus, error) { return true, executor.EtcdStatus{Members: 2}, nil }
		}, statusFail},
		{"datastore/fail-etcd-member-nospace", checkDatastore, func(e *doctorEnv) {
			e.etcdMember = func() (bool, executor.EtcdStatus, error) {
				return true, executor.EtcdStatus{Members: 3, LeaderPresent: true, Alarms: []string{"NOSPACE"}}, nil
			}
		}, statusFail},
		{"datastore/skip-etcd-member-not-started", checkDatastore, func(e *doctorEnv) {
			e.etcdMember = func() (bool, executor.EtcdStatus, error) { return true, executor.EtcdStatus{}, fs.ErrNotExist }
		}, statusSkip},
		{"datastore/warn-etcd-record-unreadable", checkDatastore, func(e *doctorEnv) {
			e.etcdMember = func() (bool, executor.EtcdStatus, error) { return true, executor.EtcdStatus{}, fs.ErrPermission }
		}, statusWarn},
		{"datastore/kine-when-no-etcd-member", checkDatastore, func(e *doctorEnv) {
			e.etcdMember = func() (bool, executor.EtcdStatus, error) { return false, executor.EtcdStatus{}, nil }
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
	// row must not describe a wait that will never end — and it must not
	// describe the stale <DataRoot>/server database an earlier server-era
	// install left behind either, readable or not. All three worker cases say
	// ONE sentence, the one `k3sm status` says, and none of them reads a
	// posture: the seam is asserted never to have been called.
	t.Run("datastore/a-worker-is-told-it-runs-no-datastore", func(t *testing.T) {
		t.Parallel()
		cases := map[string]func() (bool, int, string, error){
			"absent":     func() (bool, int, string, error) { return false, 0, "", nil },
			"present":    func() (bool, int, string, error) { return true, 3, "wal", nil },
			"unreadable": func() (bool, int, string, error) { return false, 0, "", errors.New("permission denied") },
		}
		for name, posture := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				probes := 0
				e := agentEnv()
				e.datastorePosture = func() (bool, int, string, error) {
					probes++
					return posture()
				}
				got := checkDatastore(e)
				if got.status != statusSkip {
					t.Fatalf("status = %v (%q), want SKIP", got.status, got.detail)
				}
				if got.detail != status.WorkerDatastoreDetail {
					t.Errorf("detail = %q, want the shared sentence %q", got.detail, status.WorkerDatastoreDetail)
				}
				if got.remedy != "" {
					t.Errorf("remedy = %q; there is no datastore here to repair", got.remedy)
				}
				if strings.Contains(got.detail, "has not initialized") {
					t.Errorf("a worker is told to wait for a control plane it does not run: %q", got.detail)
				}
				if probes != 0 {
					t.Errorf("the datastore posture was read %d time(s) on a worker; the role decides before any probe", probes)
				}
			})
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
		for _, want := range []string{"arch", "macos", "sip", "netd-helper", "datastore", "toolchain", "agent-daemon", "keystore-logs", "keystore-floor", "keystore-maintenance", "keystore-maintenance-runs", "keystore-user-scope"} {
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

// A standing maintenance marker's WARN names the verb that left it and the
// command to run.
func TestDoctorKeystoreMaintenanceNamesVerb(t *testing.T) {
	e := healthyDoctorEnv()
	e.keystoreMaintenance = func(context.Context) (string, bool, error) { return "audit --rotate", true, nil }
	r := checkKeystoreMaintenance(e)
	if r.status != statusWarn || !strings.Contains(r.detail, "left by keys audit --rotate") || !strings.HasPrefix(r.remedy, "sudo k3sm keys audit --rotate") {
		t.Fatalf("the row is %+v, want WARN naming audit --rotate and its rerun", r)
	}
}

// userScopeChecks is a doctor seam over socket.Preconditions under which
// every start check passes and a socket of the service user's is at the
// path; mut changes the one under test.
func userScopeChecks(mut func(*socket.Preconditions)) func() (doctorUserScope, error) {
	return userScope(func(u *doctorUserScope) { mut(&u.pre) })
}

// userScope is userScopeChecks over the whole seam.
func userScope(mut func(*doctorUserScope)) func() (doctorUserScope, error) {
	return func() (doctorUserScope, error) {
		p := socket.Preconditions{
			EUID:              func() int { return 260 },
			ServiceUID:        260,
			MaintenanceMarked: func() (bool, error) { return false, nil },
			OpenLogs:          func(context.Context) error { return nil },
			SandboxCheck:      func() error { return nil },
			IgnoresOwnership:  func() (bool, error) { return false, nil },
			CheckInstall:      func(context.Context) error { return nil },
			ServerCount:       func(context.Context) (int, error) { return 1, nil },
		}
		u := doctorUserScope{
			pre:       p,
			release:   func() {},
			sockPath:  "/var/lib/k3sm/keystore-sock/keys.sock",
			sockState: func() error { return nil },
		}
		mut(&u)
		return u, nil
	}
}

// TestDoctorKeystoreUserScopeRow checks the user scope's row re-runs the
// server's start checks and says why it is off with the supervisor's reason
// for each, naming `sudo k3sm install` only for the installed files: two
// servers registered, a rootless or uninstalled server, a data root mounted
// ignoring ownership, a failed install check, a standing maintenance marker
// and a server count that cannot be read.
func TestDoctorKeystoreUserScopeRow(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	for _, tt := range []struct {
		name      string
		seam      func() (doctorUserScope, error)
		status    doctorStatus
		detail    string
		remedy    string
		detailHas string
	}{
		{name: "start checks pass", seam: userScopeChecks(func(*socket.Preconditions) {}), status: statusPass, detail: "keystore user scope: start checks pass; launchd's socket (root's, mode 0666) is at /var/lib/k3sm/keystore-sock/keys.sock"},
		{name: "start checks pass, no socket", seam: userScope(func(u *doctorUserScope) {
			u.sockState = func() error { return fmt.Errorf("%w: nothing is at the path", errNoListeningSocket) }
		}), status: statusWarn, detail: "keystore user scope: start checks pass, but no listening socket at /var/lib/k3sm/keystore-sock/keys.sock", detailHas: "nothing is at the path"},
		{name: "two servers", seam: userScope(func(u *doctorUserScope) {
			u.pre.ServerCount = func(context.Context) (int, error) { return 2, nil }
			u.servers = func() ([]string, error) { return []string{"mac-a", "mac-b"}, nil }
		}), status: statusWarn, detail: "keystore user scope: off (more than one server registered)", detailHas: "2 servers registered] servers: mac-a, mac-b"},
		{name: "ten servers", seam: userScope(func(u *doctorUserScope) {
			u.pre.ServerCount = func(context.Context) (int, error) { return 10, nil }
			u.servers = func() ([]string, error) {
				return []string{"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"}, nil
			}
		}), status: statusWarn, detail: "keystore user scope: off (more than one server registered)", detailHas: "servers: s0, s1, s2, s3, s4, s5, s6, s7 and 2 more"},
		{name: "count unreadable as this user", seam: userScope(func(u *doctorUserScope) {
			denied := fmt.Errorf("read the admin kubeconfig: %w", fs.ErrPermission)
			u.pre.ServerCount = func(context.Context) (int, error) { return 0, denied }
			u.servers = func() ([]string, error) { return nil, denied }
		}), status: statusWarn, detail: "keystore user scope: the server count cannot be read as this user", remedy: "sudo k3sm doctor   # the admin kubeconfig is root's"},
		{name: "rootless server", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.EUID = func() int { return 501 }
		}), status: statusWarn, detail: "keystore user scope: off (user scope needs the installed server)"},
		{name: "service uid in the login range", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.EUID, p.ServiceUID = func() int { return 600 }, 600
		}), status: statusWarn, detail: "keystore user scope: off (the service uid is in the login range)", detailHas: "the service uid 600 is not below 501"},
		{name: "service user unknown", seam: func() (doctorUserScope, error) {
			return doctorUserScope{}, boom
		}, status: statusWarn, detail: "keystore user scope: off (user scope needs the installed server)", detailHas: "boom"},
		{name: "ignore-ownership mount", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.IgnoresOwnership = func() (bool, error) { return true, nil }
		}), status: statusWarn, detail: "keystore user scope: off (the data root is mounted ignoring ownership)"},
		{name: "install check failed", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.CheckInstall = func(context.Context) error { return errors.New("the socket directory keystore-sock is missing") }
		}), status: statusWarn, detail: "keystore user scope: off (the socket directory or an append-only log is missing, wrong or unflagged); run `sudo k3sm install`", remedy: "sudo k3sm install", detailHas: "keystore-sock is missing"},
		{name: "install predates the logs", seam: userScopeChecks(func(p *socket.Preconditions) {
			// An install with no audit log: the marker and the log judgement
			// fail too, but the install check runs first and names install.
			missing := errors.New("the append-only log keystore-audit.log is missing")
			p.CheckInstall = func(context.Context) error { return missing }
			p.MaintenanceMarked = func() (bool, error) { return false, missing }
			p.OpenLogs = func(context.Context) error { return missing }
		}), status: statusWarn, detail: "keystore user scope: off (the socket directory or an append-only log is missing, wrong or unflagged); run `sudo k3sm install`", remedy: "sudo k3sm install", detailHas: "keystore-audit.log is missing"},
		{name: "logs unavailable", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.OpenLogs = func(context.Context) error { return boom }
		}), status: statusWarn, detail: "keystore user scope: off (the append-only logs cannot be opened (logs-unavailable))", detailHas: "boom"},
		{name: "maintenance", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.MaintenanceMarked = func() (bool, error) { return true, nil }
		}), status: statusWarn, detail: "keystore user scope: off (a maintenance verb is running)"},
		{name: "server count unknown", seam: userScopeChecks(func(p *socket.Preconditions) {
			p.ServerCount = func(context.Context) (int, error) { return 0, boom }
		}), status: statusWarn, detail: "keystore user scope: off (the server count is unknown)", detailHas: "boom"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := healthyDoctorEnv()
			e.keystoreUserScope = tt.seam
			r := checkKeystoreUserScope(e)
			if r.name != "keystore-user-scope" || r.status != tt.status {
				t.Fatalf("row = %+v, want %v", r, tt.status)
			}
			if !strings.HasPrefix(r.detail, tt.detail) {
				t.Errorf("detail = %q, want it to start %q", r.detail, tt.detail)
			}
			if tt.detailHas != "" && !strings.Contains(r.detail, tt.detailHas) {
				t.Errorf("detail = %q, want it to carry %q", r.detail, tt.detailHas)
			}
			if r.remedy != tt.remedy {
				t.Errorf("remedy = %q, want %q", r.remedy, tt.remedy)
			}
			if strings.Contains(r.detail, "scope: on") || (tt.name == "count unreadable as this user" && strings.Contains(r.detail, "off")) {
				t.Errorf("detail = %q claims a state doctor cannot establish", r.detail)
			}
			if tt.remedy == "" && strings.Contains(r.detail, "sudo k3sm install") {
				t.Errorf("detail = %q names install for a reason install does not fix", r.detail)
			}
		})
	}

	t.Run("a worker is skipped", func(t *testing.T) {
		t.Parallel()
		e := agentEnv()
		e.keystoreUserScope = func() (doctorUserScope, error) {
			t.Error("a worker ran the user scope's checks")
			return doctorUserScope{}, nil
		}
		if r := checkKeystoreUserScope(e); r.status != statusSkip {
			t.Fatalf("row = %+v, want SKIP", r)
		}
	})
	t.Run("an unprobed row is skipped", func(t *testing.T) {
		t.Parallel()
		if r := checkKeystoreUserScope(healthyDoctorEnv()); r.status != statusSkip {
			t.Fatalf("row = %+v, want SKIP", r)
		}
	})
}
