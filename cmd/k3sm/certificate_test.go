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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// rotateSuccessSentence is the fragment ONLY the closing line of a COMPLETED
// rotation prints. Asserting on it is how the gate proves a failed rotation never
// claims success.
const rotateSuccessSentence = "is serving and both CA pins re-verified unchanged"

// reportPIDs matches the launchd pid pair that closing line names.
var reportPIDs = regexp.MustCompile(`\(pid \d+ -> \d+\)`)

// fakeRestarter is the injected launchd seam. It records every label a rotation
// kickstarts, models launchd's pid bookkeeping (a kickstart replaces the running
// instance, so the reported pid moves), and can be told to fail, to refuse the pid
// read (an unloaded job), to keep the pid FROZEN (the daemon never comes back), or to
// mutate the work dir mid-kickstart. No real launchctl, no privilege, no live cluster
// (GO-STANDARDS: fake at seams).
type fakeRestarter struct {
	labels []string
	err    error
	// pid is what launchd reports for the label; frozenPID keeps it unchanged across
	// a kickstart, modelling a daemon that never respawned (or one whose old instance
	// is still the only thing on the port).
	pid       int
	pidErr    error
	frozenPID bool
	// onKickstart runs INSIDE the kickstart, modelling what the restarting daemon
	// does to the work dir (the CA re-mint the rotation must catch).
	onKickstart func()
	// calls records the seam calls in order, so the gate can pin that the pid is
	// read BEFORE the kickstart — without a pre-restart pid there is nothing to
	// compare the post-restart one against.
	calls []string
}

func (f *fakeRestarter) LaunchctlKickstart(label string) error {
	f.calls = append(f.calls, "kickstart")
	f.labels = append(f.labels, label)
	if f.onKickstart != nil {
		f.onKickstart()
	}
	if f.err != nil {
		return f.err
	}
	if !f.frozenPID {
		f.pid++
	}
	return nil
}

func (f *fakeRestarter) LaunchctlServicePID(label string) (int, error) {
	f.calls = append(f.calls, "pid")
	if f.pidErr != nil {
		return 0, f.pidErr
	}
	return f.pid, nil
}

// fileState is one entry of a work-dir tree snapshot: its mode, owner, whether it is
// a directory, and (when the walk captured contents) its exact bytes.
type fileState struct {
	mode fs.FileMode
	uid  uint32
	gid  uint32
	dir  bool
	data []byte
}

// walkTree records every path under root. withData selects whether file CONTENTS are
// read, so a snapshot can be taken while a case has a file chmod 0000'd.
//
// Mode AND owner are always captured: R2's hazard is "the unprivileged _k3sm daemon
// can no longer open this path on its next boot", and a root chmod 0600 / chown 0:0
// causes that just as surely as a write does. A snapshot that recorded only contents
// would make the whole permission class of damage structurally invisible.
func walkTree(t *testing.T, root string, withData bool) map[string]fileState {
	t.Helper()
	out := map[string]fileState{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: FileInfo carries no *syscall.Stat_t (cannot check ownership)", p)
		}
		st := fileState{mode: info.Mode().Perm(), uid: sys.Uid, gid: sys.Gid, dir: d.IsDir()}
		if !st.dir && withData {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			st.data = b
		}
		out[p] = st
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// rebaseline folds the TEST's own post-lock mutations into the baseline: paths the
// lock removed are dropped and mode/owner are re-read (a chmod cannot change contents,
// so those are carried over). Without it, a case that chmod 0000's the CA keys would
// look like the ROTATION changed their mode.
func rebaseline(t *testing.T, pre map[string]fileState) map[string]fileState {
	t.Helper()
	out := make(map[string]fileState, len(pre))
	for p, st := range pre {
		info, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("re-stat %s: %v", p, err)
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("%s: FileInfo carries no *syscall.Stat_t", p)
		}
		st.mode, st.uid, st.gid = info.Mode().Perm(), sys.Uid, sys.Gid
		out[p] = st
	}
	return out
}

// restoreModes re-applies the modes recorded in snap so a later content read can
// succeed. A path the case removed on purpose is skipped.
func restoreModes(t *testing.T, snap map[string]fileState) {
	t.Helper()
	for p, st := range snap {
		if st.dir {
			continue
		}
		if err := os.Chmod(p, st.mode); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			t.Fatalf("restore mode %s: %v", p, err)
		}
	}
}

// diffMeta reports every path added or removed, and every kind, mode or ownership
// change, between two snapshots. It must be evaluated BEFORE any mode is restored,
// or a chmod by the code under test would be masked by the test's own repair.
func diffMeta(pre, post map[string]fileState) []string {
	var diffs []string
	for p, before := range pre {
		after, ok := post[p]
		if !ok {
			diffs = append(diffs, "removed: "+p)
			continue
		}
		switch {
		case before.dir != after.dir:
			diffs = append(diffs, "kind changed: "+p)
		case before.mode != after.mode:
			diffs = append(diffs, fmt.Sprintf("mode changed: %s (%v -> %v)", p, before.mode, after.mode))
		case before.uid != after.uid || before.gid != after.gid:
			diffs = append(diffs, fmt.Sprintf("owner changed: %s (%d:%d -> %d:%d)", p, before.uid, before.gid, after.uid, after.gid))
		}
	}
	for p := range post {
		if _, ok := pre[p]; !ok {
			diffs = append(diffs, "created: "+p)
		}
	}
	sort.Strings(diffs)
	return diffs
}

// diffData reports every content change for a file present in both snapshots.
func diffData(pre, post map[string]fileState) []string {
	var diffs []string
	for p, before := range pre {
		after, ok := post[p]
		if !ok || before.dir || after.dir {
			continue
		}
		if !bytes.Equal(before.data, after.data) {
			diffs = append(diffs, "modified: "+p)
		}
	}
	sort.Strings(diffs)
	return diffs
}

// remintCAHierarchy destroys the PKI dir and mints a FRESH one — exactly the
// cluster-orphaning mistake `k3sm certificate rotate` exists to detect. It is what a
// boot that fell through to EnsureHierarchy against an emptied PKI dir would do.
func remintCAHierarchy(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(certs.PKIDir(dir)); err != nil {
		t.Fatalf("remove PKI dir: %v", err)
	}
	if _, err := certs.EnsureHierarchy(dir); err != nil {
		t.Fatalf("re-mint CA hierarchy: %v", err)
	}
}

// pinOf computes the CA pin (lowercase-hex SHA-256 of the certificate DER) from a
// certificate PEM file, INDEPENDENTLY of the code under test — a pin invariance
// assertion that re-used the implementation would prove nothing.
func pinOf(t *testing.T, certPath string) string {
	t.Helper()
	b, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read %s: %v", certPath, err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("%s: no CERTIFICATE PEM block", certPath)
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", certPath, err)
	}
	sum := sha256.Sum256(crt.Raw)
	return hex.EncodeToString(sum[:])
}

// writeSentinel writes a recognizable file the rotation must never touch.
func writeSentinel(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("sentinel:"+filepath.Base(path)+"\n"), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestCertificateRotatePreservesCAPin is the B97 gate. `k3sm certificate rotate`
// re-issues LEAF credentials over the EXISTING CA hierarchy; it must NEVER re-mint
// a CA — a re-minted cluster CA would orphan every node's K10<sha256(CA)> join-token
// pin. The gate pins that invariant (both CA pins AND all four CA PEMs byte-identical),
// the never-open-the-CA-key rule, the fail-closed behaviour on an absent/half-present
// hierarchy, the dry-run default, the single kickstart of the server LaunchDaemon, the
// scope fence, health-verification failure propagation, and idempotency.
func TestCertificateRotatePreservesCAPin(t *testing.T) {
	t.Parallel()

	// errBoom is a distinguishable injected failure.
	errBoom := errors.New("injected failure")

	cases := []struct {
		name string
		// noHierarchy skips the certs.EnsureHierarchy seeding (an empty work dir).
		noHierarchy bool
		// seed writes extra fixture files BEFORE the pre-snapshot.
		seed func(t *testing.T, dir string)
		// lock runs AFTER the pre-snapshot (mode changes the snapshot must record first).
		lock func(t *testing.T, dir string)
		// skip, when non-nil, reports why the case cannot run in this environment.
		skip func() string

		restart      bool
		restarterErr error
		pidErr       error
		frozenPID    bool
		noHealth     bool
		healthErr    error
		runs         int // default 1

		wantErrIs     error
		wantErrSubstr string
		wantLabels    []string
		wantHealth    bool // whether the health probe must have been consulted
		wantOutHas    []string
	}{
		{
			// 1 + 5: the default is REPORT ONLY — the pins are printed, nothing restarts.
			name:       "dry-run reports both pins and never restarts",
			wantLabels: nil,
			wantOutHas: []string{
				"cluster CA", "signing CA",
				executor.SchedulerKubeconfigPath(""),
				executor.ControllerManagerKubeconfigPath(""),
				"BLAST RADIUS", "does not revoke",
			},
		},
		{
			// 6: --restart kickstarts EXACTLY the server LaunchDaemon, exactly once.
			name:       "restart kickstarts the server daemon exactly once",
			restart:    true,
			wantLabels: []string{install.ServerLabel},
			wantHealth: true,
		},
		{
			// 2: pin verification reads ONLY the CA certificates (0644); the CA private
			// keys are Stat'ed, never opened. chmod 0000 both keys and rotation still works.
			name: "never opens the CA private keys",
			skip: func() string {
				if os.Geteuid() == 0 {
					return "root bypasses file mode bits — the 0000 keys would be readable"
				}
				return ""
			},
			lock: func(t *testing.T, dir string) {
				for _, p := range []string{certs.ClusterCAKeyPath(dir), certs.SigningCAKeyPath(dir)} {
					if err := os.Chmod(p, 0o000); err != nil {
						t.Fatalf("chmod 0000 %s: %v", p, err)
					}
				}
			},
		},
		{
			// 3: an absent hierarchy is a hard, typed failure — never a silent success
			// (certs.EnsureHierarchy would MINT a stray CA here; rotation must not).
			name:          "absent hierarchy fails closed",
			noHierarchy:   true,
			restart:       true,
			wantErrIs:     certs.ErrNoHierarchy,
			wantErrSubstr: "sudo",
			wantLabels:    nil,
		},
		{
			// 4: half-present (cert without key) is a distinct, typed failure.
			name: "half-present hierarchy fails closed",
			lock: func(t *testing.T, dir string) {
				if err := os.Remove(certs.SigningCAKeyPath(dir)); err != nil {
					t.Fatalf("remove signing CA key: %v", err)
				}
			},
			restart:    true,
			wantErrIs:  certs.ErrIncompleteHierarchy,
			wantLabels: nil,
		},
		{
			// 7: the scope fence — rotation never touches the admin kubeconfig, the
			// static token file, the service-account keypair, or the apiserver's own
			// self-signed cert dir (also the KCM --root-ca-file and every pod's
			// projected kube-root-ca.crt).
			name: "scope fence leaves out-of-scope material byte-identical",
			seed: func(t *testing.T, dir string) {
				writeSentinel(t, executor.KubeconfigPath(dir), 0o600)
				writeSentinel(t, executor.TokenFilePath(dir), 0o600)
				writeSentinel(t, executor.ServiceAccountKeyPath(dir), 0o600)
				writeSentinel(t, executor.ServiceAccountPubPath(dir), 0o644)
				writeSentinel(t, filepath.Join(executor.APIServerCertDir(dir), "apiserver.crt"), 0o644)
				writeSentinel(t, filepath.Join(dir, "server-token"), 0o600)
			},
			restart:    true,
			wantLabels: []string{install.ServerLabel},
			wantHealth: true,
		},
		{
			// 8: a health-verification failure after the restart propagates (non-zero
			// exit) and names where to look.
			name:          "health verification failure propagates",
			restart:       true,
			healthErr:     errBoom,
			wantErrIs:     errBoom,
			wantErrSubstr: "server.log",
			wantLabels:    []string{install.ServerLabel},
			wantHealth:    true,
		},
		{
			// 7 (R7): an unloaded/not-installed daemon errors — never a silent success.
			name:          "kickstart failure propagates",
			restart:       true,
			restarterErr:  errBoom,
			wantErrIs:     errBoom,
			wantErrSubstr: install.ServerLabel,
			wantLabels:    []string{install.ServerLabel},
		},
		{
			// Fail closed: a restart with no way to verify health is refused BEFORE the
			// blast radius is incurred.
			name:       "restart without a health probe is refused",
			restart:    true,
			noHealth:   true,
			wantErrIs:  executor.ErrNoHealthProbe,
			wantLabels: nil,
		},
		{
			// The pid read happens BEFORE the kickstart, so an unloaded daemon is
			// refused without incurring the blast radius — and never reported as
			// restarted.
			name:          "unloaded daemon is refused before the restart",
			restart:       true,
			pidErr:        errBoom,
			wantErrIs:     errBoom,
			wantErrSubstr: "installed and loaded",
			wantLabels:    nil,
		},
		{
			// THE false-success case. `launchctl kickstart -k` returns when the restart
			// is REQUESTED; the outgoing control plane keeps its listeners while it
			// drains its components serially. A probe that accepted that answer would
			// report success for a daemon that never came back (the invisible KeepAlive
			// crash loop). Here launchd's pid never changes, so no health answer is ever
			// accepted (wantHealth false) and the rotation fails.
			name:          "old instance still on the port is not accepted as the restart",
			restart:       true,
			frozenPID:     true,
			wantErrIs:     executor.ErrRestartUnconfirmed,
			wantErrSubstr: install.ServerLogPath(),
			wantLabels:    []string{install.ServerLabel},
			wantHealth:    false,
		},
		{
			// 9: two consecutive runs are a safe repeat — identical pins, identical report.
			name:       "repeat run is idempotent",
			restart:    true,
			runs:       2,
			wantLabels: []string{install.ServerLabel, install.ServerLabel},
			wantHealth: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.skip != nil {
				if why := tc.skip(); why != "" {
					t.Skip(why)
				}
			}
			dir := t.TempDir()
			if !tc.noHierarchy {
				if _, err := certs.EnsureHierarchy(dir); err != nil {
					t.Fatalf("seed CA hierarchy: %v", err)
				}
			}
			if tc.seed != nil {
				tc.seed(t, dir)
			}
			pre := walkTree(t, dir, true)
			baseline := pre
			if tc.lock != nil {
				// The lock step is the TEST's own mutation (a chmod, or the removal
				// that seeds a half-present hierarchy); re-baseline so the diffs below
				// measure only what ROTATION did.
				tc.lock(t, dir)
				baseline = rebaseline(t, pre)
			}

			// Independent pin computation (never via the code under test).
			var preClusterPin, preSigningPin string
			if !tc.noHierarchy {
				preClusterPin = pinOf(t, certs.ClusterCACertPath(dir))
				preSigningPin = pinOf(t, certs.SigningCACertPath(dir))
			}

			restarter := &fakeRestarter{
				err:       tc.restarterErr,
				pid:       4242,
				pidErr:    tc.pidErr,
				frozenPID: tc.frozenPID,
			}
			var healthCalls int
			health := func(context.Context) error {
				healthCalls++
				return tc.healthErr
			}
			if tc.noHealth {
				health = nil
			}

			runs := tc.runs
			if runs == 0 {
				runs = 1
			}
			outputs := make([]string, 0, runs)
			var lastErr error
			for i := 0; i < runs; i++ {
				var buf bytes.Buffer
				lastErr = certificateRotate(context.Background(), &buf, executor.RotateOptions{
					WorkDir: dir,
					Restart: tc.restart,
					// DaemonLabel deliberately left empty: the CLI layer must bind it to
					// install.ServerLabel, so the assertion below is not circular.
					Restarter:     restarter,
					Health:        health,
					HealthTimeout: 30 * time.Millisecond,
					HealthPoll:    5 * time.Millisecond,
				})
				outputs = append(outputs, buf.String())
				if lastErr != nil {
					break
				}
			}

			// --- error expectations -------------------------------------------------
			switch {
			case tc.wantErrIs != nil && lastErr == nil:
				t.Fatalf("certificateRotate: want error %v, got nil", tc.wantErrIs)
			case tc.wantErrIs != nil && !errors.Is(lastErr, tc.wantErrIs):
				t.Fatalf("certificateRotate error = %v, want errors.Is %v", lastErr, tc.wantErrIs)
			case tc.wantErrIs == nil && lastErr != nil:
				t.Fatalf("certificateRotate: unexpected error: %v", lastErr)
			}
			if tc.wantErrSubstr != "" && !strings.Contains(fmt.Sprint(lastErr), tc.wantErrSubstr) {
				t.Errorf("error %q does not mention %q", lastErr, tc.wantErrSubstr)
			}

			// --- restart expectations -----------------------------------------------
			if len(restarter.labels) != len(tc.wantLabels) {
				t.Fatalf("kickstart labels = %v, want %v", restarter.labels, tc.wantLabels)
			}
			for i, want := range tc.wantLabels {
				if restarter.labels[i] != want {
					t.Errorf("kickstart[%d] = %q, want %q", i, restarter.labels[i], want)
				}
			}
			if got := healthCalls > 0; got != tc.wantHealth {
				t.Errorf("health probe consulted = %v, want %v", got, tc.wantHealth)
			}
			// The pre-restart pid read must come FIRST: without it there is no
			// baseline to tell the new instance from the old one still draining.
			if len(restarter.labels) > 0 && (len(restarter.calls) == 0 || restarter.calls[0] != "pid") {
				t.Errorf("seam calls = %v, want the pid read before the kickstart", restarter.calls)
			}

			// --- the load-bearing invariant: the CA hierarchy is untouched ----------
			// Metadata FIRST, while any mode the case set is still in force: a chmod or
			// chown by the rotation must not be able to hide behind the test's own
			// mode repair below.
			if diffs := diffMeta(baseline, walkTree(t, dir, false)); len(diffs) > 0 {
				t.Errorf("rotation changed work-dir metadata (it must write NOTHING there, and never re-permission it): %v", diffs)
			}
			restoreModes(t, pre)
			if diffs := diffData(baseline, walkTree(t, dir, true)); len(diffs) > 0 {
				t.Errorf("rotation modified the work dir (it must write NOTHING there): %v", diffs)
			}
			if !tc.noHierarchy {
				if got := pinOf(t, certs.ClusterCACertPath(dir)); got != preClusterPin {
					t.Errorf("cluster CA pin changed: %s -> %s", preClusterPin, got)
				}
				if got := pinOf(t, certs.SigningCACertPath(dir)); got != preSigningPin {
					t.Errorf("signing CA pin changed: %s -> %s", preSigningPin, got)
				}
			}

			// --- report expectations -------------------------------------------------
			// A failed rotation must never claim success, whatever it got through.
			if lastErr != nil {
				for _, out := range outputs {
					if strings.Contains(out, rotateSuccessSentence) {
						t.Errorf("a failed rotation reported success:\n%s", out)
					}
				}
			}
			if lastErr == nil {
				out := outputs[len(outputs)-1]
				if !strings.Contains(out, preClusterPin) {
					t.Errorf("report does not print the cluster CA pin %s:\n%s", preClusterPin, out)
				}
				if !strings.Contains(out, preSigningPin) {
					t.Errorf("report does not print the signing CA pin %s:\n%s", preSigningPin, out)
				}
				for _, want := range tc.wantOutHas {
					if !strings.Contains(out, want) {
						t.Errorf("report does not mention %q:\n%s", want, out)
					}
				}
				for i := 1; i < len(outputs); i++ {
					// Modulo the launchd pids: a second rotation restarts the daemon
					// again, so reporting a DIFFERENT instance is the correct
					// behaviour, not a loss of idempotency.
					if got, want := reportPIDs.ReplaceAllString(outputs[i], "(pid)"), reportPIDs.ReplaceAllString(outputs[0], "(pid)"); got != want {
						t.Errorf("run %d report differs from run 0 (rotation is not idempotent):\n%s\n---\n%s", i, outputs[0], outputs[i])
					}
				}
			}
		})
	}

	// THE invariant this gate is named for, driven to its failure mode. The cases
	// above prove rotation does not re-mint a CA ITSELF; these prove the command
	// DETECTS a re-mint by whatever else did it — which is the whole point of
	// recording the pins on both sides of a restart. The two cases cover both
	// windows: a hierarchy replaced while the daemon is being kickstarted, and one
	// replaced by the booting daemon itself (a boot that fell through to
	// EnsureHierarchy's mint arm against an emptied PKI dir).
	//
	// They live outside the table because they deliberately MUTATE the work dir,
	// which the table's write-nothing assertions would flag.
	for _, tc := range []struct {
		name       string
		duringBoot bool
		wantHealth bool
	}{
		{name: "CA re-minted during the kickstart is caught"},
		{name: "CA re-minted by the booting daemon is caught", duringBoot: true, wantHealth: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if _, err := certs.EnsureHierarchy(dir); err != nil {
				t.Fatalf("seed CA hierarchy: %v", err)
			}
			prePin := pinOf(t, certs.ClusterCACertPath(dir))

			restarter := &fakeRestarter{pid: 4242}
			var healthCalls int
			health := func(context.Context) error {
				healthCalls++
				if tc.duringBoot {
					remintCAHierarchy(t, dir)
				}
				return nil
			}
			if !tc.duringBoot {
				restarter.onKickstart = func() { remintCAHierarchy(t, dir) }
			}

			var buf bytes.Buffer
			err := certificateRotate(context.Background(), &buf, executor.RotateOptions{
				WorkDir:       dir,
				Restart:       true,
				Restarter:     restarter,
				Health:        health,
				HealthTimeout: 30 * time.Millisecond,
				HealthPoll:    5 * time.Millisecond,
			})
			if !errors.Is(err, executor.ErrCAPinChanged) {
				t.Fatalf("certificateRotate error = %v, want errors.Is executor.ErrCAPinChanged", err)
			}
			// The fake must really have replaced the hierarchy — otherwise the
			// assertion above would pass for a reason that is not the one under test.
			if got := pinOf(t, certs.ClusterCACertPath(dir)); got == prePin {
				t.Fatalf("the case did not re-mint the cluster CA (pin still %s); it proves nothing", prePin)
			}
			if strings.Contains(buf.String(), rotateSuccessSentence) {
				t.Errorf("a rotation that orphaned every node's join-token pin reported success:\n%s", buf.String())
			}
			for _, want := range []string{"orphaned", "restored from backup"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not mention %q", err, want)
				}
			}
			if got := healthCalls > 0; got != tc.wantHealth {
				t.Errorf("health probe consulted = %v, want %v", got, tc.wantHealth)
			}
		})
	}

	// Re-minting the CA is the one thing rotation must never do: `rotate-ca` is an
	// explicit, informative refusal, not an unknown-subcommand error.
	t.Run("rotate-ca is refused with the pin-orphaning reason", func(t *testing.T) {
		t.Parallel()
		err := runCertificate([]string{"rotate-ca"})
		if err == nil {
			t.Fatal("k3sm certificate rotate-ca: want a refusal error, got nil")
		}
		for _, want := range []string{"K10", "re-join"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not mention %q", err, want)
			}
		}
	})
}

// TestCertificateSubcommandDispatch pins the `k3sm certificate` dispatch surface:
// no args and an unknown verb both fail with usage, touching no state.
func TestCertificateSubcommandDispatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"no subcommand", nil},
		{"unknown subcommand", []string{"renew"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := runCertificate(tc.args); err == nil {
				t.Fatalf("runCertificate(%v): want error, got nil", tc.args)
			}
		})
	}
}

// servingChain mints a CA and a serving keypair from it. bundleIssuer selects the
// posture: false presents the LEAF ONLY (the multi-node apiserver, whose serving cert
// comes from certs.CA.IssueServing — a leaf-only PEM, which is why the peer carries no
// CA to pin and a RootCAs pool is the right anchor); true presents leaf + issuer,
// mirroring what kube-apiserver writes into --cert-dir/apiserver.crt on a single-node
// server. The returned pool is the anchor that posture's on-disk file produces.
func servingChain(t *testing.T, cn string, bundleIssuer bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	ca, err := certs.NewCA(cn + "-ca")
	if err != nil {
		t.Fatalf("mint CA: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueServing(cn, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatalf("issue serving cert: %v", err)
	}
	anchorPEM := ca.CertPEM
	if bundleIssuer {
		certPEM = append(certPEM, ca.CertPEM...)
		anchorPEM = certPEM
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build serving keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(anchorPEM) {
		t.Fatal("anchor PEM holds no certificate")
	}
	return pair, pool
}

// serveTLS starts a hermetic HTTPS server answering every request with status. It
// returns the dial address and a stop func (a case that needs a DEAD apiserver calls
// it to free the port). Loopback only, no privilege.
func serveTLS(t *testing.T, status int, chain tls.Certificate) (addr string, stop func()) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{chain}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), srv.Close
}

// TestProbeAPIServerServing pins the post-restart health predicate. It is the one
// security-relevant function in this command: with --anonymous-auth=false the status
// code alone degenerates to "a TLS handshake succeeded and the answer was 401", which
// any local process squatting the (non-privileged) apiserver port during the restart
// window satisfies. The peer's certificate must therefore chain to an anchor the CLI
// already holds; a peer that does not is NOT the control plane coming back.
func TestProbeAPIServerServing(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// setup returns the address to probe and the anchor to verify it against.
		setup     func(t *testing.T) (string, *x509.CertPool)
		wantErr   bool
		errSubstr string
	}{
		{
			name: "healthz 200 is serving",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", false)
				addr, _ := serveTLS(t, http.StatusOK, chain)
				return addr, pool
			},
		},
		{
			name: "401 is serving (anonymous-auth is off, so this is the normal answer)",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", false)
				addr, _ := serveTLS(t, http.StatusUnauthorized, chain)
				return addr, pool
			},
		},
		{
			name: "403 is serving",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", false)
				addr, _ := serveTLS(t, http.StatusForbidden, chain)
				return addr, pool
			},
		},
		{
			name: "single-node self-signed chain verifies against its own cert file",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", true)
				addr, _ := serveTLS(t, http.StatusUnauthorized, chain)
				return addr, pool
			},
		},
		{
			name: "500 is not serving",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", false)
				addr, _ := serveTLS(t, http.StatusInternalServerError, chain)
				return addr, pool
			},
			wantErr:   true,
			errSubstr: "HTTP 500",
		},
		{
			name: "a squatter on the port is rejected: its cert chains to a different anchor",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				squatter, _ := servingChain(t, "squatter", false)
				_, realAnchor := servingChain(t, "kube-apiserver", false)
				// The squatter answers 401 exactly like the real apiserver does: the
				// status code separates nothing, only the anchor does.
				addr, _ := serveTLS(t, http.StatusUnauthorized, squatter)
				return addr, realAnchor
			},
			wantErr:   true,
			errSubstr: "is not the k3sm apiserver",
		},
		{
			name: "no anchor is refused rather than trusted",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, _ := servingChain(t, "kube-apiserver", false)
				addr, _ := serveTLS(t, http.StatusOK, chain)
				return addr, nil
			},
			wantErr:   true,
			errSubstr: "no apiserver trust anchor",
		},
		{
			name: "nothing listening is not serving",
			setup: func(t *testing.T) (string, *x509.CertPool) {
				chain, pool := servingChain(t, "kube-apiserver", false)
				addr, stop := serveTLS(t, http.StatusOK, chain)
				// Free the port: the apiserver is DOWN, which is the state the
				// post-restart wait loop keeps retrying through.
				stop()
				return addr, pool
			},
			wantErr:   true,
			errSubstr: "not reachable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			addr, anchor := tc.setup(t)
			err := probeAPIServerServing(context.Background(), addr, anchor, "the-anchor")
			switch {
			case tc.wantErr && err == nil:
				t.Fatalf("probeAPIServerServing(%s): want an error, got nil", addr)
			case !tc.wantErr && err != nil:
				t.Fatalf("probeAPIServerServing(%s): unexpected error: %v", addr, err)
			}
			if tc.errSubstr != "" && !strings.Contains(fmt.Sprint(err), tc.errSubstr) {
				t.Errorf("error %q does not mention %q", err, tc.errSubstr)
			}
		})
	}
}

// TestAPIServerTrustAnchor pins which certificate the probe anchors on in each server
// posture, and that an absent anchor is a REFUSAL — never a silent fallback to an
// unverified probe.
func TestAPIServerTrustAnchor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		seed      func(t *testing.T, dir string)
		wantPath  func(dir string) string
		wantErr   bool
		errSubstr string
	}{
		{
			name: "multi-node server anchors on the cluster CA",
			seed: func(t *testing.T, dir string) {
				seedHierarchy(t, dir)
				// A cluster-CA-signed serving cert in the PKI dir IS the mesh posture.
				writeCertFile(t, certs.APIServerServingCertPath(dir), "kube-apiserver")
			},
			wantPath: certs.ClusterCACertPath,
		},
		{
			name: "single-node server anchors on the apiserver's own self-signed cert",
			seed: func(t *testing.T, dir string) {
				seedHierarchy(t, dir)
				writeCertFile(t, apiServerSelfSignedCertPath(dir), "kube-apiserver-self-signed")
			},
			wantPath: apiServerSelfSignedCertPath,
		},
		{
			name:      "no anchor at all fails closed",
			seed:      seedHierarchy,
			wantErr:   true,
			errSubstr: "refusing to restart without it",
		},
		{
			name: "an anchor file holding no certificate fails closed",
			seed: func(t *testing.T, dir string) {
				seedHierarchy(t, dir)
				if err := os.MkdirAll(executor.APIServerCertDir(dir), 0o755); err != nil {
					t.Fatalf("mkdir cert dir: %v", err)
				}
				if err := os.WriteFile(apiServerSelfSignedCertPath(dir), []byte("not a PEM\n"), 0o644); err != nil {
					t.Fatalf("write anchor: %v", err)
				}
			},
			wantErr:   true,
			errSubstr: "holds no certificate",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tc.seed(t, dir)
			pool, path, err := apiServerTrustAnchor(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("apiServerTrustAnchor(%s): want an error, got anchor %s", dir, path)
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not mention %q", err, tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("apiServerTrustAnchor: %v", err)
			}
			if pool == nil {
				t.Fatal("apiServerTrustAnchor returned a nil pool with no error")
			}
			if want := tc.wantPath(dir); path != want {
				t.Errorf("anchor = %s, want %s", path, want)
			}
		})
	}
}

// seedHierarchy mints the two-CA hierarchy in dir.
func seedHierarchy(t *testing.T, dir string) {
	t.Helper()
	if _, err := certs.EnsureHierarchy(dir); err != nil {
		t.Fatalf("seed CA hierarchy: %v", err)
	}
}

// writeCertFile writes a real, parseable self-signed certificate at path.
func writeCertFile(t *testing.T, path, cn string) {
	t.Helper()
	ca, err := certs.NewCA(cn)
	if err != nil {
		t.Fatalf("mint %s: %v", cn, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	if err := os.WriteFile(path, ca.CertPEM, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
