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
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// fakeRestarter is the injected launchd seam: it records every label a rotation
// kickstarts (and optionally fails), so the gate proves the dry-run default never
// restarts and that `--restart` kickstarts exactly the server LaunchDaemon. No
// real launchctl, no privilege, no live cluster (GO-STANDARDS: fake at seams).
type fakeRestarter struct {
	labels []string
	err    error
}

func (f *fakeRestarter) LaunchctlKickstart(label string) error {
	f.labels = append(f.labels, label)
	return f.err
}

// fileState is one entry of a work-dir tree snapshot: its mode, whether it is a
// directory, and (for files) its exact bytes.
type fileState struct {
	mode fs.FileMode
	dir  bool
	data []byte
}

// snapshotTree records every path under root with its mode and contents. The gate
// compares a pre/post snapshot to prove the rotation writes NOTHING under the work
// dir — a root-written file there would EACCES the unprivileged _k3sm daemon on its
// next boot (an invisible launchd KeepAlive crash loop).
func snapshotTree(t *testing.T, root string) map[string]fileState {
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
		if d.IsDir() {
			out[p] = fileState{mode: info.Mode().Perm(), dir: true}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = fileState{mode: info.Mode().Perm(), data: b}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return out
}

// restoreModes re-applies the modes recorded in snap. A case that chmod 0000's the
// CA keys (proving rotation never opens them) would otherwise block the TEST's own
// post-run snapshot read.
func restoreModes(t *testing.T, snap map[string]fileState) {
	t.Helper()
	for p, st := range snap {
		if st.dir {
			continue
		}
		if err := os.Chmod(p, st.mode); err != nil {
			t.Fatalf("restore mode %s: %v", p, err)
		}
	}
}

// diffTree reports every path added, removed, or modified between two snapshots.
func diffTree(pre, post map[string]fileState) []string {
	var diffs []string
	for p, before := range pre {
		after, ok := post[p]
		if !ok {
			diffs = append(diffs, "removed: "+p)
			continue
		}
		if before.dir != after.dir {
			diffs = append(diffs, "kind changed: "+p)
			continue
		}
		if !before.dir && !bytes.Equal(before.data, after.data) {
			diffs = append(diffs, "modified: "+p)
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
			pre := snapshotTree(t, dir)
			if tc.lock != nil {
				tc.lock(t, dir)
			}

			// Independent pin computation (never via the code under test).
			var preClusterPin, preSigningPin string
			if !tc.noHierarchy {
				preClusterPin = pinOf(t, certs.ClusterCACertPath(dir))
				preSigningPin = pinOf(t, certs.SigningCACertPath(dir))
			}

			restarter := &fakeRestarter{err: tc.restarterErr}
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

			// --- the load-bearing invariant: the CA hierarchy is untouched ----------
			restoreModes(t, pre)
			post := snapshotTree(t, dir)
			if diffs := diffTree(pre, post); len(diffs) > 0 {
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
					if outputs[i] != outputs[0] {
						t.Errorf("run %d report differs from run 0 (rotation is not idempotent):\n%s\n---\n%s", i, outputs[0], outputs[i])
					}
				}
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
