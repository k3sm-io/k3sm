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
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/install"
	"k3sm.io/k3sm/pkg/nodecred"
	"k3sm.io/k3sm/pkg/status"
)

// TestStatusReportsTheAgentDaemon is the cmd half of the B310 gate: the log view
// tails the daemons this Mac actually has, and `agent` is a job an operator can
// name. The report half — the rows, the credential and the screens — is
// pkg/status's own TestStatusReportsTheAgentDaemon.
func TestStatusReportsTheAgentDaemon(t *testing.T) {
	t.Parallel()

	t.Run("the default log list follows the installed role", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			role install.Role
			want []string
		}{
			{install.RoleServer, []string{"netd", "server"}},
			{install.RoleAgent, []string{"netd", "agent"}},
		}
		for _, c := range cases {
			if got := defaultLogTargets(c.role); !reflect.DeepEqual(got, c.want) {
				t.Errorf("defaultLogTargets(%q) = %v, want %v", c.role, got, c.want)
			}
		}
	})

	t.Run("a worker tails netd and the agent, and never the server", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		r.logPaths = map[string]string{
			"netd":   "/var/log/k3sm/netd.log",
			"server": "/var/log/k3sm/server.log",
			"agent":  "/var/log/k3sm/agent.log",
		}
		r.logTargets = defaultLogTargets(install.RoleAgent)
		var read []string
		r.readLog = func(path string, _ int) ([]string, error) {
			read = append(read, path)
			return []string{"line from " + filepath.Base(path)}, nil
		}

		if code := r.run(context.Background(), statusOptions{format: "text", view: "logs", lines: 10}); code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
		}
		want := []string{"/var/log/k3sm/netd.log", "/var/log/k3sm/agent.log"}
		if !reflect.DeepEqual(read, want) {
			t.Errorf("tailed %v, want %v", read, want)
		}
		if strings.Contains(out.String()+errOut.String(), "server.log") {
			t.Errorf("a worker's log view mentioned the control-plane log:\n%s\n%s", out.String(), errOut.String())
		}
	})

	t.Run("a missing log on the default list is not an error", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		r.logTargets = defaultLogTargets(install.RoleAgent)
		r.logPaths = map[string]string{"netd": "/var/log/k3sm/netd.log", "agent": "/var/log/k3sm/agent.log"}
		r.readLog = func(path string, _ int) ([]string, error) {
			if strings.HasSuffix(path, "agent.log") {
				return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
			}
			return []string{"netd is up"}, nil
		}

		if code := r.run(context.Background(), statusOptions{format: "text", view: "logs", lines: 10}); code != 0 {
			t.Fatalf("exit = %d, want 0: a daemon that has not written a log yet is not a failure (stderr: %s)", code, errOut.String())
		}
		if strings.Contains(errOut.String(), "agent.log") {
			t.Errorf("the default list complained about a log that is simply not there yet:\n%s", errOut.String())
		}
	})

	t.Run("a NAMED log that is missing is still an error", func(t *testing.T) {
		t.Parallel()
		var out, errOut bytes.Buffer
		r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
		r.logPaths = map[string]string{"agent": "/var/log/k3sm/agent.log"}
		r.readLog = func(path string, _ int) ([]string, error) {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
		}

		if code := r.run(context.Background(), statusOptions{format: "text", view: "logs", target: "agent", lines: 10}); code == 0 {
			t.Fatalf("exit = 0 for a log the caller asked for by name and that is not there")
		}
		if !strings.Contains(errOut.String(), "agent.log") {
			t.Errorf("the error does not name the file:\n%s", errOut.String())
		}
	})

	t.Run("agent is an accepted log target", func(t *testing.T) {
		t.Parallel()
		got, err := parseStatusArgs([]string{"logs", "agent"}, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got.view != "logs" || got.target != "agent" {
			t.Fatalf("parsed %+v, want the agent log view", got)
		}
		names := make([]string, 0, len(statusLogTargets))
		for name := range statusLogTargets {
			names = append(names, name)
		}
		sort.Strings(names)
		if want := []string{"agent", "netd", "server"}; !reflect.DeepEqual(names, want) {
			t.Errorf("log targets = %v, want %v", names, want)
		}
	})
}

// TestAgentCredentialPathsMatchTheStore binds `k3sm status`'s verdict about a
// node credential to the AGENT's verdict about the same directory.
//
// They are one implementation now (pkg/nodecred), which is exactly what makes
// this test cheap to state and worth keeping: it walks every way a store can be
// incomplete or damaged and asserts the two answers are equal every time. The
// defect it forecloses is a report that says "valid" about a credential the
// daemon refuses to start with — a green row on a Mac that is not in the
// cluster, which sends an operator to the wrong machine.
func TestAgentCredentialPathsMatchTheStore(t *testing.T) {
	t.Parallel()

	// agree asserts the report and the agent reach the same verdict about dir,
	// and returns it.
	agree := func(t *testing.T, store nodeCredentialStore, now time.Time, want status.CredentialState) {
		t.Helper()
		got, _ := status.NodeCredentialState(osStatusFS{}, store.dir, now)
		if got != want {
			t.Errorf("the report says %q, want %q", got, want)
		}
		own, _, err := store.Status(now)
		if reported := reportWord(own); reported != got {
			t.Errorf("the report says %q and the agent says %s (err %v) — they must not disagree", got, own, err)
		}
	}

	t.Run("a store the agent just wrote reads as valid", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)

		state, notAfter := status.NodeCredentialState(osStatusFS{}, store.dir, time.Now())
		if state != status.CredentialValid {
			t.Fatalf("NodeCredentialState = %q, want %q", state, status.CredentialValid)
		}
		if notAfter.IsZero() {
			t.Error("no expiry read from the node client certificate")
		}
		agree(t, store, time.Now(), status.CredentialValid)
	})

	t.Run("removing ANY of the five artifacts makes it absent", func(t *testing.T) {
		t.Parallel()
		// Every file the store consists of, by construction rather than by
		// sampling: a report that checked only three of them would call a
		// credential valid while the agent found it incomplete.
		for _, name := range []string{
			nodecred.KubeconfigFile, nodecred.ServingCertFile, nodecred.ServingKeyFile,
			nodecred.ClientCAFile, nodecred.NodeAssignmentFile,
		} {
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			store := savedStore(t, res)
			if err := os.Remove(filepath.Join(store.dir, name)); err != nil {
				t.Fatalf("remove %s: %v", name, err)
			}
			t.Run("without "+name, func(t *testing.T) {
				agree(t, store, time.Now(), status.CredentialAbsent)
			})
		}
	})

	t.Run("content that does not validate is corrupt, not valid", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name   string
			damage func(*testing.T, nodeCredentialStore)
		}{
			{
				// The file is there and is a certificate; it is simply not the
				// key's certificate. Only tls.X509KeyPair catches this, and a
				// report that merely stat'ed the pair would call it valid.
				name: "a serving pair whose halves do not match",
				damage: func(t *testing.T, store nodeCredentialStore) {
					other, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
					write(t, filepath.Join(store.dir, nodecred.ServingCertFile), other.KubeletServingCertPEM)
				},
			},
			{
				name: "a truncated serving key",
				damage: func(t *testing.T, store nodeCredentialStore) {
					path := filepath.Join(store.dir, nodecred.ServingKeyFile)
					blob, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("read %s: %v", path, err)
					}
					write(t, path, blob[:len(blob)/2])
				},
			},
			{
				name: "a client CA that is not a certificate",
				damage: func(t *testing.T, store nodeCredentialStore) {
					write(t, filepath.Join(store.dir, nodecred.ClientCAFile), []byte("-----BEGIN CERTIFICATE-----\nnope\n"))
				},
			},
			{
				// The mesh device and the pod IPAM are both built from the
				// assigned podCIDR, so an assignment without one is a
				// credential the agent cannot start from.
				name: "an assignment with no podCIDR",
				damage: func(t *testing.T, store nodeCredentialStore) {
					write(t, filepath.Join(store.dir, nodecred.NodeAssignmentFile), []byte(`{"meshIP":"100.64.1.2"}`))
				},
			},
			{
				name: "a kubeconfig that does not parse",
				damage: func(t *testing.T, store nodeCredentialStore) {
					write(t, filepath.Join(store.dir, nodecred.KubeconfigFile), []byte("not a kubeconfig"))
				},
			},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
				store := savedStore(t, res)
				c.damage(t, store)
				agree(t, store, time.Now(), status.CredentialCorrupt)
			})
		}
	})

	t.Run("a certificate for another address is a mismatch to both of them", func(t *testing.T) {
		t.Parallel()
		store := savedStore(t, credentialForAddresses(t, assignedAddress, certAddress))
		agree(t, store, time.Now(), status.CredentialAddressMismatch)
	})

	t.Run("the expiry margin is the agent's own", func(t *testing.T) {
		t.Parallel()
		if status.CredentialExpiryMargin != nodecred.ExpiryMargin {
			t.Fatalf("status.CredentialExpiryMargin = %s, the agent uses %s — a report and a start decision that disagree about expiry send an operator to the wrong remedy",
				status.CredentialExpiryMargin, nodecred.ExpiryMargin)
		}
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		// One hour inside the margin: both must call it expired at the same
		// moment, and one hour before that, neither may.
		inside := time.Now().Add(nodeCredClientTTL - nodecred.ExpiryMargin + time.Hour)
		agree(t, store, inside, status.CredentialExpired)
		agree(t, store, inside.Add(-2*time.Hour), status.CredentialValid)
	})

	t.Run("the reported directory is the one the installer verifies", func(t *testing.T) {
		t.Parallel()
		paths := statusPaths("/tmp/does-not-matter")
		want := filepath.Dir(install.AgentCredentialPath(install.DefaultDataRoot))
		if paths.AgentCredentialDir != want {
			t.Fatalf("AgentCredentialDir = %q, want %q", paths.AgentCredentialDir, want)
		}
		if paths.AgentLabel != install.AgentLabel || paths.AgentLog != install.AgentLogPath() {
			t.Fatalf("agent label/log = %q/%q, want %q/%q", paths.AgentLabel, paths.AgentLog, install.AgentLabel, install.AgentLogPath())
		}
	})
}

// reportWord is the agent's own credential state in the report's vocabulary, so
// the two verdicts can be compared as values rather than as prose.
func reportWord(s nodecred.State) status.CredentialState {
	switch s {
	case nodecred.Valid:
		return status.CredentialValid
	case nodecred.Absent:
		return status.CredentialAbsent
	case nodecred.Expired:
		return status.CredentialExpired
	case nodecred.AddressMismatch:
		return status.CredentialAddressMismatch
	default:
		return status.CredentialCorrupt
	}
}

// write replaces a file in a credential store, keeping its mode.
func write(t *testing.T, path string, blob []byte) {
	t.Helper()
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
