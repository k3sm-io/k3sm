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

// TestAgentCredentialPathsMatchTheStore binds the report's read of the node
// credential to the store that WRITES it.
//
// The two are deliberately not one package — pkg/status is a reporting leaf and
// the store lives beside the join that fills it — so the file names and the
// expiry margin exist twice. This test is what makes that safe: if either copy
// drifts, `k3sm status` is describing a credential the daemon does not use, and
// the row would be green on a Mac that cannot start.
func TestAgentCredentialPathsMatchTheStore(t *testing.T) {
	t.Parallel()

	t.Run("a store the agent just wrote reads as valid", func(t *testing.T) {
		t.Parallel()
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)

		state, notAfter := status.NodeCredentialState(osStatusFS{}, store.dir, time.Now())
		if state != status.CredentialValid {
			t.Fatalf("NodeCredentialState = %q, want %q — the report is reading different files than the store writes",
				state, status.CredentialValid)
		}
		if notAfter.IsZero() {
			t.Error("no expiry read from the node client certificate")
		}
		// The agent's own verdict on the same directory, so the two answers are
		// compared rather than merely both being plausible.
		if own, _, err := store.Status(time.Now()); err != nil || own != credentialValid {
			t.Fatalf("the store's own Status = %s (err %v), want valid", own, err)
		}
	})

	t.Run("removing any artifact the report reads makes it absent", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{nodeKubeconfigFile, kubeletServingCertFile, kubeletServingKeyFile} {
			res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
			store := savedStore(t, res)
			if err := os.Remove(filepath.Join(store.dir, name)); err != nil {
				t.Fatalf("remove %s: %v", name, err)
			}
			if state, _ := status.NodeCredentialState(osStatusFS{}, store.dir, time.Now()); state != status.CredentialAbsent {
				t.Errorf("without %s the report says %q, want %q", name, state, status.CredentialAbsent)
			}
		}
	})

	t.Run("the expiry margin is the agent's own", func(t *testing.T) {
		t.Parallel()
		if status.CredentialExpiryMargin != credentialExpiryMargin {
			t.Fatalf("status.CredentialExpiryMargin = %s, the agent uses %s — a report and a start decision that disagree about expiry send an operator to the wrong remedy",
				status.CredentialExpiryMargin, credentialExpiryMargin)
		}
		res, _, _ := nodeCredFixture(t, nodeCredClientTTL, nodeCredClientTTL)
		store := savedStore(t, res)
		// One hour inside the margin: both the report and the agent must call
		// it expired at the same moment.
		inside := time.Now().Add(nodeCredClientTTL - credentialExpiryMargin + time.Hour)
		if state, _ := status.NodeCredentialState(osStatusFS{}, store.dir, inside); state != status.CredentialExpired {
			t.Errorf("inside the margin the report says %q, want %q", state, status.CredentialExpired)
		}
		if own, _, err := store.Status(inside); err != nil || own != credentialExpired {
			t.Errorf("inside the margin the agent says %s (err %v), want expired", own, err)
		}
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
