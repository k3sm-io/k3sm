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

package status

import (
	"reflect"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// row is a terse Row constructor for the verdict tables.
func row(name string, state RowState, sev Severity, detail, remedy string) Row {
	return Row{Name: name, State: state, Severity: sev, Detail: detail, Remedy: remedy}
}

// serverRow builds a server row carrying its launchd label, which is what the
// stopped summary names.
func serverRow(state RowState, sev Severity, detail, remedy string) Row {
	r := row(RowServer, state, sev, detail, remedy)
	r.Wide = map[string]string{"label": "io.k3sm.server"}
	return r
}

// agentRowFor builds a worker's node-daemon row carrying its launchd label,
// which is what the stopped summary names.
func agentRowFor(state RowState, sev Severity, detail, remedy string) Row {
	r := row(RowAgent, state, sev, detail, remedy)
	r.Wide = map[string]string{"label": "io.k3sm.agent", "credential": string(CredentialValid)}
	return r
}

// healthyAgentRows is a joined worker with nothing wrong: its daemon is up with
// a valid credential, and the two control-plane rows say what they always say
// on a Mac that runs no control plane.
func healthyAgentRows() []Row {
	return []Row{
		row(RowInstall, StateOK, SeverityOK, "installed", ""),
		row(RowNetd, StateRunning, SeverityOK, "pid 1292", ""),
		agentRowFor(StateRunning, SeverityOK, "pid 903 · joined, node credential valid until 2027-09-05", ""),
		row(RowAPIServer, StateUnknown, SeverityUnknown, "no kubeconfig: no k3sm context in ~/.kube/config", ""),
		row(RowNode, StateUnknown, SeverityUnknown, "apiserver unreachable", ""),
		row(RowWorkloads, StateUnknown, SeverityUnknown, "apiserver unreachable", ""),
		row(RowDataRoot, StateOK, SeverityOK, "/var/lib/k3sm (apfs volume k3sm, mounted)", ""),
		row(RowDatastore, StateSkip, SeveritySkip, "no state.db yet", ""),
		row(RowKubeconfig, StateMissing, SeverityWarn, "no k3sm context in ~/.kube/config", "k3sm kubeconfig --write"),
		row(RowRuntimed, StateHealthy, SeverityOK, "k3sm-runtimed healthy", ""),
	}
}

// healthyRows is the row set of a cluster with nothing wrong, reused as the base
// of the cases that perturb exactly one row.
func healthyRows() []Row {
	return []Row{
		row(RowInstall, StateOK, SeverityOK, "installed", ""),
		row(RowNetd, StateRunning, SeverityOK, "pid 1292", ""),
		serverRow(StateRunning, SeverityOK, "pid 840", ""),
		row(RowAPIServer, StateReady, SeverityOK, "https://127.0.0.1:6444 readyz ok", ""),
		row(RowNode, StateReady, SeverityOK, "1/1 nodes ready · my-mac kubelet v1.36.2", ""),
		row(RowWorkloads, StateOK, SeverityOK, "3 running", ""),
		row(RowDataRoot, StateOK, SeverityOK, "/var/lib/k3sm (apfs volume k3sm, mounted)", ""),
		row(RowDatastore, StateOK, SeverityOK, "kine sqlite, wal, user_version 1", ""),
		row(RowKubeconfig, StateOK, SeverityOK, "~/.kube/config context \"k3sm\"", ""),
		row(RowRuntimed, StateHealthy, SeverityOK, "k3sm-runtimed healthy", ""),
	}
}

// replace returns rows with the named row swapped for r.
func replace(rows []Row, r Row) []Row {
	out := append([]Row(nil), rows...)
	for i := range out {
		if out[i].Name == r.Name {
			out[i] = r
			return out
		}
	}
	return append(out, r)
}

// TestAggregateVerdicts is the verdict contract: every verdict the exit-code
// table names, decided from rows alone. Aggregate is pure, so each case is the
// literal machine state an operator would be in.
func TestAggregateVerdicts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rows      []Row
		installed bool
		// role is the node this Mac is installed as. The zero value is the
		// server, so every control-plane case below reads exactly as it did
		// before roles existed.
		role        install.Role
		wantVerdict Verdict
		wantSummary string
		wantNext    []string
	}{
		{
			name: "running", rows: healthyRows(), installed: true,
			wantVerdict: VerdictRunning,
			wantSummary: "1/1 nodes ready",
			wantNext:    []string{"k3sm kubectl get pods -A"},
		},
		{
			name:        "degraded — a warning while the apiserver still serves",
			rows:        replace(healthyRows(), row(RowWorkloads, StateNotReady, SeverityWarn, "1 running · 2 pending", "k3sm kubectl get pods -A")),
			installed:   true,
			wantVerdict: VerdictDegraded,
			wantSummary: "workloads: 1 running · 2 pending",
			wantNext:    []string{"k3sm kubectl get pods -A"},
		},
		{
			name: "degraded — a failure outranks a warning in the summary",
			rows: replace(
				replace(healthyRows(), row(RowWorkloads, StateNotReady, SeverityWarn, "1 pending", "k3sm kubectl get pods -A")),
				row(RowDatastore, StateNotReady, SeverityFail, "kine sqlite is corrupt", "k3sm snapshot restore")),
			installed:   true,
			wantVerdict: VerdictDegraded,
			wantSummary: "datastore: kine sqlite is corrupt",
			wantNext:    []string{"k3sm snapshot restore", "k3sm kubectl get pods -A"},
		},
		{
			name: "stopped cleanly — the server is idle and nothing is serving",
			rows: replace(
				replace(healthyRows(), serverRow(StateStopped, SeverityFail, "loaded but not running (3 runs)", "sudo launchctl kickstart -k system/io.k3sm.server")),
				row(RowAPIServer, StateDown, SeverityFail, "https://127.0.0.1:6444: connection refused", "sudo launchctl kickstart -k system/io.k3sm.server")),
			installed:   true,
			wantVerdict: VerdictStopped,
			wantSummary: "io.k3sm.server is stopped and the apiserver is not serving",
			wantNext:    []string{"sudo launchctl kickstart -k system/io.k3sm.server"},
		},
		{
			name: "stopped — the server is crash-looping, and the summary names it",
			rows: replace(healthyRows(), serverRow(StateCrashLoop, SeverityFail, "497 runs, last exit 1",
				"sudo launchctl kickstart -k system/io.k3sm.server\nk3sm status logs server")),
			installed:   true,
			wantVerdict: VerdictStopped,
			wantSummary: "io.k3sm.server is crash-looping (497 runs, last exit 1)",
			wantNext:    []string{"sudo launchctl kickstart -k system/io.k3sm.server", "k3sm status logs server"},
		},
		{
			name:        "not installed",
			rows:        []Row{row(RowInstall, StateAbsent, SeverityFail, "no k3sm install found on this Mac", "sudo k3sm install")},
			installed:   false,
			wantVerdict: VerdictNotInstalled,
			wantSummary: "k3sm is not installed on this Mac",
			wantNext:    []string{"sudo k3sm install"},
		},
		{
			name:        "a partial install is degraded, not absent",
			rows:        replace(healthyRows(), row(RowInstall, StatePartial, SeverityWarn, "missing: /usr/local/bin/k3sm launcher symlink", "sudo k3sm install")),
			installed:   true,
			wantVerdict: VerdictDegraded,
			wantSummary: "install: missing: /usr/local/bin/k3sm launcher symlink",
			wantNext:    []string{"sudo k3sm install"},
		},
		{
			name: "an unmounted data root while the server crash-loops is STOPPED — the cause wins",
			rows: replace(
				replace(healthyRows(), serverRow(StateCrashLoop, SeverityFail, "12 runs, last exit 1", "sudo launchctl kickstart -k system/io.k3sm.server")),
				row(RowDataRoot, StateNotMounted, SeverityFail, "declared in /etc/fstab (apfs) but nothing is mounted there", "sudo diskutil mount -mountPoint /var/lib/k3sm <volume>")),
			installed:   true,
			wantVerdict: VerdictStopped,
			wantSummary: "io.k3sm.server is crash-looping (12 runs, last exit 1)",
			wantNext: []string{
				"sudo launchctl kickstart -k system/io.k3sm.server",
				"sudo diskutil mount -mountPoint /var/lib/k3sm <volume>",
			},
		},
		{
			name: "an unmounted data root on its own is degraded",
			rows: replace(healthyRows(), row(RowDataRoot, StateNotMounted, SeverityFail,
				"declared in /etc/fstab (apfs) but nothing is mounted there", "sudo diskutil mount -mountPoint /var/lib/k3sm <volume>")),
			installed:   true,
			wantVerdict: VerdictDegraded,
			wantSummary: "data-root: declared in /etc/fstab (apfs) but nothing is mounted there",
			wantNext:    []string{"sudo diskutil mount -mountPoint /var/lib/k3sm <volume>"},
		},
		{
			name: "unknown — an ordinary user who can see nothing",
			rows: []Row{
				row(RowInstall, StateOK, SeverityOK, "installed", ""),
				row(RowNetd, StateUnknown, SeverityUnknown, "launchd was not probed", "sudo k3sm status"),
				serverRow(StateUnknown, SeverityUnknown, "launchd was not probed", "sudo k3sm status"),
				row(RowAPIServer, StateUnknown, SeverityUnknown, "no kubeconfig", ""),
				row(RowNode, StateUnknown, SeverityUnknown, "apiserver unreachable", ""),
				row(RowDatastore, StateUnknown, SeverityUnknown, "state.db not readable as this user (re-run with sudo)", "sudo k3sm status"),
				// A readable side-fact that WARNS must not turn the verdict into
				// "degraded": that word asserts the control plane is serving,
				// which nothing here established.
				row(RowKubeconfig, StateMissing, SeverityWarn, "no k3sm context in ~/.kube/config", "k3sm kubeconfig --write"),
			},
			installed:   true,
			wantVerdict: VerdictUnknown,
			wantSummary: "could not determine cluster state as this user (re-run with sudo)",
			wantNext:    []string{"k3sm kubeconfig --write", "sudo k3sm status"},
		},
		{
			// A worker is healthy on its OWN two facts: the agent daemon is up
			// and its node credential is valid. The datastore and kubeconfig
			// rows describe a control plane it does not run, so neither may
			// make it permanently degraded.
			name:        "running — a joined worker with a valid credential",
			rows:        healthyAgentRows(),
			installed:   true,
			role:        install.RoleAgent,
			wantVerdict: VerdictRunning,
			wantSummary: "this Mac is a joined worker: the agent daemon is running with a valid node credential",
			wantNext:    []string{"k3sm kubectl get pods -A"},
		},
		{
			name: "degraded — the agent is up and has never joined",
			rows: replace(healthyAgentRows(), agentRowFor(StateWaiting, SeverityWarn,
				"pid 903 · waiting for a join: this Mac holds no node credential yet", "k3sm token create   # on the control-plane Mac")),
			installed:   true,
			role:        install.RoleAgent,
			wantVerdict: VerdictDegraded,
			wantSummary: "agent: pid 903 · waiting for a join: this Mac holds no node credential yet",
			// The kubeconfig row's own remedy still rides along: its WARN is
			// advisory on a worker, which keeps it out of the VERDICT, not out
			// of the list of things an operator might do next.
			wantNext: []string{"k3sm token create   # on the control-plane Mac", "k3sm kubeconfig --write"},
		},
		{
			name: "stopped — the worker's own daemon is not running",
			rows: replace(healthyAgentRows(), agentRowFor(StateStopped, SeverityFail,
				"loaded but not running (3 runs)", "sudo launchctl kickstart -k system/io.k3sm.agent")),
			installed:   true,
			role:        install.RoleAgent,
			wantVerdict: VerdictStopped,
			wantSummary: "io.k3sm.agent is stopped, so this Mac is not serving pods",
			wantNext:    []string{"sudo launchctl kickstart -k system/io.k3sm.agent", "k3sm kubeconfig --write"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotV, gotSummary, gotNext := Aggregate(tc.rows, tc.installed, tc.role)
			if gotV != tc.wantVerdict {
				t.Errorf("verdict = %v, want %v", gotV, tc.wantVerdict)
			}
			if gotSummary != tc.wantSummary {
				t.Errorf("summary = %q, want %q", gotSummary, tc.wantSummary)
			}
			if !reflect.DeepEqual(gotNext, tc.wantNext) {
				t.Errorf("next = %#v, want %#v", gotNext, tc.wantNext)
			}
		})
	}
}

// TestVerdictExitCodes pins the numbers scripts branch on. They are additive-only
// and never renumbered, so this table IS the contract, not a restatement of it.
func TestVerdictExitCodes(t *testing.T) {
	t.Parallel()
	want := map[Verdict]int{
		VerdictRunning:      0,
		VerdictStopped:      3,
		VerdictDegraded:     4,
		VerdictNotInstalled: 5,
		VerdictUnknown:      6,
	}
	for v, code := range want {
		if got := v.ExitCode(); got != code {
			t.Errorf("%v.ExitCode() = %d, want %d", v, got, code)
		}
	}
	// 1 (internal error) and 2 (usage) are NOT verdicts; nothing may map to them.
	for v := range want {
		if c := v.ExitCode(); c == 1 || c == 2 {
			t.Errorf("%v.ExitCode() = %d, which is reserved for an internal error / bad usage", v, c)
		}
	}
}
