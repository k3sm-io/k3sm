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
	"fmt"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
)

// Row names. They are the tokens `-o json` consumers key on, so they are stable
// and lowercase, and Aggregate reads three of them by name.
const (
	RowInstall = "install"
	RowNetd    = "netd"
	RowServer  = "server"
	// RowAgent is the joining worker's node daemon and the credential that
	// makes it a cluster member. The row exists only on a Mac whose installed
	// role is the agent, and it stands in the server row's place — a node is
	// one role or the other, so the two rows are never both present.
	RowAgent = "agent"
	// RowServerArgs is the operator-supplied `k3sm server` arguments the
	// installed daemon runs with. The row exists only when a server plist is
	// there to read and a parser was wired in.
	RowServerArgs = "server-args"
	RowAPIServer  = "apiserver"
	RowNode       = "node"
	RowWorkloads  = "workloads"
	RowDataRoot   = "data-root"
	// RowPreVolume is the copy a data-root migration left behind. The row
	// exists only while the copy does.
	RowPreVolume = "pre-volume"
	// RowDatavol is the data-volume mount oneshot. The row exists only on a Mac
	// that has a data volume.
	RowDatavol    = "datavol"
	RowDatastore  = "datastore"
	RowKubeconfig = "kubeconfig"
	RowRuntimed   = "runtimed"
)

// advisoryRows are the rows whose WARN is a note to the operator rather than a
// claim about the cluster, and which therefore do not move the verdict off
// running. There is exactly one on a control plane, and it earns the exemption:
//
// pre-volume reports a leftover copy of the data root after a successful
// migration. It is housekeeping — disk an operator may reclaim once they are
// satisfied — and a cluster that is serving every request is not degraded
// because a backup directory exists. Reporting it as degraded would teach an
// operator that "degraded" does not mean anything, which is how a health
// signal stops being read. The row itself still warns, in the table, with its
// remedy; only the headline verdict is unmoved.
//
// A FAIL is never exempt, on any row.
var advisoryRows = map[string]bool{RowPreVolume: true}

// workerAdvisoryRows are the rows that are advisory ON A WORKER, because they
// describe a control plane this Mac does not run.
//
// A joined worker has no kine datastore and no admin kubeconfig: the datastore
// row reads "no state.db yet" and the kubeconfig row warns that it found no
// credentials, and both of those are the CORRECT state of a healthy agent node.
// Letting either move the verdict would make every worker permanently
// "degraded", which is how a health signal stops being read — the same argument
// the pre-volume exemption above rests on.
//
// What is NOT exempt is the worker's own health: the agent daemon and its node
// credential (RowAgent) carry the verdict here exactly as the server row does
// on a control plane, and a FAIL is never exempt on any row.
var workerAdvisoryRows = map[string]bool{RowDatastore: true, RowKubeconfig: true}

// advisory reports whether a row's WARN is a note rather than a claim about
// this node, for the role being reported.
func advisory(role dataroot.Role, name string) bool {
	if advisoryRows[name] {
		return true
	}
	return role == dataroot.RoleAgent && workerAdvisoryRows[name]
}

// nodeRowName is the row that carries this Mac's node daemon: the control plane
// on a server, the joining worker on an agent. Every verdict that reads "the
// daemon" reads this row.
func nodeRowName(role dataroot.Role) string {
	if role == dataroot.RoleAgent {
		return RowAgent
	}
	return RowServer
}

// runningNext is the one suggestion a healthy cluster gets: there is nothing to
// fix, so the next thing to run is the thing you came here to do.
const runningNext = "k3sm kubectl get pods -A"

// downStates are the server states that mean "loaded, and not serving". A
// crash-loop or a failed start is handled separately, because those name a
// cause and these do not.
var downStates = map[RowState]bool{
	StateStopped:   true,
	StateNotLoaded: true,
	StateDisabled:  true,
}

// Aggregate folds the rows into a verdict, the one-line summary under it, and
// the ordered next commands. It is PURE — no clock, no filesystem, no seams —
// so every verdict in the contract is a table row in TestAggregateVerdicts.
//
// The order of the tests is the contract:
//
//  1. Not installed wins outright: there is no cluster to have an opinion about.
//  2. A crash-looping or failed server, or a server that is down while the
//     apiserver is unreachable, is STOPPED — and the summary names the cause,
//     because "stopped" alone sends an operator to the wrong log.
//  3. If the four core rows are ALL unprobeable, UNKNOWN — an ordinary user
//     reading a root daemon's private state. This outranks the Fail/Warn tests
//     below, and that ordering is the honest one: DEGRADED asserts the control
//     plane is serving, and a report that could not reach the apiserver has not
//     established that. Reporting a readable side-fact as "degraded" would put a
//     claim in the headline that nothing observed supports.
//  4. Any Fail, then any Warn, is DEGRADED, naming the first one.
//  5. Otherwise RUNNING.
func Aggregate(rows []Row, installed bool, role dataroot.Role) (Verdict, string, []string) {
	if !installed {
		return VerdictNotInstalled, "k3sm is not installed on this Mac", nextSteps(rows, VerdictNotInstalled)
	}
	if v, summary, ok := stoppedVerdict(rows, role); ok {
		return v, summary, nextSteps(rows, v)
	}
	if allUnknown(rows, RowNetd, nodeRowName(role), RowAPIServer, RowNode) {
		return VerdictUnknown, "could not determine cluster state as this user (re-run with sudo)", nextSteps(rows, VerdictUnknown)
	}
	for _, sev := range []Severity{SeverityFail, SeverityWarn} {
		for _, r := range rows {
			if r.Severity == sev && !(sev == SeverityWarn && advisory(role, r.Name)) {
				return VerdictDegraded, fmt.Sprintf("%s: %s", r.Name, r.Detail), nextSteps(rows, VerdictDegraded)
			}
		}
	}
	return VerdictRunning, runningSummary(rows, role), nextSteps(rows, VerdictRunning)
}

// stoppedVerdict reports the STOPPED verdict and the sentence that names its
// cause, or ok=false when this Mac's node daemon is not stopped. Which daemon that is
// comes from the role: the control plane on a server, the joining worker on an
// agent.
func stoppedVerdict(rows []Row, role dataroot.Role) (Verdict, string, bool) {
	node, haveNode := rowByName(rows, nodeRowName(role))
	if !haveNode {
		return 0, "", false
	}
	// The launchd LABEL, when the row carries one, is what an operator greps for
	// in a log; the row name is only the column header.
	name := node.Wide["label"]
	if name == "" {
		name = nodeRowName(role)
	}
	switch node.State {
	case StateCrashLoop:
		return VerdictStopped, fmt.Sprintf("%s is crash-looping (%s)", name, node.Detail), true
	case StateFailed:
		return VerdictStopped, fmt.Sprintf("%s failed to start (%s)", name, node.Detail), true
	}
	if !downStates[node.State] {
		return 0, "", false
	}
	// A WORKER's own daemon being down is the whole stop: there is no apiserver
	// on this Mac to corroborate it with, and the agent's kubeconfig points at a
	// server it can only reach once it is running.
	if role == dataroot.RoleAgent {
		return VerdictStopped, fmt.Sprintf("%s is %s, so this Mac is not serving pods", name, node.State), true
	}
	if api, ok := rowByName(rows, RowAPIServer); ok && api.State == StateDown {
		return VerdictStopped, fmt.Sprintf("%s is %s and the apiserver is not serving", name, node.State), true
	}
	return 0, "", false
}

// runningSummary is the headline a healthy node gets: the node row's own
// leading clause ("1/1 nodes ready"), which is the fact an operator wanted.
//
// A WORKER only gets that clause when it could actually read the apiserver. Its
// kubeconfig is the node's own, pointing at the server's mesh address, so on
// most workers the node row says "apiserver unreachable" — a true sentence
// about the probe and a misleading headline for a Mac that is joined and
// running. There it falls back to what this report DID establish: the agent
// daemon is up and its node credential is valid.
func runningSummary(rows []Row, role dataroot.Role) string {
	node, ok := rowByName(rows, RowNode)
	if ok && node.Detail != "" && (role != dataroot.RoleAgent || node.Severity == SeverityOK) {
		head, _, _ := strings.Cut(node.Detail, " · ")
		return head
	}
	if role == dataroot.RoleAgent {
		return "this Mac is a joined worker: the agent daemon is running with a valid node credential"
	}
	return "the control plane is serving"
}

// allUnknown reports whether every named row is present and unprobeable.
func allUnknown(rows []Row, names ...string) bool {
	for _, name := range names {
		r, ok := rowByName(rows, name)
		if !ok || r.Severity != SeverityUnknown {
			return false
		}
	}
	return true
}

// rowByName finds a row by its stable name.
func rowByName(rows []Row, name string) (Row, bool) {
	for _, r := range rows {
		if r.Name == name {
			return r, true
		}
	}
	return Row{}, false
}

// nextSteps is the ordered, deduped remedy list. Failures come first because
// they are what is actually broken; a Remedy may carry several lines when the
// repair genuinely takes more than one command, and each becomes its own step.
// A healthy cluster gets exactly one step, and it is not a repair.
func nextSteps(rows []Row, v Verdict) []string {
	if v == VerdictRunning {
		return []string{runningNext}
	}
	var out []string
	seen := make(map[string]bool)
	for _, sev := range []Severity{SeverityFail, SeverityWarn, SeverityUnknown, SeveritySkip, SeverityOK} {
		for _, r := range rows {
			if r.Severity != sev || r.Remedy == "" {
				continue
			}
			for _, step := range strings.Split(r.Remedy, "\n") {
				step = strings.TrimSpace(step)
				if step == "" || seen[step] {
					continue
				}
				seen[step] = true
				out = append(out, step)
			}
		}
	}
	return out
}
