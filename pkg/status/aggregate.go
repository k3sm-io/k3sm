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
)

// Row names. They are the tokens `-o json` consumers key on, so they are stable
// and lowercase, and Aggregate reads three of them by name.
const (
	RowInstall    = "install"
	RowNetd       = "netd"
	RowServer     = "server"
	RowAPIServer  = "apiserver"
	RowNode       = "node"
	RowWorkloads  = "workloads"
	RowDataRoot   = "data-root"
	RowDatastore  = "datastore"
	RowKubeconfig = "kubeconfig"
	RowRuntimed   = "runtimed"
)

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
func Aggregate(rows []Row, installed bool) (Verdict, string, []string) {
	if !installed {
		return VerdictNotInstalled, "k3sm is not installed on this Mac", nextSteps(rows, VerdictNotInstalled)
	}
	if v, summary, ok := stoppedVerdict(rows); ok {
		return v, summary, nextSteps(rows, v)
	}
	if allUnknown(rows, RowNetd, RowServer, RowAPIServer, RowNode) {
		return VerdictUnknown, "could not determine cluster state as this user (re-run with sudo)", nextSteps(rows, VerdictUnknown)
	}
	for _, sev := range []Severity{SeverityFail, SeverityWarn} {
		for _, r := range rows {
			if r.Severity == sev {
				return VerdictDegraded, fmt.Sprintf("%s: %s", r.Name, r.Detail), nextSteps(rows, VerdictDegraded)
			}
		}
	}
	return VerdictRunning, runningSummary(rows), nextSteps(rows, VerdictRunning)
}

// stoppedVerdict reports the STOPPED verdict and the sentence that names its
// cause, or ok=false when the control plane is not stopped.
func stoppedVerdict(rows []Row) (Verdict, string, bool) {
	server, haveServer := rowByName(rows, RowServer)
	if !haveServer {
		return 0, "", false
	}
	// The launchd LABEL, when the row carries one, is what an operator greps for
	// in a log; the row name is only the column header.
	name := server.Wide["label"]
	if name == "" {
		name = RowServer
	}
	switch server.State {
	case StateCrashLoop:
		return VerdictStopped, fmt.Sprintf("%s is crash-looping (%s)", name, server.Detail), true
	case StateFailed:
		return VerdictStopped, fmt.Sprintf("%s failed to start (%s)", name, server.Detail), true
	}
	if api, ok := rowByName(rows, RowAPIServer); ok && downStates[server.State] && api.State == StateDown {
		return VerdictStopped, fmt.Sprintf("%s is %s and the apiserver is not serving", name, server.State), true
	}
	return 0, "", false
}

// runningSummary is the headline a healthy cluster gets: the node row's own
// leading clause ("1/1 nodes ready"), which is the fact an operator wanted.
func runningSummary(rows []Row) string {
	if node, ok := rowByName(rows, RowNode); ok && node.Detail != "" {
		head, _, _ := strings.Cut(node.Detail, " · ")
		return head
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
