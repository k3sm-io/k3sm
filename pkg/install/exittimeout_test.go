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

package install

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// TestExitTimeOutCoversTheDaemonTeardown is the drift alarm on the budget table
// itself: that it names every step TestExitTimeOutCoversEveryTeardownStep
// expects, at the same bound and on the same lane; that the step owned by an
// importable package matches its owner; and that the derivation reaches the
// rendered plists.
//
// The server's two longest stretches, the node lane (the embedded runtime's close
// first) and the control-plane lane (the node drain, the ingest registry's
// teardown and the control-plane stop), do not queue: the node starts the
// control-plane lane from its own teardown and closes the runtime while it runs
// (cmd/k3sm/exitoverlap.go), so the pair costs the LONGER of them. The cases
// below assert that as an invariant rather than as arithmetic.
//
// HONEST SCOPE. The assertions that can go red on a moved owner are the one
// binding the control-plane step to executor.StopBound here, and, for runtimed's
// two unexported constants, hack/acceptance/B253.sh. The steps whose owners live
// in package main are bound only by the expected list in the other test, which a
// reader keeps in step with cmd/k3sm by hand.
func TestExitTimeOutCoversTheDaemonTeardown(t *testing.T) {
	// launchd's own default, stated so the "> 20" assertions below read as the
	// claim they are: the default is a SIGKILL deadline k3sm cannot live inside.
	const launchdDefaultExitTimeOut = 20

	// The binding assertion: the control-plane step is a literal in the budget
	// table, and this is what makes it track the package that owns the bound.
	if got, want := teardownControlPlane, int(executor.StopBound/time.Second); got != want {
		t.Errorf("the control-plane teardown step budgets %ds, but executor.StopBound is %ds — raise the step (and re-read the whole budget) or the daemon is SIGKILLed mid-stop", got, want)
	}

	// The literal the shell gates fall back on is the derivation's value.
	if serverExitTimeOutSeconds != serverExitTimeOut {
		t.Errorf("serverExitTimeOutSeconds = %d, but the derived server ExitTimeOut is %ds; the shell gates' fallback would size their waits wrong", serverExitTimeOutSeconds, serverExitTimeOut)
	}

	for _, tc := range []struct {
		name   string
		got    int
		table  []teardownStep
		expect []expectedTeardownStep
	}{
		{"io.k3sm.server", serverExitTimeOut, serverTeardownSteps, expectedServerTeardown},
		{"io.k3sm.agent", agentExitTimeOut, agentTeardownSteps, expectedAgentTeardown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The table and the expected account name the same steps, one each, at
			// the same bound on the same lane.
			byName := map[string]teardownStep{}
			for _, s := range tc.table {
				if _, dup := byName[s.name]; dup {
					t.Errorf("the budget table names %q twice", s.name)
				}
				byName[s.name] = s
			}
			for _, e := range tc.expect {
				s, ok := byName[e.name]
				switch {
				case !ok:
					t.Errorf("the budget table has no step %q (%ds); a step it does not name is a step launchd may SIGKILL", e.name, e.bound)
				case s.bound != e.bound || int(s.lane) != e.lane:
					t.Errorf("the budget table budgets %q at %ds on lane %d, want %ds on lane %d", e.name, s.bound, s.lane, e.bound, e.lane)
				}
				delete(byName, e.name)
			}
			for name := range byName {
				t.Errorf("the budget table names %q, which the expected account does not; add it there too", name)
			}

			// The derivation covers its own table, rounded up, and is worth setting.
			if need := teardownBudget(tc.table); tc.got < need || tc.got%10 != 0 || tc.got-need >= 10 {
				t.Errorf("ExitTimeOut = %ds for a %ds budget, want that budget rounded up to the next multiple of ten", tc.got, need)
			}
			if tc.got <= launchdDefaultExitTimeOut {
				t.Errorf("ExitTimeOut = %ds, which is not above launchd's %ds default; the plist would be setting nothing worth setting",
					tc.got, launchdDefaultExitTimeOut)
			}
		})
	}

	// The overlap invariant, and the whole reason the server's budget is not the
	// sum of its steps: the two lanes run at the same time, so the budget must
	// cover each of them on its own, and must be less than paying for both.
	lane := func(steps []teardownStep, l teardownLane) int {
		n := 0
		for _, s := range steps {
			if s.lane == l {
				n += s.bound
			}
		}
		return n
	}
	node, cp, after := lane(serverTeardownSteps, laneNode), lane(serverTeardownSteps, laneControlPlane), lane(serverTeardownSteps, laneAfterWait)
	if b := teardownBudget(serverTeardownSteps); b < node+after || b < cp+after {
		t.Errorf("the server budget is %ds but its node lane costs %ds and its control-plane lane %ds, each before the %ds after the wait", b, node, cp, after)
	}
	if b := teardownBudget(serverTeardownSteps); b >= node+cp+after {
		t.Errorf("the server budget is %ds, no better than the %ds a SERIAL teardown needs; the two lanes are not being overlapped", b, node+cp+after)
	}
	// A worker has no control-plane lane at all.
	if n := lane(agentTeardownSteps, laneControlPlane); n != 0 {
		t.Errorf("the agent's table budgets %ds on a control-plane lane a worker never runs", n)
	}

	// The rendered plists are what launchd reads, so the derivation is worth
	// nothing until it reaches them.
	for _, tc := range []struct {
		name  string
		plist []byte
		want  int
	}{
		{"server", ServerPlist(Config{}), serverExitTimeOut},
		{"agent", AgentPlist(Config{JoinServer: "192.0.2.10", NodeIP: "100.64.0.7"}), agentExitTimeOut},
	} {
		want := fmt.Sprintf("<key>ExitTimeOut</key>\n  <integer>%d</integer>", tc.want)
		if !strings.Contains(string(tc.plist), want) {
			t.Errorf("the %s plist does not render the derived ExitTimeOut %ds", tc.name, tc.want)
		}
	}
}
