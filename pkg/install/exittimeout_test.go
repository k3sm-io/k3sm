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

// TestExitTimeOutCoversTheSerialTeardown is the drift alarm on the one number
// that decides whether a stopping daemon finishes or is SIGKILLed mid-teardown.
//
// Every stage a k3sm daemon runs on its way out runs serially inside the plist's
// single ExitTimeOut, and the stages are owned by four different packages. The
// arithmetic is therefore asserted rather than assumed: if a stage's bound grows
// and this number does not, launchd starts killing the daemon part-way through
// its own shutdown — which orphans kine and the apiserver on the server path, and
// a vm host helper on either, the exact failure the teardown exists to prevent.
//
// HONEST SCOPE. The "at least the sum" assertion is structural today — the
// ExitTimeOut is computed from those same stages, so it cannot currently fail; it
// is here because it is the invariant the derivation exists to satisfy, and it is
// what fails first the day someone sets the plists' value by hand again. The
// assertions that can actually go red are the ones binding a stage LITERAL to the
// owner of that bound: executor.StopBound here, and — for runtimed's two, which
// are unexported — hack/acceptance/B253.sh, which reads them out of the runtimed
// module and compares. One stage has no gate at all: runtimedSocketShutdownGrace
// lives in package main.
func TestExitTimeOutCoversTheSerialTeardown(t *testing.T) {
	// launchd's own default, stated so the "> 20" assertions below read as the
	// claim they are: the default is a SIGKILL deadline k3sm cannot live inside.
	const launchdDefaultExitTimeOut = 20

	// The binding assertion: the control-plane stage is a literal in the budget
	// table, and this is what makes it track the package that owns the bound.
	if got, want := teardownControlPlane, int(executor.StopBound/time.Second); got != want {
		t.Errorf("the control-plane teardown stage budgets %ds, but executor.StopBound is %ds — raise the stage (and re-read the whole budget) or the daemon is SIGKILLed mid-stop", got, want)
	}

	cases := []struct {
		name   string
		got    int
		stages []struct {
			name  string
			bound int
		}
	}{
		{
			name: "io.k3sm.server",
			got:  serverExitTimeOut,
			stages: []struct {
				name  string
				bound int
			}{
				{"runtimed close (vmShutdownBound + defaultCloseGrace)", teardownRuntimedClose},
				{"runtimed control socket (runtimedSocketShutdownGrace)", teardownControlSocket},
				{"control-plane stop (executor.StopBound)", teardownControlPlane},
				{"mesh teardown (meshTeardownTimeout)", teardownMesh},
				{"launchd signal/reap headroom", teardownHeadroom},
			},
		},
		{
			// A worker runs no control plane, so its budget omits that stage and
			// only that stage — it still embeds a runtime with vm guests to stop.
			name: "io.k3sm.agent",
			got:  agentExitTimeOut,
			stages: []struct {
				name  string
				bound int
			}{
				{"runtimed close (vmShutdownBound + defaultCloseGrace)", teardownRuntimedClose},
				{"runtimed control socket (runtimedSocketShutdownGrace)", teardownControlSocket},
				{"mesh teardown (meshTeardownTimeout)", teardownMesh},
				{"launchd signal/reap headroom", teardownHeadroom},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := 0
			var named []string
			for _, s := range tc.stages {
				sum += s.bound
				named = append(named, fmt.Sprintf("%s=%ds", s.name, s.bound))
			}
			if tc.got < sum {
				t.Errorf("ExitTimeOut = %ds, but the serial teardown needs at least %ds (%s) — launchd would SIGKILL the daemon mid-stop",
					tc.got, sum, strings.Join(named, " + "))
			}
			if tc.got <= launchdDefaultExitTimeOut {
				t.Errorf("ExitTimeOut = %ds, which is not above launchd's %ds default; the plist would be setting nothing worth setting",
					tc.got, launchdDefaultExitTimeOut)
			}
		})
	}

	// The server's budget must exceed the agent's by exactly the stage the agent
	// does not run, before rounding. A future stage added to one role only would
	// otherwise be easy to add to the wrong budget.
	if serverTeardownBudget-agentTeardownBudget != teardownControlPlane {
		t.Errorf("the server budget exceeds the agent's by %ds, want exactly the control-plane stop (%ds)",
			serverTeardownBudget-agentTeardownBudget, teardownControlPlane)
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
