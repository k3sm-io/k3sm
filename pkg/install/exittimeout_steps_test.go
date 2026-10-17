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
)

// The lanes a deferred step runs on, restated here rather than read from the
// budget table: this test is the independent account of the teardown that table
// has to agree with.
const (
	expectNodeLane         = 0 // the daemon's own goroutine, up to its wait for the control-plane lane
	expectControlPlaneLane = 1 // the server's control-plane lane, concurrent with the node lane
	expectAfterWait        = 2 // the daemon's own goroutine after that wait
)

// expectedTeardownStep is one deferred step as this test knows it: its name, the
// bound its owner gives it in seconds, and its lane.
type expectedTeardownStep struct {
	name  string
	bound int
	lane  int
}

// expectedServerTeardown is every step a stopping `k3sm server` runs, read off
// cmd/k3sm: runServer's defers and startNode's, the node's exit hook, and what
// each step's stop waits for. A step whose stop only cancels a context and waits
// for a goroutine that returns on it is listed at 0, so the day it can block is a
// row that has to change.
var expectedServerTeardown = []expectedTeardownStep{
	{"runtimed close (vmShutdownBound + defaultCloseGrace)", 37, expectNodeLane},
	{"node update watcher stop (nodeUpdateStopGrace)", 2, expectNodeLane},
	{"node interconnect handlers stop (context drain)", 0, expectNodeLane},
	{"heartbeat watch stop (context drain)", 0, expectNodeLane},
	{"svclb hoster stop (context drain)", 0, expectNodeLane},
	{"runtimed control socket (runtimedSocketShutdownGrace)", 5, expectNodeLane},
	{"event broadcaster shutdown (non-blocking)", 0, expectNodeLane},
	{"update controller stop (updateControllerStopWait)", 30, expectNodeLane},
	{"interconnect resolver stop (context drain)", 0, expectNodeLane},
	{"mlx operator stop (context drain)", 0, expectNodeLane},
	{"local-path provisioner stop (context drain)", 0, expectNodeLane},
	{"etcd admin client close", 0, expectNodeLane},
	{"ingest registry backstop (waits out the early run within its bound)", 0, expectNodeLane},
	{"manifest directory stop (context drain)", 0, expectNodeLane},
	{"helm controller stop (context drain)", 0, expectNodeLane},
	{"add-on regate stop (context drain)", 0, expectNodeLane},

	{"node drain (nodeDrainGrace)", 5, expectControlPlaneLane},
	{"ingest registry advertisement retract (registryRetractGrace)", 5, expectControlPlaneLane},
	{"ingest registry Service retract (registryRetractGrace)", 5, expectControlPlaneLane},
	{"ingest registry child stop (registryShutdownGrace)", 10, expectControlPlaneLane},
	{"ingest registry teardown margin (registryTeardownMargin)", 5, expectControlPlaneLane},
	{"control-plane stop (executor.StopBound)", 30, expectControlPlaneLane},
	{"control-plane wait margin (controlPlaneStopWaitMargin)", 5, expectControlPlaneLane},

	{"mesh teardown (meshTeardownTimeout)", 5, expectAfterWait},
	{"launchd signal/reap headroom", 10, expectAfterWait},
}

// expectedAgentTeardown is every step a stopping `k3sm agent` runs: its node's,
// then its mesh teardown. A worker runs no control plane, no ingest registry and
// no server operators.
var expectedAgentTeardown = []expectedTeardownStep{
	{"runtimed close (vmShutdownBound + defaultCloseGrace)", 37, expectNodeLane},
	{"node update watcher stop (nodeUpdateStopGrace)", 2, expectNodeLane},
	{"node interconnect handlers stop (context drain)", 0, expectNodeLane},
	{"heartbeat watch stop (context drain)", 0, expectNodeLane},
	{"svclb hoster stop (context drain)", 0, expectNodeLane},
	{"runtimed control socket (runtimedSocketShutdownGrace)", 5, expectNodeLane},
	{"event broadcaster shutdown (non-blocking)", 0, expectNodeLane},

	{"mesh teardown (meshTeardownTimeout)", 5, expectAfterWait},
	{"launchd signal/reap headroom", 10, expectAfterWait},
}

// expectedBudget is the seconds a step list needs: the longer of the two
// concurrent lanes, then the steps after the wait.
func expectedBudget(steps []expectedTeardownStep) (int, string) {
	var lanes [3]int
	var named [3][]string
	for _, s := range steps {
		lanes[s.lane] += s.bound
		if s.bound > 0 {
			named[s.lane] = append(named[s.lane], fmt.Sprintf("%s=%ds", s.name, s.bound))
		}
	}
	explain := fmt.Sprintf("max(node lane %ds [%s], control-plane lane %ds [%s]) + after the wait %ds [%s]",
		lanes[expectNodeLane], strings.Join(named[expectNodeLane], " + "),
		lanes[expectControlPlaneLane], strings.Join(named[expectControlPlaneLane], " + "),
		lanes[expectAfterWait], strings.Join(named[expectAfterWait], " + "))
	return max(lanes[expectNodeLane], lanes[expectControlPlaneLane]) + lanes[expectAfterWait], explain
}

// TestExitTimeOutCoversEveryTeardownStep is the gate on the one number that
// decides whether a stopping daemon finishes its teardown or is SIGKILLed part
// way through it: the plist's ExitTimeOut must cover every deferred step, each
// named, at its owner's bound.
//
// It exists because the earlier account was missing steps. On 2026-10-16 a
// server's teardown ran past its 60s ExitTimeOut: the runtime close took its
// 30s, the managed-update watcher's stop then waited on a root-helper stream
// that could not end before the daemon did, and launchd's SIGKILL landed before
// the ingest registry's teardown (two retractions and the zot child's stop),
// which ran last. The registry child, in its own process group, kept serving.
// None of the registry's steps, the watcher's stop or the update controller's
// 30s stop wait was in the table.
//
// The expected steps here are written out independently of the budget table in
// plist.go, so this compares two accounts rather than one derivation with
// itself; TestExitTimeOutCoversTheDaemonTeardown checks the table names the same
// steps at the same bounds.
func TestExitTimeOutCoversEveryTeardownStep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		got   int
		steps []expectedTeardownStep
	}{
		{"io.k3sm.server", serverExitTimeOut, expectedServerTeardown},
		{"io.k3sm.agent", agentExitTimeOut, expectedAgentTeardown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			need, explain := expectedBudget(tc.steps)
			if tc.got < need {
				t.Errorf("ExitTimeOut = %ds, but the teardown needs at least %ds: %s; launchd would SIGKILL the daemon mid-stop",
					tc.got, need, explain)
			}
		})
	}

	// The ordering the server's budget depends on: the registry's teardown is on
	// the control-plane lane, which begins with the node's teardown, so it never
	// waits behind the runtime close or anything after it.
	for _, s := range expectedServerTeardown {
		if strings.HasPrefix(s.name, "ingest registry ") && s.bound > 0 && s.lane != expectControlPlaneLane {
			t.Errorf("%q is budgeted on lane %d; the registry's teardown runs on the control-plane lane, before the control plane goes", s.name, s.lane)
		}
	}
}
