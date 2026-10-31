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
	"slices"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/provider"
)

// evictionStopStep is the eviction loop stop's name in the teardown tables.
const evictionStopStep = "eviction loop stop (provider.EvictionStopTimeout)"

// TestExitTimeOutCountsTheEvictionLoopStop: the node teardown waits up to
// provider.EvictionStopTimeout for the eviction loop before it flushes the
// budget history and closes the runtime, so the step belongs to both daemons'
// node lanes and the agent's budget, whose node lane is its only lane before
// the wait, grows by exactly that bound. The server's budget is the longer of
// its two lanes, so it is asserted through the step only.
//
// Fails-before: neither table named the step, so up to the bound of the exit
// sat outside the derived ExitTimeOut.
func TestExitTimeOutCountsTheEvictionLoopStop(t *testing.T) {
	want := int((provider.EvictionStopTimeout + time.Second - 1) / time.Second)
	for _, tc := range []struct {
		name  string
		table []teardownStep
	}{
		{"io.k3sm.server", serverTeardownSteps},
		{"io.k3sm.agent", agentTeardownSteps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := slices.IndexFunc(tc.table, func(s teardownStep) bool { return s.name == evictionStopStep })
			if i < 0 {
				t.Fatalf("the budget table has no %q step", evictionStopStep)
			}
			if s := tc.table[i]; s.bound != want || s.lane != laneNode {
				t.Fatalf("%q budgets %ds on lane %d, want %ds on the node lane", s.name, s.bound, s.lane, want)
			}
			without := slices.DeleteFunc(slices.Clone(tc.table), func(s teardownStep) bool { return s.name == evictionStopStep })
			var node, base int
			for _, s := range tc.table {
				if s.lane == laneNode {
					node += s.bound
				}
			}
			for _, s := range without {
				if s.lane == laneNode {
					base += s.bound
				}
			}
			if node != base+want {
				t.Fatalf("the node lane costs %ds, want %ds (%ds without the eviction loop stop, plus %ds)", node, base+want, base, want)
			}
		})
	}
	without := slices.DeleteFunc(slices.Clone(agentTeardownSteps), func(s teardownStep) bool { return s.name == evictionStopStep })
	if got, base := teardownBudget(agentTeardownSteps), teardownBudget(without); got != base+want {
		t.Fatalf("the agent's teardown budget is %ds, want %ds (%ds without the eviction loop stop, plus %ds)", got, base+want, base, want)
	}
}
