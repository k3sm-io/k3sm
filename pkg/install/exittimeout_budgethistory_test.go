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

// budgetHistoryStep is the budget history stop's name in the teardown tables.
const budgetHistoryStep = "budget history stop (provider.BudgetHistoryStopBound)"

// TestExitTimeOutCountsTheBudgetHistoryStop: the node teardown's budget history
// stop (StopBudgetHistory, run on the node lane before the runtime closes) is a
// step of both daemons' budgets, at its owner's bound rounded up to whole
// seconds, and the agent's budget, whose node lane is its only lane before the
// wait, grows by exactly that bound.
//
// Fails-before: neither table named the step, so up to
// provider.BudgetHistoryStopBound of the exit sat outside the derived
// ExitTimeOut.
func TestExitTimeOutCountsTheBudgetHistoryStop(t *testing.T) {
	want := int((provider.BudgetHistoryStopBound + time.Second - 1) / time.Second)
	for _, tc := range []struct {
		name  string
		table []teardownStep
	}{
		{"io.k3sm.server", serverTeardownSteps},
		{"io.k3sm.agent", agentTeardownSteps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := slices.IndexFunc(tc.table, func(s teardownStep) bool { return s.name == budgetHistoryStep })
			if i < 0 {
				t.Fatalf("the budget table has no %q step", budgetHistoryStep)
			}
			if s := tc.table[i]; s.bound != want || s.lane != laneNode {
				t.Fatalf("%q budgets %ds on lane %d, want %ds on the node lane", s.name, s.bound, s.lane, want)
			}
		})
	}
	without := slices.DeleteFunc(slices.Clone(agentTeardownSteps), func(s teardownStep) bool { return s.name == budgetHistoryStep })
	if got, base := teardownBudget(agentTeardownSteps), teardownBudget(without); got != base+want {
		t.Fatalf("the agent's teardown budget is %ds, want %ds (%ds without the budget history stop, plus %ds)", got, base+want, base, want)
	}
}
