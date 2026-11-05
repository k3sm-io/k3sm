//go:build darwin

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

package provider

import (
	"testing"

	"golang.org/x/sys/unix"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
)

// TestSampleCPUCoreSplitSumsToLogicalCPU reads this host's performance
// levels: on a split host the two counts are positive and add up to
// hw.logicalcpu.
func TestSampleCPUCoreSplitSumsToLogicalCPU(t *testing.T) {
	t.Parallel()
	s, err := sampleCPUCoreSplit()
	if err != nil {
		t.Fatalf("sampleCPUCoreSplit: %v", err)
	}
	if !s.split {
		t.Skip("this host reports no performance level split")
	}
	total, err := unix.SysctlUint32("hw.logicalcpu")
	if err != nil {
		t.Fatal(err)
	}
	if s.performance <= 0 || s.efficiency <= 0 || s.performance+s.efficiency != int64(total) {
		t.Fatalf("performance %d + efficiency %d, want positive counts summing to hw.logicalcpu %d", s.performance, s.efficiency, total)
	}
}

// TestFillBudgetTopologySetsTheSplit fills a capacity on this host.
func TestFillBudgetTopologySetsTheSplit(t *testing.T) {
	t.Parallel()
	s, err := sampleCPUCoreSplit()
	if err != nil {
		t.Fatal(err)
	}
	var c budgetv1alpha1.BudgetCapacity
	if err := FillBudgetTopology(&c, nil); err != nil {
		t.Fatalf("FillBudgetTopology: %v", err)
	}
	if s.split != (c.CPUPerformanceCores != nil && c.CPUEfficiencyCores != nil) {
		t.Fatalf("split %v, but the capacity holds %v and %v", s.split, c.CPUPerformanceCores, c.CPUEfficiencyCores)
	}
	if c.GPUPresent != nil || c.GPUCount != nil {
		t.Fatal("nil GPU facts must leave the GPU fields unset")
	}
}
