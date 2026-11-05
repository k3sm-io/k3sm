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

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/mlx"
)

func TestBudgetCapacityTopology(t *testing.T) {
	t.Parallel()
	const gib = int64(1) << 30
	usable := &runtimev1.GPUFacts{
		MetalAvailable: true, SandboxGpuSupported: true,
		RecommendedMaxWorkingSetBytes: uint64(48 * gib),
	}
	split := cpuCoreSplit{performance: 8, efficiency: 4, split: true}
	cases := []struct {
		name              string
		cores             cpuCoreSplit
		gpu               *runtimev1.GPUFacts
		wantPerf, wantEff *int64
		wantPresent       *bool
		wantCount         *int64
	}{
		{name: "split and an advertised GPU", cores: split, gpu: usable,
			wantPerf: ptr(int64(8)), wantEff: ptr(int64(4)), wantPresent: ptr(true), wantCount: ptr(mlx.GPUSlots(usable))},
		{name: "no split leaves the core counts unknown", cores: cpuCoreSplit{}, gpu: usable,
			wantPresent: ptr(true), wantCount: ptr(mlx.GPUSlots(usable))},
		{name: "no GPU facts leaves presence unknown", cores: split,
			wantPerf: ptr(int64(8)), wantEff: ptr(int64(4))},
		{name: "metal without a GPU sandbox advertises none", cores: split,
			gpu:      &runtimev1.GPUFacts{MetalAvailable: true},
			wantPerf: ptr(int64(8)), wantEff: ptr(int64(4)), wantPresent: ptr(false), wantCount: ptr(int64(0))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := budgetv1alpha1.BudgetCapacity{
				CPUPerformanceCores: ptr(int64(99)), GPUPresent: ptr(true), GPUCount: ptr(int64(99)),
			}
			applyBudgetTopology(&c, tc.cores, tc.gpu)
			eq := func(name string, got, want *int64) {
				if (got == nil) != (want == nil) || (got != nil && *got != *want) {
					t.Errorf("%s = %v, want %v", name, int64OrNil(got), int64OrNil(want))
				}
			}
			eq("CPUPerformanceCores", c.CPUPerformanceCores, tc.wantPerf)
			eq("CPUEfficiencyCores", c.CPUEfficiencyCores, tc.wantEff)
			eq("GPUCount", c.GPUCount, tc.wantCount)
			if (c.GPUPresent == nil) != (tc.wantPresent == nil) || (c.GPUPresent != nil && *c.GPUPresent != *tc.wantPresent) {
				t.Errorf("GPUPresent = %v, want %v", c.GPUPresent, tc.wantPresent)
			}
			if c.GPUPresent != nil && *c.GPUPresent != mlx.GPUAdvertisable(tc.gpu) {
				t.Error("GPUPresent disagrees with the node advertiser's verdict")
			}
		})
	}
}

// int64OrNil formats an optional count for a failure message.
func int64OrNil(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
