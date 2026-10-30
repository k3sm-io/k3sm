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
	"fmt"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/mlx"
)

// cpuCoreSplit is the host's logical CPUs by performance level. split is
// false on a host with no performance and efficiency levels, where both
// counts are unknown rather than zero.
type cpuCoreSplit struct {
	performance int64
	efficiency  int64
	split       bool
}

// applyBudgetTopology fills the budget capacity's CPU core split and GPU
// fields. A host with no core split leaves both core counts unset. A nil gpu
// (a runtimed that reports no GPU facts) leaves the GPU fields unset, since
// presence is unknown; otherwise GPUPresent is the advertisement verdict and
// GPUCount the mlx.k3sm.io/gpu count the node advertises, 0 when it
// advertises none, both from the same mlx functions the node advertiser
// uses, so the budget and the Node never disagree.
func applyBudgetTopology(c *budgetv1alpha1.BudgetCapacity, cores cpuCoreSplit, gpu *runtimev1.GPUFacts) {
	c.CPUPerformanceCores, c.CPUEfficiencyCores = nil, nil
	if cores.split {
		p, e := cores.performance, cores.efficiency
		c.CPUPerformanceCores, c.CPUEfficiencyCores = &p, &e
	}
	c.GPUPresent, c.GPUCount = nil, nil
	if gpu == nil {
		return
	}
	present := mlx.GPUAdvertisable(gpu)
	var count int64
	if present {
		count = mlx.GPUSlots(gpu)
	}
	c.GPUPresent, c.GPUCount = &present, &count
}

// FillBudgetTopology samples this host's CPU core split and fills it, with
// the GPU presence and count from gpu, into c (see applyBudgetTopology). The
// budget producer calls it for every observation. On a sampling error c is
// left unchanged.
func FillBudgetTopology(c *budgetv1alpha1.BudgetCapacity, gpu *runtimev1.GPUFacts) error {
	cores, err := sampleCPUCoreSplit()
	if err != nil {
		return fmt.Errorf("sample the CPU core split: %w", err)
	}
	applyBudgetTopology(c, cores, gpu)
	return nil
}
