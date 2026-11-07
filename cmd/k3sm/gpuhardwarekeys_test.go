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

package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestNodeAdvertisesHardwareKeys pins the node's advertisement under both sets of
// names: the engine-named mlx.k3sm.io keys and the hardware-named k3sm.io keys
// beside them.
//
// Each row states the WHOLE outcome, every key of both sets, so a key that appears
// where it should not fails as surely as one that goes missing. Each row runs through
// two entry points, and both matter. configureNode proves the shipped wiring, but it
// rebuilds the resource lists on every call, so only the direct applyGPUAdvertisement
// run can show a pre-seeded resource being deleted.
//
// It is not t.Parallel: configureNode reads the hostMemBytes package var that
// TestNodeCapacityFromHostMemory swaps.
func TestNodeAdvertisesHardwareKeys(t *testing.T) {
	const gib = uint64(1) << 30

	capable := func(mutate ...func(*runtimev1.GPUFacts)) *runtimev1.GPUFacts {
		f := &runtimev1.GPUFacts{
			MetalAvailable:                true,
			SandboxGpuSupported:           true,
			ChipBrand:                     "Apple M4 Max",
			ChipFamily:                    "M4",
			MemBytes:                      128 * gib,
			RecommendedMaxWorkingSetBytes: 96 * gib,
		}
		for _, m := range mutate {
			m(f)
		}
		return f
	}
	noSandboxGPU := func(f *runtimev1.GPUFacts) { f.SandboxGpuSupported = false }
	noMetal := func(f *runtimev1.GPUFacts) { f.MetalAvailable = false }

	// fullyAdvertised is a node carrying every key under both names, so a row that
	// starts from it proves a delete and not an omission.
	fullyAdvertised := func() *corev1.Node {
		two := func() resource.Quantity { return *resource.NewQuantity(2, resource.DecimalSI) }
		cpu := func() resource.Quantity { return *resource.NewQuantity(8, resource.DecimalSI) }
		n := &corev1.Node{}
		n.Labels = map[string]string{
			mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
			mlxv1alpha1.LabelChip:       "apple-m4-max",
			mlxv1alpha1.LabelChipFamily: "m4",
			mlxv1alpha1.LabelMemoryGB:   "128",
			runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
			runtimev1.LabelGPUMemoryGB:  "96",
			runtimev1.LabelChip:         "apple-m4-max",
			runtimev1.LabelChipFamily:   "m4",
			runtimev1.LabelMemoryGB:     "128",
		}
		n.Status.Capacity = corev1.ResourceList{
			corev1.ResourceName(mlxv1alpha1.ResourceGPU): two(),
			corev1.ResourceName(runtimev1.ResourceGPU):   two(),
			corev1.ResourceCPU:                           cpu(),
		}
		n.Status.Allocatable = corev1.ResourceList{
			corev1.ResourceName(mlxv1alpha1.ResourceGPU): two(),
			corev1.ResourceName(runtimev1.ResourceGPU):   two(),
			corev1.ResourceCPU:                           cpu(),
		}
		return n
	}
	emptyNode := func() *corev1.Node { return &corev1.Node{} }

	// allLabels is the closed set of keys this advertisement owns; a key a row does
	// not name must be absent.
	allLabels := []string{
		mlxv1alpha1.LabelGPUPresent,
		mlxv1alpha1.LabelChip,
		mlxv1alpha1.LabelChipFamily,
		mlxv1alpha1.LabelMemoryGB,
		runtimev1.LabelGPUPresent,
		runtimev1.LabelGPUMemoryGB,
		runtimev1.LabelChip,
		runtimev1.LabelChipFamily,
		runtimev1.LabelMemoryGB,
	}
	// bothNamesAdvertised is the whole advertisement of the capable host above.
	bothNamesAdvertised := map[string]string{
		mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
		mlxv1alpha1.LabelChip:       "apple-m4-max",
		mlxv1alpha1.LabelChipFamily: "m4",
		mlxv1alpha1.LabelMemoryGB:   "128",
		runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
		runtimev1.LabelGPUMemoryGB:  "96",
		runtimev1.LabelChip:         "apple-m4-max",
		runtimev1.LabelChipFamily:   "m4",
		runtimev1.LabelMemoryGB:     "128",
	}
	// hardwareFactsOnly is what a host with Metal and no sandbox GPU shows: the
	// hardware-named facts, and nothing that says a pod can use the GPU.
	hardwareFactsOnly := map[string]string{
		runtimev1.LabelChip:       "apple-m4-max",
		runtimev1.LabelChipFamily: "m4",
		runtimev1.LabelMemoryGB:   "128",
	}

	cases := []struct {
		name       string
		node       func() *corev1.Node
		facts      *runtimev1.GPUFacts
		wantLabels map[string]string
		// wantSlots is the count under BOTH resource names; 0 means both absent.
		wantSlots int64
	}{
		{
			name:       "capable_host_advertises_both_names",
			node:       emptyNode,
			facts:      capable(),
			wantLabels: bothNamesAdvertised,
			wantSlots:  2,
		},
		{
			name: "both_names_carry_the_same_slot_count",
			node: emptyNode,
			facts: capable(func(f *runtimev1.GPUFacts) {
				f.RecommendedMaxWorkingSetBytes = 1 * gib
			}),
			wantLabels: map[string]string{
				mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
				mlxv1alpha1.LabelChip:       "apple-m4-max",
				mlxv1alpha1.LabelChipFamily: "m4",
				mlxv1alpha1.LabelMemoryGB:   "128",
				runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
				runtimev1.LabelGPUMemoryGB:  "1",
				runtimev1.LabelChip:         "apple-m4-max",
				runtimev1.LabelChipFamily:   "m4",
				runtimev1.LabelMemoryGB:     "128",
			},
			wantSlots: 1,
		},
		{
			// The tighter of the two ceilings decides, and a part GiB rounds down.
			name: "gpu_memory_label_is_the_effective_ceiling_rounded_down",
			node: emptyNode,
			facts: capable(func(f *runtimev1.GPUFacts) {
				f.IogpuWiredLimitBytes = 48*gib + gib/2
			}),
			wantLabels: map[string]string{
				mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
				mlxv1alpha1.LabelChip:       "apple-m4-max",
				mlxv1alpha1.LabelChipFamily: "m4",
				mlxv1alpha1.LabelMemoryGB:   "128",
				runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
				runtimev1.LabelGPUMemoryGB:  "48",
				runtimev1.LabelChip:         "apple-m4-max",
				runtimev1.LabelChipFamily:   "m4",
				runtimev1.LabelMemoryGB:     "128",
			},
			wantSlots: 2,
		},
		{
			// An unknown ceiling still advertises one slot, and its label is absent:
			// a "0" would read as a measured number.
			name: "unknown_ceiling_omits_only_the_gpu_memory_label",
			node: fullyAdvertised,
			facts: capable(func(f *runtimev1.GPUFacts) {
				f.RecommendedMaxWorkingSetBytes = 0
			}),
			wantLabels: map[string]string{
				mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
				mlxv1alpha1.LabelChip:       "apple-m4-max",
				mlxv1alpha1.LabelChipFamily: "m4",
				mlxv1alpha1.LabelMemoryGB:   "128",
				runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
				runtimev1.LabelChip:         "apple-m4-max",
				runtimev1.LabelChipFamily:   "m4",
				runtimev1.LabelMemoryGB:     "128",
			},
			wantSlots: 1,
		},
		{
			name: "ceiling_under_one_gib_omits_the_gpu_memory_label",
			node: emptyNode,
			facts: capable(func(f *runtimev1.GPUFacts) {
				f.RecommendedMaxWorkingSetBytes = gib / 2
			}),
			wantLabels: map[string]string{
				mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
				mlxv1alpha1.LabelChip:       "apple-m4-max",
				mlxv1alpha1.LabelChipFamily: "m4",
				mlxv1alpha1.LabelMemoryGB:   "128",
				runtimev1.LabelGPUPresent:   runtimeclass.LabelTrue,
				runtimev1.LabelChip:         "apple-m4-max",
				runtimev1.LabelChipFamily:   "m4",
				runtimev1.LabelMemoryGB:     "128",
			},
			wantSlots: 1,
		},
		{
			// THE CASE THE TWO GATES DIFFER ON. The hardware facts ride metal_available
			// and the old labels ride the advertisement verdict, so only the new chip,
			// family and memory labels show. Nothing says a pod can get the GPU.
			name:       "metal_without_sandbox_gpu_shows_only_the_hardware_facts",
			node:       emptyNode,
			facts:      capable(noSandboxGPU),
			wantLabels: hardwareFactsOnly,
		},
		{
			// The same case reached by withdrawal: the facts stay and both resources,
			// both presence labels, the old facts and the GPU memory label all go.
			name:       "sandbox_gpu_lost_withdraws_both_names_and_keeps_the_hardware_facts",
			node:       fullyAdvertised,
			facts:      capable(noSandboxGPU),
			wantLabels: hardwareFactsOnly,
		},
		{
			// The gate is the fact itself, not the emptiness of the fields beside it.
			name:  "no_metal_shows_nothing_even_with_chip_facts_reported",
			node:  emptyNode,
			facts: capable(noMetal),
		},
		{
			name:  "metal_lost_withdraws_every_key_under_both_names",
			node:  fullyAdvertised,
			facts: capable(noMetal),
		},
		{
			name:  "neither_fact_withdraws_every_key_under_both_names",
			node:  fullyAdvertised,
			facts: capable(noMetal, noSandboxGPU),
		},
		{
			name:  "nil_facts_show_nothing",
			node:  emptyNode,
			facts: nil,
		},
		{
			name:  "nil_facts_withdraw_every_key_under_both_names",
			node:  fullyAdvertised,
			facts: nil,
		},
		{
			// Metal with unread host facts: a label with no value is deleted, never
			// published blank.
			name:  "metal_with_unread_chip_facts_deletes_the_hardware_facts",
			node:  fullyAdvertised,
			facts: &runtimev1.GPUFacts{MetalAvailable: true},
		},
	}

	assertAdvertisement := func(t *testing.T, n *corev1.Node, wantLabels map[string]string, wantSlots int64) {
		t.Helper()
		for _, key := range allLabels {
			got, ok := n.Labels[key]
			want, wantOK := wantLabels[key]
			if ok != wantOK || got != want {
				t.Errorf("label %s = %q (present %v), want %q (present %v)", key, got, ok, want, wantOK)
			}
		}
		for _, name := range []corev1.ResourceName{
			corev1.ResourceName(mlxv1alpha1.ResourceGPU),
			corev1.ResourceName(runtimev1.ResourceGPU),
		} {
			for _, l := range []struct {
				name string
				list corev1.ResourceList
			}{{"Capacity", n.Status.Capacity}, {"Allocatable", n.Status.Allocatable}} {
				q, ok := l.list[name]
				switch {
				case wantSlots == 0 && ok:
					t.Errorf("%s: %s = %s, want absent", l.name, name, q.String())
				case wantSlots != 0 && !ok:
					t.Errorf("%s: %s absent, want %d", l.name, name, wantSlots)
				case wantSlots != 0 && q.Value() != wantSlots:
					t.Errorf("%s: %s = %d, want %d", l.name, name, q.Value(), wantSlots)
				}
			}
		}
	}

	withHostArchFacts(t, nativeAppleSilicon, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("applyGPUAdvertisement", func(t *testing.T) {
				n := tc.node()
				seeded := n.Status.Capacity != nil
				applyGPUAdvertisement(n, tc.facts)
				assertAdvertisement(t, n, tc.wantLabels, tc.wantSlots)
				// A removal that cleared the whole list would pass the rows above.
				if seeded {
					if _, ok := n.Status.Capacity[corev1.ResourceCPU]; !ok {
						t.Errorf("Capacity lost cpu; list=%v", n.Status.Capacity)
					}
					if _, ok := n.Status.Allocatable[corev1.ResourceCPU]; !ok {
						t.Errorf("Allocatable lost cpu; list=%v", n.Status.Allocatable)
					}
				}
			})
			t.Run("configureNode", func(t *testing.T) {
				n := tc.node()
				configureNode(n, "k3sm-node", "10.0.0.1", nodeKubeletListen, provider.NodeCapabilities{GPU: tc.facts})
				assertAdvertisement(t, n, tc.wantLabels, tc.wantSlots)
			})
		})
	}
}
