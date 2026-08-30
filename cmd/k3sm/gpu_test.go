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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider"
	"k3sm.io/k3sm/pkg/runtimeclass"
)

// TestNodeAdvertisesGPUExtendedResource is the proof of the M8 node GPU
// advertisement: the mlx.k3sm.io/gpu extended resource in BOTH Capacity and
// Allocatable, and the mlx.k3sm.io presence/chip/chip-family/memory labels, derived
// fail-closed from runtimed's GPUFacts and REMOVED on capability loss.
//
// The GPUFacts arrive through the provider.NodeCapabilities seam, so every row here
// drives configureNode itself with FAKE facts — no live runtimed, no Metal device, and
// no dependence on whether the machine running the tests has a GPU at all.
//
// Four properties are pinned, and the last two are why the loss rows pre-seed:
//
//  1. the resource and label KEYS come from apis and are never respelled — every
//     assertion below reads the same constants the production code writes, so a
//     renamed constant is a compile error rather than a silently-renamed node
//     advertisement;
//  2. the advertisement is a CONJUNCTION of metal_available and
//     sandbox_gpu_supported — either alone advertises nothing;
//  3. loss DELETES, in the resource lists as well as the labels. An absence-only
//     assertion also passes against an empty node, i.e. before any code exists, so it
//     cannot distinguish delete() from "never set";
//  4. nil facts (a daemon predating them) advertise nothing and do not panic.
//
// Every assertion is a t.Run SUBTEST of this one function on purpose — the named gate
// runs `go test -run '^TestNodeAdvertisesGPUExtendedResource$'`, so a sibling
// top-level test would be silently filtered out and never run.
//
// It is deliberately NOT t.Parallel: it calls configureNode, which reads the
// hostMemBytes package var that TestNodeCapacityFromHostMemory swaps. A non-parallel
// test runs entirely in the sequential phase, so the swap can never race these reads.
func TestNodeAdvertisesGPUExtendedResource(t *testing.T) {
	// capableFacts is a real-shaped report from an Apple Silicon Mac whose selected
	// sandbox backend can grant GPU access. chip_brand carries its SPACES, which is the
	// point of the slug assertions: the raw fact is not a legal label value.
	capableFacts := func() *runtimev1.GPUFacts {
		return &runtimev1.GPUFacts{
			MetalAvailable:                true,
			ChipBrand:                     "Apple M4 Max",
			ChipFamily:                    "M4",
			MemBytes:                      128 * 1024 * 1024 * 1024,
			RecommendedMaxWorkingSetBytes: 96 * 1024 * 1024 * 1024,
			SandboxGpuSupported:           true,
		}
	}

	// advertisedNode is a node that ALREADY carries the full advertisement, so a row
	// asserting removal proves a delete rather than an omission.
	advertisedNode := func() *corev1.Node {
		n := &corev1.Node{}
		n.Labels = map[string]string{
			mlxv1alpha1.LabelGPUPresent: runtimeclass.LabelTrue,
			mlxv1alpha1.LabelChip:       "apple-m4-max",
			mlxv1alpha1.LabelChipFamily: "m4",
			mlxv1alpha1.LabelMemoryGB:   "128",
		}
		n.Status.Capacity = corev1.ResourceList{gpuResourceName: *resource.NewQuantity(1, resource.DecimalSI)}
		n.Status.Allocatable = corev1.ResourceList{gpuResourceName: *resource.NewQuantity(1, resource.DecimalSI)}
		return n
	}

	wantLabel := func(t *testing.T, n *corev1.Node, key, want string) {
		t.Helper()
		got, ok := n.Labels[key]
		if !ok {
			t.Errorf("label %s absent, want %q; labels=%v", key, want, n.Labels)
			return
		}
		if got != want {
			t.Errorf("label %s = %q, want %q", key, got, want)
		}
	}
	// wantLabelAbsent uses the two-value lookup — the only form that distinguishes
	// "absent" from "present but empty", and an empty value would still satisfy a
	// selector written as `exists`.
	wantLabelAbsent := func(t *testing.T, n *corev1.Node, key string) {
		t.Helper()
		if v, ok := n.Labels[key]; ok {
			t.Errorf("label %s must be ABSENT (deleted, never blank or \"false\"), got %q", key, v)
		}
	}
	wantGPUQuantity := func(t *testing.T, n *corev1.Node, want int64) {
		t.Helper()
		for _, l := range []struct {
			name string
			list corev1.ResourceList
		}{{"Capacity", n.Status.Capacity}, {"Allocatable", n.Status.Allocatable}} {
			q, ok := l.list[gpuResourceName]
			if !ok {
				t.Errorf("%s: %s absent, want %d; list=%v", l.name, mlxv1alpha1.ResourceGPU, want, l.list)
				continue
			}
			if got := q.Value(); got != want {
				t.Errorf("%s: %s = %d, want %d", l.name, mlxv1alpha1.ResourceGPU, got, want)
			}
		}
	}
	wantNoGPUResource := func(t *testing.T, n *corev1.Node) {
		t.Helper()
		for _, l := range []struct {
			name string
			list corev1.ResourceList
		}{{"Capacity", n.Status.Capacity}, {"Allocatable", n.Status.Allocatable}} {
			if q, ok := l.list[gpuResourceName]; ok {
				t.Errorf("%s: %s must be ABSENT (removed on capability loss), got %s", l.name, mlxv1alpha1.ResourceGPU, q.String())
			}
		}
	}
	// wantNothingAdvertised is the whole fail-closed verdict in one place: neither the
	// resource nor ANY of the four labels.
	wantNothingAdvertised := func(t *testing.T, n *corev1.Node) {
		t.Helper()
		wantNoGPUResource(t, n)
		for _, key := range []string{
			mlxv1alpha1.LabelGPUPresent,
			mlxv1alpha1.LabelChip,
			mlxv1alpha1.LabelChipFamily,
			mlxv1alpha1.LabelMemoryGB,
		} {
			wantLabelAbsent(t, n, key)
		}
	}

	// THE PRODUCTION-WIRING ROWS: every case drives configureNode, not the leaf helper.
	// Without them a change that dropped the applyGPUAdvertisement CALL would leave the
	// unit rows green while the shipped node advertised no GPU at all. The host facts
	// are pinned so the rows stay hermetic on any machine.
	t.Run("configureNode", func(t *testing.T) {
		withHostArchFacts(t, nativeAppleSilicon, nil)

		cases := []struct {
			name string
			// node is the node BEFORE configureNode — pre-seeded on the loss rows.
			node  func() *corev1.Node
			facts *runtimev1.GPUFacts
			// wantAdvertised is the whole verdict; the value assertions below only
			// run when it is true.
			wantAdvertised bool
		}{
			{
				name:           "capable_host_advertises",
				node:           func() *corev1.Node { return &corev1.Node{} },
				facts:          capableFacts(),
				wantAdvertised: true,
			},
			{
				// A host with no Metal device the daemon can open. The sandbox backend
				// COULD grant GPU access, which is exactly why this row is not
				// redundant with the next one.
				name: "no_metal_device_advertises_nothing",
				node: func() *corev1.Node { return &corev1.Node{} },
				facts: func() *runtimev1.GPUFacts {
					f := capableFacts()
					f.MetalAvailable = false
					return f
				}(),
			},
			{
				// A real GPU the SELECTED sandbox backend cannot expose to a pod.
				// Advertising here would attract MLX workloads to a node that denies
				// every one of them — the fail-OPEN mislabel the conjunction prevents.
				name: "sandbox_cannot_grant_gpu_advertises_nothing",
				node: func() *corev1.Node { return &corev1.Node{} },
				facts: func() *runtimev1.GPUFacts {
					f := capableFacts()
					f.SandboxGpuSupported = false
					return f
				}(),
			},
			{
				// CAPABILITY LOSS: the node already advertises, and the daemon now
				// reports a host whose Metal device it cannot open (a backend change,
				// an eGPU unplugged, a daemon reconfigured). Everything must be REMOVED.
				name: "capability_loss_removes_resource_and_labels",
				node: advertisedNode,
				facts: func() *runtimev1.GPUFacts {
					f := capableFacts()
					f.MetalAvailable = false
					f.SandboxGpuSupported = false
					return f
				}(),
			},
			{
				// An older daemon that reports no gpu field at all. Distinct from
				// "known to have none", same fail-closed answer, and it must not panic
				// on the nil.
				name:  "nil_facts_advertise_nothing",
				node:  func() *corev1.Node { return &corev1.Node{} },
				facts: nil,
			},
			{
				// The nil case ALSO has to remove a stale advertisement: a node that
				// advertised under a newer daemon and then downgraded must stop.
				name:  "nil_facts_remove_a_stale_advertisement",
				node:  advertisedNode,
				facts: nil,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				n := tc.node()
				configureNode(n, "k3sm-node", "10.0.0.1", provider.NodeCapabilities{GPU: tc.facts})

				if !tc.wantAdvertised {
					wantNothingAdvertised(t, n)
				} else {
					wantGPUQuantity(t, n, gpuDeviceCount)
					wantLabel(t, n, mlxv1alpha1.LabelGPUPresent, runtimeclass.LabelTrue)
					// The SLUG, not the raw fact: "Apple M4 Max" is not a legal label
					// value, and a consumer comparing the label to the raw chip_brand
					// would silently never match.
					wantLabel(t, n, mlxv1alpha1.LabelChip, "apple-m4-max")
					wantLabel(t, n, mlxv1alpha1.LabelChipFamily, "m4")
					// Whole GiB, decimal, NO unit suffix.
					wantLabel(t, n, mlxv1alpha1.LabelMemoryGB, "128")
				}

				// The GPU advertisement must never disturb the rest of the node
				// configuration — Capacity keeps its cpu/memory/pods, and the identity
				// labels survive. A removal implemented by clearing the resource list
				// would pass every assertion above.
				for _, r := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourcePods} {
					if _, ok := n.Status.Capacity[r]; !ok {
						t.Errorf("Capacity lost %s; list=%v", r, n.Status.Capacity)
					}
					if _, ok := n.Status.Allocatable[r]; !ok {
						t.Errorf("Allocatable lost %s; list=%v", r, n.Status.Allocatable)
					}
				}
				if got := n.Labels["kubernetes.io/os"]; got != "darwin" {
					t.Errorf("kubernetes.io/os = %q, want darwin; labels=%v", got, n.Labels)
				}
			})
		}
	})

	// THE RESOURCE-REMOVAL ROW, driven through applyGPUAdvertisement directly rather
	// than configureNode. It is NOT redundant with the configureNode loss rows above:
	// configureNode REBUILDS Capacity and Allocatable from host facts on every call, so
	// a pre-seeded GPU quantity disappears there whether or not anything deletes it —
	// those rows can only prove the LABEL removal. Here the lists survive the call, so
	// the resource's absence afterwards is a delete and nothing else.
	t.Run("capability_loss_deletes_the_resource_from_both_lists", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			facts *runtimev1.GPUFacts
		}{
			{"metal_lost", &runtimev1.GPUFacts{SandboxGpuSupported: true}},
			{"sandbox_lost", &runtimev1.GPUFacts{MetalAvailable: true}},
			{"facts_gone", nil},
		} {
			t.Run(tc.name, func(t *testing.T) {
				n := advertisedNode()
				// Co-resident resources the removal must leave alone: deleting the whole
				// list would satisfy a bare absence assertion.
				n.Status.Capacity[corev1.ResourceCPU] = *resource.NewQuantity(8, resource.DecimalSI)
				n.Status.Allocatable[corev1.ResourceCPU] = *resource.NewQuantity(8, resource.DecimalSI)

				applyGPUAdvertisement(n, tc.facts)

				wantNothingAdvertised(t, n)
				for _, l := range []struct {
					name string
					list corev1.ResourceList
				}{{"Capacity", n.Status.Capacity}, {"Allocatable", n.Status.Allocatable}} {
					if _, ok := l.list[corev1.ResourceCPU]; !ok {
						t.Errorf("%s: the GPU removal must not disturb co-resident resources; cpu is gone (list=%v)", l.name, l.list)
					}
				}
			})
		}
	})

	// The gain direction on a node whose lists already exist: the resource is ADDED to
	// both, not substituted for them.
	t.Run("capability_gain_adds_the_resource_to_both_lists", func(t *testing.T) {
		n := &corev1.Node{}
		n.Status.Capacity = corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(8, resource.DecimalSI)}
		n.Status.Allocatable = corev1.ResourceList{corev1.ResourceCPU: *resource.NewQuantity(8, resource.DecimalSI)}
		applyGPUAdvertisement(n, capableFacts())
		wantGPUQuantity(t, n, gpuDeviceCount)
		if _, ok := n.Status.Capacity[corev1.ResourceCPU]; !ok {
			t.Errorf("Capacity lost cpu; list=%v", n.Status.Capacity)
		}
		// A node with NIL lists must not panic and must end up advertising.
		bare := &corev1.Node{}
		applyGPUAdvertisement(bare, capableFacts())
		wantGPUQuantity(t, bare, gpuDeviceCount)
	})

	// The four keys are DISTINCT strings. Reusing one for two purposes would make a
	// nodeSelector silently match on capacity semantics, and the resource key is
	// deliberately not the presence-label key.
	t.Run("keys_are_distinct", func(t *testing.T) {
		keys := map[string]string{
			mlxv1alpha1.ResourceGPU:     "ResourceGPU",
			mlxv1alpha1.LabelGPUPresent: "LabelGPUPresent",
			mlxv1alpha1.LabelChip:       "LabelChip",
			mlxv1alpha1.LabelChipFamily: "LabelChipFamily",
			mlxv1alpha1.LabelMemoryGB:   "LabelMemoryGB",
		}
		if len(keys) != 5 {
			t.Errorf("the mlx node-advertisement keys must be five DISTINCT strings, got %d: %v", len(keys), keys)
		}
		if string(gpuResourceName) != mlxv1alpha1.ResourceGPU {
			t.Errorf("gpuResourceName = %q, want the apis constant %q", gpuResourceName, mlxv1alpha1.ResourceGPU)
		}
	})

	// gpuAdvertisable is the conjunction, exercised over all four corners directly —
	// the configureNode rows above cover three of them, and a leaf table makes the
	// fourth (neither fact) explicit.
	t.Run("gpuAdvertisable_conjunction", func(t *testing.T) {
		for _, tc := range []struct {
			metal, sandbox, want bool
		}{
			{false, false, false},
			{true, false, false},
			{false, true, false},
			{true, true, true},
		} {
			got := gpuAdvertisable(&runtimev1.GPUFacts{MetalAvailable: tc.metal, SandboxGpuSupported: tc.sandbox})
			if got != tc.want {
				t.Errorf("gpuAdvertisable(metal=%v, sandbox=%v) = %v, want %v", tc.metal, tc.sandbox, got, tc.want)
			}
		}
		if gpuAdvertisable(nil) {
			t.Error("gpuAdvertisable(nil) = true, want false (nil facts must fail closed)")
		}
	})

	// The chip-slug rule from the apis label constants, step by step.
	t.Run("chipSlug", func(t *testing.T) {
		long := strings.Repeat("Apple M4 Max ", 12) // > 63 chars once slugged
		for _, tc := range []struct {
			name, raw, want string
		}{
			{"brand_with_spaces", "Apple M4 Max", "apple-m4-max"},
			{"family", "M4", "m4"},
			{"already_a_slug", "apple-m4-max", "apple-m4-max"},
			{"leading_and_trailing_junk", "  Apple M4 Max!! ", "apple-m4-max"},
			{"run_collapses_to_one_dash", "Apple   M4///Max", "apple-m4-max"},
			{"non_ascii_becomes_a_separator", "Apple™ M4", "apple-m4"},
			{"empty", "", ""},
			{"all_junk", " -- ", ""},
		} {
			if got := chipSlug(tc.raw); got != tc.want {
				t.Errorf("%s: chipSlug(%q) = %q, want %q", tc.name, tc.raw, got, tc.want)
			}
		}
		got := chipSlug(long)
		if len(got) > maxLabelValueLen {
			t.Errorf("chipSlug truncation: len = %d, want <= %d (%q)", len(got), maxLabelValueLen, got)
		}
		// Truncation must not leave a trailing "-": a label value has to end
		// alphanumeric or the apiserver rejects the node update outright.
		if strings.HasSuffix(got, "-") || strings.HasPrefix(got, "-") {
			t.Errorf("chipSlug truncation left a boundary dash: %q", got)
		}
	})

	// memory-gb is whole GiB, decimal, no suffix — and absent below 1GiB rather than
	// advertising a "0" no selector should match.
	t.Run("memoryGiBLabel", func(t *testing.T) {
		for _, tc := range []struct {
			bytes uint64
			want  string
		}{
			{128 * 1024 * 1024 * 1024, "128"},
			{16 * 1024 * 1024 * 1024, "16"},
			{0, ""},
			{512 * 1024 * 1024, ""},
			// Truncating (not rounding) keeps the value a floor, so it never
			// over-reports memory the host does not have.
			{24*1024*1024*1024 + 900*1024*1024, "24"},
		} {
			if got := memoryGiBLabel(tc.bytes); got != tc.want {
				t.Errorf("memoryGiBLabel(%d) = %q, want %q", tc.bytes, got, tc.want)
			}
		}
	})

	// The advertisement flows from the RPC response through the SAME mapper the
	// virtualization probe uses; the field is carried verbatim, spaces and all.
	t.Run("facts_flow_from_the_runtime_info_seam", func(t *testing.T) {
		facts := capableFacts()
		caps := provider.NodeCapabilities{GPU: facts}
		n := &corev1.Node{}
		applyGPUAdvertisement(n, caps.GPU)
		wantGPUQuantity(t, n, gpuDeviceCount)
		if facts.GetChipBrand() != "Apple M4 Max" {
			t.Errorf("the advertiser must not mutate the raw facts: chip_brand = %q", facts.GetChipBrand())
		}
	})
}
