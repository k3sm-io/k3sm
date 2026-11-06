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
	"log/slog"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"

	"k3sm.io/k3sm/pkg/gpucapacity"
)

// gpuResourceName is the mlx.k3sm.io/gpu extended resource as a corev1.ResourceName.
// The string comes from apis and is never respelled here: every consumer (this
// advertiser, the operator that requests it, the scheduler predicates) must agree on
// the exact byte string, and a literal in one consumer is a second source of truth
// that compiles perfectly while being wrong.
const gpuResourceName = corev1.ResourceName(mlxv1alpha1.ResourceGPU)

// bytesPerGiB converts GPUFacts.mem_bytes to the whole-gibibyte label value.
const bytesPerGiB = 1 << 30

// applyGPUAdvertisement advertises — or REMOVES — this node's GPU: the
// mlx.k3sm.io/gpu extended resource in both Capacity and Allocatable, plus the
// mlx.k3sm.io presence/chip/chip-family/memory labels. It is the MLX counterpart of
// applyVirtualizationLabel and follows the same delete-on-loss discipline: a node
// that LOSES the capability across a restart must stop advertising it, in the
// resource as well as the labels, or the scheduler keeps binding GPU pods to a node
// that can no longer run them.
//
// It is FAIL-CLOSED on a conjunction of two INDEPENDENT facts, and both are load
// bearing:
//
//   - metal_available — the host has a Metal device the daemon can open;
//   - sandbox_gpu_supported — the CURRENTLY-SELECTED sandbox backend can grant a pod
//     GPU access at all.
//
// Neither implies the other (the same Mac supports GPU pods under one backend and not
// another), so advertising on metal_available alone would attract MLX workloads to a
// node whose sandbox denies every one of them at admission — a fail-OPEN mislabel.
//
// HOW MANY is a separate question from WHETHER, and it is not answered here: the
// count comes from gpucapacity.GPUSlots over the same facts (N is 1 or 2, from the host's
// usable GPU memory ceiling). The one arithmetic serves both this advertiser and the
// provider's admission-time fit check, which is what keeps the scheduler from binding
// a pod the node then refuses.
//
// facts nil means the daemon reports no GPU facts at all (a daemon predating them),
// which is DISTINCT from a report of a host with no usable GPU. Both advertise
// nothing here, but only because "unknown" and "known absent" happen to share the
// fail-closed answer; the distinction is preserved in the log line, since only one of
// the two is fixed by upgrading the daemon.
func applyGPUAdvertisement(n *corev1.Node, facts *runtimev1.GPUFacts) {
	present := gpuAdvertisable(facts)
	slots := gpucapacity.GPUSlots(facts)
	setGPUResource(n, present, slots)
	setLabelPresence(n, mlxv1alpha1.LabelGPUPresent, present)
	// The three descriptive labels ride the SAME verdict as the presence label rather
	// than their own emptiness checks: a node that is not advertising a GPU must not
	// carry a chip label either, or a selector on the chip alone would bind a pod to a
	// node whose GPU was withheld.
	setLabelValue(n, mlxv1alpha1.LabelChip, gpuLabelValue(present, runtimev1.ChipSlug(facts.GetChipBrand())))
	setLabelValue(n, mlxv1alpha1.LabelChipFamily, gpuLabelValue(present, runtimev1.ChipSlug(facts.GetChipFamily())))
	setLabelValue(n, mlxv1alpha1.LabelMemoryGB, gpuLabelValue(present, memoryGiBLabel(facts.GetMemBytes())))
	if present {
		slog.Debug("node GPU advertised",
			"resource", mlxv1alpha1.ResourceGPU, "count", slots,
			"gpu_ceiling_bytes", gpucapacity.GPUCeilingBytes(facts),
			"chip_brand", facts.GetChipBrand(), "chip_family", facts.GetChipFamily())
		return
	}
	if facts == nil {
		slog.Info("node GPU withheld: runtimed reports no GPU facts (a daemon predating them); failing closed",
			"resource", mlxv1alpha1.ResourceGPU)
		return
	}
	slog.Info("node GPU withheld: advertising needs BOTH a usable Metal device and a sandbox backend that can grant GPU access",
		"resource", mlxv1alpha1.ResourceGPU,
		"metal_available", facts.GetMetalAvailable(),
		"sandbox_gpu_supported", facts.GetSandboxGpuSupported())
}

// gpuAdvertisable reports whether facts justify advertising a GPU on this node: a
// usable Metal device AND a sandbox backend that can grant a pod GPU access. It is
// pure and nil-safe (the proto getters are), so the fail-closed verdict is unit-tested
// without a live runtimed.
func gpuAdvertisable(facts *runtimev1.GPUFacts) bool {
	return gpucapacity.GPUAdvertisable(facts)
}

// gpuLabelValue gates a derived label value on the advertisement verdict, returning
// "" (which setLabelValue deletes) whenever the GPU is not advertised.
func gpuLabelValue(present bool, value string) string {
	if !present {
		return ""
	}
	return value
}

// setGPUResource adds slots units of mlx.k3sm.io/gpu to the node's Capacity AND
// Allocatable, or deletes it from both. Both lists matter: the scheduler fits pods
// against Allocatable, while Capacity is what an operator reads — advertising only
// one makes `kubectl describe node` and the scheduler disagree.
//
// SLOTS ARE CO-TENANTS, NOT DEVICES. N (1 or 2, see gpucapacity.GPUSlots) says this node's
// GPU memory holds N floor-sized workloads under benign co-tenancy; it does not say
// the workloads are isolated from each other, because there is one integrated GPU and
// they share it. That is the same distinction DESIGN §5a draws for CPU, and it is why
// the memory fit is re-checked at admission rather than being trusted to the slot
// count alone.
//
// Allocatable gets the FULL count with no hold-back, unlike memory (see
// nodeAllocatable): no co-located control-plane component reserves a share of GPU
// memory, so a carve-out here would strand capacity nothing else is going to claim.
// The reasoning does not rest on N being 1 — it holds at any N, because the thing
// being reserved for is absent, not small.
//
// A DAEMON RESTART MAY LOWER N below what is already bound (a changed iogpu limit, a
// working set that now reads smaller). Kubernetes tolerates an Allocatable that drops
// below what is committed: the bound pods keep running and the scheduler simply stops
// fitting new ones until the arithmetic works again. That is the same direction as the
// delete-on-loss discipline above, one step short of it.
func setGPUResource(n *corev1.Node, present bool, slots int64) {
	if !present {
		// delete on a nil map is a no-op, so this needs no guard — and it is what
		// makes a node that LOST the capability stop advertising it.
		delete(n.Status.Capacity, gpuResourceName)
		delete(n.Status.Allocatable, gpuResourceName)
		return
	}
	n.Status.Capacity = withResource(n.Status.Capacity, gpuResourceName, slots)
	n.Status.Allocatable = withResource(n.Status.Allocatable, gpuResourceName, slots)
}

// withResource sets name=count (DecimalSI, the form an integer extended resource is
// spelled in) on list, allocating the list when nil, and returns it. Each call mints
// its OWN Quantity so two lists never share one value.
func withResource(list corev1.ResourceList, name corev1.ResourceName, count int64) corev1.ResourceList {
	if list == nil {
		list = corev1.ResourceList{}
	}
	list[name] = *resource.NewQuantity(count, resource.DecimalSI)
	return list
}

// setLabelValue stamps key=value on n, and DELETES key when value is empty — the
// value-carrying sibling of setLabelPresence, sharing its delete-never-blank
// discipline. An empty label value is legal Kubernetes but meaningless as a fact, and
// leaving a stale value behind is worse: a chip label that survives the loss of the
// GPU it describes is a lie a nodeSelector still matches.
func setLabelValue(n *corev1.Node, key, value string) {
	labels := nodeLabels(n)
	if value == "" {
		delete(labels, key)
		slog.Debug("node label absent: no value to advertise, so the key is DELETED", "label", key)
		return
	}
	labels[key] = value
}

// memoryGiBLabel renders mem_bytes as the whole-gibibyte decimal string the
// mlx.k3sm.io/memory-gb label carries — no unit suffix and no fractional spelling, so
// two nodes with identical memory cannot carry non-matching values. It returns "" for
// anything under 1GiB (including 0, the unread-fact value), so the label is deleted
// rather than advertising a "0" no selector should ever match.
func memoryGiBLabel(memBytes uint64) string {
	gib := memBytes / bytesPerGiB
	if gib == 0 {
		return ""
	}
	return strconv.FormatUint(gib, 10)
}
