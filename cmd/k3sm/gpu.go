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
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// gpuResourceName is the mlx.k3sm.io/gpu extended resource as a corev1.ResourceName.
// The string comes from apis and is never respelled here: every consumer (this
// advertiser, the operator that requests it, the scheduler predicates) must agree on
// the exact byte string, and a literal in one consumer is a second source of truth
// that compiles perfectly while being wrong.
const gpuResourceName = corev1.ResourceName(mlxv1alpha1.ResourceGPU)

// gpuDeviceCount is how many units of mlx.k3sm.io/gpu a capable node advertises.
// Apple Silicon exposes ONE integrated GPU per host — GPUFacts carries no device
// count because there is nothing to count — so this is 1 by construction, not a
// tunable. Advertising 1 makes the resource a MUTEX: the second GPU pod stays
// Pending rather than contending for the same Metal device with the first.
const gpuDeviceCount int64 = 1

// bytesPerGiB converts GPUFacts.mem_bytes to the whole-gibibyte label value.
const bytesPerGiB = 1 << 30

// maxLabelValueLen is the Kubernetes label-value length limit the chip slug is
// truncated to (step 4 of the apis chip-slug rule).
const maxLabelValueLen = 63

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
// facts nil means the daemon reports no GPU facts at all (a daemon predating them),
// which is DISTINCT from a report of a host with no usable GPU. Both advertise
// nothing here, but only because "unknown" and "known absent" happen to share the
// fail-closed answer; the distinction is preserved in the log line, since only one of
// the two is fixed by upgrading the daemon.
func applyGPUAdvertisement(n *corev1.Node, facts *runtimev1.GPUFacts) {
	present := gpuAdvertisable(facts)
	setGPUResource(n, present)
	setLabelPresence(n, mlxv1alpha1.LabelGPUPresent, present)
	// The three descriptive labels ride the SAME verdict as the presence label rather
	// than their own emptiness checks: a node that is not advertising a GPU must not
	// carry a chip label either, or a selector on the chip alone would bind a pod to a
	// node whose GPU was withheld.
	setLabelValue(n, mlxv1alpha1.LabelChip, gpuLabelValue(present, chipSlug(facts.GetChipBrand())))
	setLabelValue(n, mlxv1alpha1.LabelChipFamily, gpuLabelValue(present, chipSlug(facts.GetChipFamily())))
	setLabelValue(n, mlxv1alpha1.LabelMemoryGB, gpuLabelValue(present, memoryGiBLabel(facts.GetMemBytes())))
	if present {
		slog.Debug("node GPU advertised",
			"resource", mlxv1alpha1.ResourceGPU, "count", gpuDeviceCount,
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
	return facts.GetMetalAvailable() && facts.GetSandboxGpuSupported()
}

// gpuLabelValue gates a derived label value on the advertisement verdict, returning
// "" (which setLabelValue deletes) whenever the GPU is not advertised.
func gpuLabelValue(present bool, value string) string {
	if !present {
		return ""
	}
	return value
}

// setGPUResource adds gpuDeviceCount of mlx.k3sm.io/gpu to the node's Capacity AND
// Allocatable, or deletes it from both. Both lists matter: the scheduler fits pods
// against Allocatable, while Capacity is what an operator reads — advertising only
// one makes `kubectl describe node` and the scheduler disagree.
//
// Allocatable gets the FULL count with no hold-back, unlike memory (see
// nodeAllocatable): there is exactly one integrated GPU and no co-located control
// plane component reserves a share of it, so any carve-out would simply strand it.
func setGPUResource(n *corev1.Node, present bool) {
	if !present {
		// delete on a nil map is a no-op, so this needs no guard — and it is what
		// makes a node that LOST the capability stop advertising it.
		delete(n.Status.Capacity, gpuResourceName)
		delete(n.Status.Allocatable, gpuResourceName)
		return
	}
	n.Status.Capacity = withResource(n.Status.Capacity, gpuResourceName, gpuDeviceCount)
	n.Status.Allocatable = withResource(n.Status.Allocatable, gpuResourceName, gpuDeviceCount)
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

// chipSlug normalizes a raw GPUFacts chip fact ("Apple M4 Max") into the label-value
// slug ("apple-m4-max") the mlx.k3sm.io/chip and /chip-family keys carry, implementing
// the chip-slug rule documented on the apis label constants: lowercase, every run of
// non-[a-z0-9] to a single "-", trim leading/trailing "-", truncate to 63 and re-trim.
//
// The derivation lives HERE, in the single consumer that both holds the raw host facts
// and advertises the node, exactly as the apis rule prescribes — apis owns the KEY and
// the value SHAPE, not the transformation. A caller must never compare a label value
// against a raw chip_brand: the raw fact is not the slug and the comparison silently
// never matches.
func chipSlug(raw string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(raw) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if pendingDash {
				b.WriteByte('-')
				pendingDash = false
			}
			b.WriteRune(r)
			continue
		}
		// A run of non-alphanumerics collapses to ONE dash, and a dash is only
		// emitted once an alphanumeric follows it — which trims the leading and
		// trailing runs without a second pass.
		if b.Len() > 0 {
			pendingDash = true
		}
	}
	s := b.String()
	if len(s) > maxLabelValueLen {
		s = strings.TrimRight(s[:maxLabelValueLen], "-")
	}
	return s
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
