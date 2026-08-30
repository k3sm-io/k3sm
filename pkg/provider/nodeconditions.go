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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Node-pressure helpers: a pure, side-effect-free reduction of a node-resource
// snapshot to the kubelet's node-pressure / network NodeConditions, plus the
// equally pure transition reconciler that turns two consecutive reductions into
// the slice actually published.
//
// The split is deliberate and load-bearing:
//
//   - computeNodeConditions is STATELESS. It sees one snapshot and emits the raw
//     verdict for it. No syscalls, no time.Now, no I/O, no memory of the past.
//   - reconcileTransitions is where every fact about the PREVIOUS publication
//     lives: LastTransitionTime preservation, and the DiskPressure Schmitt
//     trigger (trip low, clear high) that a single snapshot cannot express.
//
// Sampling lives elsewhere (nodesample_darwin.go fills a hostStats from
// host_statistics64, statfs and sysctl); the node-status loop in nodestatus.go
// drives both functions and publishes the result. Keeping the threshold math
// hermetic here lets every boundary be pinned by a faked snapshot with no
// privilege and no host.
//
// HONEST LIMITATION, true of every condition below: these signals are
// HOST-SHARED. k3sm runs pods as native Darwin processes on a Mac that is also
// somebody's desktop, so memory, disk and the process table are all consumed by
// software k3sm neither owns nor can reclaim. A condition here reports the state
// of the MACHINE, not of a k3sm-exclusive resource pool.
//
// HONEST LIMITATION, second: k3sm has no eviction manager. A True pressure
// condition is an ADVERTISEMENT — it makes the node-lifecycle controller apply
// the matching NoSchedule taint, and nothing more. No pod is ranked, evicted, or
// restarted to relieve it, so the taint is ABSORBING: it persists until a human
// (or, for the image store, the runtime's own garbage collector) frees space.
// Nothing in this file promises eviction, and callers must not read it as such.
//
// Allocatable and the system reserve are deliberately NOT computed here; they
// are derived from the node's published Capacity at registration.

// memAvailableHardEvictionBytes is the upstream kubelet hard-eviction default for
// the memory.available signal — `memory.available<100Mi`. We mirror the absolute
// floor exactly (100 * 1024 * 1024 = 104857600 bytes) rather than a percentage,
// because that is the upstream contract for this signal.
const memAvailableHardEvictionBytes int64 = 100 * 1024 * 1024

// diskPressureTripFreeBytes is the ABSOLUTE free-space floor below which k3sm
// raises DiskPressure on the volume backing the node's data root. It is an
// absolute figure, not a percentage of the volume: k3sm shares one APFS volume
// with a human's $HOME, Xcode caches and simulators, where a routine steady state
// is well under any sane percentage floor — a percentage would NoSchedule-taint a
// perfectly healthy dev Mac, and with no eviction manager to relieve it (see the
// package note above) that taint never clears on its own.
//
// 2 GiB is chosen to sit BELOW the image garbage collector's own reclaim band, so
// the GC fires first by construction and DiskPressure is the rare backstop rather
// than the primary control. It is a reasoned round number and the single figure
// here most likely to want tuning against real fill behaviour.
//
// We deliberately add NO independent inodesFree signal: APFS reports f_ffree as a
// function of free space, so an inode threshold would be redundant with this one.
const diskPressureTripFreeBytes int64 = 2 << 30

// diskPressureClearFreeBytes is the free-space level at or above which an already
// raised DiskPressure clears — the high edge of a Schmitt trigger whose low edge
// is diskPressureTripFreeBytes. The gap between the two is the whole point: a node
// hovering at the trip point would otherwise flap True/False every status
// interval, and each flap adds and removes a NoSchedule taint cluster-wide.
//
// It matches the image garbage collector's own recovery target, so the condition
// cannot flap against an in-progress reclaim: the GC stops freeing at exactly the
// level that clears this condition.
const diskPressureClearFreeBytes int64 = 10 << 30

// pidPressureUsedPercent is the fraction, in percent, of the SYSTEMWIDE process
// ceiling above which k3sm raises PIDPressure. Upstream Kubernetes ships NO
// default pid.available eviction threshold, so this is a k3sm-specific default,
// not a "kubelet default".
//
// The denominator is kern.maxproc — the machine's global process table — because
// that is the wall that actually stops a pod from forking. It is the honest
// choice for a node that shares its process table with a human's login session:
// the per-uid ceiling (kern.maxprocperuid) can be nowhere near exhausted on a
// machine that nonetheless cannot spawn, and the per-uid figure varies by an
// order of magnitude across Macs. A per-uid leg scoped to k3sm's own service
// account is a separate, additive signal and is not sampled here.
const pidPressureUsedPercent int64 = 90

// The DiskPressure Reason/Message literals. They are named because BOTH
// computeNodeConditions (which raises the condition) and reconcileTransitions
// (which HOLDS it raised across the hysteresis band) must emit exactly the same
// strings; two hand-written copies are how the held state comes to read
// differently from the raised state.
const (
	diskPressureReason    = "KubeletHasDiskPressure"
	diskPressureMessage   = "kubelet has disk pressure"
	noDiskPressureReason  = "KubeletHasNoDiskPressure"
	noDiskPressureMessage = "kubelet has no disk pressure"
)

// hostStats is the k3sm-local snapshot of node-level resource availability that
// computeNodeConditions reduces to NodeConditions. It is the injection seam:
// computeNodeConditions is pure over this struct and the live Darwin sampler
// fills it. Keeping the struct here — not the syscalls — lets the pressure math
// be unit-tested with a faked snapshot and zero privilege.
type hostStats struct {
	// MemAvailableBytes is the memory a new workload could actually obtain:
	// MemCapacityBytes MINUS the working set, where the working set is
	//
	//	(wire_count + internal_page_count - purgeable_count + compressor_page_count) * pageSize
	//
	// from a single host_statistics64(HOST_VM_INFO64) reading. This is the
	// capacity-minus-working-set shape of the upstream kubelet's
	// `memory.available`, expressed in the page classes Darwin actually exposes.
	//
	// Two page classes are deliberately ABSENT, and both absences are load-bearing:
	//
	//   - speculative_count is NEVER added. mach/vm_statistics.h states that
	//     speculative pages are ALREADY accounted for inside free_count, and
	//     host_statistics64 returns the raw free_count (vm_stat(1) is what
	//     subtracts them for display). Adding them would double-count, with an
	//     error that GROWS during heavy file I/O — precisely when a node is
	//     approaching real pressure.
	//   - `inactive` is never added wholesale. Darwin's inactive queue mixes clean
	//     file-backed pages (genuinely reclaimable) with DIRTY ANONYMOUS pages
	//     that cannot be freed at all, only compressed or swapped, and
	//     host_statistics64 exposes no clean/dirty split of it. Counting the
	//     queue whole overstates availability by more than 2x on a real host.
	//
	// external_page_count is likewise absent from the working set: file-backed
	// pages fall on the AVAILABLE side by construction in this formulation.
	MemAvailableBytes int64
	// MemCapacityBytes is total physical memory (hw.memsize). It does not gate
	// MemoryPressure directly (the upstream default is an absolute <100Mi floor,
	// not a percentage) — it is the minuend of the MemAvailableBytes formula
	// above. The node's advertised Capacity/Allocatable are computed separately at
	// registration from the same host fact.
	MemCapacityBytes int64
	// DiskAvailableBytes is free bytes on the volume backing the node's data root
	// — the image store, the writable pod layers, and the co-located datastore all
	// live there. Sourced from statfs (f_bavail*f_bsize), so it is the
	// unprivileged-user free figure, not the root reserve.
	DiskAvailableBytes int64
	// DiskCapacityBytes is the total size of that same volume (f_blocks*f_bsize).
	// The DiskPressure threshold is absolute, so this value is not a denominator;
	// it is the SAMPLED WITNESS. A zero here means "not yet sampled" and is
	// treated as no pressure, which is what keeps an unsampled snapshot (where
	// DiskAvailableBytes is also zero) from reading as a full disk.
	DiskCapacityBytes int64
	// PIDCount is the current number of processes in the machine's global process
	// table, counted from a size-only kern.proc query. The kernel's size answer
	// carries a small slack allowance over the true count (single digits on a
	// live host), so this figure is a slight OVER-estimate — the safe direction
	// for a pressure signal.
	PIDCount int64
	// PIDMax is the systemwide process ceiling, kern.maxproc. A zero value means
	// "not yet sampled" and is treated as no pressure.
	PIDMax int64
}

// computeNodeConditions reduces a hostStats snapshot to the node's four
// pressure / network NodeConditions at instant now. It is PURE and STATELESS: no
// syscalls, no time.Now (now is injected by the caller), no I/O, and no knowledge
// of any previous snapshot — every field of every returned condition is a
// deterministic function of (s, now).
//
// The verdicts it returns are RAW: the DiskPressure verdict here is the trip-edge
// answer only. Hysteresis (holding DiskPressure True until free space recovers to
// diskPressureClearFreeBytes) and LastTransitionTime preservation both need the
// previously published conditions, so both live in reconcileTransitions. A caller
// that publishes this function's output directly gets a correct but FLAPPING
// DiskPressure and a LastTransitionTime that churns every heartbeat.
//
// Every returned condition carries an EXPLICIT Status — corev1.ConditionTrue or
// corev1.ConditionFalse, never the zero-value "". An empty Status is reported as
// ConditionUnknown by node-status consumers, which would, for MemoryPressure,
// make the scheduler treat a perfectly healthy node as under pressure. Both the
// True and False branches therefore set Status, Reason, and Message explicitly.
func computeNodeConditions(s hostStats, now metav1.Time) []corev1.NodeCondition {
	// MemoryPressure: True iff available memory is below the upstream
	// memory.available<100Mi hard-eviction floor.
	mem := corev1.NodeCondition{
		Type:               corev1.NodeMemoryPressure,
		Status:             corev1.ConditionFalse,
		Reason:             "KubeletHasSufficientMemory",
		Message:            "kubelet has sufficient memory available",
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if s.MemAvailableBytes < memAvailableHardEvictionBytes {
		mem.Status = corev1.ConditionTrue
		mem.Reason = "KubeletHasInsufficientMemory"
		mem.Message = "kubelet has insufficient memory available"
	}

	// DiskPressure: the TRIP edge only — True iff free space on the data-root
	// volume is below the absolute diskPressureTripFreeBytes floor. The clear edge
	// is reconcileTransitions'. A zero (unsampled) capacity is no pressure rather
	// than a comparison against a snapshot that was never taken.
	disk := corev1.NodeCondition{
		Type:               corev1.NodeDiskPressure,
		Status:             corev1.ConditionFalse,
		Reason:             noDiskPressureReason,
		Message:            noDiskPressureMessage,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if s.DiskCapacityBytes > 0 && s.DiskAvailableBytes < diskPressureTripFreeBytes {
		disk.Status = corev1.ConditionTrue
		disk.Reason = diskPressureReason
		disk.Message = diskPressureMessage
	}

	// PIDPressure: True iff systemwide PID usage exceeds pidPressureUsedPercent of
	// kern.maxproc. Cross-multiply to avoid floating point; guard a zero
	// (unsampled) PIDMax.
	pid := corev1.NodeCondition{
		Type:               corev1.NodePIDPressure,
		Status:             corev1.ConditionFalse,
		Reason:             "KubeletHasSufficientPID",
		Message:            "kubelet has sufficient PID available",
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if s.PIDMax > 0 && s.PIDCount*100 > s.PIDMax*pidPressureUsedPercent {
		pid.Status = corev1.ConditionTrue
		pid.Reason = "KubeletHasInsufficientPID"
		pid.Message = "kubelet has insufficient PID available"
	}

	// NetworkUnavailable: always False. k3sm sets this statically — the node's
	// lo0 pod network is up by the time the node registers, and there is no
	// route-controller or CNI whose readiness it could reflect. A cross-node
	// wireguard mesh partition is deliberately NOT surfaced here: this condition
	// is about the local node network, and conflating it with mesh reachability
	// would falsely NotReady a node whose own pods are fine. The "RouteCreated"
	// reason mirrors the string upstream node controllers recognize as "network
	// is configured".
	network := corev1.NodeCondition{
		Type:               corev1.NodeNetworkUnavailable,
		Status:             corev1.ConditionFalse,
		Reason:             "RouteCreated",
		Message:            "k3sm node network is configured",
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}

	return []corev1.NodeCondition{mem, disk, pid, network}
}

// reconcileTransitions turns the raw verdicts in next into the slice that is
// actually published, given the conditions published last time (prev, nil on the
// first pass) and the snapshot s that next was computed from. It is PURE: it
// mutates neither argument and returns a fresh slice.
//
// It owns exactly two things, both of which are statements about HISTORY and so
// cannot live in the stateless computeNodeConditions:
//
//  1. The DiskPressure Schmitt trigger. computeNodeConditions raises DiskPressure
//     below diskPressureTripFreeBytes; this function HOLDS it raised until free
//     space recovers to diskPressureClearFreeBytes. Between the two levels the
//     previous verdict wins in BOTH directions — a node on the way down stays
//     False until it crosses the trip floor, and a node on the way up stays True
//     until it crosses the clear level.
//  2. LastTransitionTime preservation. computeNodeConditions stamps every
//     condition with now, which is correct only for a condition that just
//     changed. Emitting it verbatim every heartbeat would restart "time under
//     pressure" on each sample and break any controller keyed off it, so an
//     unchanged Status keeps the previous LastTransitionTime.
//
// s is the snapshot next was computed from. It is a parameter because the
// hysteresis band is a statement about a NUMBER (free bytes), and a boolean
// condition has already thrown that number away: prev and next alone cannot tell
// "recovered to 3 GiB" from "recovered to 30 GiB". An unsampled snapshot
// (DiskCapacityBytes == 0) is outside the band, so a sampler failure clears a
// held condition rather than pinning it True forever.
func reconcileTransitions(prev, next []corev1.NodeCondition, s hostStats) []corev1.NodeCondition {
	out := make([]corev1.NodeCondition, len(next))
	copy(out, next)
	for i := range out {
		p := findNodeCondition(prev, out[i].Type)
		if out[i].Type == corev1.NodeDiskPressure && p != nil &&
			p.Status == corev1.ConditionTrue && out[i].Status == corev1.ConditionFalse &&
			diskInHysteresisBand(s) {
			// Held, not re-raised: the node is still short of the clear level, so it
			// reports the SAME Reason/Message it reported when it tripped. A distinct
			// "recovering" vocabulary would be a second string for one node state, and
			// consumers key off Status, not prose.
			out[i].Status = corev1.ConditionTrue
			out[i].Reason = diskPressureReason
			out[i].Message = diskPressureMessage
		}
		if p != nil && p.Status == out[i].Status {
			out[i].LastTransitionTime = p.LastTransitionTime
		}
	}
	return out
}

// diskInHysteresisBand reports whether s sits below the DiskPressure clear level
// on a volume that was actually sampled — i.e. whether an already-raised
// DiskPressure must stay raised. It is false for an unsampled snapshot, so a
// sampler failure can never wedge the condition True.
func diskInHysteresisBand(s hostStats) bool {
	return s.DiskCapacityBytes > 0 && s.DiskAvailableBytes < diskPressureClearFreeBytes
}

// findNodeCondition returns a pointer to the condition of type typ in conds, or
// nil when it is absent. The returned pointer aliases conds; callers read it and
// must not mutate through it.
func findNodeCondition(conds []corev1.NodeCondition, typ corev1.NodeConditionType) *corev1.NodeCondition {
	for i := range conds {
		if conds[i].Type == typ {
			return &conds[i]
		}
	}
	return nil
}
