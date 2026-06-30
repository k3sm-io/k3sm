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
// snapshot to the kubelet's node-pressure / network NodeConditions. They encode
// the eviction-signal thresholds WITHOUT performing any sampling — no syscalls,
// no time.Now, no I/O.
//
// Currently unwired by design, mirroring B8's restartpolicy.go / B26. The live
// VK node-status loop does not yet publish these conditions. Item B27
// (depends_on B15) is the consumer that samples the live Darwin sources into a
// hostStats — host_statistics64 for memory, unix.Statfs for the shared APFS
// volume, kern.maxprocperuid plus a per-uid process count for PIDs — and
// publishes computeNodeConditions on the periodic status loop. Splitting the
// threshold math (here, hermetically testable) from the sampling (B27, which
// needs the host) lets the pressure boundaries be pinned by a faked snapshot
// with no privilege, and lets B27 wire the live read atomically.
//
// Allocatable and the system reserve are deliberately NOT computed here; that is
// item B41 (depends_on B13). B15 is the conditions helper only.

// memAvailableHardEvictionBytes is the upstream kubelet hard-eviction default for
// the memory.available signal — `memory.available<100Mi`. We mirror the absolute
// floor exactly (100 * 1024 * 1024 = 104857600 bytes) rather than a percentage,
// because that is the upstream contract for this signal.
const memAvailableHardEvictionBytes int64 = 100 * 1024 * 1024

// diskPressureFreePercent is the free-space floor, in percent, below which k3sm
// raises DiskPressure on its single shared APFS volume. It is one documented
// threshold (15% free) — NOT the upstream pair of nodefs/imagefs signals —
// because k3sm co-locates the image store, the writable pod layers, AND the kine
// state.db on one volume; a single conservative floor shields the datastore from
// a pod filling the disk. We deliberately add NO independent inodesFree signal:
// APFS reports f_ffree as a function of free space, so an inode threshold would
// be redundant with this one.
const diskPressureFreePercent int64 = 15

// pidPressureUsedPercent is the fraction, in percent, of the per-uid process
// ceiling above which k3sm raises PIDPressure. Upstream Kubernetes ships NO
// default pid.available eviction threshold, so this is a k3sm-specific default,
// not a "kubelet default": every pod process runs under the one shared _k3sm
// service uid, so the binding limit is kern.maxprocperuid (~1067 on macOS), a
// single hard wall the whole node shares. 90% used leaves headroom to react
// before that wall blocks fork() cluster-wide.
const pidPressureUsedPercent int64 = 90

// hostStats is the k3sm-local snapshot of node-level resource availability that
// computeNodeConditions reduces to NodeConditions. It is the injection seam:
// computeNodeConditions is pure over this struct, and item B27 fills it from the
// live Darwin sources. Keeping the struct here — not the syscalls — lets the
// pressure math be unit-tested with a faked snapshot and zero privilege.
type hostStats struct {
	// MemAvailableBytes is reclaimable-inclusive available memory, matching the
	// upstream kubelet eviction signal `memory.available`: free PLUS inactive
	// PLUS purgeable PLUS speculative pages — every page the kernel can reclaim
	// under pressure — which is exactly what the kubelet's eviction manager
	// uses. It is explicitly NOT the macOS `vm_stat` "Pages free" figure alone:
	// on a healthy Mac free-pages-only is routinely well under 100Mi (the kernel
	// keeps memory warm on purpose), so feeding free-pages-only here would peg
	// MemoryPressure True forever and evict every pod. B27's adapter MUST sum
	// free + inactive + purgeable + speculative to honor this contract.
	MemAvailableBytes int64
	// MemCapacityBytes is total physical memory (hw.memsize). It does not gate
	// MemoryPressure (the upstream default is an absolute <100Mi floor, not a
	// percentage); it is carried for the Allocatable reserve (item B41) and for
	// surfacing node Capacity.
	MemCapacityBytes int64
	// DiskAvailableBytes is free bytes on the single shared APFS volume backing
	// the node — the image store, the writable pod layers, and the co-located
	// kine state.db all live there. Sourced from unix.Statfs (f_bavail*f_bsize).
	DiskAvailableBytes int64
	// DiskCapacityBytes is the total size of that same volume
	// (f_blocks*f_bsize). A zero value means "not yet sampled" and is treated as
	// no pressure by computeNodeConditions.
	DiskCapacityBytes int64
	// PIDCount is the current number of processes owned by the node's _k3sm
	// service uid. Because every pod process shares that one uid, this single
	// count covers the whole node.
	PIDCount int64
	// PIDMax is the per-uid process ceiling, kern.maxprocperuid (~1067 on
	// macOS). As all pods run under the one shared _k3sm uid, this single wall —
	// not a global proc table — is the binding PID limit for the node. A zero
	// value means "not yet sampled" and is treated as no pressure.
	PIDMax int64
}

// computeNodeConditions reduces a hostStats snapshot to the node's four
// pressure / network NodeConditions at instant now. It is PURE: no syscalls, no
// time.Now (now is injected by the caller), no I/O — every field of every
// returned condition is a deterministic function of (s, now). This is item B15's
// unwired decision core; item B27 samples the live host into s and publishes the
// result on the VK node-status loop.
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

	// DiskPressure: True iff free space on the shared APFS volume is below
	// diskPressureFreePercent. Cross-multiply to avoid floating point; guard a
	// zero (unsampled) capacity as no pressure rather than comparing against an
	// unknown denominator.
	disk := corev1.NodeCondition{
		Type:               corev1.NodeDiskPressure,
		Status:             corev1.ConditionFalse,
		Reason:             "KubeletHasNoDiskPressure",
		Message:            "kubelet has no disk pressure",
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if s.DiskCapacityBytes > 0 && s.DiskAvailableBytes*100 < s.DiskCapacityBytes*diskPressureFreePercent {
		disk.Status = corev1.ConditionTrue
		disk.Reason = "KubeletHasDiskPressure"
		disk.Message = "kubelet has disk pressure"
	}

	// PIDPressure: True iff PID usage exceeds pidPressureUsedPercent of the
	// per-uid ceiling. Cross-multiply; guard a zero (unsampled) PIDMax.
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
