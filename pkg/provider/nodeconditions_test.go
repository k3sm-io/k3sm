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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestComputeNodeConditionsPressure is item B15's gate: it pins the pure
// node-pressure helper over a FAKED hostStats (no Statfs / sysctl / Mach in the
// test). For each of Memory/Disk/PID it drives a snapshot just below, at, and
// just above the threshold to prove the exact (and direction-correct) boundary
// math; it asserts every healthy condition is an EXPLICIT corev1.ConditionFalse
// (never the zero-value ""), the exact Kubelet* Reason literals on both the True
// and False branches, that NetworkUnavailable is always False, and that the
// heartbeat/transition timestamps echo the injected now.
func TestComputeNodeConditionsPressure(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))

	// healthy sits well clear of every threshold: gigabytes of reclaimable
	// memory, 85% disk free, a handful of the ~1067 PID wall used. Per-signal
	// subtests clone it and perturb exactly one field.
	healthy := hostStats{
		MemAvailableBytes:  8 << 30, // 8 GiB, far above the 100Mi floor
		MemCapacityBytes:   16 << 30,
		DiskAvailableBytes: 850,
		DiskCapacityBytes:  1000, // 85% free
		PIDCount:           50,
		PIDMax:             1000, // 5% used
	}

	t.Run("all healthy: every condition explicitly False", func(t *testing.T) {
		conds := computeNodeConditions(healthy, now)
		if len(conds) != 4 {
			t.Fatalf("got %d conditions, want 4: %+v", len(conds), conds)
		}
		checkCond(t, conds, corev1.NodeMemoryPressure, corev1.ConditionFalse,
			"KubeletHasSufficientMemory", "kubelet has sufficient memory available", now)
		checkCond(t, conds, corev1.NodeDiskPressure, corev1.ConditionFalse,
			"KubeletHasNoDiskPressure", "kubelet has no disk pressure", now)
		checkCond(t, conds, corev1.NodePIDPressure, corev1.ConditionFalse,
			"KubeletHasSufficientPID", "kubelet has sufficient PID available", now)
		checkCond(t, conds, corev1.NodeNetworkUnavailable, corev1.ConditionFalse,
			"RouteCreated", "k3sm node network is configured", now)
	})

	t.Run("MemoryPressure threshold (<100Mi -> True)", func(t *testing.T) {
		const thr = memAvailableHardEvictionBytes // 104857600
		cases := []struct {
			name       string
			avail      int64
			wantStatus corev1.ConditionStatus
			wantReason string
			wantMsg    string
		}{
			{"just below 100Mi -> pressure", thr - 1, corev1.ConditionTrue,
				"KubeletHasInsufficientMemory", "kubelet has insufficient memory available"},
			{"exactly 100Mi -> no pressure (strict <)", thr, corev1.ConditionFalse,
				"KubeletHasSufficientMemory", "kubelet has sufficient memory available"},
			{"just above 100Mi -> no pressure", thr + 1, corev1.ConditionFalse,
				"KubeletHasSufficientMemory", "kubelet has sufficient memory available"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := healthy
				s.MemAvailableBytes = tc.avail
				checkCond(t, computeNodeConditions(s, now), corev1.NodeMemoryPressure,
					tc.wantStatus, tc.wantReason, tc.wantMsg, now)
			})
		}
	})

	t.Run("DiskPressure threshold (<15% free -> True)", func(t *testing.T) {
		// Capacity 1000 -> 15% free is exactly 150 available bytes.
		cases := []struct {
			name       string
			avail      int64
			wantStatus corev1.ConditionStatus
			wantReason string
			wantMsg    string
		}{
			{"just below 15% free -> pressure", 149, corev1.ConditionTrue,
				"KubeletHasDiskPressure", "kubelet has disk pressure"},
			{"exactly 15% free -> no pressure (strict <)", 150, corev1.ConditionFalse,
				"KubeletHasNoDiskPressure", "kubelet has no disk pressure"},
			{"just above 15% free -> no pressure", 151, corev1.ConditionFalse,
				"KubeletHasNoDiskPressure", "kubelet has no disk pressure"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := healthy
				s.DiskCapacityBytes = 1000
				s.DiskAvailableBytes = tc.avail
				checkCond(t, computeNodeConditions(s, now), corev1.NodeDiskPressure,
					tc.wantStatus, tc.wantReason, tc.wantMsg, now)
			})
		}
	})

	t.Run("PIDPressure threshold (>90% used -> True)", func(t *testing.T) {
		// PIDMax 1000 -> 90% used is exactly 900 PIDs; True only ABOVE it.
		cases := []struct {
			name       string
			count      int64
			wantStatus corev1.ConditionStatus
			wantReason string
			wantMsg    string
		}{
			{"just below 90% used -> sufficient", 899, corev1.ConditionFalse,
				"KubeletHasSufficientPID", "kubelet has sufficient PID available"},
			{"exactly 90% used -> sufficient (strict >)", 900, corev1.ConditionFalse,
				"KubeletHasSufficientPID", "kubelet has sufficient PID available"},
			{"just above 90% used -> insufficient", 901, corev1.ConditionTrue,
				"KubeletHasInsufficientPID", "kubelet has insufficient PID available"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := healthy
				s.PIDMax = 1000
				s.PIDCount = tc.count
				checkCond(t, computeNodeConditions(s, now), corev1.NodePIDPressure,
					tc.wantStatus, tc.wantReason, tc.wantMsg, now)
			})
		}
	})

	t.Run("zero-capacity / zero-PIDMax guards report no pressure", func(t *testing.T) {
		s := healthy
		s.DiskCapacityBytes = 0
		s.DiskAvailableBytes = 0
		s.PIDMax = 0
		s.PIDCount = 0
		conds := computeNodeConditions(s, now)
		checkCond(t, conds, corev1.NodeDiskPressure, corev1.ConditionFalse,
			"KubeletHasNoDiskPressure", "kubelet has no disk pressure", now)
		checkCond(t, conds, corev1.NodePIDPressure, corev1.ConditionFalse,
			"KubeletHasSufficientPID", "kubelet has sufficient PID available", now)
	})

	t.Run("NetworkUnavailable is always False, even under other pressure", func(t *testing.T) {
		// Drive every other signal True; NetworkUnavailable must stay False.
		s := hostStats{
			MemAvailableBytes:  0,
			DiskAvailableBytes: 0,
			DiskCapacityBytes:  1000,
			PIDCount:           1000,
			PIDMax:             1000,
		}
		conds := computeNodeConditions(s, now)
		// Sanity: the others really are True here, so this isn't vacuous.
		checkCond(t, conds, corev1.NodeMemoryPressure, corev1.ConditionTrue,
			"KubeletHasInsufficientMemory", "kubelet has insufficient memory available", now)
		checkCond(t, conds, corev1.NodeNetworkUnavailable, corev1.ConditionFalse,
			"RouteCreated", "k3sm node network is configured", now)
	})
}

// checkCond finds the condition of type typ in conds and asserts its Status is
// the explicit (non-empty) want, its Reason/Message match exactly, and both
// timestamps echo now.
func checkCond(t *testing.T, conds []corev1.NodeCondition, typ corev1.NodeConditionType,
	wantStatus corev1.ConditionStatus, wantReason, wantMsg string, now metav1.Time) {
	t.Helper()
	var c corev1.NodeCondition
	found := false
	for i := range conds {
		if conds[i].Type == typ {
			c = conds[i]
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("condition %q not present in %+v", typ, conds)
	}
	if c.Status == "" {
		t.Errorf("%s: Status is the zero value %q; it must be an explicit True/False", typ, c.Status)
	}
	if c.Status != wantStatus {
		t.Errorf("%s: Status = %q, want %q", typ, c.Status, wantStatus)
	}
	if c.Reason != wantReason {
		t.Errorf("%s: Reason = %q, want %q", typ, c.Reason, wantReason)
	}
	if c.Message != wantMsg {
		t.Errorf("%s: Message = %q, want %q", typ, c.Message, wantMsg)
	}
	if !c.LastHeartbeatTime.Equal(&now) {
		t.Errorf("%s: LastHeartbeatTime = %v, want %v", typ, c.LastHeartbeatTime, now)
	}
	if !c.LastTransitionTime.Equal(&now) {
		t.Errorf("%s: LastTransitionTime = %v, want %v", typ, c.LastTransitionTime, now)
	}
}
