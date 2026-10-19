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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestSwapArmSplitNamesSwapfsAsLimitingResource pins the split of the swap arm
// into its memory leg (memory.swap: in use and rising, no disk term) and its
// space leg (swapfs.available: free space on the swap volume under
// max(8Gi, memsize/4)). The hard trigger still needs both; what changes is the
// name the condition and the eviction report (the swap volume, not memory), the
// floor on hosts with more than 32 GiB of memory, and DiskPressure on a swap
// volume that does not share the data root's container.
func TestSwapArmSplitNamesSwapfsAsLimitingResource(t *testing.T) {
	const gi = int64(1) << 30
	now := metav1.NewTime(time.Unix(0, 0))

	// host is a snapshot of a host with mem bytes of memory, swap in use and
	// free space on the swap volume; the data root has plenty of room.
	host := func(mem, swapUsed, swapFree int64) hostStats {
		s := compressorAt(0)
		s.MemCapacityBytes = mem
		s.SwapUsedBytes = swapUsed
		s.SwapVolumeAvailableBytes = swapFree
		return s
	}
	// monitored runs seq through a pressure monitor and returns its last
	// snapshot, so the swap arm has the previous reading it needs.
	monitored := func(t *testing.T, seq ...hostStats) hostStats {
		t.Helper()
		cs := &countingSampler{}
		m := newPressureMonitor(func() (hostStats, error) { return cs.sample("") }, discardLog())
		for _, s := range seq {
			cs.set(s, nil)
			m.sampleOnce()
		}
		return mustLatest(t, m)
	}

	t.Run("a nearly full swap volume with growing swap names swapfs, not memory", func(t *testing.T) {
		s := monitored(t, host(16*gi, 2*gi, 6*gi), host(16*gi, 3*gi, 6*gi))
		if p, sig := memoryPressured(s); !p || sig != signalSwapfs {
			t.Fatalf("memoryPressured = %v/%q, want true/%q", p, sig, signalSwapfs)
		}
		c := findNodeCondition(computeNodeConditions(s, now), corev1.NodeMemoryPressure)
		if c.Status != corev1.ConditionTrue || c.Reason != insufficientMemoryReason {
			t.Fatalf("MemoryPressure = %s/%s, want True/%s", c.Status, c.Reason, insufficientMemoryReason)
		}
		for _, want := range []string{"swapfs.available 6.0Gi", "floor 8.0Gi", "memory.swap growing (3.0Gi used)", "disk space on the swap volume is the limiting resource"} {
			if !strings.Contains(c.Message, want) {
				t.Errorf("Message %q does not contain %q", c.Message, want)
			}
		}
	})

	t.Run("the memory leg alone never trips: no disk term, no pressure", func(t *testing.T) {
		s := monitored(t, host(16*gi, 2*gi, 100*gi), host(16*gi, 6*gi, 100*gi))
		if !memorySwapLeg(s) || swapfsLeg(s) {
			t.Fatalf("legs = memory.swap %v, swapfs.available %v, want true/false", memorySwapLeg(s), swapfsLeg(s))
		}
		if p, _ := memoryPressured(s); p {
			t.Error("growing swap with a roomy swap volume raised MemoryPressure")
		}
	})

	t.Run("the space leg alone never trips: flat swap on a short volume", func(t *testing.T) {
		s := monitored(t, host(16*gi, 3*gi, 1*gi), host(16*gi, 3*gi, 1*gi))
		if p, _ := memoryPressured(s); p {
			t.Error("flat swap on a short swap volume raised MemoryPressure")
		}
	})

	t.Run("the floor is max(8Gi, memsize/4)", func(t *testing.T) {
		for _, tc := range []struct {
			mem, floor int64
		}{
			{0, 8 * gi}, // unsampled capacity: the minimum
			{8 * gi, 8 * gi},
			{16 * gi, 8 * gi},
			{32 * gi, 8 * gi},
			{64 * gi, 16 * gi},
			{128 * gi, 32 * gi},
		} {
			if got := swapfsFloor(tc.mem); got != tc.floor {
				t.Errorf("swapfsFloor(%dGi) = %dGi, want %dGi", tc.mem/gi, got/gi, tc.floor/gi)
			}
			below := monitored(t, host(tc.mem, 2*gi, tc.floor-1), host(tc.mem, 3*gi, tc.floor-1))
			if p, sig := memoryPressured(below); !p || sig != signalSwapfs {
				t.Errorf("%dGi host, one byte under the floor: %v/%q, want true/%q", tc.mem/gi, p, sig, signalSwapfs)
			}
			at := monitored(t, host(tc.mem, 2*gi, tc.floor), host(tc.mem, 3*gi, tc.floor))
			if p, _ := memoryPressured(at); p {
				t.Errorf("%dGi host, exactly at the floor: pressured, want not (strict <)", tc.mem/gi)
			}
		}
	})

	t.Run("larger hosts evict earlier: 12Gi free trips a 64Gi host, not a 16Gi one", func(t *testing.T) {
		big := monitored(t, host(64*gi, 2*gi, 12*gi), host(64*gi, 3*gi, 12*gi))
		if p, _ := memoryPressured(big); !p {
			t.Error("64Gi host with 12Gi free on the swap volume and growing swap: not pressured")
		}
		small := monitored(t, host(16*gi, 2*gi, 12*gi), host(16*gi, 3*gi, 12*gi))
		if p, _ := memoryPressured(small); p {
			t.Error("16Gi host with 12Gi free on the swap volume: pressured")
		}
	})

	t.Run("the fast cadence starts at twice the host's floor", func(t *testing.T) {
		s := host(64*gi, 600<<20, 31*gi)
		if !pressureElevated(s) {
			t.Error("64Gi host, 31Gi free (under twice the 16Gi floor): not elevated")
		}
		s.SwapVolumeAvailableBytes = 32 * gi
		if pressureElevated(s) {
			t.Error("64Gi host, exactly 32Gi free: elevated, want not")
		}
	})

	t.Run("DiskPressure trips on a separate swap volume under its floor", func(t *testing.T) {
		s := host(16*gi, 0, 6*gi) // no swap in use: a disk fact, not a memory one
		s.SwapVolumeSeparate = true
		conds := computeNodeConditions(s, now)
		d := findNodeCondition(conds, corev1.NodeDiskPressure)
		if d.Status != corev1.ConditionTrue || d.Reason != diskPressureReason {
			t.Fatalf("DiskPressure = %s/%s, want True/%s", d.Status, d.Reason, diskPressureReason)
		}
		if want := "kubelet has disk pressure: swapfs.available 6.0Gi on the swap volume (floor 8.0Gi)"; d.Message != want {
			t.Errorf("DiskPressure Message = %q, want %q", d.Message, want)
		}
		if m := findNodeCondition(conds, corev1.NodeMemoryPressure); m.Status != corev1.ConditionFalse {
			t.Errorf("MemoryPressure = %s with no swap in use, want False", m.Status)
		}
	})

	t.Run("a swap volume sharing the data root's container leaves DiskPressure to the data root", func(t *testing.T) {
		s := host(16*gi, 0, 6*gi)
		s.SwapVolumeSeparate = false
		if d := findNodeCondition(computeNodeConditions(s, now), corev1.NodeDiskPressure); d.Status != corev1.ConditionFalse {
			t.Errorf("DiskPressure = %s on a shared container with the data root roomy, want False", d.Status)
		}
	})

	t.Run("an unsampled separate swap volume is no DiskPressure", func(t *testing.T) {
		s := host(16*gi, 0, 0)
		s.SwapVolumeCapacityBytes = 0
		s.SwapVolumeSeparate = true
		if d := findNodeCondition(computeNodeConditions(s, now), corev1.NodeDiskPressure); d.Status != corev1.ConditionFalse {
			t.Errorf("DiskPressure = %s on an unsampled swap volume, want False", d.Status)
		}
	})

	t.Run("the swap-volume DiskPressure holds until 1.5x the floor", func(t *testing.T) {
		// A 64Gi host: floor 16Gi, clear level 24Gi.
		seq := []int64{17 * gi, 16*gi - 1, 20 * gi, 24*gi - 1, 24 * gi, 20 * gi}
		want := []corev1.ConditionStatus{
			corev1.ConditionFalse, // above the floor, never tripped
			corev1.ConditionTrue,  // under the floor: trips
			corev1.ConditionTrue,  // in the band: held
			corev1.ConditionTrue,  // one byte under the clear level: held
			corev1.ConditionFalse, // at the clear level: clears
			corev1.ConditionFalse, // back in the band from above: stays clear
		}
		var prev []corev1.NodeCondition
		for i, free := range seq {
			s := host(64*gi, 0, free)
			s.SwapVolumeSeparate = true
			prev = reconcileTransitions(prev, computeNodeConditions(s, now), s)
			d := findNodeCondition(prev, corev1.NodeDiskPressure)
			if d.Status != want[i] {
				t.Errorf("sample %d (%dMi free): DiskPressure = %s, want %s", i, free>>20, d.Status, want[i])
			}
			if i == 2 && !strings.Contains(d.Message, "swap volume") {
				t.Errorf("held DiskPressure Message = %q, want the swap-volume message it tripped with", d.Message)
			}
		}
	})

	t.Run("containers compare by f_mntfromname, not by volume", func(t *testing.T) {
		for _, tc := range []struct {
			from, want string
		}{
			{"/dev/disk3s6", "disk3"},   // the swap volume
			{"/dev/disk3s7", "disk3"},   // a data volume in the same container
			{"/dev/disk3s1s1", "disk3"}, // the sealed system snapshot
			{"/dev/disk12s2", "disk12"},
			{"/dev/disk5", "disk5"},
			{"/dev/diskX", "/dev/diskX"},
			{"/dev/disk3x1", "/dev/disk3x1"},
			{"map auto_home", "map auto_home"},
			{"", ""},
		} {
			if got := apfsContainer(tc.from); got != tc.want {
				t.Errorf("apfsContainer(%q) = %q, want %q", tc.from, got, tc.want)
			}
		}
	})
}
