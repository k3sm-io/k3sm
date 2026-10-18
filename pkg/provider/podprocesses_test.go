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
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestPIDPressureUIDScopedNumerator pins PIDPressure's per-uid leg end to end
// over the wire shape: PodStats.process.process_count summed over the pods
// that report it (sumPodProcessCounts) against kern.maxprocperuid, through
// computeNodeConditions. The systemwide leg is held clear in every case, so a
// True verdict is the per-uid leg's alone.
func TestPIDPressureUIDScopedNumerator(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	reporting := func(n uint64) *runtimev1.PodStats {
		return &runtimev1.PodStats{Process: &runtimev1.ProcessStats{ProcessCount: n}}
	}
	silent := func() *runtimev1.PodStats { return &runtimev1.PodStats{} }

	const (
		sufficient   = "kubelet has sufficient PID available"
		insufficient = "kubelet has insufficient PID available"
	)
	cases := []struct {
		name         string
		pods         []*runtimev1.PodStats
		perUID       int64
		wantCount    int64
		wantReported bool
		wantStatus   corev1.ConditionStatus
		wantReason   string
		wantMsg      string
	}{
		{"uid leg trips above 90% while systemwide is clear",
			[]*runtimev1.PodStats{reporting(500), reporting(401)}, 1000, 901, true,
			corev1.ConditionTrue, "KubeletHasInsufficientPID",
			insufficient + ": per-uid 901 pod processes of kern.maxprocperuid 1000"},
		{"exactly 90% does not trip (strict >)",
			[]*runtimev1.PodStats{reporting(450), reporting(450)}, 1000, 900, true,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"just below 90% does not trip",
			[]*runtimev1.PodStats{reporting(899)}, 1000, 899, true,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"PIDMaxPerUID 0 skips the leg",
			[]*runtimev1.PodStats{reporting(5000)}, 0, 5000, true,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"mixed nil and non-nil pods sum the reporters only",
			[]*runtimev1.PodStats{reporting(600), silent(), nil, reporting(301), silent()}, 1000, 901, true,
			corev1.ConditionTrue, "KubeletHasInsufficientPID",
			insufficient + ": per-uid 901 pod processes of kern.maxprocperuid 1000"},
		{"a present zero is a real count",
			[]*runtimev1.PodStats{reporting(0), silent()}, 1000, 0, true,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"all-nil pods skip the leg",
			[]*runtimev1.PodStats{silent(), silent(), nil}, 1, 0, false,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"no pods skip the leg",
			nil, 1, 0, false,
			corev1.ConditionFalse, "KubeletHasSufficientPID", sufficient},
		{"a count past the ceiling trips without overflow",
			[]*runtimev1.PodStats{reporting(math.MaxUint64), reporting(1)}, 1000, math.MaxInt64, true,
			corev1.ConditionTrue, "KubeletHasInsufficientPID",
			insufficient + ": per-uid 9223372036854775807 pod processes of kern.maxprocperuid 1000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count, reported := sumPodProcessCounts(tc.pods)
			if count != tc.wantCount || reported != tc.wantReported {
				t.Fatalf("sumPodProcessCounts = (%d, %v), want (%d, %v)", count, reported, tc.wantCount, tc.wantReported)
			}
			s := hostStats{
				MemAvailableBytes:  8 << 30,
				MemCapacityBytes:   16 << 30,
				DiskAvailableBytes: 100 << 30,
				DiskCapacityBytes:  500 << 30,
				PIDCount:           50,
				PIDMax:             10000, // 0.5%: the systemwide leg is clear
				PIDMaxPerUID:       tc.perUID,
				PodProcCount:       count,
				PodProcReported:    reported,
			}
			checkCond(t, computeNodeConditions(s, now), corev1.NodePIDPressure,
				tc.wantStatus, tc.wantReason, tc.wantMsg, now)
		})
	}

	t.Run("the systemwide leg is named first when both trip", func(t *testing.T) {
		s := hostStats{
			MemAvailableBytes: 8 << 30, MemCapacityBytes: 16 << 30,
			DiskAvailableBytes: 100 << 30, DiskCapacityBytes: 500 << 30,
			PIDCount: 1901, PIDMax: 2000,
			PIDMaxPerUID: 1000, PodProcCount: 950, PodProcReported: true,
		}
		checkCond(t, computeNodeConditions(s, now), corev1.NodePIDPressure, corev1.ConditionTrue,
			"KubeletHasInsufficientPID", insufficient+": systemwide 1901 of kern.maxproc 2000", now)
	})
}

// fakePodProcessCounter answers PodProcessCount with a settable reply.
type fakePodProcessCounter struct {
	mu       sync.Mutex
	count    int64
	reported bool
	err      error
}

func (f *fakePodProcessCounter) set(count int64, reported bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.count, f.reported, f.err = count, reported, err
}

func (f *fakePodProcessCounter) PodProcessCount(context.Context) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count, f.reported, f.err
}

// TestNodeStatusPodProcessCount pins the status loop's half of the per-uid
// leg: the count passed through NodeStatusConfig.PodProcesses reaches the
// published PIDPressure, and a failed count keeps the previous one.
func TestNodeStatusPodProcessCount(t *testing.T) {
	counter := &fakePodProcessCounter{}
	h := newNodeStatusHarness(t, bootstrapNode())
	p, err := NewNodeStatusProvider(NodeStatusConfig{
		Node:           bootstrapNode(),
		DataRoot:       "/var/lib/k3sm",
		RuntimeHealthy: h.runtimeHealthy,
		PodProcesses:   counter,
		Log:            discardLog(),
	})
	if err != nil {
		t.Fatalf("NewNodeStatusProvider: %v", err)
	}
	p.sample = h.sample
	p.now = h.nowFn
	p.publish = h.publishFn
	h.p = p
	stats := healthyStats()
	stats.PIDMaxPerUID = 1000
	h.setStats(stats)
	refresh := func() *corev1.Node {
		h.step()
		p.procWG.Wait()
		n := h.step()
		p.procWG.Wait()
		return n
	}

	counter.set(901, true, nil)
	wantStatus(t, refresh(), corev1.NodePIDPressure, corev1.ConditionTrue)

	counter.set(0, false, errors.New("runtimed unavailable"))
	wantStatus(t, refresh(), corev1.NodePIDPressure, corev1.ConditionTrue)

	counter.set(900, true, nil)
	wantStatus(t, refresh(), corev1.NodePIDPressure, corev1.ConditionFalse)

	counter.set(0, false, nil)
	wantStatus(t, refresh(), corev1.NodePIDPressure, corev1.ConditionFalse)
}
