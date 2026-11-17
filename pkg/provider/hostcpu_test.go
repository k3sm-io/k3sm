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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/hostload"
)

// errNoHostCPUInTests is the CPU read the shared status harness installs.
var errNoHostCPUInTests = errors.New("host cpu is not read in unit tests")

// cpuFeed drives a tracker with a fixed utilization per minute.
type cpuFeed struct {
	t     *hostCPUBusyTracker
	cores int64
	at    time.Time
	nanos uint64
}

func newCPUFeed(cores int64) *cpuFeed {
	f := &cpuFeed{t: newHostCPUBusyTracker(cores), cores: cores, at: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}
	f.t.observe(f.at, f.nanos)
	return f
}

// minute advances one minute at utilization util (0..1) of every core.
func (f *cpuFeed) minute(util float64) {
	f.at = f.at.Add(time.Minute)
	f.nanos += uint64(util * float64(time.Minute) * float64(f.cores))
	f.t.observe(f.at, f.nanos)
}

func (f *cpuFeed) status() corev1.ConditionStatus {
	c := f.t.condition(metav1.NewTime(f.at))
	if c == nil {
		return ""
	}
	return c.Status
}

func TestHostCPUBusyTrackerNoConditionBeforeARate(t *testing.T) {
	f := newCPUFeed(8)
	if c := f.t.condition(metav1.NewTime(f.at)); c != nil {
		t.Fatalf("condition after one reading = %+v, want none", c)
	}
	if newHostCPUBusyTracker(0) != nil {
		t.Fatal("a zero-core node got a tracker")
	}
	var nilTracker *hostCPUBusyTracker
	if nilTracker.condition(metav1.Now()) != nil {
		t.Fatal("a nil tracker published a condition")
	}
}

// TestHostCPUBusyTrackerHysteresis is the node half of the B1855 unit gate: a
// busy Mac reads busy from the first rate, a short dip does not clear it, and it
// clears only once the average is under the leave threshold; a short burst on a
// calm Mac does not raise it.
func TestHostCPUBusyTrackerHysteresis(t *testing.T) {
	t.Run("busy from the first rate", func(t *testing.T) {
		f := newCPUFeed(20)
		f.minute(0.95)
		if got := f.status(); got != corev1.ConditionTrue {
			t.Fatalf("status = %q, want True", got)
		}
		c := f.t.condition(metav1.NewTime(f.at))
		if c.Reason != hostload.ReasonBusy || c.Type != hostload.ConditionHostCPUBusy {
			t.Fatalf("condition = %+v", c)
		}
	})
	t.Run("a dip inside the band holds busy", func(t *testing.T) {
		f := newCPUFeed(20)
		f.minute(1.0)
		f.minute(0.3) // average about 0.72: below enter, above leave
		if got := f.status(); got != corev1.ConditionTrue {
			t.Fatalf("after one calm minute status = %q, want True (held)", got)
		}
	})
	t.Run("a calm spell after sustained load clears it on the second minute", func(t *testing.T) {
		f := newCPUFeed(20)
		for range 5 {
			f.minute(1.0)
		}
		f.minute(0.05) // average about 0.63
		if got := f.status(); got != corev1.ConditionTrue {
			t.Fatalf("after one calm minute status = %q, want True", got)
		}
		f.minute(0.05) // average about 0.40
		if got := f.status(); got != corev1.ConditionFalse {
			t.Fatalf("after two calm minutes status = %q, want False", got)
		}
	})
	t.Run("a one-minute burst on a calm Mac does not raise it", func(t *testing.T) {
		f := newCPUFeed(8)
		for range 5 {
			f.minute(0.1)
		}
		f.minute(1.0)
		if got := f.status(); got != corev1.ConditionFalse {
			t.Fatalf("status = %q, want False", got)
		}
		for range 3 {
			f.minute(1.0)
		}
		if got := f.status(); got != corev1.ConditionTrue {
			t.Fatalf("after a sustained load status = %q, want True", got)
		}
	})
}

// TestHostCPUBusyTrackerGoesSilentWhenStale: once the last good reading is
// older than hostCPUStaleAfter, no condition is published (and the server then
// clears the taint), rather than a verdict that can no longer be measured.
func TestHostCPUBusyTrackerGoesSilentWhenStale(t *testing.T) {
	f := newCPUFeed(4)
	f.minute(1.0)
	if f.t.condition(metav1.NewTime(f.at.Add(hostCPUStaleAfter))) == nil {
		t.Fatal("condition dropped at the stale bound, want it kept up to it")
	}
	if c := f.t.condition(metav1.NewTime(f.at.Add(hostCPUStaleAfter + time.Second))); c != nil {
		t.Fatalf("stale condition = %+v, want none", c)
	}
}

func TestHostCPUBusyTrackerIgnoresBadWindows(t *testing.T) {
	f := newCPUFeed(4)
	f.minute(0.9)
	before := f.t.avg
	// A reading a second later is too short a window: no change.
	f.t.observe(f.at.Add(time.Second), f.nanos+uint64(4*time.Second))
	if f.t.avg != before {
		t.Fatalf("a 1s window moved the average: %v -> %v", before, f.t.avg)
	}
	// A counter that went backwards reseeds without moving the average.
	f.at = f.at.Add(time.Minute)
	f.nanos = 0
	f.t.observe(f.at, f.nanos)
	if f.t.avg != before || f.status() != corev1.ConditionTrue {
		t.Fatalf("a reseed moved the verdict: avg %v status %q", f.t.avg, f.status())
	}
	// A window longer than hostCPUMaxWindow (the Mac slept) reseeds without
	// moving the average, even though the CPU was idle all along.
	f.at = f.at.Add(time.Hour)
	f.t.observe(f.at, f.nanos)
	if f.t.avg != before || f.status() != corev1.ConditionTrue {
		t.Fatalf("a long window moved the verdict: avg %v status %q", f.t.avg, f.status())
	}
	// Utilization over 100% (a clock skew) is clamped.
	f.at = f.at.Add(time.Minute)
	f.nanos += uint64(10 * float64(time.Minute) * 4)
	f.t.observe(f.at, f.nanos)
	if f.t.avg > 1 {
		t.Fatalf("average %v above 1", f.t.avg)
	}
}

// TestNodeStatusPublishesHostCPUBusy drives the status loop: the condition
// appears from the second publication, rides beside the others, keeps its
// LastTransitionTime while unchanged, and a failed read keeps the verdict.
func TestNodeStatusPublishesHostCPUBusy(t *testing.T) {
	h := newNodeStatusHarness(t, bootstrapNode())
	var nanos uint64
	var readErr error
	h.p.sampleCPU = func() (uint64, error) {
		// bootstrapNode has 10 cores; each publication is one minute: full load.
		nanos += uint64(10 * time.Minute)
		return nanos, readErr
	}
	publish := func() *corev1.Node {
		t.Helper()
		if err := h.p.publishOnce(context.Background()); err != nil {
			t.Fatalf("publishOnce: %v", err)
		}
		return h.published[len(h.published)-1]
	}
	if c := findNodeCondition(publish().Status.Conditions, hostload.ConditionHostCPUBusy); c != nil {
		t.Fatalf("first publication carries %+v, want no HostCPUBusy yet", c)
	}
	n := publish()
	c := findNodeCondition(n.Status.Conditions, hostload.ConditionHostCPUBusy)
	if c == nil || c.Status != corev1.ConditionTrue {
		t.Fatalf("second publication HostCPUBusy = %+v, want True", c)
	}
	if findNodeCondition(n.Status.Conditions, corev1.NodeReady) == nil {
		t.Fatal("Ready condition missing beside HostCPUBusy")
	}
	if !n.Status.Allocatable.Cpu().Equal(*bootstrapNode().Status.Allocatable.Cpu()) {
		t.Fatalf("allocatable cpu moved: %v", n.Status.Allocatable.Cpu())
	}
	first := c.LastTransitionTime
	readErr = errors.New("mach failure")
	c = findNodeCondition(publish().Status.Conditions, hostload.ConditionHostCPUBusy)
	if c == nil || c.Status != corev1.ConditionTrue || !c.LastTransitionTime.Equal(&first) {
		t.Fatalf("after a failed read HostCPUBusy = %+v, want True since %v", c, first)
	}
}
