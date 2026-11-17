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
	"fmt"
	"math"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/hostload"
)

// The HostCPUBusy condition: how busy the whole Mac's CPU is, pods and every
// other process alike. The scheduler cannot see it, because it scores requests
// against a static allocatable, and on a Mac the operator also works on most of
// the load is not pods at all. The server turns a True condition into the
// hostload.TaintKey PreferNoSchedule taint (pkg/hostload), so new unpinned pods
// prefer a calmer node.
//
// The utilization is the busy (user+system+nice) share of every core over the
// time between two publications, smoothed by an exponential average with
// hostCPUSmoothing as its time constant, so a one-minute compile does not move
// placement but a build session does. The verdict has hysteresis: it rises at
// hostCPUBusyEnter and falls below hostCPUBusyLeave.
const (
	hostCPUBusyEnter = 0.75
	hostCPUBusyLeave = 0.50
	hostCPUSmoothing = 2 * time.Minute
	// hostCPUMinWindow is the least time between two readings that yields a
	// rate. A publication triggered by a pressure edge can follow the last one
	// by a moment; a rate over that would be noise, so it is skipped and the
	// previous verdict stands.
	hostCPUMinWindow = 10 * time.Second
)

// hostCPUBusyTracker turns cumulative host CPU readings into the smoothed
// utilization and its busy verdict. It is not safe for concurrent use; the
// status provider calls it under its mutex.
type hostCPUBusyTracker struct {
	cores float64

	seeded    bool
	lastAt    time.Time
	lastNanos uint64

	rated bool
	avg   float64
	busy  bool
}

// newHostCPUBusyTracker returns a tracker for a host with cores CPUs, or nil
// when cores is not positive (no condition is then published).
func newHostCPUBusyTracker(cores int64) *hostCPUBusyTracker {
	if cores <= 0 {
		return nil
	}
	return &hostCPUBusyTracker{cores: float64(cores)}
}

// observe folds one reading in: busyNanos is the cumulative busy CPU time of
// every core at instant at. A reading that goes backwards (a counter reseed
// after a restart) or arrives within hostCPUMinWindow of the last one starts a
// new window without moving the average.
func (t *hostCPUBusyTracker) observe(at time.Time, busyNanos uint64) {
	if !t.seeded || busyNanos < t.lastNanos || !at.After(t.lastAt) {
		t.seeded, t.lastAt, t.lastNanos = true, at, busyNanos
		return
	}
	dt := at.Sub(t.lastAt)
	if dt < hostCPUMinWindow {
		return
	}
	util := float64(busyNanos-t.lastNanos) / (float64(dt.Nanoseconds()) * t.cores)
	util = min(max(util, 0), 1)
	t.lastAt, t.lastNanos = at, busyNanos
	if !t.rated {
		// The first rate seeds the average, so a node that restarts on a busy
		// Mac reports busy at once instead of climbing from zero.
		t.avg, t.rated = util, true
	} else {
		alpha := 1 - math.Exp(-float64(dt)/float64(hostCPUSmoothing))
		t.avg += alpha * (util - t.avg)
	}
	switch {
	case t.avg >= hostCPUBusyEnter:
		t.busy = true
	case t.avg < hostCPUBusyLeave:
		t.busy = false
	}
}

// condition returns the HostCPUBusy condition at now, or nil before the first
// rate: an absent condition is the truthful "not measured", and the server
// treats it as calm. LastTransitionTime is left for reconcileTransitions.
func (t *hostCPUBusyTracker) condition(now metav1.Time) *corev1.NodeCondition {
	if t == nil || !t.rated {
		return nil
	}
	pct := int(math.Round(t.avg * 100))
	c := &corev1.NodeCondition{
		Type:               hostload.ConditionHostCPUBusy,
		Status:             corev1.ConditionFalse,
		Reason:             hostload.ReasonAvailable,
		Message:            fmt.Sprintf("host cpu %d%% busy (smoothed); busy from %d%%", pct, int(hostCPUBusyEnter*100)),
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	if t.busy {
		c.Status = corev1.ConditionTrue
		c.Reason = hostload.ReasonBusy
		c.Message = fmt.Sprintf("host cpu %d%% busy (smoothed); new pods prefer other nodes until it is below %d%%", pct, int(hostCPUBusyLeave*100))
	}
	return c
}

// readHostCPUBusyNanos returns the cumulative busy CPU time of every core,
// read through the process-wide tick accumulator the stats summary uses.
func readHostCPUBusyNanos() (uint64, error) {
	ticks, hz, err := hostCPUTicks.sample(readHostCPUTicks)
	if err != nil {
		return 0, err
	}
	if hz == 0 || hz > uint64(time.Second) {
		return 0, fmt.Errorf("host cpu: implausible tick rate %d Hz", hz)
	}
	return ticks * (uint64(time.Second) / hz), nil
}
