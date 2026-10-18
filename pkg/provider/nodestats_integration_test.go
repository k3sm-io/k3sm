//go:build integration && darwin

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
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestHostCPUCalibration is the real-host tick-unit calibration: a 1s spin on
// one thread must move the host-wide CPU counter into a plausible window. It is
// integration-tier (build tag) because the counter is host-wide and
// the window is a statement about the whole Mac: a concurrent package run
// pushed the delta past the CPU-count ceiling (38s observed on 20 CPUs), so
// the check is not deterministic on a shared host and must not ride the unit
// tier. The deterministic checks live in TestStatsSummaryCarriesNodeCPUAndMemory.
func TestHostCPUCalibration(t *testing.T) {
	if testing.Short() {
		t.Skip("spins a CPU for 1s")
	}
	if !hostCPUSupported {
		t.Skip("node CPU sampling requires darwin with cgo")
	}
	// The brief's window: a 1s spin on one locked OS thread moves the
	// host-wide counter by [0.5s, 3s]. The counter is host-wide, so on a
	// shared Mac other processes add to the spin; when the raw delta is over
	// 3s, the same window is judged on the delta minus an idle baseline taken
	// over an equal 1s sleep just before. Each attempt also checks two
	// physical bounds that catch a unit error under any load: the host delta
	// covers at least half of THIS process's own CPU time (getrusage), and
	// never exceeds every logical CPU busy for the wall window (+10%).
	// Three attempts. A window where the spin got under 0.6s of CPU, or the
	// idle baseline itself exceeded 0.5s, is too loaded to judge against the
	// window; when every attempt was such a window the subtest skips (the
	// physical bounds have still been asserted on each).
	const lo, hi = 500 * time.Millisecond, 3 * time.Second
	var s darwinHostSampler
	sample := func() hostSample {
		t.Helper()
		hs, err := s.Sample()
		if err != nil {
			t.Fatalf("Sample: %v", err)
		}
		return hs
	}
	judged := false
	for attempt := 1; attempt <= 3; attempt++ {
		b0 := sample()
		time.Sleep(time.Second)
		b1 := sample()
		baseline := time.Duration(b1.cpuUsageNanos - b0.cpuUsageNanos)

		var ru0, ru1 unix.Rusage
		if err := unix.Getrusage(unix.RUSAGE_SELF, &ru0); err != nil {
			t.Fatalf("getrusage: %v", err)
		}
		start := time.Now()
		before := sample()
		done := make(chan struct{})
		go func() {
			defer close(done)
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			for end := time.Now().Add(time.Second); time.Now().Before(end); {
			}
		}()
		<-done
		after := sample()
		wall := time.Since(start)
		if err := unix.Getrusage(unix.RUSAGE_SELF, &ru1); err != nil {
			t.Fatalf("getrusage: %v", err)
		}
		self := time.Duration(ru1.Utime.Nano() + ru1.Stime.Nano() - ru0.Utime.Nano() - ru0.Stime.Nano())
		delta := time.Duration(after.cpuUsageNanos - before.cpuUsageNanos)
		ceiling := time.Duration(float64(wall) * float64(runtime.NumCPU()) * 1.1)
		t.Logf("attempt %d: host CPU delta %v over a 1s single-thread spin (idle baseline %v, own CPU %v, ceiling %v); working set %d of %d bytes",
			attempt, delta, baseline, self, ceiling, after.workingSetBytes, after.memsizeBytes)

		if after.workingSetBytes == 0 || after.workingSetBytes > after.memsizeBytes {
			t.Fatalf("working set %d outside (0, memsize %d]", after.workingSetBytes, after.memsizeBytes)
		}
		if delta < self/2 {
			t.Fatalf("host CPU delta %v is under half this process's own CPU %v: a tick-unit error", delta, self)
		}
		if delta > ceiling {
			t.Fatalf("host CPU delta %v exceeds %d CPUs busy for %v: a tick-unit error", delta, runtime.NumCPU(), wall)
		}
		if (delta >= lo && delta <= hi) || (delta-baseline >= lo && delta-baseline <= hi) {
			return
		}
		if self >= 600*time.Millisecond && baseline <= lo {
			judged = true
		}
	}
	if !judged {
		t.Skip("host too loaded in all three windows to judge [0.5s, 3s]; the physical bounds held")
	}
	t.Fatalf("host CPU delta for a 1s spin stayed outside [%v, %v] (raw and baseline-corrected) in three attempts", lo, hi)
}
