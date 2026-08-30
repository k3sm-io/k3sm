//go:build darwin && cgo

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
)

// TestSampleHostStatsLive exercises the real Darwin sampler against the machine
// running the test — unprivileged reads of Mach VM statistics, statfs and two
// sysctls, no network and no elevated rights.
//
// Its assertions are deliberately host-independent PLAUSIBILITY BANDS rather than
// exact values, because the answer legitimately differs on every Mac. The bands
// are chosen to catch the specific ways this shim silently returns nonsense:
//
//   - a working set of zero or near-zero (the shim read uninitialised fields, or
//     host_statistics64 wrote fewer units than we consumed),
//   - a working set exceeding physical memory (a page-size or sign error — a
//     reflexive 4096 on a 16 KiB-page machine gets this wrong by 4x in one
//     direction, and using the wrong page classes by more in the other),
//   - a process count of zero or above the ceiling (the size-only sysctl query
//     mis-divided by sizeof(kinfo_proc)).
func TestSampleHostStatsLive(t *testing.T) {
	s, err := sampleHostStats("/")
	if err != nil {
		t.Fatalf("sampleHostStats: %v", err)
	}

	if s.MemCapacityBytes <= 0 {
		t.Fatalf("MemCapacityBytes = %d, want the machine's physical memory", s.MemCapacityBytes)
	}
	if s.MemAvailableBytes < 0 || s.MemAvailableBytes > s.MemCapacityBytes {
		t.Errorf("MemAvailableBytes = %d, want 0..%d", s.MemAvailableBytes, s.MemCapacityBytes)
	}
	// A machine running this test has a real working set: macOS alone wires far
	// more than 128 MiB. A near-capacity "available" figure means the page classes
	// were misread.
	if workingSet := s.MemCapacityBytes - s.MemAvailableBytes; workingSet < 128<<20 {
		t.Errorf("derived working set = %d bytes, implausibly small for a running macOS host", workingSet)
	}

	if s.DiskCapacityBytes <= 0 {
		t.Errorf("DiskCapacityBytes = %d, want the size of the volume backing /", s.DiskCapacityBytes)
	}
	if s.DiskAvailableBytes < 0 || s.DiskAvailableBytes > s.DiskCapacityBytes {
		t.Errorf("DiskAvailableBytes = %d, want 0..%d", s.DiskAvailableBytes, s.DiskCapacityBytes)
	}

	if s.PIDMax <= 0 {
		t.Fatalf("PIDMax = %d, want kern.maxproc", s.PIDMax)
	}
	// The test binary and its parent shell are running, so the count is at least a
	// handful; and a machine over its own ceiling could not have started them.
	if s.PIDCount < 2 || s.PIDCount > s.PIDMax {
		t.Errorf("PIDCount = %d, want 2..%d", s.PIDCount, s.PIDMax)
	}

	// A missing path must fail the whole snapshot rather than yield a zeroed one
	// that the unsampled guards would read as "no pressure".
	if _, err := sampleHostStats("/nonexistent-k3sm-node-sample-path"); err == nil {
		t.Error("sampleHostStats on a missing data root returned no error")
	}
}
