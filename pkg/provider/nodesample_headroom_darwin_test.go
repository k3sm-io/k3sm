//go:build darwin

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

import "testing"

// TestSampleMemoryHeadroomLive reads the real compressor and swap counters on
// this Mac: every sysctl the headroom arms depend on exists, decodes at a width
// the sampler accepts, and yields a coherent reading. No privilege is needed.
func TestSampleMemoryHeadroomLive(t *testing.T) {
	h, err := sampleMemoryHeadroom()
	if err != nil {
		t.Fatalf("sampleMemoryHeadroom: %v", err)
	}
	if h.compressorPagesLimit <= 0 || h.compressorSegmentsLimit <= 0 {
		t.Errorf("compressor limits = %d pages / %d segments, want both > 0", h.compressorPagesLimit, h.compressorSegmentsLimit)
	}
	if h.compressorPages < 0 || h.compressorPages > h.compressorPagesLimit {
		t.Errorf("compressed pages %d outside 0..%d", h.compressorPages, h.compressorPagesLimit)
	}
	if h.compressorSegments < 0 || h.compressorSegments > h.compressorSegmentsLimit {
		t.Errorf("compressor segments %d outside 0..%d", h.compressorSegments, h.compressorSegmentsLimit)
	}
	if h.swapUsed < 0 {
		t.Errorf("swap used = %d, want >= 0", h.swapUsed)
	}
	if h.swapVolumeCapacity <= 0 || h.swapVolumeAvailable < 0 || h.swapVolumeAvailable > h.swapVolumeCapacity {
		t.Errorf("swap volume %d free of %d, want 0 <= free <= capacity > 0", h.swapVolumeAvailable, h.swapVolumeCapacity)
	}
}
