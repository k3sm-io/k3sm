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

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// sampleMemoryHeadroom reads the compressor and swap counters behind the
// k3sm-specific memory-pressure arms. Every read is a plain sysctl or statfs, so
// this file needs no cgo; it is still darwin-only, because the names exist only
// on macOS.
//
// All-or-nothing, like sampleHostStats: a missing counter fails the sample rather
// than leaving a zero that would read as "no pressure".
func sampleMemoryHeadroom() (memoryHeadroom, error) {
	var h memoryHeadroom
	counters := []struct {
		name string
		dst  *int64
	}{
		{"vm.compressor.pages_compressed", &h.compressorPages},
		{"vm.compressor.pages_compressed_limit", &h.compressorPagesLimit},
		{"vm.compressor.segment.total", &h.compressorSegments},
		{"vm.compressor.segment.limit", &h.compressorSegmentsLimit},
	}
	for _, c := range counters {
		raw, err := unix.SysctlRaw(c.name)
		if err != nil {
			return memoryHeadroom{}, fmt.Errorf("sysctl %s: %w", c.name, err)
		}
		v, err := decodeSysctlCounter(c.name, raw)
		if err != nil {
			return memoryHeadroom{}, err
		}
		*c.dst = v
	}
	raw, err := unix.SysctlRaw("vm.swapusage")
	if err != nil {
		return memoryHeadroom{}, fmt.Errorf("sysctl vm.swapusage: %w", err)
	}
	if h.swapUsed, err = decodeSwapUsed(raw); err != nil {
		return memoryHeadroom{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(swapVolumePath, &fs); err != nil {
		return memoryHeadroom{}, fmt.Errorf("statfs %s: %w", swapVolumePath, err)
	}
	bsize := int64(fs.Bsize)
	h.swapVolumeAvailable = int64(fs.Bavail) * bsize
	h.swapVolumeCapacity = int64(fs.Blocks) * bsize
	return h, nil
}
