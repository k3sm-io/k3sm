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
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"
)

// sampleHostStats takes ONE live snapshot of node-level resource availability:
// memory from host_statistics64, disk from statfs of the volume backing dataRoot,
// the process table from sysctl, and the compressor and swap counters behind the
// memory-pressure headroom arms (sampleMemoryHeadroom). It is the only impure half of the
// node-pressure path — computeNodeConditions and reconcileTransitions consume its
// output and touch the host not at all.
//
// It is all-or-nothing: any failing leg fails the whole snapshot, because a
// partially-filled hostStats reads as "no pressure" for the missing signals (the
// unsampled guards are deliberately fail-open) and that is a lie the caller
// cannot distinguish from a healthy node. The caller carries the previously
// published conditions forward instead.
//
// HONEST LIMITATION: every figure here describes the MACHINE, not k3sm's share of
// it. The memory, the volume and the process table are shared with whatever else
// the Mac is running.
func sampleHostStats(dataRoot string) (hostStats, error) {
	capacity, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return hostStats{}, fmt.Errorf("sysctl hw.memsize: %w", err)
	}
	if capacity == 0 || capacity > 1<<62 {
		return hostStats{}, fmt.Errorf("sysctl hw.memsize: implausible value %d", capacity)
	}
	memAvail, err := sampleHostMemory(int64(capacity))
	if err != nil {
		return hostStats{}, fmt.Errorf("sample host memory: %w", err)
	}

	var fs unix.Statfs_t
	if err := unix.Statfs(dataRoot, &fs); err != nil {
		return hostStats{}, fmt.Errorf("statfs %s: %w", dataRoot, err)
	}
	blockSize := int64(fs.Bsize)

	// kern.maxproc is the machine's global process-table ceiling — the wall that
	// actually stops a pod from forking. See pidPressureUsedPercent for why the
	// per-uid ceiling is not the denominator here.
	maxProc, err := unix.SysctlUint32("kern.maxproc")
	if err != nil {
		return hostStats{}, fmt.Errorf("sysctl kern.maxproc: %w", err)
	}
	procCount, err := sampleProcessCount()
	if err != nil {
		return hostStats{}, fmt.Errorf("sample process count: %w", err)
	}

	head, err := sampleMemoryHeadroom()
	if err != nil {
		return hostStats{}, fmt.Errorf("sample memory headroom: %w", err)
	}

	return hostStats{
		MemAvailableBytes:        memAvail,
		MemCapacityBytes:         int64(capacity),
		DiskAvailableBytes:       int64(fs.Bavail) * blockSize,
		DiskCapacityBytes:        int64(fs.Blocks) * blockSize,
		PIDCount:                 procCount,
		PIDMax:                   int64(maxProc),
		CompressorPages:          head.compressorPages,
		CompressorPagesLimit:     head.compressorPagesLimit,
		CompressorSegments:       head.compressorSegments,
		CompressorSegmentsLimit:  head.compressorSegmentsLimit,
		SwapUsedBytes:            head.swapUsed,
		SwapVolumeAvailableBytes: head.swapVolumeAvailable,
		SwapVolumeCapacityBytes:  head.swapVolumeCapacity,
	}, nil
}

// memoryHeadroom is the raw reading behind the compressor and swap arms of
// memoryPressured: four compressor counters, the swap in use, and the swap
// volume's free space and size.
type memoryHeadroom struct {
	compressorPages         int64
	compressorPagesLimit    int64
	compressorSegments      int64
	compressorSegmentsLimit int64
	swapUsed                int64
	swapVolumeAvailable     int64
	swapVolumeCapacity      int64
}

// decodeSysctlCounter decodes a raw sysctl integer. The vm.compressor counters
// are 32-bit on current macOS; an 8-byte answer is accepted too, so a kernel that
// widens one does not stop the sample. Any other length is an error, never a
// guess.
func decodeSysctlCounter(name string, raw []byte) (int64, error) {
	switch len(raw) {
	case 4:
		return int64(binary.NativeEndian.Uint32(raw)), nil
	case 8:
		v := binary.NativeEndian.Uint64(raw)
		if v > 1<<62 {
			return 0, fmt.Errorf("sysctl %s: implausible value %d", name, v)
		}
		return int64(v), nil
	default:
		return 0, fmt.Errorf("sysctl %s: %d-byte answer, want 4 or 8", name, len(raw))
	}
}

// xswUsageLen is sizeof(struct xsw_usage) from the SDK's <sys/sysctl.h>:
//
//	struct xsw_usage {
//		u_int64_t xsu_total;     // offset 0
//		u_int64_t xsu_avail;     // offset 8
//		u_int64_t xsu_used;      // offset 16
//		u_int32_t xsu_pagesize;  // offset 24
//		boolean_t xsu_encrypted; // offset 28 (boolean_t is an int)
//	};
const xswUsageLen = 32

// decodeSwapUsed returns xsu_used from a raw vm.swapusage answer, decoded by
// offset after an exact length check: a struct of any other size is a layout this
// code has not read, and a wrong offset would publish a plausible lie.
func decodeSwapUsed(raw []byte) (int64, error) {
	if len(raw) != xswUsageLen {
		return 0, fmt.Errorf("sysctl vm.swapusage: %d-byte answer, want %d (struct xsw_usage)", len(raw), xswUsageLen)
	}
	used := binary.NativeEndian.Uint64(raw[16:24])
	if used > 1<<62 {
		return 0, fmt.Errorf("sysctl vm.swapusage: implausible used %d", used)
	}
	return int64(used), nil
}
