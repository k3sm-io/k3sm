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

// sampleHostStats takes ONE live snapshot of node-level resource availability:
// memory from host_statistics64, disk from statfs of the volume backing dataRoot,
// and the process table from sysctl. It is the only impure half of the
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

	return hostStats{
		MemAvailableBytes:  memAvail,
		MemCapacityBytes:   int64(capacity),
		DiskAvailableBytes: int64(fs.Bavail) * blockSize,
		DiskCapacityBytes:  int64(fs.Blocks) * blockSize,
		PIDCount:           procCount,
		PIDMax:             int64(maxProc),
	}, nil
}
