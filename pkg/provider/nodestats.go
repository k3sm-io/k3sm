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
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// hostMemory is one host-wide memory reading, in bytes (readHostMemory).
type hostMemory struct {
	workingSetBytes int64
	freeBytes       int64
}

// cpuTicks is one raw aggregate HOST_CPU_LOAD_INFO reading. user, system and
// nice are 32-bit natural_t counters widened to uint64 (they still wrap at
// 2^32); hz is the tick rate, sysconf(_SC_CLK_TCK).
type cpuTicks struct {
	user, system, nice uint64
	hz                 uint64
}

// cpuTickAccumulator turns the wrapping 32-bit tick counters into one cumulative
// uint64 tick count. Each counter keeps its last raw value and an accumulated
// total; a new reading adds the wrapping (uint32) difference, so a wrap between
// two readings is absorbed as a small forward step rather than a huge backward
// one. The totals are seeded from the FIRST reading, so the count is
// cumulative-since-boot until a counter has wrapped.
//
// A daemon restart after a wrap re-seeds from the wrapped raw value, so the
// counter then restarts lower than it was published before. metrics-server
// computes a rate between two samples and discards a negative one, so this costs
// one scrape interval, not a wrong figure.
//
// mu guards every field AND is held across the counter read (sample), so the
// readings are folded in the order they were taken. Reading outside the lock
// would let two concurrent summary requests fold out of order: the later
// reading folded first makes the earlier one's wrapping difference ~2^32
// ticks, inflating the counter permanently.
type cpuTickAccumulator struct {
	mu     sync.Mutex
	seeded bool
	last   [3]uint32
	total  [3]uint64
}

// sample takes one reading with read and folds it in, holding mu across both,
// and returns the cumulative user+system+nice ticks (idle is excluded by
// construction) and the reading's tick rate.
func (a *cpuTickAccumulator) sample(read func() (cpuTicks, error)) (ticks, hz uint64, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, err := read()
	if err != nil {
		return 0, 0, err
	}
	raw := [3]uint32{uint32(t.user), uint32(t.system), uint32(t.nice)}
	if !a.seeded {
		for i, r := range raw {
			a.total[i] = uint64(r)
		}
		a.seeded = true
	} else {
		for i, r := range raw {
			a.total[i] += uint64(r - a.last[i]) // wrapping uint32 subtraction
		}
	}
	a.last = raw
	return a.total[0] + a.total[1] + a.total[2], t.hz, nil
}

// hostCPUTicks is the process-wide accumulator behind the real sampler. One per
// process, because the raw counters are machine-wide.
var hostCPUTicks cpuTickAccumulator

// hostSample is one host-wide resource reading, in nanoseconds and bytes.
type hostSample struct {
	cpuUsageNanos   uint64
	memsizeBytes    uint64
	workingSetBytes uint64
	freeBytes       uint64
}

// hostSampler reads the host for the node stats summary. The darwin
// implementation is darwinHostSampler; tests inject a fake.
type hostSampler interface {
	BootTime() (time.Time, error)
	Sample() (hostSample, error)
}

// darwinHostSampler reads the real host: kern.boottime, hw.memsize, the
// host_statistics64 page classes (readHostMemory) and the HOST_CPU_LOAD_INFO
// tick counters (readHostCPUTicks) through the process-wide accumulator.
type darwinHostSampler struct{}

// defaultHostSampler is used by every provider that was not handed one.
var defaultHostSampler hostSampler = darwinHostSampler{}

// BootTime returns kern.boottime.
func (darwinHostSampler) BootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, fmt.Errorf("sysctl kern.boottime: %w", err)
	}
	return time.Unix(tv.Sec, int64(tv.Usec)*int64(time.Microsecond)), nil
}

// Sample reads memory and CPU once.
func (darwinHostSampler) Sample() (hostSample, error) {
	memsize, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return hostSample{}, fmt.Errorf("sysctl hw.memsize: %w", err)
	}
	mem, err := readHostMemory()
	if err != nil {
		return hostSample{}, fmt.Errorf("sample host memory: %w", err)
	}
	ticks, hz, err := hostCPUTicks.sample(readHostCPUTicks)
	if err != nil {
		return hostSample{}, fmt.Errorf("sample host cpu: %w", err)
	}
	if hz == 0 || hz > uint64(time.Second) {
		return hostSample{}, fmt.Errorf("sample host cpu: implausible tick rate %d Hz", hz)
	}
	return hostSample{
		cpuUsageNanos:   ticks * (uint64(time.Second) / hz),
		memsizeBytes:    memsize,
		workingSetBytes: uint64(max(mem.workingSetBytes, 0)),
		freeBytes:       uint64(max(mem.freeBytes, 0)),
	}, nil
}

// nodeStatsWarnOnce bounds the sampler-failure log to one line per process: the
// summary is requested every scrape, and the failure (a CGO=0 build, a Mach
// error) does not heal between scrapes.
var nodeStatsWarnOnce sync.Once

// errIncompleteHostSample marks a reading that would publish a zero half.
var errIncompleteHostSample = errors.New("host sample has a zero cpu, memory size or working set")

// nodeStats builds the node half of the kubelet stats Summary from one host
// reading, stamping CPU and Memory with the SAME now so the joint-emission rule
// in buildResourceMetrics holds. On any sampler error it returns only
// NodeName and StartTime, never a half-filled row.
//
// The mapping (host-wide, not cgroup-scoped):
//
//   - CPU.UsageCoreNanoSeconds: cumulative user+system+nice scheduler ticks of
//     the aggregate HOST_CPU_LOAD_INFO, times 1e9/_SC_CLK_TCK. Idle is excluded.
//   - Memory.WorkingSetBytes: the same working set the MemoryPressure condition
//     uses, (wire + internal - purgeable + compressor) pages x host_page_size.
//   - Memory.AvailableBytes: hw.memsize - working set.
//   - Memory.UsageBytes: hw.memsize - free pages x host_page_size.
//
// Every figure describes the whole Mac, including processes k3sm did not start,
// so node usage can exceed the node's Allocatable. That is the honest reading and
// is deliberately never clamped.
func nodeStats(s hostSampler, nodeName string, now time.Time) statsv1alpha1.NodeStats {
	if s == nil {
		s = defaultHostSampler
	}
	ns := statsv1alpha1.NodeStats{NodeName: nodeName}
	if boot, err := s.BootTime(); err == nil {
		ns.StartTime = metav1.NewTime(boot)
	}
	hs, err := s.Sample()
	if err == nil && (hs.cpuUsageNanos == 0 || hs.memsizeBytes == 0 || hs.workingSetBytes == 0) {
		err = errIncompleteHostSample
	}
	if err != nil {
		nodeStatsWarnOnce.Do(func() {
			slog.Warn("node stats: host sample unavailable; node cpu and memory are not reported", "node", nodeName, "err", err)
		})
		return ns
	}
	var available, usage uint64
	if hs.memsizeBytes > hs.workingSetBytes {
		available = hs.memsizeBytes - hs.workingSetBytes
	}
	if hs.memsizeBytes > hs.freeBytes {
		usage = hs.memsizeBytes - hs.freeBytes
	}
	ts := metav1.NewTime(now)
	cpu := hs.cpuUsageNanos
	ws := hs.workingSetBytes
	ns.CPU = &statsv1alpha1.CPUStats{Time: ts, UsageCoreNanoSeconds: &cpu}
	ns.Memory = &statsv1alpha1.MemoryStats{
		Time:            ts,
		WorkingSetBytes: &ws,
		AvailableBytes:  &available,
		UsageBytes:      &usage,
	}
	return ns
}
