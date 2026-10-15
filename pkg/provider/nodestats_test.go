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
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// fakeHostSampler is a deterministic hostSampler: each Sample advances the CPU
// counter by one tick of tickNanos, and err (when set) fails every Sample.
type fakeHostSampler struct {
	mu        sync.Mutex
	boot      time.Time
	cpuNanos  uint64
	tickNanos uint64
	memsize   uint64
	ws        uint64
	free      uint64
	err       error
}

func newFakeHostSampler() *fakeHostSampler {
	return &fakeHostSampler{
		boot:      time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC),
		cpuNanos:  40_000_000_000,
		tickNanos: 10_000_000, // one 100 Hz tick
		memsize:   16 << 30,
		ws:        6 << 30,
		free:      2 << 30,
	}
}

func (f *fakeHostSampler) BootTime() (time.Time, error) { return f.boot, nil }

func (f *fakeHostSampler) Sample() (hostSample, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return hostSample{}, f.err
	}
	f.cpuNanos += f.tickNanos
	return hostSample{cpuUsageNanos: f.cpuNanos, memsizeBytes: f.memsize, workingSetBytes: f.ws, freeBytes: f.free}, nil
}

// summaryFunc returns one provider's GetStatsSummary wired to sampler s.
type summaryFunc func(t *testing.T, s hostSampler) func() (*statsv1alpha1.Summary, error)

func statsProviders() []struct {
	name  string
	build summaryFunc
} {
	ctx := context.Background()
	return []struct {
		name  string
		build summaryFunc
	}{
		{"HostProcess", func(t *testing.T, s hostSampler) func() (*statsv1alpha1.Summary, error) {
			p := NewHostProcess("k3sm-node", t.TempDir(), "127.0.0.1", nil)
			p.nodeSampler = s
			return func() (*statsv1alpha1.Summary, error) { return p.GetStatsSummary(ctx) }
		}},
		{"runtimed", func(t *testing.T, s hostSampler) func() (*statsv1alpha1.Summary, error) {
			r, _ := newRuntimedFake(t)
			r.nodeSampler = s
			v := NewVKProvider(r, "k3sm-node")
			return func() (*statsv1alpha1.Summary, error) { return v.GetStatsSummary(ctx) }
		}},
		{"VKProvider without StatsSource", func(t *testing.T, s hostSampler) func() (*statsv1alpha1.Summary, error) {
			v := NewVKProvider(&statsLessRuntime{}, "k3sm-node")
			v.nodeSampler = s
			return func() (*statsv1alpha1.Summary, error) { return v.GetStatsSummary(ctx) }
		}},
	}
}

// TestStatsSummaryCarriesNodeCPUAndMemory is the gate for the node row of the
// stats summary: every provider fills host-wide CPU and memory, stamped with one
// time, so metrics-server's node decode keeps the record.
func TestStatsSummaryCarriesNodeCPUAndMemory(t *testing.T) {
	for _, tc := range statsProviders() {
		t.Run(tc.name+"/filled", func(t *testing.T) {
			fake := newFakeHostSampler()
			get := tc.build(t, fake)
			s1, err := get()
			if err != nil {
				t.Fatalf("GetStatsSummary: %v", err)
			}
			n := s1.Node
			if n.CPU == nil || n.CPU.UsageCoreNanoSeconds == nil || *n.CPU.UsageCoreNanoSeconds == 0 {
				t.Fatalf("node CPU missing or zero: %+v", n.CPU)
			}
			if n.Memory == nil || n.Memory.WorkingSetBytes == nil || *n.Memory.WorkingSetBytes == 0 ||
				n.Memory.AvailableBytes == nil || n.Memory.UsageBytes == nil {
				t.Fatalf("node memory missing or zero: %+v", n.Memory)
			}
			if n.CPU.Time.IsZero() || !n.CPU.Time.Equal(&n.Memory.Time) {
				t.Errorf("CPU.Time %v and Memory.Time %v must be equal and non-zero", n.CPU.Time, n.Memory.Time)
			}
			if !n.StartTime.Time.Equal(fake.boot) {
				t.Errorf("StartTime = %v, want boot time %v", n.StartTime, fake.boot)
			}
			ws, avail, usage := *n.Memory.WorkingSetBytes, *n.Memory.AvailableBytes, *n.Memory.UsageBytes
			if ws > fake.memsize {
				t.Errorf("working set %d exceeds memsize %d", ws, fake.memsize)
			}
			if avail != fake.memsize-ws {
				t.Errorf("available = %d, want memsize - working set = %d", avail, fake.memsize-ws)
			}
			if usage != fake.memsize-fake.free {
				t.Errorf("usage = %d, want memsize - free = %d", usage, fake.memsize-fake.free)
			}

			time.Sleep(time.Millisecond)
			s2, err := get()
			if err != nil {
				t.Fatalf("second GetStatsSummary: %v", err)
			}
			if c1, c2 := *n.CPU.UsageCoreNanoSeconds, *s2.Node.CPU.UsageCoreNanoSeconds; c2 <= c1 {
				t.Errorf("UsageCoreNanoSeconds not strictly increasing: %d then %d", c1, c2)
			}
			if !s2.Node.CPU.Time.After(n.CPU.Time.Time) {
				t.Errorf("CPU.Time did not advance: %v then %v", n.CPU.Time, s2.Node.CPU.Time)
			}

			fams := buildResourceMetrics(s1)
			batch, text := scrapeAsMetricsServer(t, fams)
			if !strings.Contains(text, nodeCPUFamily) || !strings.Contains(text, nodeMemoryFamily) {
				t.Fatalf("both node families must be emitted; served text:\n%s", text)
			}
			pt, ok := batch.nodes["k3sm-node"] // the consumer fake keys its one node by this name
			if !ok {
				t.Fatalf("metrics-server dropped the node record; served text:\n%s", text)
			}
			if !pt.timestamp.Equal(n.CPU.Time.Time.Truncate(time.Millisecond)) {
				t.Errorf("node timestamp = %v, want %v", pt.timestamp, n.CPU.Time.Time)
			}
		})

		t.Run(tc.name+"/sampler error", func(t *testing.T) {
			fake := newFakeHostSampler()
			fake.err = errors.New("host_statistics: rc -5")
			get := tc.build(t, fake)
			s, err := get()
			if err != nil {
				t.Fatalf("GetStatsSummary: %v", err)
			}
			if s.Node.CPU != nil || s.Node.Memory != nil {
				t.Errorf("a failed sample must leave no node rows, got CPU=%+v Memory=%+v", s.Node.CPU, s.Node.Memory)
			}
			if s.Node.NodeName == "" || s.Node.StartTime.IsZero() {
				t.Errorf("bare node row must keep NodeName and StartTime: %+v", s.Node)
			}
			for _, mf := range buildResourceMetrics(s) {
				if strings.HasPrefix(mf.GetName(), "node_") {
					t.Errorf("node family %q emitted from a failed sample", mf.GetName())
				}
			}
		})
	}

	t.Run("tick counter wrap is monotonic", func(t *testing.T) {
		var a cpuTickAccumulator
		first := mustSample(t, &a, cpuTicks{user: 1<<32 - 10, system: 100, nice: 1, hz: 100})
		second := mustSample(t, &a, cpuTicks{user: 5, system: 101, nice: 1, hz: 100})
		if first != (1<<32-10)+100+1 {
			t.Errorf("first observation = %d, want the seeded raw sum", first)
		}
		if second != first+15+1 {
			t.Errorf("after the wrap = %d, want %d (15 user + 1 system ticks)", second, first+16)
		}
	})

	t.Run("real host", func(t *testing.T) {
		if testing.Short() {
			t.Skip("reads the real host and spins a CPU for 1s")
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
	})
}

// mustSample folds one fixed reading into a through sample.
func mustSample(t *testing.T, a *cpuTickAccumulator, r cpuTicks) uint64 {
	t.Helper()
	total, _, err := a.sample(func() (cpuTicks, error) { return r, nil })
	if err != nil {
		t.Fatalf("sample: %v", err)
	}
	return total
}

// TestCPUTickAccumulatorSerializesReadAndFold pins that the counter read and the
// fold happen under one lock: the readings are folded in the order they were
// taken, so concurrent summary requests can never fold a later reading before
// an earlier one (which would wrap the difference to ~2^32 ticks).
func TestCPUTickAccumulatorSerializesReadAndFold(t *testing.T) {
	t.Run("a sample arriving during a slow read waits for it", func(t *testing.T) {
		var a cpuTickAccumulator
		mustSample(t, &a, cpuTicks{user: 1000, hz: 100})

		// A's read starts first and is held mid-read; B arrives while A is
		// still reading and would observe the LATER counter value. Under the
		// lock B cannot read until A has folded, so the readings fold in the
		// order they were taken.
		var mu sync.Mutex
		counter := uint64(1000)
		read := func() (cpuTicks, error) {
			mu.Lock()
			defer mu.Unlock()
			counter += 50
			return cpuTicks{user: counter, hz: 100}, nil
		}
		inRead, release := make(chan struct{}), make(chan struct{})
		aDone, bDone := make(chan uint64), make(chan uint64)
		go func() {
			total, _, _ := a.sample(func() (cpuTicks, error) {
				close(inRead)
				<-release
				return read()
			})
			aDone <- total
		}()
		<-inRead
		go func() {
			total, _, _ := a.sample(read)
			bDone <- total
		}()
		select {
		case <-bDone:
			t.Fatal("B folded while A held the accumulator mid-read")
		case <-time.After(50 * time.Millisecond):
		}
		close(release)
		gotA, gotB := <-aDone, <-bDone
		if gotA != 1050 || gotB != 1100 {
			t.Errorf("totals = %d then %d, want 1050 then 1100 (the true deltas)", gotA, gotB)
		}
	})

	t.Run("concurrent hammer totals the true delta", func(t *testing.T) {
		const goroutines, perG, step = 8, 100, 3
		var a cpuTickAccumulator
		var mu sync.Mutex
		raw := uint64(1<<32 - 1000) // wraps part-way through the hammer
		read := func() (cpuTicks, error) {
			mu.Lock()
			defer mu.Unlock()
			raw += step
			return cpuTicks{user: raw, hz: 100}, nil
		}
		first := mustSample(t, &a, cpuTicks{user: raw, hz: 100})
		var wg sync.WaitGroup
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				prev := uint64(0)
				for range perG {
					total, _, err := a.sample(read)
					if err != nil {
						t.Errorf("sample: %v", err)
						return
					}
					if total <= prev {
						t.Errorf("total went %d -> %d, not monotonic", prev, total)
					}
					prev = total
				}
			}()
		}
		wg.Wait()
		final := mustSample(t, &a, cpuTicks{user: raw, hz: 100}) // re-read the last raw: zero delta
		if want := first + goroutines*perG*step; final != want {
			t.Errorf("final total = %d, want %d (first + every step)", final, want)
		}
	})
}
