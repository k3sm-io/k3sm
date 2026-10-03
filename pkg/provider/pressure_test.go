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
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// fakeAfter is the monitor's cadence seam: every wait the monitor asks for is
// recorded, and the test decides when it fires.
type fakeAfter struct {
	waits chan time.Duration
	fire  chan time.Time
}

func newFakeAfter() *fakeAfter {
	return &fakeAfter{waits: make(chan time.Duration, 64), fire: make(chan time.Time)}
}

func (f *fakeAfter) after(d time.Duration) <-chan time.Time {
	f.waits <- d
	return f.fire
}

// nextWait returns the next wait the monitor asked for.
func (f *fakeAfter) nextWait(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-f.waits:
		return d
	case <-time.After(5 * time.Second):
		t.Fatal("the monitor asked for no further wait")
		return 0
	}
}

// countingSampler is a host sampler that counts its calls and serves a settable
// snapshot or error.
type countingSampler struct {
	mu    sync.Mutex
	calls int
	s     hostStats
	err   error
}

func (c *countingSampler) sample(string) (hostStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return c.s, c.err
}

func (c *countingSampler) set(s hostStats, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s, c.err = s, err
}

func (c *countingSampler) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// feedPressure runs snapshots through a fresh monitor, the way production stamps the
// hysteresis history, and returns the MemoryPressure verdict after each.
func feedPressure(t *testing.T, seq ...hostStats) []bool {
	t.Helper()
	cs := &countingSampler{}
	m := newPressureMonitor(func() (hostStats, error) { return cs.sample("") }, discardLog())
	out := make([]bool, 0, len(seq))
	for _, s := range seq {
		cs.set(s, nil)
		m.sampleOnce()
		p, _ := memoryPressured(mustLatest(t, m))
		out = append(out, p)
	}
	return out
}

func boolsEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// segmentsAt is healthy stats with the compressor SEGMENTS at pct% of limit.
func segmentsAt(pct int64) hostStats {
	s := compressorAt(0)
	s.CompressorSegments = pct * 10
	return s
}

// availableAt is healthy stats with memory.available at b bytes.
func availableAt(b int64) hostStats {
	s := compressorAt(0)
	s.MemAvailableBytes = b
	return s
}

// swapAt is healthy stats with used swap and free swap-volume space.
func swapAt(used, volFree int64) hostStats {
	s := compressorAt(0)
	s.SwapUsedBytes = used
	s.SwapVolumeAvailableBytes = volFree
	return s
}

// TestComputeNodeConditionsCompressorHeadroom pins every trip and release edge
// of the k3sm-specific arms (and the hysteresis now riding memory.available),
// the unsampled-limit rule, and the two false-positive shapes the swap arm is
// conjunctive to avoid.
func TestComputeNodeConditionsCompressorHeadroom(t *testing.T) {
	const gi = int64(1) << 30
	const mi = int64(1) << 20
	cases := []struct {
		name string
		seq  []hostStats
		want []bool
	}{
		{"compressor pages: trip at 80%, hold above 70%, release at 70%",
			[]hostStats{compressorAt(79), compressorAt(80), compressorAt(75), compressorAt(71), compressorAt(70), compressorAt(79)},
			[]bool{false, true, true, true, false, false}},
		{"compressor segments: the same edges on the second limit",
			[]hostStats{segmentsAt(79), segmentsAt(80), segmentsAt(71), segmentsAt(70)},
			[]bool{false, true, true, false}},
		{"memory.available: trip below 100Mi, hold below 200Mi, release at 200Mi",
			[]hostStats{availableAt(100 * mi), availableAt(100*mi - 1), availableAt(150 * mi), availableAt(200*mi - 1), availableAt(200 * mi)},
			[]bool{false, true, true, true, false}},
		{"swap: in use, rising and the volume short; released after two calm samples",
			[]hostStats{swapAt(2*gi, 7*gi), swapAt(3*gi, 7*gi), swapAt(3*gi, 7*gi), swapAt(3*gi, 7*gi), swapAt(3*gi, 7*gi)},
			[]bool{false, true, true, false, false}},
		{"swap: under 1Gi in use never trips, however short the volume",
			[]hostStats{swapAt(100*mi, 1*gi), swapAt(900*mi, 1*gi)},
			[]bool{false, false}},
		{"swap: exactly 8Gi free on the volume does not trip (strict <)",
			[]hostStats{swapAt(2*gi, 8*gi), swapAt(3*gi, 8*gi)},
			[]bool{false, false}},
		{"swap in use but flat: no pressure",
			[]hostStats{swapAt(4*gi, 2*gi), swapAt(4*gi, 2*gi), swapAt(4*gi, 2*gi)},
			[]bool{false, false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := feedPressure(t, tc.seq...); !boolsEqual(got, tc.want) {
				t.Errorf("MemoryPressure per sample = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("a zero limit is unsampled, not pressure", func(t *testing.T) {
		s := healthyStats()
		s.CompressorPages, s.CompressorPagesLimit = 1<<40, 0
		s.CompressorSegments, s.CompressorSegmentsLimit = 1<<40, 0
		if p, _ := memoryPressured(s); p {
			t.Error("a counter over a zero limit read as pressure")
		}
	})

	t.Run("full disk with no swap in use: DiskPressure, never MemoryPressure", func(t *testing.T) {
		s := compressorAt(0)
		s.DiskAvailableBytes = 512 << 20
		s.SwapVolumeAvailableBytes = 512 << 20
		s.SwapUsedBytes = 0
		got := feedPressure(t, s, s, s)
		if !boolsEqual(got, []bool{false, false, false}) {
			t.Errorf("MemoryPressure on a full disk with no swap = %v, want all false", got)
		}
		now := metav1.NewTime(time.Unix(0, 0))
		conds := computeNodeConditions(s, now)
		if c := findNodeCondition(conds, corev1.NodeDiskPressure); c == nil || c.Status != corev1.ConditionTrue {
			t.Errorf("fixture: DiskPressure = %+v, want True (the disk really is full)", c)
		}
		if c := findNodeCondition(conds, corev1.NodeMemoryPressure); c == nil || c.Status != corev1.ConditionFalse {
			t.Errorf("MemoryPressure = %+v, want False", c)
		}
	})

	t.Run("the raised condition names its signal; the Reason stays the kubelet's", func(t *testing.T) {
		now := metav1.NewTime(time.Unix(0, 0))
		c := findNodeCondition(computeNodeConditions(compressorAt(83), now), corev1.NodeMemoryPressure)
		if c.Status != corev1.ConditionTrue || c.Reason != "KubeletHasInsufficientMemory" ||
			c.Message != "kubelet has insufficient memory available: compressor 83% of limit" {
			t.Errorf("MemoryPressure = %s/%s/%q", c.Status, c.Reason, c.Message)
		}
	})
}

// TestPressureMonitorSharesMemoryPressurePredicate is the one-sample, one-verdict
// gate: the monitor's adaptive cadence, the status loop taking no sample of its
// own, the published MemoryPressure and the eviction trigger agreeing at every
// edge of every arm, the signal-naming Message, the immediate publish on a
// False->True edge, and a sampler error that keeps the snapshot and ages it.
func TestPressureMonitorSharesMemoryPressurePredicate(t *testing.T) {
	t.Run("cadence: 10s calm, 1s past the half-way mark, 10s after three calm samples", func(t *testing.T) {
		cs := &countingSampler{s: compressorAt(10)}
		m := newPressureMonitor(func() (hostStats, error) { return cs.sample("") }, discardLog())
		fa := newFakeAfter()
		m.after = fa.after
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		m.sampleOnce()
		go func() { defer close(done); m.run(ctx) }()
		defer func() { cancel(); <-done }()

		fire := func(s hostStats) {
			cs.set(s, nil)
			fa.fire <- time.Time{}
		}
		if d := fa.nextWait(t); d != 10*time.Second {
			t.Fatalf("calm wait = %v, want 10s", d)
		}
		fire(compressorAt(40)) // half of the 80% trip
		if d := fa.nextWait(t); d != time.Second {
			t.Fatalf("wait past the half-way mark = %v, want 1s", d)
		}
		for i, want := range []time.Duration{time.Second, time.Second, 10 * time.Second} {
			fire(compressorAt(39))
			if d := fa.nextWait(t); d != want {
				t.Fatalf("wait after calm sample %d = %v, want %v", i+1, d, want)
			}
		}
		// Each arm's half-way mark switches it, not only the compressor's.
		for name, s := range map[string]hostStats{
			"memory.available under 200Mi": availableAt(150 << 20),
			"segments at 40%":              segmentsAt(40),
			"swap volume under 16Gi":       swapAt(600<<20, 15<<30),
		} {
			fire(s)
			if d := fa.nextWait(t); d != time.Second {
				t.Errorf("%s: wait = %v, want 1s", name, d)
			}
			for range 3 {
				fire(compressorAt(10))
				fa.nextWait(t)
			}
		}
	})

	t.Run("the status loop takes no sample of its own", func(t *testing.T) {
		cs := &countingSampler{s: compressorAt(10)}
		p, err := NewNodeStatusProvider(NodeStatusConfig{Node: bootstrapNode(), DataRoot: "/", Interval: time.Hour, Log: discardLog()})
		if err != nil {
			t.Fatalf("NewNodeStatusProvider: %v", err)
		}
		p.sample = cs.sample
		p.publish = func(context.Context, *corev1.Node) error { return nil }
		for range 3 {
			if err := p.publishOnce(context.Background()); err != nil {
				t.Fatalf("publishOnce: %v", err)
			}
		}
		if n := cs.count(); n != 0 {
			t.Errorf("three publishes took %d samples, want 0 (only the monitor samples)", n)
		}
		p.monitor.sampleOnce()
		if n := cs.count(); n != 1 {
			t.Errorf("one monitor sample = %d sampler calls, want 1", n)
		}
	})

	t.Run("published MemoryPressure and the eviction trigger agree at every edge", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		seq := []hostStats{
			compressorAt(10), compressorAt(80), compressorAt(71), compressorAt(70),
			segmentsAt(80), segmentsAt(70),
			availableAt(99 << 20), availableAt(199 << 20), availableAt(200 << 20),
			swapAt(2<<30, 7<<30), swapAt(3<<30, 7<<30), swapAt(3<<30, 7<<30), swapAt(3<<30, 7<<30),
		}
		// The first swap sample already rises (the sample before it had no swap
		// in use), so the swap arm trips there and releases on the second calm one.
		want := []bool{false, true, true, false, true, false, true, true, false, true, true, true, false}
		for i, s := range seq {
			h.setStats(s)
			node := h.step()
			snap := mustLatest(t, h.p.monitor)
			trigger, _ := memoryPressured(snap)
			computed := findNodeCondition(computeNodeConditions(snap, metav1.Now()), corev1.NodeMemoryPressure).Status == corev1.ConditionTrue
			published := condOf(t, node, corev1.NodeMemoryPressure).Status == corev1.ConditionTrue
			if trigger != published || computed != published || published != want[i] {
				t.Errorf("sample %d: published=%v computeNodeConditions=%v trigger=%v, want all %v", i, published, computed, trigger, want[i])
			}
		}
	})

	t.Run("the Message names the firing signal", func(t *testing.T) {
		for _, tc := range []struct {
			seq  []hostStats
			want string
		}{
			{[]hostStats{compressorAt(85)}, "kubelet has insufficient memory available: compressor 85% of limit"},
			{[]hostStats{availableAt(50 << 20)}, "kubelet has insufficient memory available: memory.available 50Mi"},
			{[]hostStats{swapAt(2<<30, 6<<30), swapAt(3<<30, 6<<30)}, "kubelet has insufficient memory available: swap growing, 6.0Gi free on the swap volume"},
		} {
			h := newNodeStatusHarness(t, bootstrapNode())
			var node *corev1.Node
			for _, s := range tc.seq {
				h.setStats(s)
				node = h.step()
			}
			if got := condOf(t, node, corev1.NodeMemoryPressure).Message; got != tc.want {
				t.Errorf("Message = %q, want %q", got, tc.want)
			}
		}
	})

	t.Run("a False->True edge publishes without waiting for the status tick", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		h.p.interval = time.Hour
		fa := newFakeAfter()
		h.p.monitor.after = fa.after
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- h.p.Run(ctx) }()
		defer func() { cancel(); <-done }()

		published := func() []*corev1.Node {
			h.mu.Lock()
			defer h.mu.Unlock()
			return append([]*corev1.Node(nil), h.published...)
		}
		waitFor := func(what string, cond func([]*corev1.Node) bool) {
			t.Helper()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if cond(published()) {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Fatalf("timed out waiting for %s", what)
		}
		waitFor("the first publication", func(ns []*corev1.Node) bool { return len(ns) == 1 })
		wantStatus(t, published()[0], corev1.NodeMemoryPressure, corev1.ConditionFalse)
		fa.nextWait(t)
		h.setStats(compressorAt(90))
		fa.fire <- time.Time{}
		waitFor("the edge publication", func(ns []*corev1.Node) bool { return len(ns) >= 2 })
		wantStatus(t, published()[1], corev1.NodeMemoryPressure, corev1.ConditionTrue)
	})

	t.Run("a sampler error keeps the previous snapshot and ages it", func(t *testing.T) {
		cs := &countingSampler{s: compressorAt(85)}
		m := newPressureMonitor(func() (hostStats, error) { return cs.sample("") }, discardLog())
		clock := time.Unix(1000, 0)
		m.now = func() time.Time { return clock }
		m.sampleOnce()
		before, seq, _ := m.latest()
		cs.set(hostStats{}, errors.New("sysctl vm.swapusage: no such file"))
		clock = clock.Add(30 * time.Second)
		m.sampleOnce()
		after, seq2, ok := m.latest()
		if !ok || seq2 != seq || after != before {
			t.Errorf("after a failed sample: snapshot changed (seq %d->%d), want the previous one kept", seq, seq2)
		}
		if p, _ := memoryPressured(after); !p {
			t.Error("a failed sample cleared the pressure verdict; a failure is never \"no pressure\"")
		}
		if age := m.sampleAge(); age != 30*time.Second {
			t.Errorf("last-successful-sample age = %v, want 30s", age)
		}
	})
}

// TestDecodeHeadroomSysctls pins the raw sysctl decoders: the counter widths the
// sampler accepts, and the xsw_usage layout decoded by offset.
func TestDecodeHeadroomSysctls(t *testing.T) {
	four := binary.NativeEndian.AppendUint32(nil, 780238)
	eight := binary.NativeEndian.AppendUint64(nil, 3120952)
	for _, tc := range []struct {
		name    string
		raw     []byte
		want    int64
		wantErr bool
	}{
		{"4-byte counter", four, 780238, false},
		{"8-byte counter accepted defensively", eight, 3120952, false},
		{"2-byte answer refused", []byte{1, 2}, 0, true},
		{"empty answer refused", nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSysctlCounter("vm.compressor.segment.limit", tc.raw)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("decode = %d, %v; want %d, err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}

	xsw := make([]byte, 0, xswUsageLen)
	xsw = binary.NativeEndian.AppendUint64(xsw, 2048<<20) // total
	xsw = binary.NativeEndian.AppendUint64(xsw, 1152<<20) // avail
	xsw = binary.NativeEndian.AppendUint64(xsw, 896<<20)  // used
	xsw = binary.NativeEndian.AppendUint32(xsw, 16384)    // pagesize
	xsw = binary.NativeEndian.AppendUint32(xsw, 1)        // encrypted
	if used, err := decodeSwapUsed(xsw); err != nil || used != 896<<20 {
		t.Errorf("decodeSwapUsed = %d, %v; want %d", used, err, int64(896<<20))
	}
	if _, err := decodeSwapUsed(xsw[:24]); err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Errorf("a short xsw_usage was not refused: %v", err)
	}
}
