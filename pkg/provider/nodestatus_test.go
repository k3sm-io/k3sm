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
	"reflect"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/ports"
)

// nodeStatusHarness drives a NodeStatusProvider with every host- and
// cluster-facing seam faked: no Mach, no statfs, no sysctl, no apiserver, no
// wall clock. Each step() call is exactly one status cycle.
type nodeStatusHarness struct {
	t *testing.T
	p *NodeStatusProvider

	mu        sync.Mutex
	stats     hostStats
	statsErr  error
	healthy   bool
	clock     time.Time
	published []*corev1.Node
}

// healthyStats is a snapshot clear of every threshold, in both directions: 8 GiB
// available memory, 100 GiB free disk (above the hysteresis CLEAR level, not just
// the trip floor), 50 of 2000 systemwide PIDs.
func healthyStats() hostStats {
	return hostStats{
		MemAvailableBytes:  8 << 30,
		MemCapacityBytes:   16 << 30,
		DiskAvailableBytes: 100 << 30,
		DiskCapacityBytes:  500 << 30,
		PIDCount:           50,
		PIDMax:             2000,
	}
}

// bootstrapNode is the node object as it is handed to the status provider at
// registration: identity labels, real capacity and the memory-reserved
// allocatable, the InternalIP the apiserver dials, the kubelet daemon endpoint,
// the provider taint, and the five empty conditions the node helper seeds.
func bootstrapNode() *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "mac-0",
			Labels: map[string]string{
				"kubernetes.io/os":       "darwin",
				"kubernetes.io/arch":     "arm64",
				"kubernetes.io/hostname": "mac-0",
				"k3sm.io/native":         "true",
			},
		},
		Spec: corev1.NodeSpec{
			Taints: []corev1.Taint{{Key: "k3sm.io/provider", Effect: corev1.TaintEffectNoSchedule}},
		},
		Status: corev1.NodeStatus{
			Phase: corev1.NodePending,
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:    *resource.NewQuantity(10, resource.DecimalSI),
				corev1.ResourceMemory: *resource.NewQuantity(64<<30, resource.BinarySI),
				corev1.ResourcePods:   *resource.NewQuantity(110, resource.DecimalSI),
			},
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:    *resource.NewQuantity(10, resource.DecimalSI),
				corev1.ResourceMemory: *resource.NewQuantity(64<<30-(64<<30)/10, resource.BinarySI),
				corev1.ResourcePods:   *resource.NewQuantity(110, resource.DecimalSI),
			},
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.4.0.7"},
				{Type: corev1.NodeHostName, Address: "mac-0"},
			},
			NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "darwin", Architecture: "arm64"},
			DaemonEndpoints: corev1.NodeDaemonEndpoints{
				KubeletEndpoint: corev1.DaemonEndpoint{Port: ports.KubeletAPIPort},
			},
			Conditions: []corev1.NodeCondition{
				{Type: corev1.NodeReady},
				{Type: corev1.NodeDiskPressure},
				{Type: corev1.NodeMemoryPressure},
				{Type: corev1.NodePIDPressure},
				{Type: corev1.NodeNetworkUnavailable},
			},
		},
	}
}

func newNodeStatusHarness(t *testing.T, node *corev1.Node) *nodeStatusHarness {
	t.Helper()
	h := &nodeStatusHarness{
		t:       t,
		stats:   healthyStats(),
		healthy: true,
		clock:   time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC),
	}
	p, err := NewNodeStatusProvider(NodeStatusConfig{
		Node:           node,
		DataRoot:       "/var/lib/k3sm",
		RuntimeHealthy: h.runtimeHealthy,
		Interval:       time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewNodeStatusProvider: %v", err)
	}
	p.sample = h.sample
	p.now = h.nowFn
	p.publish = h.publishFn
	h.p = p
	return h
}

func (h *nodeStatusHarness) sample(string) (hostStats, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stats, h.statsErr
}

func (h *nodeStatusHarness) runtimeHealthy(context.Context) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.healthy
}

func (h *nodeStatusHarness) nowFn() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clock = h.clock.Add(time.Minute)
	return h.clock
}

func (h *nodeStatusHarness) publishFn(_ context.Context, n *corev1.Node) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.published = append(h.published, n)
	return nil
}

// setStats installs the snapshot the next cycle will observe.
func (h *nodeStatusHarness) setStats(s hostStats) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stats = s
}

// setHealthy installs the runtime-health answer the next cycle will observe.
func (h *nodeStatusHarness) setHealthy(v bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.healthy = v
}

// step runs exactly one status cycle and returns the node it published.
func (h *nodeStatusHarness) step() *corev1.Node {
	h.t.Helper()
	if err := h.p.publishOnce(context.Background()); err != nil {
		h.t.Fatalf("publishOnce: %v", err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.published) == 0 {
		h.t.Fatal("publishOnce returned nil error but published nothing")
	}
	return h.published[len(h.published)-1]
}

// condOf returns the named condition of the published node, failing if absent.
func condOf(t *testing.T, n *corev1.Node, typ corev1.NodeConditionType) corev1.NodeCondition {
	t.Helper()
	c := findNodeCondition(n.Status.Conditions, typ)
	if c == nil {
		t.Fatalf("published node carries no %s condition: %+v", typ, n.Status.Conditions)
	}
	return *c
}

// wantStatus asserts a published condition's Status, naming the condition.
func wantStatus(t *testing.T, n *corev1.Node, typ corev1.NodeConditionType, want corev1.ConditionStatus) {
	t.Helper()
	if got := condOf(t, n, typ).Status; got != want {
		t.Errorf("%s = %q, want %q", typ, got, want)
	}
}

// TestNodeProviderReportsConditionsAndReady is the gate for the wired node
// provider: it drives whole status cycles through NodeStatusProvider (sample →
// compute → reconcile → publish) with every host seam faked, and pins the four
// properties the wiring exists to guarantee.
//
//  1. Each pressure condition trips and clears at its own documented threshold,
//     end to end through a publication rather than through the pure helper alone.
//  2. DiskPressure is a Schmitt trigger: a sample inside the 2 GiB..10 GiB band
//     keeps the PREVIOUS verdict, in BOTH directions.
//  3. Ready is debounced: one unhealthy sample does not flip it, the configured
//     number of consecutive unhealthy samples does, and one healthy sample
//     restores it.
//  4. Every bootstrap fact — InternalIP, Addresses, Capacity, Allocatable,
//     DaemonEndpoints, labels, taints — survives a full recompute-and-publish
//     cycle. The node controller assigns the published Status wholesale, so a
//     conditions-only publication would silently erase all of it.
func TestNodeProviderReportsConditionsAndReady(t *testing.T) {
	t.Run("pressure conditions trip and clear per their formulas", func(t *testing.T) {
		cases := []struct {
			name string
			typ  corev1.NodeConditionType
			// trip and clear are snapshots that must read True and False.
			trip  func(hostStats) hostStats
			clear func(hostStats) hostStats
		}{
			{
				name: "MemoryPressure at the 100Mi available floor",
				typ:  corev1.NodeMemoryPressure,
				trip: func(s hostStats) hostStats {
					s.MemAvailableBytes = memAvailableHardEvictionBytes - 1
					return s
				},
				clear: func(s hostStats) hostStats {
					s.MemAvailableBytes = memAvailableHardEvictionBytes
					return s
				},
			},
			{
				name: "DiskPressure at the absolute 2GiB free floor",
				typ:  corev1.NodeDiskPressure,
				trip: func(s hostStats) hostStats {
					s.DiskAvailableBytes = diskPressureTripFreeBytes - 1
					return s
				},
				// Clearing needs the CLEAR level, not merely the trip level: the
				// hysteresis band between them holds the previous verdict.
				clear: func(s hostStats) hostStats {
					s.DiskAvailableBytes = diskPressureClearFreeBytes
					return s
				},
			},
			{
				name: "PIDPressure at 90% of the systemwide kern.maxproc ceiling",
				typ:  corev1.NodePIDPressure,
				trip: func(s hostStats) hostStats {
					s.PIDMax, s.PIDCount = 2000, 1801 // >90%
					return s
				},
				clear: func(s hostStats) hostStats {
					s.PIDMax, s.PIDCount = 2000, 1800 // ==90%, strict >
					return s
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				h := newNodeStatusHarness(t, bootstrapNode())

				healthyNode := h.step()
				wantStatus(t, healthyNode, tc.typ, corev1.ConditionFalse)

				h.setStats(tc.trip(healthyStats()))
				tripped := h.step()
				wantStatus(t, tripped, tc.typ, corev1.ConditionTrue)

				h.setStats(tc.clear(healthyStats()))
				cleared := h.step()
				wantStatus(t, cleared, tc.typ, corev1.ConditionFalse)

				// Every other pressure condition stayed False throughout — the
				// perturbation drove exactly the signal under test.
				for _, other := range []corev1.NodeConditionType{
					corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure,
				} {
					if other == tc.typ {
						continue
					}
					wantStatus(t, tripped, other, corev1.ConditionFalse)
				}
				// NetworkUnavailable is statically False and Ready stayed True: a
				// resource pressure is not a runtime-health verdict.
				wantStatus(t, tripped, corev1.NodeNetworkUnavailable, corev1.ConditionFalse)
				wantStatus(t, tripped, corev1.NodeReady, corev1.ConditionTrue)
			})
		}
	})

	t.Run("LastTransitionTime is preserved while the status is unchanged", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		first := h.step()
		firstMem := condOf(t, first, corev1.NodeMemoryPressure).LastTransitionTime
		second := h.step()
		secondMem := condOf(t, second, corev1.NodeMemoryPressure)
		if !secondMem.LastTransitionTime.Equal(&firstMem) {
			t.Errorf("unchanged MemoryPressure moved LastTransitionTime %v -> %v",
				firstMem, secondMem.LastTransitionTime)
		}
		if secondMem.LastHeartbeatTime.Equal(&firstMem) {
			t.Error("LastHeartbeatTime did not advance; the heartbeat must refresh every cycle")
		}

		// A real transition DOES move it.
		s := healthyStats()
		s.MemAvailableBytes = 0
		h.setStats(s)
		third := condOf(t, h.step(), corev1.NodeMemoryPressure)
		if third.LastTransitionTime.Equal(&firstMem) {
			t.Error("MemoryPressure flipped to True but kept the old LastTransitionTime")
		}
	})

	t.Run("DiskPressure hysteresis band holds the previous verdict in both directions", func(t *testing.T) {
		// A free-space figure strictly inside (trip, clear): it is above the trip
		// floor so the raw verdict is False, and below the clear level so an
		// already-raised condition must stay raised.
		const inBand = diskPressureTripFreeBytes + (diskPressureClearFreeBytes-diskPressureTripFreeBytes)/2

		t.Run("falling: healthy -> band keeps False", func(t *testing.T) {
			h := newNodeStatusHarness(t, bootstrapNode())
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionFalse)

			s := healthyStats()
			s.DiskAvailableBytes = inBand
			h.setStats(s)
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionFalse)

			// Only crossing the trip floor raises it.
			s.DiskAvailableBytes = diskPressureTripFreeBytes - 1
			h.setStats(s)
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionTrue)
		})

		t.Run("rising: pressured -> band keeps True until the clear level", func(t *testing.T) {
			h := newNodeStatusHarness(t, bootstrapNode())
			s := healthyStats()
			s.DiskAvailableBytes = diskPressureTripFreeBytes - 1
			h.setStats(s)
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionTrue)

			// Recovered past the trip floor but still inside the band: held True,
			// and held with the SAME reason it tripped with.
			s.DiskAvailableBytes = inBand
			h.setStats(s)
			held := condOf(t, h.step(), corev1.NodeDiskPressure)
			if held.Status != corev1.ConditionTrue {
				t.Errorf("DiskPressure = %q inside the hysteresis band, want True (held)", held.Status)
			}
			if held.Reason != diskPressureReason || held.Message != diskPressureMessage {
				t.Errorf("held DiskPressure reason/message = %q/%q, want %q/%q",
					held.Reason, held.Message, diskPressureReason, diskPressureMessage)
			}

			// Just short of the clear level: still held.
			s.DiskAvailableBytes = diskPressureClearFreeBytes - 1
			h.setStats(s)
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionTrue)

			// At the clear level: released.
			s.DiskAvailableBytes = diskPressureClearFreeBytes
			h.setStats(s)
			wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionFalse)
		})
	})

	t.Run("Ready is debounced over consecutive unhealthy samples", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		wantStatus(t, h.step(), corev1.NodeReady, corev1.ConditionTrue)

		// One bad sample is NOT enough. Neither is any count below the threshold:
		// a self-reported NotReady is acted on immediately and starts deleting
		// pods, so a single transient probe must never reach the node object.
		h.setHealthy(false)
		for i := int32(1); i < defaultProbeFailureThreshold; i++ {
			node := h.step()
			if got := condOf(t, node, corev1.NodeReady).Status; got != corev1.ConditionTrue {
				t.Fatalf("Ready = %q after %d consecutive unhealthy samples, want True (threshold is %d)",
					got, i, defaultProbeFailureThreshold)
			}
			if node.Status.Phase != corev1.NodeRunning {
				t.Errorf("Phase = %q while still Ready, want %q", node.Status.Phase, corev1.NodeRunning)
			}
		}

		// The threshold'th consecutive unhealthy sample flips it.
		flipped := h.step()
		ready := condOf(t, flipped, corev1.NodeReady)
		if ready.Status != corev1.ConditionFalse {
			t.Fatalf("Ready = %q after %d consecutive unhealthy samples, want False",
				ready.Status, defaultProbeFailureThreshold)
		}
		if ready.Reason != nodeNotReadyReason || ready.Message != nodeNotReadyMessage {
			t.Errorf("NotReady reason/message = %q/%q, want %q/%q",
				ready.Reason, ready.Message, nodeNotReadyReason, nodeNotReadyMessage)
		}
		if flipped.Status.Phase == corev1.NodeRunning {
			t.Error("Phase stayed Running while Ready is False")
		}

		// A single healthy sample restores Ready (successThreshold 1): recovery is
		// deliberately fast where the flip is deliberately slow.
		h.setHealthy(true)
		restored := condOf(t, h.step(), corev1.NodeReady)
		if restored.Status != corev1.ConditionTrue {
			t.Errorf("Ready = %q after one healthy sample, want True", restored.Status)
		}
		if restored.Reason != nodeReadyReason {
			t.Errorf("Ready reason = %q, want %q", restored.Reason, nodeReadyReason)
		}
	})

	t.Run("an interrupted unhealthy run resets the debounce", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		h.step()
		for i := int32(1); i < defaultProbeFailureThreshold; i++ {
			h.setHealthy(false)
			h.step()
			h.setHealthy(true)
			h.step()
		}
		// Alternating samples never accumulate a consecutive run, so Ready held.
		h.setHealthy(false)
		wantStatus(t, h.step(), corev1.NodeReady, corev1.ConditionTrue)
	})

	t.Run("bootstrap fields survive a full recompute and publish cycle", func(t *testing.T) {
		want := bootstrapNode()
		h := newNodeStatusHarness(t, bootstrapNode())

		// Drive a cycle that changes something in every direction: pressure raised,
		// Ready flipped, so the publication is maximally different from the input.
		s := healthyStats()
		s.MemAvailableBytes = 0
		s.DiskAvailableBytes = 0
		h.setStats(s)
		h.setHealthy(false)
		for i := int32(0); i <= defaultProbeFailureThreshold; i++ {
			h.step()
		}
		got := h.step()

		if !reflect.DeepEqual(got.Status.Addresses, want.Status.Addresses) {
			t.Errorf("Addresses = %+v, want %+v", got.Status.Addresses, want.Status.Addresses)
		}
		if ip := nodeAddressOf(got, corev1.NodeInternalIP); ip != "10.4.0.7" {
			t.Errorf("NodeInternalIP = %q, want 10.4.0.7 — the apiserver dials this for logs/exec", ip)
		}
		for _, res := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourcePods} {
			if g, w := got.Status.Capacity[res], want.Status.Capacity[res]; g.Cmp(w) != 0 {
				t.Errorf("Capacity[%s] = %s, want %s", res, g.String(), w.String())
			}
			if g, w := got.Status.Allocatable[res], want.Status.Allocatable[res]; g.Cmp(w) != 0 {
				t.Errorf("Allocatable[%s] = %s, want %s", res, g.String(), w.String())
			}
		}
		if got.Status.DaemonEndpoints != want.Status.DaemonEndpoints {
			t.Errorf("DaemonEndpoints = %+v, want %+v", got.Status.DaemonEndpoints, want.Status.DaemonEndpoints)
		}
		if !reflect.DeepEqual(got.Labels, want.Labels) {
			t.Errorf("Labels = %+v, want %+v", got.Labels, want.Labels)
		}
		if !reflect.DeepEqual(got.Spec.Taints, want.Spec.Taints) {
			t.Errorf("Taints = %+v, want %+v", got.Spec.Taints, want.Spec.Taints)
		}
		if got.Status.NodeInfo != want.Status.NodeInfo {
			t.Errorf("NodeInfo = %+v, want %+v", got.Status.NodeInfo, want.Status.NodeInfo)
		}

		// Non-vacuity: the cycle really did replace the conditions, so the
		// assertions above are about survival, not about an unchanged object.
		wantStatus(t, got, corev1.NodeMemoryPressure, corev1.ConditionTrue)
		wantStatus(t, got, corev1.NodeReady, corev1.ConditionFalse)

		// The bootstrap object the provider was handed is never mutated, so a
		// later reader of it still sees the registration-time conditions.
		if s := findNodeCondition(h.p.bootstrap.Status.Conditions, corev1.NodeReady); s == nil || s.Status != "" {
			t.Errorf("the bootstrap node was mutated: Ready = %+v", s)
		}
	})

	t.Run("a failed sample carries the previous pressure verdicts, not fabricated ones", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		s := healthyStats()
		s.DiskAvailableBytes = diskPressureTripFreeBytes - 1
		h.setStats(s)
		wantStatus(t, h.step(), corev1.NodeDiskPressure, corev1.ConditionTrue)

		h.mu.Lock()
		h.statsErr = errors.New("statfs: no such file or directory")
		h.mu.Unlock()
		carried := h.step()
		wantStatus(t, carried, corev1.NodeDiskPressure, corev1.ConditionTrue)
		wantStatus(t, carried, corev1.NodeMemoryPressure, corev1.ConditionFalse)
		// Ready is re-derived from live health even when the host sample failed —
		// the two signals are independent.
		wantStatus(t, carried, corev1.NodeReady, corev1.ConditionTrue)
	})

	t.Run("a first-pass sample failure publishes no fabricated pressure conditions", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		h.mu.Lock()
		h.statsErr = errors.New("host_statistics64: rc -1")
		h.mu.Unlock()
		got := h.step()
		for _, typ := range []corev1.NodeConditionType{
			corev1.NodeMemoryPressure, corev1.NodeDiskPressure, corev1.NodePIDPressure,
		} {
			if c := findNodeCondition(got.Status.Conditions, typ); c != nil {
				t.Errorf("%s published as %q from a failed first sample; an unobserved signal must be ABSENT", typ, c.Status)
			}
		}
		wantStatus(t, got, corev1.NodeReady, corev1.ConditionTrue)
	})

	t.Run("Run publishes immediately and stops with the context", func(t *testing.T) {
		h := newNodeStatusHarness(t, bootstrapNode())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- h.p.Run(ctx) }()

		deadline := time.After(5 * time.Second)
		for {
			h.mu.Lock()
			n := len(h.published)
			h.mu.Unlock()
			if n > 0 {
				break
			}
			select {
			case <-deadline:
				t.Fatal("Run published nothing; the first publication is what marks the node Ready")
			case <-time.After(time.Millisecond):
			}
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Run returned %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after its context was cancelled")
		}
	})

	t.Run("the constructor rejects an unusable config", func(t *testing.T) {
		if _, err := NewNodeStatusProvider(NodeStatusConfig{DataRoot: "/var/lib/k3sm"}); err == nil {
			t.Error("a nil Node must be a constructor error, not a silent never-reporting node")
		}
		if _, err := NewNodeStatusProvider(NodeStatusConfig{Node: bootstrapNode()}); err == nil {
			t.Error("an empty DataRoot must be a constructor error")
		}
	})

	t.Run("a runtime with no health surface never contradicts Ready", func(t *testing.T) {
		p, err := NewNodeStatusProvider(NodeStatusConfig{Node: bootstrapNode(), DataRoot: "/"})
		if err != nil {
			t.Fatalf("NewNodeStatusProvider: %v", err)
		}
		var got *corev1.Node
		p.sample = func(string) (hostStats, error) { return healthyStats(), nil }
		p.publish = func(_ context.Context, n *corev1.Node) error { got = n; return nil }
		for range int(defaultProbeFailureThreshold) + 2 {
			if err := p.publishOnce(context.Background()); err != nil {
				t.Fatalf("publishOnce: %v", err)
			}
		}
		wantStatus(t, got, corev1.NodeReady, corev1.ConditionTrue)
	})
}

// nodeAddressOf returns the address of the given type, or "".
func nodeAddressOf(n *corev1.Node, typ corev1.NodeAddressType) string {
	for _, a := range n.Status.Addresses {
		if a.Type == typ {
			return a.Address
		}
	}
	return ""
}

// TestNodeStatusProviderPublishesViaUpdateStatus pins the two wiring facts that
// have no other witness: the status provider satisfies the VK node contract, and
// Ping reports ONLY context cancellation. A Ping that returned runtime health
// would suppress the status update and the lease renewal instead of publishing a
// NotReady condition — strictly less information than saying nothing.
func TestNodeStatusProviderPublishesViaUpdateStatus(t *testing.T) {
	p, err := NewNodeStatusProvider(NodeStatusConfig{
		Node:           bootstrapNode(),
		DataRoot:       "/var/lib/k3sm",
		RuntimeHealthy: func(context.Context) bool { return false },
	})
	if err != nil {
		t.Fatalf("NewNodeStatusProvider: %v", err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Errorf("Ping on a live context = %v, want nil even with an unhealthy runtime", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Ping(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Ping on a cancelled context = %v, want context.Canceled", err)
	}
}

// TestBootstrapNodeFixtureIsNonVacuous guards the survival assertions of the gate
// above: they only mean something if the fixture actually carries the fields the
// real registration path stamps. A zero DaemonEndpoints port, or a fixture that
// stopped seeding the node helper's five conditions, would turn "unchanged after
// a recompute" into a comparison of two empty values.
func TestBootstrapNodeFixtureIsNonVacuous(t *testing.T) {
	n := bootstrapNode()
	if n.Status.DaemonEndpoints.KubeletEndpoint.Port != ports.KubeletAPIPort || ports.KubeletAPIPort == 0 {
		t.Errorf("fixture kubelet endpoint port = %d, want the shared ports.KubeletAPIPort (%d, non-zero)",
			n.Status.DaemonEndpoints.KubeletEndpoint.Port, ports.KubeletAPIPort)
	}
	if len(n.Status.Conditions) != 5 {
		t.Errorf("fixture seeds %d conditions, want the 5 the node helper registers", len(n.Status.Conditions))
	}
	if nodeAddressOf(n, corev1.NodeInternalIP) == "" {
		t.Error("fixture carries no NodeInternalIP; the address-survival assertion would be vacuous")
	}
}
