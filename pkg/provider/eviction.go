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
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
)

// The node-pressure eviction manager: k3sm's hard, memory-only subset of the
// kubelet's eviction manager (pkg/kubelet/eviction, read at v1.36.2).
//
// What it does, in the kubelet's shape:
//
//   - It triggers on memoryPressured over the pressure monitor's latest snapshot,
//     the same verdict the MemoryPressure condition publishes.
//   - It ranks the node's active pods with the kubelet's rankMemoryPressure order
//     (exceeds-requests, then ascending priority, then descending usage over
//     requests), skips critical pods (IsCriticalPod) and falls through to the next
//     candidate, and evicts ONE pod per cycle.
//   - A hard threshold carries a zero grace override, so no preStop hook runs.
//   - The evicted pod reports phase Failed, reason Evicted, the kubelet's message
//     shape, and the DisruptionTarget condition (reason TerminationByKubelet).
//
// What it adds, with no kubelet analog (k3sm safety bounds):
//
//   - After an eviction it waits for the victim's teardown AND one fresh sample
//     (30 s bound, the kubelet's podCleanupTimeout), and evicts again only if the
//     firing signal has not moved toward release since the last look.
//   - A cascade cap: three evictions inside five minutes in one pressure episode
//     halt it (one Error, one EvictionCascadeHalted node Event) until the episode
//     ends, leaving the remainder to macOS's own out-of-swap kill.
//   - EvictionThresholdMet is emitted once per pressure episode. Upstream emits it
//     on every synchronize cycle that finds a threshold met (eviction_manager.go,
//     v1.36.2), relying on the event recorder's aggregation; k3sm's 1 s fast
//     cadence would turn that into a stream, so it is edge-triggered here.
//
// What it does not do: soft thresholds, minimum-reclaim, disk or PID eviction,
// refusing BestEffort pods at admission, node-allocatable enforcement, and a
// --eviction-hard override. Thresholds are compiled constants (pressure.go).

// Event reasons the manager emits. Evicted and EvictionThresholdMet are the
// kubelet's; EvictionCascadeHalted is k3sm's own (the cascade cap has no
// upstream analog).
const (
	reasonEvicted               = "Evicted"
	reasonEvictionThresholdMet  = "EvictionThresholdMet"
	reasonEvictionCascadeHalted = "EvictionCascadeHalted"
)

// The kubelet's eviction-message fragments (pkg/kubelet/eviction/helpers.go,
// v1.36.2), reproduced verbatim including their trailing spaces.
const (
	nodeLowMessageFmt      = "The node was low on resource: %v. "
	thresholdMetMessageFmt = "Threshold quantity: %v, available: %v. "
	containerMessageFmt    = "Container %s was using %s, request is %s, has larger consumption of %v. "
)

// systemCriticalPriority is scheduling.SystemCriticalPriority: a pod at or above
// it is never evicted (kubelettypes.IsCriticalPodBasedOnPriority).
const systemCriticalPriority int32 = 2000000000

// The two pod annotations the kubelet's IsCriticalPod reads besides priority.
// k3sm has no static pods and no mirror pods, so neither arm is reachable in
// practice; they are ported so the predicate is the kubelet's, not a subset.
const (
	configSourceAnnotationKey = "kubernetes.io/config.source"
	configMirrorAnnotationKey = "kubernetes.io/config.mirror"
	apiserverSource           = "api"
)

// Manager timing. evictionStatsTimeout bounds the per-cycle stats fetch below the
// 1 s fast cadence, so a slow vm guest cannot stall the loop past its next tick.
const (
	evictionStatsTimeout    = 700 * time.Millisecond
	evictionCleanupTimeout  = 30 * time.Second
	evictionCascadeWindow   = 5 * time.Minute
	evictionCascadeMaxCount = 3
	// staleSampleFactor: a snapshot older than this many sampling periods
	// (3 s at the fast cadence, 30 s calm) does not start an eviction.
	staleSampleFactor = 3
)

// evictionCandidate is one active pod and its memory stats for ranking. hasStats
// false means no sample was obtained (absent from ListPodStats, or the fetch
// timed out); the kubelet ranks such a pod FIRST in both stats comparators.
type evictionCandidate struct {
	pod *corev1.Pod
	// usage is the pod's working set: the sum of its containers' footprints.
	usage int64
	// containerUsage is each container's footprint, by name, for the message.
	containerUsage map[string]int64
	hasStats       bool
}

// evictionNotice is what the manager tells the termination path about one
// eviction: the message (already in the kubelet's shape) and the firing signal.
type evictionNotice struct {
	signal  pressureSignal
	message string
}

// evictionTarget is the runtime surface the manager acts through. It is defined
// here, at the consumer; the runtimed provider implements it.
type evictionTarget interface {
	// evictionCandidates returns the node's active pods (running, not already
	// evicted or being deleted) with whatever stats could be fetched under ctx.
	evictionCandidates(ctx context.Context) []evictionCandidate
	// evictPod terminates pod as a hard eviction and records it as evicted. It
	// returns once the runtime teardown has returned.
	evictPod(ctx context.Context, pod *corev1.Pod, n evictionNotice) error
}

// EvictionConfig is the input to RunEvictionManager.
type EvictionConfig struct {
	// Status is the node's status provider; its pressure monitor is the
	// manager's only source of host samples.
	Status *NodeStatusProvider
	// Recorder receives the node-level Events (EvictionThresholdMet,
	// EvictionCascadeHalted). The pod-level Evicted Event is the runtime's.
	Recorder record.EventRecorder
	// NodeName names the node the Events are recorded against.
	NodeName string
	// Log receives the manager's diagnostics; nil uses slog.Default().
	Log *slog.Logger
}

// evictionManager is the loop. Every field after evictions is touched only by
// the loop goroutine; mu guards evictions, the evictions_total{signal} counter
// (an in-process counter: the provider has no metrics registry to export it on,
// so each eviction also logs its running total).
type evictionManager struct {
	monitor  *pressureMonitor
	target   evictionTarget
	recorder record.EventRecorder
	nodeRef  *corev1.ObjectReference
	log      *slog.Logger
	now      func() time.Time

	mu        sync.Mutex
	evictions map[pressureSignal]uint64 // evictions_total{signal}

	// episode state, reset when memoryPressured goes False.
	inEpisode   bool
	halted      bool
	staleLogged bool
	evictedAt   []time.Time
	skipLogged  map[types.UID]bool
	noneLogged  bool
	awaiting    bool      // a victim was evicted; waiting for a fresh sample
	awaitSeq    uint64    // the monitor seq when the victim's teardown returned
	awaitSince  time.Time // when the victim's teardown returned
	hasBaseline bool
	baseSignal  pressureSignal
	baseLevel   float64
}

func newEvictionManager(monitor *pressureMonitor, target evictionTarget, recorder record.EventRecorder, nodeName string, log *slog.Logger) *evictionManager {
	if log == nil {
		log = slog.Default()
	}
	if recorder == nil {
		recorder = nopRecorder{}
	}
	return &evictionManager{
		monitor:  monitor,
		target:   target,
		recorder: recorder,
		// The kubelet records node Events against a reference whose UID is the
		// node name (kubelet.go nodeRef), and so does this.
		nodeRef:    &corev1.ObjectReference{Kind: "Node", Name: nodeName, UID: types.UID(nodeName)},
		log:        log,
		now:        time.Now,
		evictions:  map[pressureSignal]uint64{},
		skipLogged: map[types.UID]bool{},
	}
}

// run evaluates one cycle per pressure-monitor sample until ctx ends.
func (m *evictionManager) run(ctx context.Context) {
	for {
		tick := m.monitor.next()
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		m.cycle(ctx)
	}
}

// cycle is one decision over the monitor's latest snapshot.
func (m *evictionManager) cycle(ctx context.Context) {
	snap, seq, ok := m.monitor.latest()
	if !ok {
		return
	}
	pressured, _ := memoryPressured(snap)
	if !pressured {
		if m.inEpisode {
			m.log.Info("eviction manager: memory pressure episode ended", "evictions", len(m.evictedAt))
		}
		m.resetEpisode()
		return
	}
	v := evaluateMemory(snap)
	now := m.now()
	if !m.inEpisode {
		m.inEpisode = true
		m.log.Warn("eviction manager: memory threshold met; attempting to reclaim memory",
			"signal", string(v.signal), "reading", v.reading)
		m.recorder.Eventf(m.nodeRef, corev1.EventTypeWarning, reasonEvictionThresholdMet, "Attempting to reclaim %s", corev1.ResourceMemory)
	}
	if m.halted {
		return
	}

	// After an eviction: nothing until the victim's teardown has returned (evict
	// is synchronous, so that already holds) AND one fresh sample has landed, or
	// the cleanup bound has passed. That first look becomes the baseline.
	if m.awaiting {
		if seq <= m.awaitSeq && now.Sub(m.awaitSince) < evictionCleanupTimeout {
			return
		}
		m.awaiting = false
		m.hasBaseline, m.baseSignal, m.baseLevel = true, v.signal, v.level
		return
	}
	// Then: evict again only if the firing signal has NOT moved toward release
	// since the last look. A different firing signal is not comparable, so it
	// counts as not moved.
	if m.hasBaseline {
		improved := v.signal == m.baseSignal && v.level < m.baseLevel
		m.baseSignal, m.baseLevel = v.signal, v.level
		if improved {
			return
		}
	}

	// A stale snapshot never starts an eviction. If the monitor's last good
	// sample is older than staleSampleFactor sampling periods (it keeps
	// failing, or is starved), the verdict above describes a node that may no
	// longer exist; the manager waits for a fresh one and says so once.
	if age, bound := m.monitor.sampleAge(), staleSampleFactor*m.monitor.interval(); age > bound {
		if !m.staleLogged {
			m.staleLogged = true
			m.log.Warn("eviction manager: the latest host sample is stale; not evicting until a fresh one lands",
				"sample_age_seconds", int64(age/time.Second), "bound_seconds", int64(bound/time.Second),
				"signal", string(v.signal), "reading", v.reading)
		}
		return
	}

	// The cascade cap: a fourth eviction inside the window halts the manager for
	// the rest of the episode.
	if m.recentEvictions(now) >= evictionCascadeMaxCount {
		m.halted = true
		m.log.Error("eviction manager: halted after repeated evictions did not relieve memory pressure; leaving the remainder to the kernel",
			"evictions", m.recentEvictions(now), "window", evictionCascadeWindow,
			"signal", string(v.signal), "reading", v.reading)
		m.recorder.Eventf(m.nodeRef, corev1.EventTypeWarning, reasonEvictionCascadeHalted,
			"Halted eviction after %d evictions in %s did not relieve memory pressure (%s)",
			evictionCascadeMaxCount, evictionCascadeWindow, v.reading)
		return
	}

	statsCtx, cancel := context.WithTimeout(ctx, evictionStatsTimeout)
	cands := m.target.evictionCandidates(statsCtx)
	cancel()
	victim, ok := m.pickVictim(cands)
	if !ok {
		if !m.noneLogged {
			m.noneLogged = true
			m.log.Warn("eviction manager: memory threshold met but no pod is eligible for eviction",
				"signal", string(v.signal), "reading", v.reading, "candidates", len(cands))
		}
		return
	}

	notice := evictionNotice{signal: v.signal, message: evictionMessage(victim, v)}
	m.log.Warn("eviction manager: evicting pod",
		"pod", victim.pod.Namespace+"/"+victim.pod.Name, "uid", string(victim.pod.UID),
		"signal", string(v.signal), "reading", v.reading,
		"usage_bytes", victim.usage, "has_stats", victim.hasStats,
		"sample_age_seconds", int64(m.monitor.sampleAge()/time.Second))
	// Only a SUCCESSFUL eviction counts: toward evictions_total, and toward the
	// cascade cap. A failed one was rolled back by the runtime (the pod is still
	// running and still a candidate), so the next cycle simply tries again.
	if err := m.target.evictPod(ctx, victim.pod, notice); err != nil {
		m.log.Error("eviction manager: evicting the pod failed; it stays a candidate",
			"pod", victim.pod.Namespace+"/"+victim.pod.Name, "err", err)
		return
	}
	m.mu.Lock()
	m.evictions[v.signal]++
	total := m.evictions[v.signal]
	m.mu.Unlock()
	m.evictedAt = append(m.evictedAt, now)
	m.log.Warn("eviction manager: pod evicted", "pod", victim.pod.Namespace+"/"+victim.pod.Name, "evictions_total", total)
	_, after, _ := m.monitor.latest()
	m.awaiting, m.awaitSeq, m.awaitSince = true, after, m.now()
	m.hasBaseline = false
}

// pickVictim ranks cands and returns the first one that is not critical. A
// critical pod is skipped (logged once per episode) and the next candidate is
// considered: a skip is not the cycle's victim, exactly as the kubelet's evictPod
// returning false moves its loop to the next pod.
func (m *evictionManager) pickVictim(cands []evictionCandidate) (evictionCandidate, bool) {
	rankMemoryPressure(cands)
	for _, c := range cands {
		if isCriticalPod(c.pod) {
			if !m.skipLogged[c.pod.UID] {
				m.skipLogged[c.pod.UID] = true
				m.log.Warn("eviction manager: cannot evict a critical pod; skipping it",
					"pod", c.pod.Namespace+"/"+c.pod.Name, "uid", string(c.pod.UID), "priority", podPriority(c.pod))
			}
			continue
		}
		return c, true
	}
	return evictionCandidate{}, false
}

// recentEvictions counts this episode's evictions inside the cascade window.
func (m *evictionManager) recentEvictions(now time.Time) int {
	n := 0
	for _, t := range m.evictedAt {
		if now.Sub(t) < evictionCascadeWindow {
			n++
		}
	}
	return n
}

// resetEpisode clears every per-episode fact.
func (m *evictionManager) resetEpisode() {
	m.inEpisode, m.halted, m.noneLogged, m.staleLogged = false, false, false, false
	m.evictedAt = nil
	m.skipLogged = map[types.UID]bool{}
	m.awaiting, m.hasBaseline = false, false
}

// rankMemoryPressure orders cands for eviction under memory pressure, in place:
// the kubelet's rankMemoryPressure, orderedBy(exceedMemoryRequests, priority,
// memory) (pkg/kubelet/eviction/helpers.go, v1.36.2). The sort is stable so equal
// pods keep their input order; upstream's sort.Sort is not, which only matters
// between pods its comparators call equal.
func rankMemoryPressure(cands []evictionCandidate) {
	cmps := []func(a, b *evictionCandidate) int{cmpExceedMemoryRequests, cmpPriority, cmpMemory}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := &cands[i], &cands[j]
		var k int
		for k = 0; k < len(cmps)-1; k++ {
			switch r := cmps[k](a, b); {
			case r < 0:
				return true
			case r > 0:
				return false
			}
		}
		return cmps[k](a, b) < 0
	})
}

// cmpExceedMemoryRequests is upstream's exceedMemoryRequests: a pod with no stats
// sorts first; otherwise a pod whose usage exceeds its request sorts first.
func cmpExceedMemoryRequests(a, b *evictionCandidate) int {
	if !a.hasStats || !b.hasStats {
		return cmpBool(!a.hasStats, !b.hasStats)
	}
	return cmpBool(a.usage > podMemoryRequestBytes(a.pod), b.usage > podMemoryRequestBytes(b.pod))
}

// cmpPriority is upstream's priority: ascending spec.priority, nil as 0.
func cmpPriority(a, b *evictionCandidate) int {
	pa, pb := podPriority(a.pod), podPriority(b.pod)
	switch {
	case pa == pb:
		return 0
	case pa > pb:
		return 1
	default:
		return -1
	}
}

// cmpMemory is upstream's memory: a pod with no stats sorts first; otherwise the
// larger usage over request sorts first.
func cmpMemory(a, b *evictionCandidate) int {
	if !a.hasStats || !b.hasStats {
		return cmpBool(!a.hasStats, !b.hasStats)
	}
	da := a.usage - podMemoryRequestBytes(a.pod)
	db := b.usage - podMemoryRequestBytes(b.pod)
	switch {
	case db > da:
		return 1
	case db < da:
		return -1
	default:
		return 0
	}
}

// cmpBool is upstream's cmpBool: true sorts before false.
func cmpBool(a, b bool) int {
	if a == b {
		return 0
	}
	if !b {
		return -1
	}
	return 1
}

// podPriority is corev1helpers.PodPriority: spec.priority, nil as 0.
func podPriority(pod *corev1.Pod) int32 {
	if pod.Spec.Priority != nil {
		return *pod.Spec.Priority
	}
	return 0
}

// isCriticalPod is the kubelet's IsCriticalPod: a static pod, a mirror pod, or a
// pod at or above system-critical priority. The manager never evicts one.
func isCriticalPod(pod *corev1.Pod) bool {
	if src, ok := pod.Annotations[configSourceAnnotationKey]; ok && src != apiserverSource {
		return true
	}
	if _, ok := pod.Annotations[configMirrorAnnotationKey]; ok {
		return true
	}
	return pod.Spec.Priority != nil && *pod.Spec.Priority >= systemCriticalPriority
}

// podMemoryRequestBytes is the pod's effective memory request, as the kubelet's
// GetResourceRequestQuantity computes it (pkg/api/v1/resource/helpers.go over
// component-helpers PodRequests, v1.36.2): pod-level requests when set,
// otherwise the sum of the regular containers and the restartable (sidecar) init
// containers, raised to the largest regular init container plus the sidecars
// started before it; then spec.overhead, added only when the total is non-zero.
func podMemoryRequestBytes(pod *corev1.Pod) int64 {
	var total int64
	if pod.Spec.Resources != nil {
		if q, ok := pod.Spec.Resources.Requests[corev1.ResourceMemory]; ok {
			total = q.Value()
		}
	}
	if total == 0 {
		for i := range pod.Spec.Containers {
			total += containerMemoryRequest(&pod.Spec.Containers[i])
		}
		var sidecars, initMax int64
		for i := range pod.Spec.InitContainers {
			c := &pod.Spec.InitContainers[i]
			req := containerMemoryRequest(c)
			if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
				total += req
				sidecars += req
				initMax = max(initMax, sidecars)
				continue
			}
			initMax = max(initMax, req+sidecars)
		}
		total = max(total, initMax)
	}
	if total != 0 && pod.Spec.Overhead != nil {
		if q, ok := pod.Spec.Overhead[corev1.ResourceMemory]; ok {
			total += q.Value()
		}
	}
	return total
}

func containerMemoryRequest(c *corev1.Container) int64 {
	if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
		return q.Value()
	}
	return 0
}

// evictionMessage builds the kubelet's eviction message for victim: the node-low
// sentence, the firing signal's threshold and reading, and one sentence per
// container whose usage exceeds its request (helpers.go evictionMessage). The
// threshold/available pair names the FIRING signal: for memory.available it is
// upstream's quantity pair; for k3sm's compressor and swap arms it is that arm's
// own trip value and reading, never a memory.available figure that did not
// cause the eviction.
func evictionMessage(victim evictionCandidate, v memoryVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, nodeLowMessageFmt, corev1.ResourceMemory)
	threshold, available := v.threshold, strings.TrimPrefix(v.reading, "memory.available ")
	if v.signal == signalMemoryAvailable {
		threshold = resource.NewQuantity(memAvailableHardEvictionBytes, resource.BinarySI).String()
	}
	fmt.Fprintf(&b, thresholdMetMessageFmt, threshold, available)
	if !victim.hasStats {
		return b.String()
	}
	containers := append([]corev1.Container{}, victim.pod.Spec.Containers...)
	containers = append(containers, victim.pod.Spec.InitContainers...)
	for i := range containers {
		c := &containers[i]
		used, ok := victim.containerUsage[c.Name]
		if !ok {
			continue
		}
		req := c.Resources.Requests[corev1.ResourceMemory]
		usage := resource.NewQuantity(used, resource.BinarySI)
		if usage.Cmp(req) > 0 {
			fmt.Fprintf(&b, containerMessageFmt, c.Name, usage.String(), req.String(), corev1.ResourceMemory)
		}
	}
	return b.String()
}

// RunEvictionManager runs the node-pressure eviction manager over the backing
// runtime until ctx ends. A runtime that cannot evict (the hostprocess opt-out)
// returns at once: there is nothing for the manager to act through.
//
// Start it after the node is Ready, so the provider's pod set is the cluster's.
func (v *VKProvider) RunEvictionManager(ctx context.Context, cfg EvictionConfig) {
	target, ok := v.rt.(evictionTarget)
	if !ok || cfg.Status == nil {
		return
	}
	newEvictionManager(cfg.Status.monitor, target, cfg.Recorder, cfg.NodeName, cfg.Log).run(ctx)
}
