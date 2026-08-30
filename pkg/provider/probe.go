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
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/clock"
)

// The provider-served probe runner. A Virtual Kubelet provider replaces the
// kubelet, so there is no kubelet to execute container probes — the provider
// must run liveness/readiness/startup probes itself and map their results onto
// the Pod status it publishes. This file is the runtime-agnostic core (timing,
// threshold counting, gating, restart bookkeeping); the concrete httpGet/tcp/exec
// checks live in probe_handlers.go and the runtimedRuntime wiring in
// runtimed_probe.go.
//
// Behavior reproduced from the kubelet prober (k8s.io/kubernetes/pkg/kubelet/
// prober): a result is committed only after success_threshold consecutive
// successes or failure_threshold consecutive failures; a startup probe gates
// liveness and readiness until it first succeeds; a readiness verdict drives the
// container Ready condition (hence Service EndpointSlice membership); a committed
// liveness failure restarts the container.

// probeKind identifies which of a container's three probes a worker serves.
type probeKind int

const (
	probeLiveness probeKind = iota
	probeReadiness
	probeStartup
)

// String renders the probe kind for structured logs (the diagnosable cause of a
// never-Ready or restarting pod).
func (k probeKind) String() string {
	switch k {
	case probeLiveness:
		return "liveness"
	case probeReadiness:
		return "readiness"
	case probeStartup:
		return "startup"
	default:
		return "unknown"
	}
}

// probeOutcome is one probe attempt's raw result, or a gauge's committed result.
// The zero value (outcomeUnknown) is the startup gauge's initial committed value
// — "not started", which gates liveness/readiness.
type probeOutcome int8

const (
	outcomeUnknown probeOutcome = iota
	outcomeSuccess
	outcomeFailure
)

// checkFunc performs one probe attempt against an already-resolved target,
// bounded by timeout. A nil error is success (httpGet 2xx-3xx, a successful tcp
// dial, an exec exit 0); any error — including a timeout — is failure. It is the
// seam tests fake to drive outcomes deterministically; the real checks
// (httpProbe/tcpProbe/exec) are built in probe_handlers.go.
type checkFunc func(ctx context.Context, timeout time.Duration) error

// probeSchedule is the timing of one probe.
type probeSchedule struct {
	initialDelay time.Duration
	period       time.Duration
	timeout      time.Duration
}

// probeGauge applies Kubernetes consecutive-threshold counting to a stream of raw
// probe outcomes: it commits a result only after successThreshold consecutive
// successes or failureThreshold consecutive failures, leaving the previously
// committed result in place until then. It is not safe for concurrent use; the
// owning containerMonitor serializes access under its mutex.
type probeGauge struct {
	successThreshold int32
	failureThreshold int32

	run       int32        // consecutive count of last
	last      probeOutcome // last raw outcome seen (outcomeUnknown = none yet)
	committed probeOutcome // currently committed (reported) result
}

// newProbeGauge returns a gauge with the given thresholds and initial committed
// result (success for liveness, failure for readiness, unknown for startup).
func newProbeGauge(successThreshold, failureThreshold int32, initial probeOutcome) *probeGauge {
	return &probeGauge{successThreshold: successThreshold, failureThreshold: failureThreshold, committed: initial}
}

// record feeds one raw outcome and returns the (possibly unchanged) committed
// result. raw is always outcomeSuccess or outcomeFailure (a probe attempt never
// yields unknown).
func (g *probeGauge) record(raw probeOutcome) probeOutcome {
	if raw == g.last {
		g.run++
	} else {
		g.last = raw
		g.run = 1
	}
	threshold := g.failureThreshold
	if raw == outcomeSuccess {
		threshold = g.successThreshold
	}
	if g.run >= threshold {
		g.committed = raw
	}
	return g.committed
}

// reset returns the gauge to its initial committed state — used when a container
// restarts so its thresholds re-accumulate from scratch.
func (g *probeGauge) reset(initial probeOutcome) {
	g.run = 0
	g.last = outcomeUnknown
	g.committed = initial
}

// probeSpec couples a probe's gauge, schedule, and check — the unit a single
// probe loop goroutine drives.
type probeSpec struct {
	gauge *probeGauge
	sched probeSchedule
	check checkFunc
}

// probeReaction is what a recorded outcome requires of the owner.
type probeReaction int

const (
	reactNone    probeReaction = iota
	reactPublish               // status changed (startup flip or readiness change) → re-publish
	reactRestart               // committed liveness failure → restart the container
)

// containerMonitor holds the live probe state for one container: its up-to-three
// gauges plus the probe-driven restart count. Concurrency: mu guards all fields;
// the (blocking) checkFunc I/O is run by the loop OUTSIDE mu, and only its raw
// result is fed back in via observe.
type containerMonitor struct {
	name string

	mu       sync.Mutex
	restarts int32 // probe(liveness)-driven container restarts

	startup   *probeSpec // nil if the container has no startup probe
	readiness *probeSpec // nil if the container has no readiness probe
	liveness  *probeSpec // nil if the container has no liveness probe
}

// startedLocked reports whether the startup gate is satisfied: true immediately
// when there is no startup probe, otherwise once the startup probe commits
// success. Caller holds mu.
func (m *containerMonitor) startedLocked() bool {
	return m.startup == nil || m.startup.gauge.committed == outcomeSuccess
}

// readyLocked reports the effective container readiness: not ready until started,
// then ready unless a readiness probe is present and not committed-success.
// Caller holds mu.
func (m *containerMonitor) readyLocked() bool {
	if !m.startedLocked() {
		return false
	}
	return m.readiness == nil || m.readiness.gauge.committed == outcomeSuccess
}

// shouldProbe reports whether a probe of the given kind should run now: the
// startup probe runs only until the gate opens; liveness/readiness run only once
// it has. It mirrors the kubelet's doProbe gating so an unstarted container is
// never killed by liveness nor marked ready by readiness.
func (m *containerMonitor) shouldProbe(kind probeKind) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if kind == probeStartup {
		return !m.startedLocked()
	}
	return m.startedLocked()
}

// observe feeds one raw outcome for the given kind through its gauge under the
// gate, returning the reaction the owner must take. It re-checks the gate (it may
// have changed while the check I/O ran) so a late result is discarded rather than
// mis-applied.
func (m *containerMonitor) observe(kind probeKind, raw probeOutcome) probeReaction {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch kind {
	case probeStartup:
		if m.startedLocked() {
			return reactNone // gate already open; startup probe is idle
		}
		m.startup.gauge.record(raw)
		if m.startedLocked() {
			return reactPublish // the gate just opened → Started/Ready changed
		}
	case probeReadiness:
		if !m.startedLocked() {
			return reactNone // gated by startup
		}
		before := m.readyLocked()
		m.readiness.gauge.record(raw)
		if m.readyLocked() != before {
			return reactPublish // readiness flipped → endpoint membership changes
		}
	case probeLiveness:
		if !m.startedLocked() {
			return reactNone // gated by startup
		}
		prev := m.liveness.gauge.committed
		if m.liveness.gauge.record(raw) == outcomeFailure && prev != outcomeFailure {
			return reactRestart // crossed into committed failure → restart once
		}
	}
	return reactNone
}

// onRestart applies a container restart: it bumps the monitor's restart tally
// (internal bookkeeping — the surfaced RestartCount is runtimed's) and resets
// every gauge so the startup gate must re-open (and liveness/readiness
// re-accumulate) for the fresh container instance.
func (m *containerMonitor) onRestart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restarts++
	if m.startup != nil {
		m.startup.gauge.reset(outcomeUnknown)
	}
	if m.readiness != nil {
		m.readiness.gauge.reset(outcomeFailure)
	}
	if m.liveness != nil {
		m.liveness.gauge.reset(outcomeSuccess)
	}
}

// verdict snapshots the monitor's state for the status overlay (applyProbeOverlay).
func (m *containerMonitor) verdict() probeVerdict {
	m.mu.Lock()
	defer m.mu.Unlock()
	return probeVerdict{
		hasReadiness: m.readiness != nil,
		hasStartup:   m.startup != nil,
		ready:        m.readyLocked(),
		started:      m.startedLocked(),
		restarts:     m.restarts,
	}
}

// eachSpec invokes fn for each probe the container actually defines.
func (m *containerMonitor) eachSpec(fn func(kind probeKind, s *probeSpec)) {
	if m.startup != nil {
		fn(probeStartup, m.startup)
	}
	if m.readiness != nil {
		fn(probeReadiness, m.readiness)
	}
	if m.liveness != nil {
		fn(probeLiveness, m.liveness)
	}
}

// probeVerdict is one container's probe state, merged into the published status
// by applyProbeOverlay: readiness drives Ready (→ endpoints), startup drives
// Started (and gates Ready). restarts is the monitor's own liveness-restart
// tally — internal gauge-reset bookkeeping observable at this seam, NEVER added
// to the surfaced RestartCount: runtimed's restart_count is the single count
// authority (the RestartContainer RPC bumps it — M10.2/B26), so adding the
// tally would double-count every liveness-driven restart.
type probeVerdict struct {
	hasReadiness bool
	hasStartup   bool
	ready        bool
	started      bool
	restarts     int32
}

// probeState is the consumer seam toPodStatus uses to overlay provider-served
// probe results onto the runtime's status. *podProber implements it; a nil
// probeState (a pod with no probes) leaves the status untouched.
type probeState interface {
	// verdict returns the probe state for the named container; ok is false when
	// the container has no probes (its status passes through unchanged).
	verdict(container string) (probeVerdict, bool)
}

// podProber runs the provider-served probes for one pod's containers and maps
// their results onto the Pod status the VK provider publishes. One is created per
// pod that has any probe (newPodProber returns nil otherwise), started at
// CreatePod and stopped at DeletePod.
//
// Goroutine discipline: each (container, probeKind) is one goroutine bounded by
// the ctx passed to start; stop cancels it and waits. monitors is built before
// start and never mutated, so its lookup needs no lock (each monitor guards its
// own mutable state). onTransition (the status re-publish) and doRestart run
// OUTSIDE any monitor lock, honoring the VK NotifyPods re-entrancy rule.
type podProber struct {
	podID string
	clk   clock.Clock
	log   *slog.Logger

	monitors map[string]*containerMonitor

	// onTransition re-publishes the pod status after a probe-driven change. It
	// must do its own locking and run the VK callback itself; the prober only
	// signals "something changed".
	onTransition func()
	// restartFunc performs the actual container process restart on a committed
	// liveness failure. The restart COUNT bookkeeping is owned by the monitor;
	// this seam is the side effect (the future runtime RestartContainer RPC). nil
	// means bookkeeping only.
	restartFunc func(ctx context.Context, podID, container string) error

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// newPodProber builds a prober for pod, resolving each probed container's checks
// via mk. It returns nil when no container defines any probe, so a probe-free pod
// carries zero overhead and identical status behavior. Only regular containers
// are probed (init containers run to completion before the probe loops matter).
func newPodProber(pod *corev1.Pod, clk clock.Clock, mk func(c *corev1.Container, p *corev1.Probe) checkFunc, log *slog.Logger) *podProber {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	monitors := map[string]*containerMonitor{}
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if m := newContainerMonitor(c, mk); m != nil {
			monitors[c.Name] = m
		}
	}
	if len(monitors) == 0 {
		return nil
	}
	return &podProber{podID: string(pod.UID), clk: clk, log: log, monitors: monitors}
}

// newContainerMonitor builds the monitor for one container, or nil when it has no
// probes. Initial committed values follow the kubelet: startup unknown (gates the
// others), readiness failure (not ready until it succeeds), liveness success
// (don't kill before it has run). successThreshold is forced to 1 for
// liveness/startup, as Kubernetes requires.
func newContainerMonitor(c *corev1.Container, mk func(c *corev1.Container, p *corev1.Probe) checkFunc) *containerMonitor {
	m := &containerMonitor{name: c.Name}
	if p := c.StartupProbe; p != nil {
		m.startup = &probeSpec{gauge: gaugeFromProbe(p, probeStartup, outcomeUnknown), sched: scheduleFromProbe(p), check: mk(c, p)}
	}
	if p := c.ReadinessProbe; p != nil {
		m.readiness = &probeSpec{gauge: gaugeFromProbe(p, probeReadiness, outcomeFailure), sched: scheduleFromProbe(p), check: mk(c, p)}
	}
	if p := c.LivenessProbe; p != nil {
		m.liveness = &probeSpec{gauge: gaugeFromProbe(p, probeLiveness, outcomeSuccess), sched: scheduleFromProbe(p), check: mk(c, p)}
	}
	if m.startup == nil && m.readiness == nil && m.liveness == nil {
		return nil
	}
	return m
}

// defaultProbeFailureThreshold is the Kubernetes default failureThreshold: how
// many CONSECUTIVE failures a gauge must see before it commits a failure verdict.
// It is named because it is applied in two places — a container probe with no
// explicit threshold, and the node Ready debounce, which deliberately reuses this
// default rather than introducing a second, separately-tunable number.
const defaultProbeFailureThreshold int32 = 3

// gaugeFromProbe builds a gauge with the probe's thresholds (Kubernetes defaults:
// successThreshold 1, failureThreshold 3), forcing successThreshold to 1 for
// liveness and startup.
func gaugeFromProbe(p *corev1.Probe, kind probeKind, initial probeOutcome) *probeGauge {
	success := orDefaultInt32(p.SuccessThreshold, 1)
	if kind == probeLiveness || kind == probeStartup {
		success = 1
	}
	return newProbeGauge(success, orDefaultInt32(p.FailureThreshold, defaultProbeFailureThreshold), initial)
}

// scheduleFromProbe derives the timing from a probe, applying the Kubernetes
// defaults (period 10s, timeout 1s) and a non-negative initial delay.
func scheduleFromProbe(p *corev1.Probe) probeSchedule {
	initial := time.Duration(0)
	if p.InitialDelaySeconds > 0 {
		initial = time.Duration(p.InitialDelaySeconds) * time.Second
	}
	return probeSchedule{
		initialDelay: initial,
		period:       time.Duration(orDefaultInt32(p.PeriodSeconds, 10)) * time.Second,
		timeout:      time.Duration(orDefaultInt32(p.TimeoutSeconds, 1)) * time.Second,
	}
}

// orDefaultInt32 returns def when v is unset (<= 0), else v.
func orDefaultInt32(v, def int32) int32 {
	if v <= 0 {
		return def
	}
	return v
}

// start launches one goroutine per probe, all bounded by ctx. The caller stores
// the cancel paired with ctx in pp.cancel so stop can end them.
func (pp *podProber) start(ctx context.Context) {
	for _, m := range pp.monitors {
		m.eachSpec(func(kind probeKind, s *probeSpec) {
			pp.wg.Add(1)
			go func() {
				defer pp.wg.Done()
				// Backstop recover: runCheck already converts a panicking check into
				// a failed probe per tick, but a panic ANYWHERE in the loop must still
				// never crash the single k3sm process (it co-hosts the embedded
				// control plane, kine, and every other pod). Recover at the goroutine
				// boundary — mirroring the kubelet's runtime.HandleCrash — so the
				// worst case is one dead probe loop, not a node-wide DoS.
				defer func() {
					if r := recover(); r != nil {
						pp.log.Error("probe loop panicked; recovered to protect the process",
							"pod", pp.podID, "container", m.name, "kind", kind, "panic", r)
					}
				}()
				pp.loop(ctx, m, kind, s)
			}()
		})
	}
}

// stop cancels every probe loop and waits for them to exit. It must NOT be called
// while holding any lock onTransition takes (the runtimedRuntime calls it after
// releasing its mutex) so the wait cannot deadlock against a re-publish in flight.
func (pp *podProber) stop() {
	if pp.cancel != nil {
		pp.cancel()
	}
	pp.wg.Wait()
}

// loop drives one probe: wait the initial delay, then probe every period until
// ctx ends. The first probe fires at initialDelay (kubelet semantics).
func (pp *podProber) loop(ctx context.Context, m *containerMonitor, kind probeKind, s *probeSpec) {
	if s.sched.initialDelay > 0 && !pp.wait(ctx, s.sched.initialDelay) {
		return
	}
	for {
		pp.tick(ctx, m, kind, s)
		if !pp.wait(ctx, s.sched.period) {
			return
		}
	}
}

// wait blocks for d on the clock, returning false if ctx is cancelled first. A
// cancelled wait is the loop's exit path, so no probe goroutine outlives stop.
func (pp *podProber) wait(ctx context.Context, d time.Duration) bool {
	t := pp.clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C():
		return true
	}
}

// tick performs one scheduled probe attempt: it skips when gated, runs the check
// OUTSIDE the monitor lock, then applies the result and reacts (re-publish on a
// status change; restart + re-publish on a committed liveness failure).
func (pp *podProber) tick(ctx context.Context, m *containerMonitor, kind probeKind, s *probeSpec) {
	if !m.shouldProbe(kind) {
		return
	}
	switch m.observe(kind, pp.runCheck(ctx, m.name, kind, s)) {
	case reactPublish:
		pp.fire()
	case reactRestart:
		m.onRestart()
		pp.doRestart(ctx, m.name)
		pp.fire()
	}
}

// runCheck runs one probe attempt and maps it to a committable outcome, failing
// CLOSED on every abnormal path: a nil check, a check that returns an error, or a
// check that PANICS all yield outcomeFailure (so an unverifiable container is
// never falsely committed healthy). The panic recovery is mandatory and not
// defensive paranoia — the prober runs inside the one k3sm binary that co-hosts
// the embedded control plane, kine, and every other pod, so a panic in a single
// container's check (mirroring the kubelet's runtime.HandleCrash) must be
// contained here rather than crash the process. A check error is surfaced to the
// logger — the diagnosable cause of a never-Ready/restarting pod — instead of
// being reduced to a silent boolean as it was before.
func (pp *podProber) runCheck(ctx context.Context, container string, kind probeKind, s *probeSpec) (outcome probeOutcome) {
	if s.check == nil {
		// Defense in depth: buildCheck now never returns nil, but a nil check must
		// fail closed, never be invoked (a nil call would panic the process).
		pp.log.Error("probe has no runnable check; failing closed",
			"pod", pp.podID, "container", container, "kind", kind)
		return outcomeFailure
	}
	defer func() {
		if r := recover(); r != nil {
			outcome = outcomeFailure
			pp.log.Error("probe check panicked; recovered and treating as a failed probe",
				"pod", pp.podID, "container", container, "kind", kind, "panic", r)
		}
	}()
	if err := s.check(ctx, s.sched.timeout); err != nil {
		pp.log.Warn("probe failed",
			"pod", pp.podID, "container", container, "kind", kind, "err", err)
		return outcomeFailure
	}
	return outcomeSuccess
}

// fire signals a status change to the owner (runs outside all monitor locks).
func (pp *podProber) fire() {
	if pp.onTransition != nil {
		pp.onTransition()
	}
}

// doRestart performs the container-restart side effect after the monitor's
// bookkeeping was applied (onRestart: tally bump + gate reset). restartFunc is
// the process re-exec seam — on the runtimed path it drives the RestartContainer
// RPC, which bumps runtimed's restart_count, the single count authority the
// published status surfaces verbatim.
func (pp *podProber) doRestart(ctx context.Context, container string) {
	pp.log.Info("liveness probe failed failureThreshold times; restarting container", "pod", pp.podID, "container", container)
	if pp.restartFunc == nil {
		return
	}
	if err := pp.restartFunc(ctx, pp.podID, container); err != nil {
		pp.log.Warn("container restart failed", "pod", pp.podID, "container", container, "err", err)
	}
}

// verdict implements probeState.
func (pp *podProber) verdict(container string) (probeVerdict, bool) {
	m, ok := pp.monitors[container]
	if !ok {
		return probeVerdict{}, false
	}
	return m.verdict(), true
}
