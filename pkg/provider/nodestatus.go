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
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// defaultNodeStatusInterval is how often the node status is recomputed and
// published. It matches the Virtual Kubelet node controller's own status-update
// interval, so a recompute lands on the same cadence the controller was going to
// push a status on anyway — sampling faster would produce work the controller
// coalesces away, and sampling slower would leave the published conditions older
// than the object carrying them.
const defaultNodeStatusInterval = time.Minute

// The Ready-condition Reason/Message vocabulary. The literals mirror the
// kubelet's so operators and controllers reading node conditions see the strings
// they already recognize.
const (
	nodeReadyReason      = "KubeletReady"
	nodeReadyMessage     = "kubelet is posting ready status"
	nodeNotReadyReason   = "KubeletNotReady"
	nodeNotReadyMessage  = "container runtime is not healthy"
	nodeUnknownReadyText = "container runtime health has not been observed"
)

// NodeStatusConfig is the input to NewNodeStatusProvider.
type NodeStatusConfig struct {
	// Node is the registering Node object, already stamped with this node's
	// identity, capacity, allocatable, addresses and labels. The provider
	// DeepCopies it once and never mutates the caller's object.
	Node *corev1.Node
	// DataRoot is a directory on the volume whose free space backs DiskPressure.
	DataRoot string
	// RuntimeHealthy reports whether the pod runtime can currently serve pods. A
	// nil value means the backing runtime exposes no health surface, in which case
	// Ready is never contradicted — a runtime that cannot answer the question must
	// not be allowed to answer it "no".
	RuntimeHealthy func(ctx context.Context) bool
	// Interval overrides the status recompute period; zero uses
	// defaultNodeStatusInterval.
	Interval time.Duration
	// Log receives the status-loop diagnostics; nil uses slog.Default().
	Log *slog.Logger
}

// NodeStatusProvider is the node-status half of the Virtual Kubelet contract: it
// samples this Mac, reduces the sample to node-pressure conditions, debounces a
// Ready verdict from the pod runtime's health, and publishes the result.
//
// Three shape decisions here are load-bearing, and each fixes a specific way this
// surface goes wrong:
//
//   - It publishes a DEEP COPY of the node it was handed at bootstrap, with ONLY
//     .Status.Conditions (and .Status.Phase) replaced. The node controller assigns
//     the published Status, Labels and Annotations WHOLESALE over its own copy, so
//     a provider that sends a conditions-only Node erases Capacity, Allocatable,
//     the InternalIP the apiserver dials for logs/exec, the DaemonEndpoints port
//     and every label — silently, with no compile-time signal.
//   - Ready is published as an explicit condition through UpdateStatus, never
//     signalled by returning an error from Ping. A Ping error only SUPPRESSES the
//     status update and the lease renewal and logs to the VK logger, which is a
//     no-op sink here: the node would go stale with no condition and no diagnostic
//     — strictly worse observability than saying nothing.
//   - Supplying any non-nil NodeProvider disables the node helper's built-in
//     auto-Ready callback, so this type owns the Ready condition outright. Nothing
//     else in the process sets it.
//
// HONEST LIMITATION: a True pressure condition here buys a NoSchedule taint and
// nothing else. k3sm has no eviction manager, so no pod is ranked or evicted to
// relieve the pressure and the taint is ABSORBING — it persists until a human (or,
// for the image store, the runtime's own garbage collector) frees the resource.
// The DiskPressure hysteresis band exists so that recovery, when it comes, is not
// immediately undone by a flap.
type NodeStatusProvider struct {
	// naive supplies the NodeProvider contract itself (Ping/NotifyNodeStatus) and
	// the UpdateStatus channel into the node controller.
	naive *vkadapter.NaiveNodeProvider
	log   *slog.Logger

	// bootstrap is the pristine node handed over at registration. It is never
	// mutated: every publication is a fresh DeepCopy of it, so no accumulated
	// edit can drift the advertised capacity or addresses.
	bootstrap *corev1.Node
	dataRoot  string
	interval  time.Duration
	health    func(ctx context.Context) bool

	// Seams, defaulted by the constructor. Tests replace them to drive the loop
	// hermetically — no Mach, no statfs, no apiserver.
	sample  func(dataRoot string) (hostStats, error)
	now     func() time.Time
	publish func(ctx context.Context, node *corev1.Node) error

	// mu guards ready and prev. It is held only across the pure recompute, never
	// across publish (which can block on the node controller's update channel).
	// Run is the single caller of publishOnce in production.
	mu    sync.Mutex
	ready *probeGauge
	prev  []corev1.NodeCondition
}

// Compile-time check that the status provider satisfies the VK node contract.
var _ vkadapter.NodeProvider = (*NodeStatusProvider)(nil)

// NewNodeStatusProvider returns a status provider over the registering node.
// It fails on a nil Node or an empty DataRoot rather than deferring either into
// the status loop, where the consequence would be a node that silently never
// reports.
func NewNodeStatusProvider(cfg NodeStatusConfig) (*NodeStatusProvider, error) {
	if cfg.Node == nil {
		return nil, errors.New("provider: NodeStatusConfig.Node is required")
	}
	if cfg.DataRoot == "" {
		return nil, errors.New("provider: NodeStatusConfig.DataRoot is required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = defaultNodeStatusInterval
	}
	naive := vkadapter.NewNaiveNodeProvider()
	p := &NodeStatusProvider{
		naive:     naive,
		log:       log,
		bootstrap: cfg.Node.DeepCopy(),
		dataRoot:  cfg.DataRoot,
		interval:  interval,
		health:    cfg.RuntimeHealthy,
		sample:    sampleHostStats,
		now:       time.Now,
		publish:   naive.UpdateStatus,
		// The Ready gauge starts COMMITTED to success and needs
		// defaultProbeFailureThreshold consecutive unhealthy samples to flip — the
		// same consecutive-threshold counting a container liveness probe uses, with
		// the same default and no new knob.
		//
		// Starting committed-healthy is deliberate. A self-reported Ready=False is
		// acted on immediately (the node-monitor grace period does not shield it),
		// and on this topology the node hosts the control plane, so a single
		// transient sample would begin deleting every pod. The cost is symmetric and
		// documented: a runtime that is broken from boot is reported Ready for
		// threshold intervals before the flip.
		ready: newProbeGauge(1, defaultProbeFailureThreshold, outcomeSuccess),
	}
	return p, nil
}

// Ping implements the VK node contract. It reports only context cancellation:
// runtime health is published as an explicit Ready condition instead, because a
// Ping error suppresses the status update rather than communicating anything.
func (p *NodeStatusProvider) Ping(ctx context.Context) error { return p.naive.Ping(ctx) }

// NotifyNodeStatus implements the VK node contract, registering the node
// controller's callback with the underlying naive provider so UpdateStatus can
// deliver to it.
func (p *NodeStatusProvider) NotifyNodeStatus(ctx context.Context, cb func(*corev1.Node)) {
	p.naive.NotifyNodeStatus(ctx, cb)
}

// Run drives the status loop until ctx is done, publishing once immediately and
// then every interval. The first publication is what makes the node Ready, so it
// must not wait for the first tick.
//
// It returns ctx.Err() on cancellation. A publication failure is logged and the
// loop continues: the next tick republishes, and a permanently failing publish is
// already visible as a node whose status goes stale.
func (p *NodeStatusProvider) Run(ctx context.Context) error {
	p.publishLogged(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			p.publishLogged(ctx)
		}
	}
}

// publishLogged runs one publish cycle, logging a failure at the boundary that
// handles it (the loop) rather than propagating it.
func (p *NodeStatusProvider) publishLogged(ctx context.Context) {
	if err := p.publishOnce(ctx); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		p.log.Warn("node status publish failed; retrying on the next interval", "error", err)
	}
}

// publishOnce samples the host, recomputes the node conditions, and publishes a
// fresh copy of the bootstrap node carrying them.
func (p *NodeStatusProvider) publishOnce(ctx context.Context) error {
	s, sampleErr := p.sample(p.dataRoot)
	if sampleErr != nil {
		// A failed sample is reported ONCE per cycle and then carried: the pressure
		// conditions keep their previous values (or, on a first-pass failure, are
		// omitted entirely — an absent condition is the truthful "not observed", and
		// it is exactly the state the node was in before any of this existed).
		p.log.Warn("node resource sample failed; carrying the previous pressure conditions",
			"error", sampleErr, "data_root", p.dataRoot)
	}
	healthy := true
	if p.health != nil {
		healthy = p.health(ctx)
	}
	node := p.recompute(s, sampleErr == nil, healthy, metav1.NewTime(p.now()))
	return p.publish(ctx, node)
}

// recompute builds the node object to publish. It is the whole decision: pure
// given (s, sampled, healthy, now) and the provider's remembered previous
// conditions, and it never touches the host.
func (p *NodeStatusProvider) recompute(s hostStats, sampled, healthy bool, now metav1.Time) *corev1.Node {
	p.mu.Lock()
	defer p.mu.Unlock()

	raw := p.pressureVerdicts(s, sampled, now)
	outcome := outcomeSuccess
	if !healthy {
		outcome = outcomeFailure
	}
	raw = append(raw, readyCondition(p.ready.record(outcome), now))

	next := reconcileTransitions(p.prev, raw, s)
	p.prev = next

	// A DeepCopy of the pristine bootstrap node, with ONLY the conditions replaced.
	// Everything the node advertises — capacity, allocatable, addresses, daemon
	// endpoints, node info, labels, taints — survives untouched by construction,
	// because it is copied fresh from the object registration produced rather than
	// carried across recomputes.
	node := p.bootstrap.DeepCopy()
	node.Status.Conditions = next
	node.Status.Phase = corev1.NodePending
	if c := findNodeCondition(next, corev1.NodeReady); c != nil && c.Status == corev1.ConditionTrue {
		node.Status.Phase = corev1.NodeRunning
	}
	return node
}

// pressureVerdicts returns the raw (pre-reconcile) pressure conditions for this
// cycle: computed from s when the sample succeeded, otherwise the previously
// published ones with a refreshed heartbeat. On a first-pass sample failure it
// returns nothing at all, so the node carries no pressure conditions rather than
// four fabricated ones.
func (p *NodeStatusProvider) pressureVerdicts(s hostStats, sampled bool, now metav1.Time) []corev1.NodeCondition {
	if sampled {
		return computeNodeConditions(s, now)
	}
	var out []corev1.NodeCondition
	for _, c := range p.prev {
		if c.Type == corev1.NodeReady {
			continue // re-derived from live health every cycle, never carried
		}
		c.LastHeartbeatTime = now
		out = append(out, c)
	}
	return out
}

// readyCondition renders a committed Ready verdict as a NodeCondition. The
// outcome is the gauge's COMMITTED value, so a single unhealthy sample cannot
// reach here as False — see NewNodeStatusProvider for the debounce contract.
func readyCondition(committed probeOutcome, now metav1.Time) corev1.NodeCondition {
	c := corev1.NodeCondition{
		Type:               corev1.NodeReady,
		Status:             corev1.ConditionUnknown,
		Reason:             nodeNotReadyReason,
		Message:            nodeUnknownReadyText,
		LastHeartbeatTime:  now,
		LastTransitionTime: now,
	}
	switch committed {
	case outcomeSuccess:
		c.Status = corev1.ConditionTrue
		c.Reason = nodeReadyReason
		c.Message = nodeReadyMessage
	case outcomeFailure:
		c.Status = corev1.ConditionFalse
		c.Reason = nodeNotReadyReason
		c.Message = nodeNotReadyMessage
	}
	return c
}
