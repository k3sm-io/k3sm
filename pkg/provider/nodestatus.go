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

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"
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
	// Images lists the runtime's image store for Node.status.images. A nil value
	// means the runtime keeps no image store (the host-process runtime), and the
	// node reports no images.
	Images ImageInventory
	// PodProcesses reports the process counts the pods hold, the numerator of
	// PIDPressure's per-uid leg. A nil value means the runtime keeps no process
	// ledger (the host-process runtime), and only the systemwide leg runs.
	PodProcesses PodProcessCounter
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
//     .Status.Conditions (and .Status.Phase and .Status.Images) replaced. The node controller assigns
//     the published Status, Labels and Annotations WHOLESALE over its own copy, so
//     a provider that sends a conditions-only Node erases Capacity, Allocatable,
//     the InternalIP the apiserver dials for logs/exec, the DaemonEndpoints port
//     and every label — silently, with no compile-time signal.
//   - Ready is published as an explicit condition through UpdateStatus, never
//     signalled by returning an error from Ping. A Ping error only SUPPRESSES the
//     status update and the lease renewal: the node would go stale with no
//     condition, only a log line — strictly worse than saying NotReady.
//   - Supplying any non-nil NodeProvider disables the node helper's built-in
//     auto-Ready callback, so this type owns the Ready condition outright. Nothing
//     else in the process sets it.
//
// It does not sample the host itself. The pressure monitor it owns (pressure.go)
// takes every host sample on its own adaptive cadence; the status loop publishes
// the monitor's latest snapshot, and the eviction manager (eviction.go) triggers
// on the same snapshot through the same predicate, so MemoryPressure and the
// eviction decision are one verdict. A True MemoryPressure is acted on by that
// manager; DiskPressure and PIDPressure buy the NoSchedule taint only, and persist
// until the resource is freed. The DiskPressure hysteresis band exists so that
// recovery, when it comes, is not immediately undone by a flap.
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
	inventory ImageInventory
	podProcs  PodProcessCounter

	// Seams, defaulted by the constructor. Tests replace them to drive the loop
	// hermetically — no Mach, no statfs, no apiserver. sample is the HOST
	// sampler; only the monitor calls it.
	sample  func(dataRoot string) (hostStats, error)
	now     func() time.Time
	publish func(ctx context.Context, node *corev1.Node) error

	// mu guards ready, prev and the image cache below. It is held only across
	// the pure recompute and the cache's read and write: never across the image
	// listing, and never across publish (which can block on the node
	// controller's update channel).
	// Run is the single caller of publishOnce in production.
	mu    sync.Mutex
	ready *probeGauge
	prev  []corev1.NodeCondition
	// images is the last image list the runtime answered, carried across a
	// failed listing so a transient error never publishes an empty list.
	// imagesFailing records that the last listing failed, so a persistent
	// failure warns once rather than every cycle. imagesInFlight is true while
	// a listing goroutine runs; at most one runs at a time.
	images         []corev1.ContainerImage
	imagesFailing  bool
	imagesInFlight bool
	// imagesWG counts the in-flight listing goroutine; tests wait on it.
	imagesWG sync.WaitGroup

	// procCount and procReported are the last pod process count the runtime
	// answered (see PodProcessCounter), carried across a failed call like the
	// image list. procFailing, procInFlight and procWG mirror the image fields.
	procCount    int64
	procReported bool
	procFailing  bool
	procInFlight bool
	procWG       sync.WaitGroup

	// monitor owns the host sample (see the type doc).
	monitor *pressureMonitor
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
		inventory: cfg.Images,
		podProcs:  cfg.PodProcesses,
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
	// The monitor reads p.sample at call time, so a test that swaps the seam
	// after construction is honoured.
	p.monitor = newPressureMonitor(func() (hostStats, error) { return p.sample(p.dataRoot) }, log)
	return p, nil
}

// Budget returns the node budget of the pressure monitor's latest snapshot,
// with the CPU and memory capacity, allocatable and reserve of the registered
// node added. ok is false until the first successful sample. It takes no sample
// and reads the same stored snapshot the conditions are computed from, so the
// budget and the SoftPressure condition agree.
func (p *NodeStatusProvider) Budget() (budgetv1alpha1.NodeBudgetObservation, bool) {
	s, _, ok := p.monitor.latest()
	if !ok {
		return budgetv1alpha1.NodeBudgetObservation{}, false
	}
	obs, _ := budgetOf(s, ladderOf(s))
	st := p.bootstrap.Status
	if c, ok := st.Capacity[corev1.ResourceCPU]; ok {
		obs.Capacity.CPUCapacityMilli = i64(c.MilliValue())
		if a, ok := st.Allocatable[corev1.ResourceCPU]; ok {
			obs.Capacity.CPUSystemReserveMilli = i64(max(0, c.MilliValue()-a.MilliValue()))
		}
	}
	if a, ok := st.Allocatable[corev1.ResourceMemory]; ok {
		obs.Capacity.MemAllocatableBytes = i64(max(0, a.Value()))
		if c, ok := st.Capacity[corev1.ResourceMemory]; ok {
			obs.Capacity.MemSystemReserveBytes = i64(max(0, c.Value()-a.Value()))
		}
	}
	return obs, true
}

// Ping implements the VK node contract. It reports only context cancellation:
// runtime health is published as an explicit Ready condition instead, because a
// Ping error suppresses the status update rather than communicating anything.
//
// Keep it that way. vkadapter's pingGuard answers for a Ping that has not
// returned within two seconds, so a Ping that did real runtime work could have
// its failure turned into a healthy heartbeat. A runtime check belongs in the
// Ready condition, never here.
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
// The pressure monitor runs inside Run, sharing its ctx: it takes its first
// sample BEFORE the first publish (so the first publication carries pressure
// conditions), then samples on its own cadence. A False->True memory-pressure
// edge publishes at once instead of waiting up to an interval. Run returns only
// after the monitor has stopped.
//
// It returns ctx.Err() on cancellation. A publication failure is logged and the
// loop continues: the next tick republishes, and a permanently failing publish is
// already visible as a node whose status goes stale.
func (p *NodeStatusProvider) Run(ctx context.Context) error {
	p.monitor.sampleOnce()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); p.monitor.run(ctx) }()
	defer wg.Wait()

	p.publishLogged(ctx)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			p.publishLogged(ctx)
		case <-p.monitor.edges():
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

// publishOnce recomputes the node conditions from the pressure monitor's latest
// snapshot and publishes a fresh copy of the bootstrap node carrying them. It
// takes no host sample of its own.
//
// A failed sample never reaches here as a zero snapshot: the monitor keeps the
// previous one (and says so), so the conditions it yields are the previous
// verdicts. Before the first successful sample there is no snapshot, and the
// pressure conditions are omitted entirely — an absent condition is the
// truthful "not observed", and it is exactly the state the node was in before
// any of this existed.
func (p *NodeStatusProvider) publishOnce(ctx context.Context) error {
	s, _, sampled := p.monitor.latest()
	healthy := true
	if p.health != nil {
		healthy = p.health(ctx)
	}
	p.startImageRefresh(ctx)
	p.startProcessCountRefresh(ctx)
	s.PodProcCount, s.PodProcReported = p.cachedProcessCount()
	node := p.recompute(s, sampled, healthy, metav1.NewTime(p.now()))
	node.Status.Images = p.cachedImages()
	return p.publish(ctx, node)
}

// nodeImagesListTimeout bounds one listing of the runtime's images. The
// listing runs off the publish path, so the bound protects the next refresh,
// not the heartbeat.
const nodeImagesListTimeout = 5 * time.Second

// startImageRefresh starts a listing of the runtime's images in its own
// goroutine, unless one is already running. A kubelet lists images on every
// node status update; here the listing refreshes a cache that each publication
// reads, so a slow or stuck listing never delays a heartbeat — the node
// publishes whatever the cache holds and the next tick picks up the answer.
//
// The goroutine's lifetime is the listing call: it holds no lock while
// listing, exits when the listing returns, and the listing is bounded by
// nodeImagesListTimeout under ctx. Run does not wait for it on return, because
// a listing that ignores its deadline must not hold up the node's shutdown
// either.
func (p *NodeStatusProvider) startImageRefresh(ctx context.Context) {
	if p.inventory == nil {
		return
	}
	p.mu.Lock()
	if p.imagesInFlight {
		p.mu.Unlock()
		return
	}
	p.imagesInFlight = true
	p.imagesWG.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.imagesWG.Done()
		p.refreshImages(ctx)
	}()
}

// refreshImages lists the runtime's images once and updates the cache.
//
// On a listing error the cache keeps the previous list: a runtime that failed
// one call still holds its images, and publishing an empty list would tell the
// scheduler the node holds nothing. A failure warns on the transition from a
// good listing to a failing one, and the recovery is logged once at Info, so a
// persistent failure (a damaged index record) is one line, not one a minute.
// A listing cut short by ctx itself (the node shutting down) changes nothing.
func (p *NodeStatusProvider) refreshImages(ctx context.Context) {
	lctx, cancel := context.WithTimeout(ctx, nodeImagesListTimeout)
	entries, err := p.inventory.ImageIndexSnapshot(lctx)
	cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.imagesInFlight = false
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if !p.imagesFailing {
			p.imagesFailing = true
			p.log.Warn("list node images failed; Node.status.images keeps the previous list until a listing succeeds", "error", err)
		}
		return
	}
	p.images = nodeImages(entries, nodeStatusMaxImages)
	if p.imagesFailing {
		p.imagesFailing = false
		p.log.Info("list node images recovered; Node.status.images is current again")
	}
}

// podProcessCountTimeout bounds one pod process count call. Like the image
// listing it runs off the publish path.
const podProcessCountTimeout = 5 * time.Second

// startProcessCountRefresh starts one pod process count call in its own
// goroutine, unless one is already running, for the same reason and with the
// same lifetime as startImageRefresh: a slow runtime never delays a heartbeat,
// and a publication reads whatever the cache holds.
func (p *NodeStatusProvider) startProcessCountRefresh(ctx context.Context) {
	if p.podProcs == nil {
		return
	}
	p.mu.Lock()
	if p.procInFlight {
		p.mu.Unlock()
		return
	}
	p.procInFlight = true
	p.procWG.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.procWG.Done()
		p.refreshProcessCount(ctx)
	}()
}

// refreshProcessCount asks the runtime for the pods' process count once and
// updates the cache. A failure keeps the previous count, warns on the
// transition into failure and logs the recovery once, as refreshImages does.
// Before the first answer the cache reports nothing and the per-uid leg is
// skipped.
func (p *NodeStatusProvider) refreshProcessCount(ctx context.Context) {
	cctx, cancel := context.WithTimeout(ctx, podProcessCountTimeout)
	count, reported, err := p.podProcs.PodProcessCount(cctx)
	cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.procInFlight = false
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if !p.procFailing {
			p.procFailing = true
			p.log.Warn("count pod processes failed; the per-uid PIDPressure leg keeps the previous count until a count succeeds", "error", err)
		}
		return
	}
	p.procCount, p.procReported = count, reported
	if p.procFailing {
		p.procFailing = false
		p.log.Info("count pod processes recovered; the per-uid PIDPressure leg is current again")
	}
}

// cachedProcessCount returns the cached pod process count for one publication.
func (p *NodeStatusProvider) cachedProcessCount() (int64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.procCount, p.procReported
}

// cachedImages returns a copy of the image cache for one publication. Before
// the first successful listing it is nil and the field is omitted.
func (p *NodeStatusProvider) cachedImages() []corev1.ContainerImage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return copyContainerImages(p.images)
}

// copyContainerImages deep-copies an image list, so the published node never
// shares a backing array with the list the provider keeps.
func copyContainerImages(in []corev1.ContainerImage) []corev1.ContainerImage {
	if in == nil {
		return nil
	}
	out := make([]corev1.ContainerImage, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
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
// five fabricated ones.
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
