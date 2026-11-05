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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"

	budgetv1alpha1 "k3sm.io/apis/budget/v1alpha1"

	"k3sm.io/k3sm/internal/atomicfile"
)

// The node's end of the budget channel. The node reports through an annotation
// on its own Node, which the Node authorizer and NodeRestriction already allow,
// and the server relay turns that annotation into NodeBudget.status. The relay
// answers with the policy annotation, which the node reads from the same Node.
//
// WRITES ARE EDGE-TRIGGERED AND QUANTIZED. Every Node write lands on the single
// writer datastore and wakes every Node watcher, so the annotation carries a
// coarse form of the observation (quantizeBudgetReport) and is written only when
// that coarse form changes, at most once per budgetAnnotationMinInterval at every
// level. A change inside the interval waits for the interval's end and is
// dropped if the value is back by then. There is no periodic rewrite: a calm node
// writes nothing, so observedAt says when the published value last changed, not
// when the node was last alive. Liveness is the Node's Lease.
//
// Fine-grained readers use the page. The annotation's signal values are good to
// one quantum, so a value may sit just past a rung its level does not claim; the
// level, admit and evict deadline fields are exact.

const (
	// budgetAnnotationMinInterval is the least time between two writes of the
	// status annotation, attempted or landed.
	budgetAnnotationMinInterval = 60 * time.Second
	// budgetAnnotationPoll is how often the publisher re-reads the budget. A
	// change is noticed within one poll, and a level edge after a quiet minute
	// is written then.
	budgetAnnotationPoll = 5 * time.Second
	// budgetAnnotationWriteTimeout bounds one Node write.
	budgetAnnotationWriteTimeout = 10 * time.Second
	// budgetAnnotationFieldManager is the field manager of the status write.
	budgetAnnotationFieldManager = "k3sm-budget"
	// budgetPolicyFile holds the last valid policy annotation in the node's
	// protected budget directory, where no pod can open it.
	budgetPolicyFile = "policy.json"
	// budgetPolicyUnparseableName names a refused policy annotation that does
	// not yield a usable name: AppliedPolicy requires an object name.
	budgetPolicyUnparseableName = "unparseable"
	// budgetQuantumDivisor sets the quantum at 5% of each denominator below.
	budgetQuantumDivisor = 20
	// budgetPermilleQuantum is 5% in permille.
	budgetPermilleQuantum = 1000 / budgetQuantumDivisor
)

// BudgetSource is the budget the publisher reports: the latest observation, ok
// false until the first sample. NodeStatusProvider implements it.
type BudgetSource interface {
	Budget() (budgetv1alpha1.NodeBudgetObservation, bool)
}

// BudgetOwnNode reads annotations from this node's own Node.
// interconnect.OwnNode implements it.
type BudgetOwnNode interface {
	// Annotation returns the named annotation; ok is false until the Node has
	// been read and while it does not exist.
	Annotation(key string) (value string, ok bool)
	// Changed delivers a signal after a change to the Node.
	Changed() <-chan struct{}
}

// BudgetPublisherConfig is the input to NewBudgetPublisher.
type BudgetPublisherConfig struct {
	// Client writes the status annotation. It is the node's own client.
	Client kubernetes.Interface
	// NodeName is this node's name.
	NodeName string
	// Own reads this node's Node.
	Own BudgetOwnNode
	// Source is the budget to report.
	Source BudgetSource
	// StateDir is the node's protected budget directory. Empty keeps the last
	// valid policy in memory only.
	StateDir string
	// Clock is the publisher's clock; nil is the real one.
	Clock clock.Clock
	// Log is the logger; nil is the default.
	Log *slog.Logger
}

// BudgetPublisher publishes the node's budget as the status annotation and
// applies the relayed policy annotation. Fields above mu belong to the Run loop.
type BudgetPublisher struct {
	cfg BudgetPublisherConfig
	clk clock.Clock
	log *slog.Logger

	// seeded is true once the status annotation a previous process left has
	// been read. written is the report the Node carries, and writtenKey its
	// comparison key; lastAttempt is the time of the last write, whether it
	// landed or not, or what a previous process's report implies.
	seeded      bool
	written     *budgetv1alpha1.NodeBudgetReport
	writtenKey  string
	lastAttempt time.Time
	lastEncode  string

	// policyInput is what the policy was last evaluated from.
	policyInput budgetPolicyInput
	evaluated   bool

	// mu guards the policy state, which InForce reads from other goroutines.
	mu sync.Mutex
	// valid is the last valid policy (nil for none) and validRaw its annotation.
	valid    *budgetv1alpha1.NodeBudgetDesiredPolicy
	validRaw string
	// spec is valid's spec after the floors and the measured clamps.
	spec *budgetv1alpha1.NodeBudgetPolicySpec
	// applied is what the node did with the policy it was last sent.
	applied *budgetv1alpha1.AppliedPolicy
}

// budgetPolicyInput is everything a policy evaluation reads, so an unchanged
// input is not evaluated again.
type budgetPolicyInput struct {
	raw                string
	cpuMilli, memBytes int64
}

// NewBudgetPublisher returns a publisher, with the last valid policy loaded from
// StateDir so it is in force before the apiserver can be reached.
func NewBudgetPublisher(cfg BudgetPublisherConfig) *BudgetPublisher {
	p := &BudgetPublisher{cfg: cfg, clk: cfg.Clock, log: cfg.Log}
	if p.clk == nil {
		p.clk = clock.RealClock{}
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	p.loadCachedPolicy()
	return p
}

// Run publishes until ctx ends. Every failure is logged and survivable: the
// budget is a report, never a reason to stop a node.
func (p *BudgetPublisher) Run(ctx context.Context) {
	for {
		p.pass(ctx)
		t := p.clk.NewTimer(budgetAnnotationPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C():
		case <-p.cfg.Own.Changed():
			t.Stop()
		}
	}
}

// InForce returns the policy the node runs, after the floors and the measured
// clamps: its reference and spec, or ok false while the shipped defaults are in
// force. The returned spec is the caller's.
func (p *BudgetPublisher) InForce() (budgetv1alpha1.PolicyRef, *budgetv1alpha1.NodeBudgetPolicySpec, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.valid == nil {
		return budgetv1alpha1.PolicyRef{}, nil, false
	}
	return budgetv1alpha1.PolicyRef{Name: p.valid.Name, ResourceVersion: p.valid.ResourceVersion}, p.spec.DeepCopy(), true
}

// pass evaluates the policy annotation and writes the status annotation if its
// quantized value changed and the interval allows. It acts only once both the
// budget and the Node have been read.
func (p *BudgetPublisher) pass(ctx context.Context) {
	obs, ok := p.cfg.Source.Budget()
	if !ok {
		return
	}
	raw, ok := p.cfg.Own.Annotation(budgetv1alpha1.AnnotationPolicy)
	if !ok {
		return
	}
	now := p.clk.Now()
	if !p.seeded {
		p.seed(now)
	}
	p.evaluatePolicy(raw, &obs.Capacity)

	report := p.reportOf(obs)
	key, err := budgetReportKey(report)
	if err != nil {
		p.logEncodeError(err)
		return
	}
	if key == p.writtenKey {
		return
	}
	if !p.lastAttempt.IsZero() && now.Sub(p.lastAttempt) < budgetAnnotationMinInterval {
		return
	}
	value, err := report.Encode()
	if err != nil {
		p.logEncodeError(err)
		return
	}
	p.lastEncode = ""
	p.lastAttempt = now
	if err := p.patchStatus(ctx, value); err != nil {
		if ctx.Err() == nil {
			p.log.Warn("could not write the node budget annotation; retrying after the write interval", "node", p.cfg.NodeName, "err", err)
		}
		return
	}
	p.written, p.writtenKey = &report, key
}

// logEncodeError reports a report that cannot be encoded. The observation is the
// producer's own, so this is a defect, and it would repeat every poll: each
// distinct message is logged once.
func (p *BudgetPublisher) logEncodeError(err error) {
	if msg := err.Error(); msg != p.lastEncode {
		p.lastEncode = msg
		p.log.Error("could not encode the node budget annotation", "node", p.cfg.NodeName, "err", err)
	}
}

// seed adopts the report a previous process left on the Node, so a restart with
// an unchanged value writes nothing and a crash loop stays inside the interval.
// An unreadable report is not adopted: writing over it is the repair.
func (p *BudgetPublisher) seed(now time.Time) {
	p.seeded = true
	raw, ok := p.cfg.Own.Annotation(budgetv1alpha1.AnnotationStatus)
	if !ok || raw == "" {
		return
	}
	r, err := budgetv1alpha1.ParseNodeBudgetReport(raw)
	if err != nil {
		p.log.Warn("replacing an unreadable node budget annotation", "node", p.cfg.NodeName, "err", err)
		return
	}
	key, err := budgetReportKey(r)
	if err != nil {
		return
	}
	p.written, p.writtenKey = &r, key
	// observedAt is the sample's time, so the write itself came up to one calm
	// sample interval later. A time ahead of this clock counts as now.
	last := r.ObservedAt.Add(pressureCalmInterval)
	if last.After(now) {
		last = now
	}
	p.lastAttempt = last
}

// patchStatus merge-patches the status annotation on this node's own Node. No
// other key is touched.
func (p *BudgetPublisher) patchStatus(ctx context.Context, value string) error {
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"annotations": map[string]any{budgetv1alpha1.AnnotationStatus: value}}})
	if err != nil {
		return fmt.Errorf("encode the annotation patch: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, budgetAnnotationWriteTimeout)
	defer cancel()
	if _, err := p.cfg.Client.CoreV1().Nodes().Patch(ctx, p.cfg.NodeName, types.MergePatchType, patch, metav1.PatchOptions{FieldManager: budgetAnnotationFieldManager}); err != nil {
		return fmt.Errorf("patch annotation %s on node %s: %w", budgetv1alpha1.AnnotationStatus, p.cfg.NodeName, err)
	}
	return nil
}

// reportOf is the annotation report for obs: the node's policy state added, then
// quantized against what the Node already carries.
func (p *BudgetPublisher) reportOf(obs budgetv1alpha1.NodeBudgetObservation) budgetv1alpha1.NodeBudgetReport {
	r := budgetv1alpha1.NodeBudgetReport{Schema: budgetv1alpha1.BudgetAnnotationSchema, NodeBudgetObservation: *obs.DeepCopy()}
	p.mu.Lock()
	if p.applied != nil {
		a := *p.applied
		a.ClampedFields = append([]budgetv1alpha1.PolicyField(nil), p.applied.ClampedFields...)
		r.Policy = &a
	}
	if p.valid != nil {
		r.InForce = &budgetv1alpha1.PolicyRef{Name: p.valid.Name, ResourceVersion: p.valid.ResourceVersion}
	}
	p.mu.Unlock()
	quantizeBudgetReport(&r, p.written)
	return r
}

// budgetReportKey is the report's comparison key: everything but the time it
// was observed, in the form the annotation carries it, so a report parsed back
// from the Node compares equal to the one that produced it.
func budgetReportKey(r budgetv1alpha1.NodeBudgetReport) (string, error) {
	r.ObservedAt = metav1.Time{}
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode the budget report key: %w", err)
	}
	return string(b), nil
}

// quantizeBudgetReport reduces r to its coarse form in place, against the report
// the Node carries (prev, nil for none). Readings round down to a bucket of 5% of
// a stable denominator: physical memory for the memory signals, the swap in use
// and the headroom; the scale itself for a permille; for a signal with no
// published total, its warn rung. A signal with no denominator publishes no value.
// What moves on every sample and only the page needs (trend, eta, the Darwin
// totals and compressor detail) is dropped.
func quantizeBudgetReport(r *budgetv1alpha1.NodeBudgetReport, prev *budgetv1alpha1.NodeBudgetReport) {
	var memQuantum int64
	if m := r.Capacity.MemCapacityBytes; m != nil {
		memQuantum = *m / budgetQuantumDivisor
	}
	prevSignal := func(id budgetv1alpha1.SignalID) *int64 {
		if prev == nil {
			return nil
		}
		for i := range prev.Signals {
			if prev.Signals[i].ID == id {
				return prev.Signals[i].Value
			}
		}
		return nil
	}
	for i := range r.Signals {
		s := &r.Signals[i]
		s.Value = quantizeWithHysteresis(s.Value, signalQuantum(s, memQuantum), prevSignal(s.ID))
		// A rate of change moves on every sample; the page carries it.
		s.Trend, s.EtaToNextRungSeconds = "", nil
	}
	var prevSwap, prevSafe, prevStatus *int64
	if prev != nil {
		prevSwap = prev.Capacity.SwapUsedBytes
		prevSafe = prev.Recommendation.SafeAdditionalBytes
		if prev.Darwin != nil {
			prevStatus = prev.Darwin.MemorystatusLevelPermille
		}
	}
	r.Capacity.SwapUsedBytes = quantizeWithHysteresis(r.Capacity.SwapUsedBytes, memQuantum, prevSwap)
	r.Recommendation.SafeAdditionalBytes = quantizeWithHysteresis(r.Recommendation.SafeAdditionalBytes, memQuantum, prevSafe)
	if d := r.Darwin; d != nil {
		d.MemorystatusLevelPermille = quantizeWithHysteresis(d.MemorystatusLevelPermille, budgetPermilleQuantum, prevStatus)
		// Running totals and compressor bytes move on every sample.
		d.Compressor, d.SwapinsTotal, d.SwapoutsTotal = nil, nil, nil
	}
}

// signalQuantum is the bucket size of s's value, 0 when it has no denominator.
func signalQuantum(s *budgetv1alpha1.BudgetSignal, memQuantum int64) int64 {
	switch s.ID {
	case budgetv1alpha1.SignalMemoryAvailable, budgetv1alpha1.SignalMemorySwap:
		return memQuantum
	case budgetv1alpha1.SignalMemoryCompressor:
		return budgetPermilleQuantum
	}
	if s.WarnThreshold == nil {
		return 0
	}
	return *s.WarnThreshold / budgetQuantumDivisor
}

// quantizeWithHysteresis rounds *v down to a multiple of q, unless v is still
// within a quarter quantum outside the bucket prev already names: then it stays
// at prev, so a reading that flaps on a bucket edge does not write on every
// flap. nil stays nil, and with no quantum there is no coarse value to publish.
func quantizeWithHysteresis(v *int64, q int64, prev *int64) *int64 {
	if v == nil || q <= 0 {
		return nil
	}
	if prev != nil && *v >= *prev-q/4 && *v < *prev+q+q/4 {
		return i64(*prev)
	}
	return i64(*v / q * q)
}

// evaluatePolicy applies the policy annotation raw against the measured capacity:
// a valid one becomes the policy in force, floored and clamped, and is cached;
// an invalid one is refused and the last valid one stays; an absent one means no
// policy selects this node, so the shipped defaults are in force again.
func (p *BudgetPublisher) evaluatePolicy(raw string, capacity *budgetv1alpha1.BudgetCapacity) {
	in := budgetPolicyInput{raw: raw, cpuMilli: measuredOrUnset(capacity.CPUCapacityMilli), memBytes: measuredOrUnset(capacity.MemCapacityBytes)}
	if p.evaluated && in == p.policyInput {
		return
	}
	p.evaluated, p.policyInput = true, in

	p.mu.Lock()
	defer p.mu.Unlock()
	if raw == "" {
		p.valid, p.validRaw, p.spec, p.applied = nil, "", nil, nil
		p.removeCachedPolicy()
		return
	}
	d, err := budgetv1alpha1.ParseNodeBudgetDesiredPolicy(raw)
	if err != nil {
		ref := refusedPolicyRef(raw)
		p.log.Warn("refusing the relayed budget policy; keeping the last valid one", "node", p.cfg.NodeName, "policy", ref.Name, "err", err)
		p.applied = &budgetv1alpha1.AppliedPolicy{PolicyRef: ref, Outcome: budgetv1alpha1.PolicyRejected}
		if p.valid != nil {
			p.spec, _ = clampBudgetPolicy(p.valid.Spec, capacity)
		}
		return
	}
	spec, clamped := clampBudgetPolicy(d.Spec, capacity)
	if raw != p.validRaw {
		p.storeCachedPolicy(raw)
	}
	p.valid, p.validRaw, p.spec = &d, raw, spec
	p.applied = &budgetv1alpha1.AppliedPolicy{
		PolicyRef: budgetv1alpha1.PolicyRef{Name: d.Name, ResourceVersion: d.ResourceVersion},
		Outcome:   budgetv1alpha1.PolicyApplied,
	}
	if len(clamped) > 0 {
		p.applied.Outcome, p.applied.ClampedFields = budgetv1alpha1.PolicyClamped, clamped
	}
}

// measuredOrUnset is a measured value, or -1 when it is not known.
func measuredOrUnset(v *int64) int64 {
	if v == nil {
		return -1
	}
	return *v
}

// clampBudgetPolicy returns spec with the compiled floors applied and every
// reserve above the measured capacity clamped down to it, and the fields it
// changed. A reserve with no measured capacity to compare against cannot be
// vouched for, so it is unset (the shipped default) and listed.
func clampBudgetPolicy(spec budgetv1alpha1.NodeBudgetPolicySpec, capacity *budgetv1alpha1.BudgetCapacity) (*budgetv1alpha1.NodeBudgetPolicySpec, []budgetv1alpha1.PolicyField) {
	out, clamped := budgetv1alpha1.ApplyFloors(spec)
	r := out.Reserves
	if r == nil {
		return &out, clamped
	}
	clamp := func(name budgetv1alpha1.PolicyField, reserve **int64, measured *int64) {
		switch {
		case *reserve == nil:
		case measured == nil:
			*reserve = nil
			clamped = append(clamped, name)
		case **reserve > *measured:
			*reserve = i64(*measured)
			clamped = append(clamped, name)
		}
	}
	clamp(budgetv1alpha1.FieldReservesCPUSystemReserveMilli, &r.CPUSystemReserveMilli, capacity.CPUCapacityMilli)
	clamp(budgetv1alpha1.FieldReservesMemSystemReserveBytes, &r.MemSystemReserveBytes, capacity.MemCapacityBytes)
	clamp(budgetv1alpha1.FieldReservesMemEvictionReserveBytes, &r.MemEvictionReserveBytes, capacity.MemCapacityBytes)
	return &out, clamped
}

// refusedPolicyRef names a refused policy annotation for the report: its name
// and resourceVersion when a lenient read yields well-formed ones, so a reader
// can tell which version was refused, else a fixed name. Nothing else from the
// value reaches the report. A value over the size bound is not parsed at all.
func refusedPolicyRef(raw string) budgetv1alpha1.PolicyRef {
	ref := budgetv1alpha1.PolicyRef{Name: budgetPolicyUnparseableName}
	if len(raw) > budgetv1alpha1.MaxBudgetAnnotationBytes {
		return ref
	}
	var probe struct {
		Name            string `json:"name"`
		ResourceVersion string `json:"resourceVersion"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return ref
	}
	// The payload's Validate is the one public check of these two shapes.
	wellFormed := func(name, rv string) bool {
		d := budgetv1alpha1.NodeBudgetDesiredPolicy{Schema: budgetv1alpha1.BudgetAnnotationSchema, Name: name, ResourceVersion: rv}
		return d.Validate() == nil
	}
	if !wellFormed(probe.Name, "0") {
		return ref
	}
	ref.Name = probe.Name
	if wellFormed(probe.Name, probe.ResourceVersion) {
		ref.ResourceVersion = probe.ResourceVersion
	}
	return ref
}

// loadCachedPolicy restores the last valid policy from the state directory. A
// missing file is no policy; an unreadable or invalid one is logged and ignored.
// Capacity is not known yet, so only the floors apply until the first evaluation.
func (p *BudgetPublisher) loadCachedPolicy() {
	if p.cfg.StateDir == "" {
		return
	}
	path := filepath.Join(p.cfg.StateDir, budgetPolicyFile)
	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.log.Warn("could not read the cached budget policy", "path", path, "err", err)
		}
		return
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, budgetv1alpha1.MaxBudgetAnnotationBytes+1))
	if err != nil {
		p.log.Warn("could not read the cached budget policy", "path", path, "err", err)
		return
	}
	d, err := budgetv1alpha1.ParseNodeBudgetDesiredPolicy(string(raw))
	if err != nil {
		p.log.Warn("ignoring an invalid cached budget policy", "path", path, "err", err)
		return
	}
	spec, _ := budgetv1alpha1.ApplyFloors(d.Spec)
	p.valid, p.validRaw, p.spec = &d, string(raw), &spec
}

// storeCachedPolicy records raw as the last valid policy. A failure is logged:
// the policy still runs, and only a restart would lose it.
func (p *BudgetPublisher) storeCachedPolicy(raw string) {
	if p.cfg.StateDir == "" {
		return
	}
	if err := os.MkdirAll(p.cfg.StateDir, 0o700); err != nil {
		p.log.Warn("could not cache the budget policy", "err", err)
		return
	}
	if err := atomicfile.Replace(filepath.Join(p.cfg.StateDir, budgetPolicyFile), []byte(raw), 0o600); err != nil {
		p.log.Warn("could not cache the budget policy", "err", err)
	}
}

// removeCachedPolicy drops the cache once no policy selects this node.
func (p *BudgetPublisher) removeCachedPolicy() {
	if p.cfg.StateDir == "" {
		return
	}
	if err := os.Remove(filepath.Join(p.cfg.StateDir, budgetPolicyFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		p.log.Warn("could not remove the cached budget policy", "err", err)
	}
}
