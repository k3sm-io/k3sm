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

package operator

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/resource"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Reasons carried by the Ready and Degraded conditions when the pre-render fit
// check refuses a spec. They are distinct from the pod-derived reasons in
// k3sm.io/k3sm/pkg/mlx because they describe a decision taken BEFORE any pod
// exists — a consumer reading ReasonMemoryExceedsWorkingSet knows no replica was
// ever created, where a pod-derived reason means one was.
const (
	// ReasonNoGPU means the node reports no usable Metal device. Nothing about
	// the spec can fix it.
	ReasonNoGPU = "NoGPU"
	// ReasonGPUUnsupported means the node has a Metal device but the sandbox
	// backend the daemon is running cannot grant a pod access to it, so a serving
	// pod would start with no GPU. It is separate from ReasonNoGPU because the
	// remedy is a daemon configuration change, not different hardware.
	ReasonGPUUnsupported = "GPUUnsupported"
	// ReasonMemoryExceedsHostMemory means spec.memory is larger than the host's
	// entire physical memory. On Apple Silicon that memory IS the GPU's memory,
	// so this is the outermost ceiling.
	ReasonMemoryExceedsHostMemory = "MemoryExceedsHostMemory"
	// ReasonMemoryExceedsWorkingSet means spec.memory exceeds the Metal device's
	// recommended maximum working-set size — the number a model-admission check
	// is meant to size against.
	ReasonMemoryExceedsWorkingSet = "MemoryExceedsWorkingSet"
	// ReasonMemoryExceedsWiredLimit means spec.memory exceeds an EXPLICITLY
	// configured iogpu wired-memory limit. For a large model that limit, not the
	// host's memory, is the binding constraint.
	ReasonMemoryExceedsWiredLimit = "MemoryExceedsWiredLimit"
	// ReasonGPUSizingUnknown means the node claims a Metal device but reports no
	// usable sizing number for it, so the fit cannot be certified either way.
	ReasonGPUSizingUnknown = "GPUSizingUnknown"
)

// ConditionDegraded is the condition type carrying a non-fatal deficiency that
// still blocks serving. It sits beside — never replaces — the Ready condition,
// which stays the one a consumer branches on.
const ConditionDegraded = "Degraded"

// FitLevel is how a pre-render fit check came out.
type FitLevel int

const (
	// FitOK means the spec fits, or the facts needed to say otherwise are not
	// available. Reconcile proceeds to render and apply.
	FitOK FitLevel = iota
	// FitDegraded means the node's facts are present but do not certify the fit.
	// No objects are applied: placing a model-sized workload on a node whose
	// ceiling is unknown is exactly the load-time kill this check exists to
	// prevent, and the unknown is a node-side fault a spec change cannot fix.
	FitDegraded
	// FitFailed means the spec provably cannot be served on this node's GPU. No
	// objects are applied, and nothing will change until the spec or the node
	// does.
	FitFailed
)

// Fit is one pre-render fit verdict.
type Fit struct {
	// Level is the verdict.
	Level FitLevel
	// Reason is the machine-readable condition reason. Empty when Level is FitOK.
	Reason string
	// Message is the human-readable explanation, naming both numbers that were
	// compared — a fit refusal that does not say what it compared against sends
	// the reader to the node object to guess.
	Message string
}

// Blocks reports whether this verdict stops the reconcile before any object is
// applied. Both non-OK levels do; they differ in what the operator can say about
// why, not in what it does.
func (f Fit) Blocks() bool { return f.Level != FitOK }

// GPUSource reports the GPU facts a spec is validated against.
//
// It is an interface at the consumer, and it is allowed to answer "I do not
// know": the facts come from the node-local runtime daemon, and an operator
// running where that daemon is not reachable must still reconcile models rather
// than refuse every one of them. nil facts mean the fit check is SKIPPED, not
// that it failed — the extended-resource request the render always emits still
// keeps a model off a node with no GPU.
type GPUSource interface {
	// GPUFacts returns this node's GPU facts, or nil when they are not known.
	GPUFacts(ctx context.Context) *runtimev1.GPUFacts
}

// GPUSourceFunc adapts a plain function to GPUSource.
type GPUSourceFunc func(ctx context.Context) *runtimev1.GPUFacts

// GPUFacts calls f.
func (f GPUSourceFunc) GPUFacts(ctx context.Context) *runtimev1.GPUFacts { return f(ctx) }

// StaticGPU returns a GPUSource that always reports facts.
func StaticGPU(facts *runtimev1.GPUFacts) GPUSource {
	return GPUSourceFunc(func(context.Context) *runtimev1.GPUFacts { return facts })
}

// ValidateFit decides, from the node's GPU facts alone, whether a model asking
// for memory can ever be served — BEFORE anything is rendered or applied.
//
// It is pure: no IO, no clock, and facts is not mutated. The checks run in
// ceiling order, widest first, so the reason a spec is refused names the
// outermost constraint it violates rather than whichever one happened to be
// tested first.
//
// The zero-valued fields of GPUFacts are read exactly as their contract defines
// them, which is the whole subtlety here:
//
//   - iogpu_wired_limit_bytes == 0 is a MODELLED SENTINEL meaning "no explicit
//     limit is configured; the kernel default applies". It is NOT unbounded
//     headroom and NOT a missing fact, so it is not compared against — the
//     recommended working set, which IS knowable, carries the check instead.
//   - recommended_max_working_set_bytes == 0 means the number could not be read.
//     On a node that claims a Metal device that is an anomaly, not a ceiling of
//     zero, so it degrades rather than failing.
func ValidateFit(memory resource.Quantity, facts *runtimev1.GPUFacts) Fit {
	if facts == nil {
		return Fit{Level: FitOK}
	}
	want := memory.Value()

	if !facts.GetMetalAvailable() {
		return Fit{
			Level:   FitFailed,
			Reason:  ReasonNoGPU,
			Message: "the node reports no usable Metal device",
		}
	}
	if !facts.GetSandboxGpuSupported() {
		return Fit{
			Level:   FitFailed,
			Reason:  ReasonGPUUnsupported,
			Message: "the node has a Metal device but its sandbox backend cannot grant a pod GPU access",
		}
	}
	if host := facts.GetMemBytes(); host > 0 && want > int64(host) {
		return Fit{
			Level:   FitFailed,
			Reason:  ReasonMemoryExceedsHostMemory,
			Message: fmt.Sprintf("spec.memory %s exceeds the host's %s of unified memory", human(want), human(int64(host))),
		}
	}
	if ws := facts.GetRecommendedMaxWorkingSetBytes(); ws > 0 && want > int64(ws) {
		return Fit{
			Level:   FitFailed,
			Reason:  ReasonMemoryExceedsWorkingSet,
			Message: fmt.Sprintf("spec.memory %s exceeds the Metal device's recommended maximum working set of %s", human(want), human(int64(ws))),
		}
	}
	if wired := facts.GetIogpuWiredLimitBytes(); wired > 0 && want > int64(wired) {
		return Fit{
			Level:   FitFailed,
			Reason:  ReasonMemoryExceedsWiredLimit,
			Message: fmt.Sprintf("spec.memory %s exceeds the node's configured iogpu wired-memory limit of %s", human(want), human(int64(wired))),
		}
	}
	if facts.GetRecommendedMaxWorkingSetBytes() == 0 {
		return Fit{
			Level:   FitDegraded,
			Reason:  ReasonGPUSizingUnknown,
			Message: "the node reports a Metal device but no recommended maximum working set, so the fit of spec.memory cannot be certified",
		}
	}
	return Fit{Level: FitOK}
}

// human renders a byte count the way a resource.Quantity is written, so a fit
// message compares two numbers in the same notation the spec used.
func human(bytes int64) string {
	q := resource.NewQuantity(bytes, resource.BinarySI)
	return q.String()
}
