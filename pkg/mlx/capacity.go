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

package mlx

import (
	"errors"
	"fmt"
	"math"

	"k8s.io/apimachinery/pkg/api/resource"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// capacity.go is the NODE-WIDE GPU capacity policy: how many units of the
// mlx.k3sm.io/gpu extended resource a node advertises, and whether one more GPU
// pod still fits in GPU memory beside the ones already admitted.
//
// It is a deliberate exception to this package's MLXModel-render framing (see
// doc.go). Nothing here renders or reads an MLXModel: the advertiser is the node
// command and the fit check is the pod provider, neither of which knows what an
// MLXModel is. It lives here anyway because the two consumers must agree on one
// arithmetic — a node that advertises two slots while the provider sizes one, or
// the reverse, is a scheduler that binds pods the node then refuses — and this
// package is the one place both already depend on for the GPU vocabulary.
//
// Everything in this file is PURE: facts in, numbers out. No IO, no clock, no
// cluster reads, so the whole policy is decided by a table test rather than by a
// Mac with a particular amount of memory in it.

// GPUSlotFloorBytes is the GPU memory one slot is sized at: 1.5 GiB.
//
// It is the per-slot FLOOR, not a measured safe working set — a later safety
// measurement may revise it, and revising it here revises both the advertised
// slot count and the request the worker pod template makes, which is the point
// of having one constant. The worker pod template requests exactly this, so a
// node advertising N slots has been asked for at most N × this much.
const GPUSlotFloorBytes int64 = 1536 << 20

// MaxGPUSlots caps the advertised slot count at 2 however much memory the host
// has. The slots are not isolated devices — they are co-tenants on ONE
// integrated GPU (see GPUSlots) — so past two the contention costs more than the
// extra concurrency buys, and a 512 GiB Mac advertising dozens of them would
// attract a workload mix no measurement here supports.
const MaxGPUSlots = 2

// ErrGPUMemoryOverCeiling is the sentinel for a GPU pod refused because it does
// not fit in GPU memory beside the GPU pods already admitted on this node. It is
// errors.Is-able so a caller can tell a capacity refusal — which another pod's
// deletion fixes — from a transient create failure.
var ErrGPUMemoryOverCeiling = errors.New("pod does not fit in the node's GPU memory ceiling beside the pods already admitted")

// GPUCeilingBytes reports the node's USABLE GPU memory ceiling in bytes, or 0
// when no ceiling is known.
//
// It is the TIGHTER (minimum) of the two nonzero ceilings GPUFacts carries, the
// Metal device's recommended maximum working set and the configured iogpu
// wired-memory limit; when only one is nonzero that one decides; when both are
// zero the answer is 0, meaning UNKNOWN. Two independent caps both bind, so the
// smaller one is the only honest answer — taking either in isolation would
// admit a pod the other one stops.
//
// It is NEVER mem_bytes. That fact is the host's total physical memory, which on
// Apple Silicon is shared with everything else running on the Mac; the proto
// names the wired limit as the binding constraint for a large model, and the
// model-level check against host memory is already made elsewhere
// (operator.ValidateFit) against the spec rather than against a slot budget.
//
// A 0 result is the modelled sentinel read HONESTLY: iogpu_wired_limit_bytes ==
// 0 means "no explicit limit is configured", never "unlimited", and a zero
// recommended working set means the value could not be read. Neither is headroom
// to hand out, so a 0 ceiling disables the cumulative fit check rather than
// admitting everything against a fabricated number — the refusal this file
// exists for is only as good as the number it compares against, and there is no
// number here.
//
// This is the ONE home of the ceiling rule. A consumer that needs the ceiling
// calls this; re-deriving it from the facts at a second site is how the
// advertiser and the admission check come to disagree.
func GPUCeilingBytes(f *runtimev1.GPUFacts) int64 {
	ws := clampToInt64(f.GetRecommendedMaxWorkingSetBytes())
	wired := clampToInt64(f.GetIogpuWiredLimitBytes())
	switch {
	case ws > 0 && wired > 0:
		return min(ws, wired)
	case ws > 0:
		return ws
	default:
		return wired // > 0, or 0 when neither fact is known
	}
}

// GPUSlots reports how many units of mlx.k3sm.io/gpu this node advertises, from
// its usable GPU memory ceiling: one slot per whole GPUSlotFloorBytes of
// ceiling, at least 1, at most MaxGPUSlots.
//
// An UNKNOWN ceiling (GPUCeilingBytes == 0) advertises exactly 1. That is the
// conservative answer and it is also the coherent one: with no ceiling the
// cumulative fit check at admission is disabled, so a second slot would be a
// second pod admitted against nothing at all.
//
// The slots are co-tenants, not devices. Apple Silicon has one integrated GPU
// and GPUFacts carries no device count because there is nothing to count; N
// slots means "this much memory holds N floor-sized workloads", not "N isolated
// accelerators". The same distinction DESIGN §5a draws for CPU applies here.
func GPUSlots(f *runtimev1.GPUFacts) int64 {
	ceiling := GPUCeilingBytes(f)
	if ceiling == 0 {
		return 1
	}
	return min(MaxGPUSlots, max(1, ceiling/GPUSlotFloorBytes))
}

// GPUFits reports whether a GPU pod wanting want bytes still fits under ceiling
// beside admitted bytes of already-admitted GPU pods, returning nil when it does
// and an ErrGPUMemoryOverCeiling-wrapping error naming all three numbers when it
// does not.
//
// A zero (unknown) ceiling admits everything: there is no number to refuse
// against, and refusing on an unknown would make every GPU pod on a node whose
// Metal working set could not be read unschedulable.
//
// The comparison is written as want ≤ ceiling-admitted rather than
// admitted+want ≤ ceiling so that a pathological admitted sum cannot overflow
// into a pass.
func GPUFits(ceiling, admitted, want int64) error {
	if ceiling <= 0 {
		return nil
	}
	if want <= ceiling-admitted {
		return nil
	}
	return fmt.Errorf("%w: want %s beside %s already admitted, ceiling %s",
		ErrGPUMemoryOverCeiling, humanBytes(want), humanBytes(admitted), humanBytes(ceiling))
}

// clampToInt64 converts a uint64 GPU fact to the int64 every byte count in this
// package and in the resource API is spelled in, saturating rather than wrapping
// negative. A fact above 2^63 bytes is not a machine that exists, but a wrapped
// negative ceiling would make GPUFits refuse every pod, so the impossible value
// is clamped to the largest representable one instead.
func clampToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// humanBytes renders a byte count the way a resource.Quantity is written, so a
// refusal compares its three numbers in the same notation the pod's memory limit
// was authored in.
func humanBytes(b int64) string {
	q := resource.NewQuantity(b, resource.BinarySI)
	return q.String()
}
