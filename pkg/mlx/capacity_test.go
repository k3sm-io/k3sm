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
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	gib  = int64(1) << 30
	half = gib / 2
)

// facts builds GPUFacts carrying only the two ceiling fields, in bytes. Every
// other field is left zero on purpose: the capacity policy must decide from the
// ceilings alone, and a row that passed only because mem_bytes happened to be
// set would be pinning a rule this package deliberately does not have.
func facts(workingSet, wired int64) *runtimev1.GPUFacts {
	return &runtimev1.GPUFacts{
		RecommendedMaxWorkingSetBytes: uint64(workingSet),
		IogpuWiredLimitBytes:          uint64(wired),
	}
}

// TestGPUCapacityPolicy is the gate for the node's GPU capacity policy: the
// usable ceiling read off GPUFacts, the slot count derived from it, and the
// cumulative memory fit an admitting node checks a new GPU pod against.
//
// Three properties are pinned, and each fails in a way a live cluster would not
// report:
//
//  1. THE TIGHTER CEILING WINS. The Metal recommended working set and the iogpu
//     wired limit are independent caps and both bind. Reading either alone
//     advertises slots the other one cannot hold, and the node then refuses pods
//     the scheduler already bound to it.
//
//  2. ZERO IS UNKNOWN, NOT UNLIMITED. Both ceiling fields carry a modelled
//     0 sentinel. Treating it as headroom would admit every pod against a
//     fabricated number; treating it as a ceiling of zero would refuse every
//     pod. It advertises one slot and disables the fit check instead.
//
//  3. THE CLAMP IS REAL. The slots share ONE integrated GPU, so a large-memory
//     Mac must not advertise a slot per floor-sized chunk of its ceiling.
//
// The whole policy is pure arithmetic over facts, so every row is hermetic —
// none of it depends on the GPU of the machine running the test, or on there
// being one.
func TestGPUCapacityPolicy(t *testing.T) {
	t.Parallel()

	t.Run("ceiling_and_slots", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name        string
			workingSet  int64
			wired       int64
			wantCeiling int64
			wantSlots   int64
		}{
			{
				// THE 0-SENTINEL on BOTH fields: no ceiling is known. One slot, and
				// GPUFits below admits everything against it.
				name: "both_zero_is_unknown", workingSet: 0, wired: 0,
				wantCeiling: 0, wantSlots: 1,
			},
			{
				// Only the working set is readable (no iogpu override configured —
				// the common Mac). It decides alone; the 0 must not win as a minimum.
				name: "wired_zero_working_set_decides", workingSet: 8 * gib, wired: 0,
				wantCeiling: 8 * gib, wantSlots: 2,
			},
			{
				// The mirror: a configured wired limit with no readable working set.
				name: "working_set_zero_wired_decides", workingSet: 0, wired: 4 * gib,
				wantCeiling: 4 * gib, wantSlots: 2,
			},
			{
				// BOTH NONZERO AND DISAGREEING, working set larger. The tighter one
				// binds, and the two orders are separate rows because a min() written
				// as a max() passes one of them.
				name: "disagreeing_wired_is_tighter", workingSet: 96 * gib, wired: 2 * gib,
				wantCeiling: 2 * gib, wantSlots: 1,
			},
			{
				name: "disagreeing_working_set_is_tighter", workingSet: 2 * gib, wired: 96 * gib,
				wantCeiling: 2 * gib, wantSlots: 1,
			},
			{
				// THE CLAMP: a ceiling that holds 256 floors still advertises 2.
				name: "huge_ceiling_clamps", workingSet: 384 * gib, wired: 384 * gib,
				wantCeiling: 384 * gib, wantSlots: MaxGPUSlots,
			},
			{
				// A ceiling BELOW one floor still advertises one slot: the node has a
				// usable GPU and refusing every pod on it is not the conservative
				// answer, it is an unusable node. The pod's own fit is what the
				// cumulative check below decides.
				name: "below_one_floor_still_advertises_one", workingSet: gib, wired: 0,
				wantCeiling: gib, wantSlots: 1,
			},
			{
				// EXACTLY two floors: the boundary the integer division decides, and
				// the one an off-by-one would answer 1 or 3 for.
				name: "exactly_two_floors", workingSet: 2 * GPUSlotFloorBytes, wired: 0,
				wantCeiling: 2 * GPUSlotFloorBytes, wantSlots: 2,
			},
			{
				// One byte short of the second floor is still one slot.
				name: "one_byte_short_of_two_floors", workingSet: 2*GPUSlotFloorBytes - 1, wired: 0,
				wantCeiling: 2*GPUSlotFloorBytes - 1, wantSlots: 1,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				f := facts(tc.workingSet, tc.wired)
				if got := GPUCeilingBytes(f); got != tc.wantCeiling {
					t.Errorf("GPUCeilingBytes() = %d, want %d", got, tc.wantCeiling)
				}
				if got := GPUSlots(f); got != tc.wantSlots {
					t.Errorf("GPUSlots() = %d, want %d", got, tc.wantSlots)
				}
			})
		}
	})

	// mem_bytes is NEVER the ceiling. It is the host's total physical memory,
	// shared with everything else on the Mac, and the proto names the wired limit
	// as the binding constraint instead. A row here because reading it would look
	// right on any real Mac — its value is always the largest of the three.
	t.Run("host_memory_is_never_the_ceiling", func(t *testing.T) {
		t.Parallel()
		f := facts(0, 0)
		f.MemBytes = uint64(128 * gib)
		f.MetalAvailable = true
		if got := GPUCeilingBytes(f); got != 0 {
			t.Errorf("GPUCeilingBytes() = %d, want 0 — mem_bytes is not a GPU ceiling", got)
		}
		if got := GPUSlots(f); got != 1 {
			t.Errorf("GPUSlots() = %d, want 1", got)
		}
	})

	// nil facts (a daemon predating them) must not panic, and must read as the
	// unknown ceiling rather than as a host with none.
	t.Run("nil_facts", func(t *testing.T) {
		t.Parallel()
		if got := GPUCeilingBytes(nil); got != 0 {
			t.Errorf("GPUCeilingBytes(nil) = %d, want 0", got)
		}
		if got := GPUSlots(nil); got != 1 {
			t.Errorf("GPUSlots(nil) = %d, want 1", got)
		}
	})

	t.Run("cumulative_fit", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			name     string
			ceiling  int64
			admitted int64
			want     int64
			wantErr  bool
			// wantUnbounded picks WHICH refusal: the unmeasurable pod carries a
			// different sentinel from the too-big one, because the operator's fix
			// differs in kind.
			wantUnbounded bool
		}{
			{
				// THE REFUSAL this whole file exists for: 3 GiB is already admitted
				// under a 4 GiB ceiling, and the next pod wants 1.5 GiB.
				name: "over_ceiling_refused", ceiling: 4 * gib, admitted: 3 * gib, want: 3 * half,
				wantErr: true,
			},
			{
				// The same node admits a pod that DOES fit. Without this row the
				// check degrades into a refuse-everything gate, which is worse than
				// the overcommit it replaces.
				name: "under_ceiling_admitted", ceiling: 4 * gib, admitted: 3 * gib, want: half,
			},
			{
				// EXACTLY at the ceiling fits: the budget is a ceiling, not a strict
				// bound, and an off-by-one here refuses the pod a 2-slot node was
				// sized for.
				name: "exactly_at_the_ceiling_admitted", ceiling: 4 * gib, admitted: 3 * gib, want: gib,
			},
			{
				// One byte over does not.
				name: "one_byte_over_refused", ceiling: 4 * gib, admitted: 3 * gib, want: gib + 1,
				wantErr: true,
			},
			{
				// The FIRST pod on an empty node, sized to the whole ceiling.
				name: "first_pod_takes_the_whole_ceiling", ceiling: 4 * gib, admitted: 0, want: 4 * gib,
			},
			{
				// AN UNKNOWN CEILING ADMITS EVERYTHING. There is no number to refuse
				// against, and refusing would make every GPU pod on a node whose
				// Metal working set could not be read unschedulable.
				name: "unknown_ceiling_admits", ceiling: 0, admitted: 64 * gib, want: 64 * gib,
			},
			{
				// A POD WITH NO ENFORCEABLE MEMORY LIMIT IS REFUSED on a node that
				// knows its ceiling. podMemoryLimitBytes measures it as 0, and
				// admitting a 0 is the one outcome that defeats this check for
				// good: the pod contributes nothing to the admitted total for its
				// whole life, so every later pod is fit against a node that looks
				// emptier than it is.
				name: "unbounded_want_refused_under_a_known_ceiling", ceiling: 4 * gib, admitted: 0, want: 0,
				wantErr: true, wantUnbounded: true,
			},
			{
				// The SAME pod on a node with no known ceiling is admitted: there is
				// no budget for it to defeat, and refusing would turn an unreadable
				// fact into an unschedulable node.
				name: "unbounded_want_admitted_under_an_unknown_ceiling", ceiling: 0, admitted: 0, want: 0,
			},
			{
				// An already-overcommitted node (a smaller ceiling after a daemon
				// restart) refuses the next pod rather than wrapping negative.
				name: "already_over_refuses", ceiling: 4 * gib, admitted: 6 * gib, want: 1,
				wantErr: true,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				err := GPUFits(tc.ceiling, tc.admitted, tc.want)
				if tc.wantErr {
					if err == nil {
						t.Fatalf("GPUFits(%d, %d, %d) = nil, want a refusal", tc.ceiling, tc.admitted, tc.want)
					}
					if tc.wantUnbounded {
						if !errors.Is(err, ErrGPUMemoryUnbounded) {
							t.Errorf("GPUFits error %v does not wrap ErrGPUMemoryUnbounded; the caller cannot tell an unmeasurable pod from one that is merely too big", err)
						}
						if errors.Is(err, ErrGPUMemoryOverCeiling) {
							t.Errorf("GPUFits error %v also wraps ErrGPUMemoryOverCeiling; the two refusals have different fixes and must stay distinguishable", err)
						}
						return
					}
					if !errors.Is(err, ErrGPUMemoryOverCeiling) {
						t.Errorf("GPUFits error %v does not wrap ErrGPUMemoryOverCeiling; a caller cannot tell it from a transient failure", err)
					}
					// All three numbers, or the operator cannot tell which pod to
					// shrink and by how much.
					for _, want := range []string{humanBytes(tc.want), humanBytes(tc.admitted), humanBytes(tc.ceiling)} {
						if !strings.Contains(err.Error(), want) {
							t.Errorf("GPUFits error %q does not name %q", err, want)
						}
					}
					return
				}
				if err != nil {
					t.Fatalf("GPUFits(%d, %d, %d) = %v, want the pod admitted", tc.ceiling, tc.admitted, tc.want, err)
				}
			})
		}
	})

	// The floor is the number the worker pod template requests, so a node
	// advertising MaxGPUSlots has been sized for that many of them. The
	// multiplication is pinned rather than the constant's value alone: a floor
	// raised without re-checking the clamp would advertise slots the ceiling it
	// was derived from cannot hold.
	t.Run("max_slots_fit_under_their_own_ceiling", func(t *testing.T) {
		t.Parallel()
		ceiling := MaxGPUSlots * GPUSlotFloorBytes
		if got := GPUSlots(facts(ceiling, 0)); got != MaxGPUSlots {
			t.Fatalf("GPUSlots() = %d, want %d at exactly %d slot floors", got, MaxGPUSlots, MaxGPUSlots)
		}
		var admitted int64
		for i := 0; i < MaxGPUSlots; i++ {
			if err := GPUFits(ceiling, admitted, GPUSlotFloorBytes); err != nil {
				t.Fatalf("slot %d of %d does not fit its own ceiling: %v", i+1, MaxGPUSlots, err)
			}
			admitted += GPUSlotFloorBytes
		}
		if err := GPUFits(ceiling, admitted, GPUSlotFloorBytes); err == nil {
			t.Error("a slot past MaxGPUSlots fits; the advertised count and the fit check disagree")
		}
	})
}
