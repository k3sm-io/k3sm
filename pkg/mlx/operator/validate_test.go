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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	gib = int64(1) << 30
)

// facts builds a plausible healthy Apple Silicon GPU report, which each case
// then perturbs in exactly one dimension. Building every case from scratch would
// make it possible for a case to pass because of a field it did not mean to set.
func facts(mutate ...func(*runtimev1.GPUFacts)) *runtimev1.GPUFacts {
	f := &runtimev1.GPUFacts{
		MetalAvailable:                true,
		SandboxGpuSupported:           true,
		ChipBrand:                     "Apple M4 Max",
		ChipFamily:                    "M4",
		MemBytes:                      uint64(64 * gib),
		RecommendedMaxWorkingSetBytes: uint64(48 * gib),
		IogpuWiredLimitBytes:          0, // the sentinel: no explicit override configured
	}
	for _, m := range mutate {
		m(f)
	}
	return f
}

// TestValidateFit is the M8.5-a1 pre-render validation table: what the operator
// decides about a spec BEFORE it renders or applies anything.
//
// Every FitFailed row below is a spec that, applied anyway, would produce a pod
// that dies at load time and restarts into a download it starts from zero — a
// crash loop whose only visible symptom is a model that never becomes ready. The
// entire value of this check is turning that into one legible condition.
func TestValidateFit(t *testing.T) {
	cases := []struct {
		name       string
		memory     string
		facts      *runtimev1.GPUFacts
		wantLevel  FitLevel
		wantReason string
	}{
		{
			name:      "no facts skips the check rather than refusing every model",
			memory:    "1Ti",
			facts:     nil,
			wantLevel: FitOK,
		},
		{
			name:      "a spec well inside every ceiling fits",
			memory:    "24Gi",
			facts:     facts(),
			wantLevel: FitOK,
		},
		{
			name:      "a spec exactly at the recommended working set fits",
			memory:    "48Gi",
			facts:     facts(),
			wantLevel: FitOK,
		},
		{
			name:       "no metal device fails regardless of the memory asked for",
			memory:     "1Gi",
			facts:      facts(func(f *runtimev1.GPUFacts) { f.MetalAvailable = false }),
			wantLevel:  FitFailed,
			wantReason: ReasonNoGPU,
		},
		{
			name:       "a metal device the sandbox backend cannot grant fails",
			memory:     "1Gi",
			facts:      facts(func(f *runtimev1.GPUFacts) { f.SandboxGpuSupported = false }),
			wantLevel:  FitFailed,
			wantReason: ReasonGPUUnsupported,
		},
		{
			name:   "more memory than the host physically has fails on the outermost ceiling",
			memory: "128Gi",
			// The working set is raised past the request so the HOST ceiling is
			// the only one violated; otherwise this row could pass on the wrong rule.
			facts: facts(func(f *runtimev1.GPUFacts) {
				f.RecommendedMaxWorkingSetBytes = uint64(256 * gib)
			}),
			wantLevel:  FitFailed,
			wantReason: ReasonMemoryExceedsHostMemory,
		},
		{
			name:       "more memory than metal recommends as a working set fails",
			memory:     "56Gi",
			facts:      facts(),
			wantLevel:  FitFailed,
			wantReason: ReasonMemoryExceedsWorkingSet,
		},
		{
			name:   "more memory than an EXPLICITLY configured wired limit fails",
			memory: "40Gi",
			facts: facts(func(f *runtimev1.GPUFacts) {
				f.IogpuWiredLimitBytes = uint64(32 * gib)
			}),
			wantLevel:  FitFailed,
			wantReason: ReasonMemoryExceedsWiredLimit,
		},
		{
			name:   "a zero wired limit is the no-override sentinel, not a ceiling of zero",
			memory: "24Gi",
			facts: facts(func(f *runtimev1.GPUFacts) {
				f.IogpuWiredLimitBytes = 0
			}),
			wantLevel: FitOK,
		},
		{
			name:   "a metal device reporting no working set degrades rather than failing",
			memory: "8Gi",
			facts: facts(func(f *runtimev1.GPUFacts) {
				f.RecommendedMaxWorkingSetBytes = 0
			}),
			wantLevel:  FitDegraded,
			wantReason: ReasonGPUSizingUnknown,
		},
		{
			name:   "a host reporting no memory at all does not fail on a ceiling of zero",
			memory: "8Gi",
			facts: facts(func(f *runtimev1.GPUFacts) {
				f.MemBytes = 0
			}),
			wantLevel: FitOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateFit(resource.MustParse(tc.memory), tc.facts)
			if got.Level != tc.wantLevel {
				t.Fatalf("level = %v (%s: %s), want %v", got.Level, got.Reason, got.Message, tc.wantLevel)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if (tc.wantLevel != FitOK) != got.Blocks() {
				t.Errorf("Blocks() = %v for level %v", got.Blocks(), got.Level)
			}
			if tc.wantLevel == FitOK {
				return
			}
			if strings.TrimSpace(got.Message) == "" {
				t.Error("a blocking verdict carries no message; the condition would say nothing actionable")
			}
		})
	}
}

// TestValidateFitMessagesNameBothNumbers pins that a memory refusal says what it
// compared against.
//
// "spec.memory is too large" sends the reader to the node object to guess which
// of three ceilings was hit and what it is. The number is the actionable part —
// it is what the user edits the spec to.
func TestValidateFitMessagesNameBothNumbers(t *testing.T) {
	cases := []struct {
		name    string
		memory  string
		facts   *runtimev1.GPUFacts
		wantSub []string
	}{
		{
			name:    "working set",
			memory:  "56Gi",
			facts:   facts(),
			wantSub: []string{"56Gi", "48Gi"},
		},
		{
			name:    "wired limit",
			memory:  "40Gi",
			facts:   facts(func(f *runtimev1.GPUFacts) { f.IogpuWiredLimitBytes = uint64(32 * gib) }),
			wantSub: []string{"40Gi", "32Gi"},
		},
		{
			name:    "host memory",
			memory:  "128Gi",
			facts:   facts(func(f *runtimev1.GPUFacts) { f.RecommendedMaxWorkingSetBytes = uint64(256 * gib) }),
			wantSub: []string{"128Gi", "64Gi"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := ValidateFit(resource.MustParse(tc.memory), tc.facts).Message
			for _, want := range tc.wantSub {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q does not name %q", msg, want)
				}
			}
		})
	}
}

// TestValidateFitIsPure asserts the check does not mutate the facts it is handed.
// The facts come from a cached probe result shared with the node-labeling path;
// a validator that scribbled on them would corrupt what that path advertises.
func TestValidateFitIsPure(t *testing.T) {
	f := facts()
	// A proto message carries a mutex, so it is snapshotted field by field rather
	// than copied wholesale.
	before := facts()
	ValidateFit(resource.MustParse("999Gi"), f)
	if f.GetMetalAvailable() != before.GetMetalAvailable() ||
		f.GetSandboxGpuSupported() != before.GetSandboxGpuSupported() ||
		f.GetMemBytes() != before.GetMemBytes() ||
		f.GetRecommendedMaxWorkingSetBytes() != before.GetRecommendedMaxWorkingSetBytes() ||
		f.GetIogpuWiredLimitBytes() != before.GetIogpuWiredLimitBytes() {
		t.Error("ValidateFit mutated the GPU facts it was given")
	}
}

// TestStaticGPUSource covers the injection seam production wires and tests fake.
func TestStaticGPUSource(t *testing.T) {
	f := facts()
	if got := StaticGPU(f).GPUFacts(t.Context()); got != f {
		t.Errorf("StaticGPU returned %v, want the facts it was built with", got)
	}
	if got := StaticGPU(nil).GPUFacts(t.Context()); got != nil {
		t.Errorf("StaticGPU(nil) returned %v, want nil", got)
	}
}
