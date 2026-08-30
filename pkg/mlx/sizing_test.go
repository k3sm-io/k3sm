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
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"
)

// updateSizingGolden regenerates the sizing golden instead of comparing against
// it:
//
//	go test ./pkg/mlx/ -run TestEngineArgsPinContextFromMemoryFormula -update
//
// It exists so a DELIBERATE change to the formula produces a reviewable diff,
// rather than a reviewer hand-editing the golden to match whatever the code now
// computes.
var updateSizingGolden = flag.Bool("update", false, "rewrite the sizing golden from the current formula")

// sizingCases are the spec.memory values the golden pins. They span the shape of
// the curve on purpose: the floor a spec may sit at, the two Mac memory
// configurations M8 actually targets, and a value large enough that the derived
// context SATURATES at maxContextTokens.
var sizingCases = []string{"2Gi", "8Gi", "16Gi", "24Gi", "64Gi", "128Gi"}

// TestEngineArgsPinContextFromMemoryFormula is the sizing contract: spec.memory
// determines the engine's context and concurrency pins, those pins ship in the
// rendered argv beside the required --continuous-batching flag, and the caller's
// own args still come last.
//
// What each part of it is defending against:
//
//   - The pins exist because the KV cache GROWS per generated token
//     (findings-s3.md §2, ~0.15 MB/token) and nothing under k3sm's sampler
//     catches the overrun (§4) — an unpinned context is a deterministic
//     mid-generation kill, not a risk.
//   - --continuous-batching exists because without it vllm-mlx 0.4.1 serves one
//     request and 503s the rest (findings-s5.md §2) while /health and the
//     readiness probe both stay green — no functional test notices.
//   - Monotonicity exists because a knob where more memory can buy less context
//     cannot be reasoned about by the operator turning it.
func TestEngineArgsPinContextFromMemoryFormula(t *testing.T) {
	t.Run("derived_sizing_and_argv_match_the_golden", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("# Engine sizing derived from spec.memory, and the argv it renders.\n")
		b.WriteString("# Regenerate: go test ./pkg/mlx/ -run TestEngineArgsPinContextFromMemoryFormula -update\n")
		b.WriteString("# Then REVIEW THE DIFF: every number here bounds a pod's runtime memory growth,\n")
		b.WriteString("# and a context that grew without spec.memory growing is a SIGKILL on a node.\n")
		for _, mem := range sizingCases {
			m := newModel()
			m.Spec.Memory = resource.MustParse(mem)
			objs, err := Render(m, testOptions())
			if err != nil {
				t.Fatalf("Render(memory=%s) error = %v, want nil", mem, err)
			}
			s, err := DeriveSizing(m.Spec.Memory)
			if err != nil {
				t.Fatalf("DeriveSizing(%s) error = %v, want nil", mem, err)
			}
			fmt.Fprintf(&b, "\nmemory=%s context=%d sequences=%d kvCacheBytes=%d\n",
				mem, s.MaxContextTokens, s.MaxSequences, s.KVCacheBytes)
			fmt.Fprintf(&b, "args=%s\n", strings.Join(objs.StatefulSet.Spec.Template.Spec.Containers[0].Args, " "))
		}
		got := b.String()

		golden := filepath.Join("testdata", "engine-args.golden")
		if *updateSizingGolden {
			if err := os.MkdirAll("testdata", 0o755); err != nil {
				t.Fatalf("mkdir testdata: %v", err)
			}
			if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
				t.Fatalf("write golden %s: %v", golden, err)
			}
			t.Logf("golden %s regenerated; REVIEW THE DIFF before committing", golden)
			return
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("read golden %s: %v (regenerate with -update)", golden, err)
		}
		if string(want) != got {
			t.Errorf("derived sizing differs from %s (regenerate with -update if the change is deliberate)\n--- got ---\n%s\n--- want ---\n%s",
				golden, got, want)
		}
	})

	t.Run("context_never_shrinks_as_memory_grows", func(t *testing.T) {
		// Includes the saturation region on purpose: past maxContextTokens the
		// curve is flat, and flat is what "no smaller context" permits. A strict
		// increase would be the wrong assertion — it would forbid the cap that
		// keeps --max-kv-size at a ceiling the weights can still be funded under.
		mems := []string{"2Gi", "3Gi", "4Gi", "6Gi", "8Gi", "12Gi", "16Gi", "24Gi", "32Gi", "48Gi", "64Gi", "96Gi", "128Gi", "192Gi", "512Gi"}
		prev := int64(-1)
		prevMem := ""
		for _, mem := range mems {
			s, err := DeriveSizing(resource.MustParse(mem))
			if err != nil {
				t.Fatalf("DeriveSizing(%s) error = %v, want nil", mem, err)
			}
			if s.MaxContextTokens < prev {
				t.Errorf("context for %s = %d, but %s already funded %d — the formula is NOT monotone: raising spec.memory bought a SMALLER context",
					mem, s.MaxContextTokens, prevMem, prev)
			}
			if s.MaxContextTokens > maxContextTokens {
				t.Errorf("context for %s = %d, want at most %d — a pin above the model's trained window makes the engine refuse to start",
					mem, s.MaxContextTokens, maxContextTokens)
			}
			if s.MaxContextTokens%contextGranularityTokens != 0 {
				t.Errorf("context for %s = %d, want a multiple of %d", mem, s.MaxContextTokens, contextGranularityTokens)
			}
			prev, prevMem = s.MaxContextTokens, mem
		}
		if prev != maxContextTokens {
			t.Errorf("context at 512Gi = %d, want it to saturate at %d — an unbounded curve pins a context no model accepts", prev, maxContextTokens)
		}
	})

	t.Run("continuous_batching_is_in_every_rendered_argv", func(t *testing.T) {
		// The S5 binding. Its absence is invisible to every other signal: the pod
		// is Running, /health answers, readiness passes, and 7 of 8 concurrent
		// clients get HTTP 503 with waiters=0.
		for _, mem := range sizingCases {
			for _, callerArgs := range [][]string{nil, {"--max-tokens", "512"}, {"--max-kv-size", "4096"}} {
				m := newModel()
				m.Spec.Memory = resource.MustParse(mem)
				m.Spec.Runtime.Args = callerArgs
				objs, err := Render(m, testOptions())
				if err != nil {
					t.Fatalf("Render(memory=%s, args=%v) error = %v, want nil", mem, callerArgs, err)
				}
				args := objs.StatefulSet.Spec.Template.Spec.Containers[0].Args
				if !slices.Contains(args, argContinuousBatching) {
					t.Errorf("argv for memory=%s callerArgs=%v = %v, want it to contain %q — without it the engine serves ONE request and 503s every other concurrent client, with a green readiness probe",
						mem, callerArgs, args, argContinuousBatching)
				}
			}
		}
	})

	t.Run("the_pins_carry_the_derived_values", func(t *testing.T) {
		m := newModel()
		m.Spec.Memory = resource.MustParse("24Gi")
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		s, err := DeriveSizing(m.Spec.Memory)
		if err != nil {
			t.Fatalf("DeriveSizing() error = %v, want nil", err)
		}
		args := objs.StatefulSet.Spec.Template.Spec.Containers[0].Args
		for _, want := range [][2]string{
			{argMaxKVSize, fmt.Sprint(s.MaxContextTokens)},
			{argMaxNumSeqs, fmt.Sprint(s.MaxSequences)},
		} {
			i := slices.Index(args, want[0])
			if i < 0 {
				t.Fatalf("argv = %v, want it to pin %s", args, want[0])
			}
			if i+1 >= len(args) || args[i+1] != want[1] {
				t.Errorf("argv %s = %v, want the derived value %q", want[0], args[i:min(i+2, len(args))], want[1])
			}
		}
	})

	t.Run("caller_args_come_after_the_pins", func(t *testing.T) {
		// The override seam: argparse takes the LAST occurrence, so a caller who
		// restates --max-kv-size wins. Reversed, the render would silently
		// clobber the operator's value while appearing to accept it.
		m := newModel()
		m.Spec.Runtime.Args = []string{"--max-kv-size", "4096", "--trust-remote-code"}
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		args := objs.StatefulSet.Spec.Template.Spec.Containers[0].Args
		if got := args[len(args)-len(m.Spec.Runtime.Args):]; !reflect.DeepEqual(got, m.Spec.Runtime.Args) {
			t.Fatalf("trailing argv = %v, want the caller's spec.runtime.args %v LAST", got, m.Spec.Runtime.Args)
		}
		lastPin := slices.Index(args, argContinuousBatching)
		firstCaller := len(args) - len(m.Spec.Runtime.Args)
		if lastPin > firstCaller {
			t.Errorf("argv = %v, want every derived pin BEFORE the caller's args (pin at %d, caller args from %d)", args, lastPin, firstCaller)
		}
	})

	t.Run("memory_below_the_minimum_is_a_typed_error", func(t *testing.T) {
		// The weights plus a minimum context do not fit, so there is nothing to
		// render. Returning a tiny context instead would produce a pod that
		// starts, serves truncated conversations, and looks like an engine bug.
		for _, mem := range []string{"1Gi", "512Mi", "600Mi"} {
			if _, err := DeriveSizing(resource.MustParse(mem)); !errors.Is(err, ErrMemoryTooSmall) {
				t.Errorf("DeriveSizing(%s) error = %v, want ErrMemoryTooSmall", mem, err)
			}
			m := newModel()
			m.Spec.Memory = resource.MustParse(mem)
			objs, err := Render(m, testOptions())
			if !errors.Is(err, ErrMemoryTooSmall) {
				t.Errorf("Render(memory=%s) error = %v, want it to wrap ErrMemoryTooSmall", mem, err)
			}
			if objs != nil {
				t.Errorf("Render(memory=%s) returned objects alongside an error; a half-rendered model looks like progress", mem)
			}
		}
		if _, err := DeriveSizing(resource.MustParse("0")); !errors.Is(err, ErrNoMemory) {
			t.Errorf("DeriveSizing(0) error = %v, want ErrNoMemory — an unstated memory is a different operator mistake than an under-stated one", err)
		}
		if !errors.Is(fmt.Errorf("wrapped: %w", ErrMemoryTooSmall), ErrMemoryTooSmall) || errors.Is(ErrMemoryTooSmall, ErrNoMemory) {
			t.Error("ErrMemoryTooSmall and ErrNoMemory must be distinguishable sentinels")
		}
	})

	t.Run("the_kv_pin_fits_inside_the_memory_it_was_derived_from", func(t *testing.T) {
		// The whole point of the formula: what the pins permit at FULL occupancy
		// must still leave the weights, the scratch and the transient headroom
		// inside spec.memory. If this fails the pins are decoration.
		for _, mem := range sizingCases {
			q := resource.MustParse(mem)
			s, err := DeriveSizing(q)
			if err != nil {
				t.Fatalf("DeriveSizing(%s) error = %v, want nil", mem, err)
			}
			if got, want := s.KVCacheBytes, s.MaxContextTokens*s.MaxSequences*kvBytesPerToken; got != want {
				t.Errorf("KVCacheBytes for %s = %d, want %d (context x sequences x %d bytes/token)", mem, got, want, kvBytesPerToken)
			}
			total := q.Value()
			headroom := total * headroomPercent / 100
			budget := (total - compileScratchBytes - headroom) * kvSharePercent / 100
			if s.KVCacheBytes > budget {
				t.Errorf("KV pin for %s costs %d bytes at full occupancy, above the %d-byte share the formula grants it — the remainder is the weights",
					mem, s.KVCacheBytes, budget)
			}
			if s.KVCacheBytes+compileScratchBytes+headroom > total {
				t.Errorf("KV pin + scratch + headroom for %s = %d bytes, above spec.memory %d", mem, s.KVCacheBytes+compileScratchBytes+headroom, total)
			}
		}
	})

	t.Run("formula_constants_document_their_measured_basis", func(t *testing.T) {
		// A sizing constant without its measurement is a guess, and a guess here
		// is someone's pod being killed mid-generation. The check is mechanical so
		// a future constant cannot land undocumented.
		measured := map[string]bool{
			"kvBytesPerToken":     true,
			"compileScratchBytes": true,
			"headroomPercent":     true,
			"kvSharePercent":      true,
			"defaultMaxSequences": true,
		}
		required := []string{"minContextTokens", "maxContextTokens", "contextGranularityTokens"}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "sizing.go", nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse sizing.go: %v", err)
		}
		docs := map[string]string{}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok || vs.Doc == nil {
					continue
				}
				for _, n := range vs.Names {
					docs[n.Name] = vs.Doc.Text()
				}
			}
		}
		for name := range measured {
			doc := docs[name]
			if len(doc) < 120 {
				t.Errorf("const %s has %d characters of doc comment, want a documented basis (>=120)", name, len(doc))
			}
			if !strings.Contains(doc, "S3") && !strings.Contains(doc, "S5") {
				t.Errorf("const %s does not cite the spike that measured it (S3/S5, hack/spike/m8/findings-*.md)", name)
			}
		}
		for _, name := range required {
			if len(docs[name]) < 120 {
				t.Errorf("const %s has %d characters of doc comment, want its rationale stated at the declaration", name, len(docs[name]))
			}
		}
	})
}
