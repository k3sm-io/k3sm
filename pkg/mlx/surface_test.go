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
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/api/resource"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
)

// measuredSurface is the `vllm_mlx.cli serve` command line as MEASURED on the rig
// against the pinned engine (0.4.1, the version hack/images/mlx-serve/build.sh
// installs), byte-for-byte reproduced host-side: the key is the option, the value
// says whether it consumes the following token.
//
// It is a TABLE CONSTANT, and the membership check below is EXACT. That is the
// whole lesson of this test: `--model` is an unambiguous abbreviation of
// `--models-config`, and Python's argparse abbreviates by default, so rendering
// `--model <repo>` did not fail — it SILENTLY bound the repository reference to
// the models-config option and served nothing anyone asked for. A prefix-tolerant
// check here would reproduce that bug in the test that exists to catch it.
//
// The model itself is a POSITIONAL on this surface; there is no option that names
// it. --host and --port are supplied by the image ENTRYPOINT and re-supplied by
// the render (the spec's port has to win over the image's default).
var measuredSurface = map[string]bool{
	"--models-config":       true,
	"--max-num-seqs":        true,
	"--max-tokens":          true,
	"--max-kv-size":         true,
	"--continuous-batching": false,
	"--port":                true,
	"--host":                true,
}

// absentFlags are the options the render used to emit and this engine does NOT
// have. Each failed differently, which is why the set is pinned by name rather
// than left to the surface check:
//
//   - --model      SILENTLY prefix-matched into --models-config (above).
//   - --revision   argparse exit 2, so the pod CrashLoopBackOffs.
//   - --max-model-len  argparse exit 2, same.
//   - --quantization   argparse exit 2, same.
var absentFlags = []string{"--model", "--revision", "--quantization", "--max-model-len"}

// scanEngineArgv walks tokens the way argparse would with the measured surface
// and returns the positionals, or the first violation. An unknown option is an
// error even when it is a prefix of a known one — see measuredSurface.
func scanEngineArgv(tokens []string) ([]string, error) {
	var positionals []string
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if !strings.HasPrefix(tok, "-") {
			positionals = append(positionals, tok)
			continue
		}
		takesValue, ok := measuredSurface[tok]
		if !ok {
			return nil, fmt.Errorf("option %q (position %d) is not in the measured vllm_mlx.cli serve surface", tok, i)
		}
		if !takesValue {
			continue
		}
		if i+1 >= len(tokens) {
			return nil, fmt.Errorf("option %q (position %d) takes a value and has none", tok, i)
		}
		if strings.HasPrefix(tokens[i+1], "--") {
			return nil, fmt.Errorf("option %q (position %d) takes a value but is followed by %q", tok, i, tokens[i+1])
		}
		i++
	}
	return positionals, nil
}

// entrypointArgv reads the serving image's ENTRYPOINT out of the build script and
// expands the shell variables it interpolates, so the composed argv this test
// reasons about is the one the image actually runs. Restating it as a literal
// here would let the two drift silently, which is the same class of bug the
// surface table exists to prevent.
func entrypointArgv(t *testing.T) []string {
	t.Helper()
	path := filepath.Join("..", "..", "hack", "images", "mlx-serve", "build.sh")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	src := string(b)

	line := regexp.MustCompile(`(?m)^ENTRYPOINT \[(.*)\]$`).FindStringSubmatch(src)
	if line == nil {
		t.Fatalf("%s has no ENTRYPOINT line; the image's serving command moved and this test must follow it", path)
	}
	assign := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^([A-Z_]+)="([^"]*)"$`).FindAllStringSubmatch(src, -1) {
		assign[m[1]] = m[2]
	}
	varRE := regexp.MustCompile(`\$([A-Z_]+)`)

	var argv []string
	for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(line[1], -1) {
		tok := varRE.ReplaceAllStringFunc(m[1], func(ref string) string {
			v, ok := assign[ref[1:]]
			if !ok {
				t.Fatalf("%s ENTRYPOINT interpolates %s, which the script does not assign", path, ref)
			}
			return v
		})
		argv = append(argv, tok)
	}
	if !slices.Contains(argv, "serve") {
		t.Fatalf("image ENTRYPOINT %v does not run the serve subcommand", argv)
	}
	return argv
}

// splitRendered returns the arguments Render produced for m, split into the part
// this package OWNS and the caller's own spec.runtime.args, which ride last and
// are deliberately unvalidated (the override seam).
func splitRendered(t *testing.T, m *mlxv1alpha1.MLXModel) (rendered, caller []string) {
	t.Helper()
	objs, err := Render(m, testOptions())
	if err != nil {
		t.Fatalf("Render() error = %v, want nil", err)
	}
	args := objs.StatefulSet.Spec.Template.Spec.Containers[0].Args
	n := len(args) - len(m.Spec.Runtime.Args)
	return args[:n], args[n:]
}

// surfaceCases are the spec shapes whose argv must satisfy the measured surface.
func surfaceCases() []struct {
	name  string
	model *mlxv1alpha1.MLXModel
} {
	pinned := newModel
	unpinned := func() *mlxv1alpha1.MLXModel {
		m := pinned()
		m.Spec.Revision = ""
		return m
	}
	return []struct {
		name  string
		model *mlxv1alpha1.MLXModel
	}{
		{"pinned_revision_with_cache", pinned()},
		{"unpinned_with_cache", unpinned()},
		{"unpinned_without_cache", func() *mlxv1alpha1.MLXModel { m := unpinned(); m.Spec.Cache = nil; return m }()},
		{"no_caller_args", func() *mlxv1alpha1.MLXModel { m := pinned(); m.Spec.Runtime.Args = nil; return m }()},
		{"smallest_fundable_memory", func() *mlxv1alpha1.MLXModel {
			m := pinned()
			m.Spec.Memory = resource.MustParse("2Gi")
			return m
		}()},
		{"saturating_memory", func() *mlxv1alpha1.MLXModel {
			m := pinned()
			m.Spec.Memory = resource.MustParse("128Gi")
			return m
		}()},
	}
}

// TestEngineArgsMatchTheMeasuredSurface is the argv contract: every option this
// package renders exists on the engine that receives it, the model arrives as the
// positional that engine expects, and a pinned revision — which has no option at
// all on this surface — is expressed as the deterministic snapshot path under the
// HF_HOME the render itself sets.
//
// It exists because the previous argv was validated against an ASSUMPTION rather
// than a measurement, and the assumption's own stated safety net ("a renamed flag
// fails loudly") is false: argparse's default abbreviation made the most important
// option of all bind silently to the wrong destination.
func TestEngineArgsMatchTheMeasuredSurface(t *testing.T) {
	t.Run("every_rendered_option_is_in_the_measured_surface", func(t *testing.T) {
		for _, tc := range surfaceCases() {
			t.Run(tc.name, func(t *testing.T) {
				rendered, _ := splitRendered(t, tc.model)
				positionals, err := scanEngineArgv(rendered)
				if err != nil {
					t.Fatalf("rendered argv %v: %v — the engine either rejects this at start or binds it to the wrong option", rendered, err)
				}
				if len(positionals) != 1 {
					t.Fatalf("rendered argv %v has %d positionals %v, want exactly 1 (the model)", rendered, len(positionals), positionals)
				}
				if rendered[0] != positionals[0] {
					t.Errorf("rendered argv %v leads with %q, want the model positional %q first", rendered, rendered[0], positionals[0])
				}
			})
		}
	})

	t.Run("the_absent_options_are_never_rendered", func(t *testing.T) {
		for _, tc := range surfaceCases() {
			rendered, _ := splitRendered(t, tc.model)
			for _, bad := range absentFlags {
				if slices.Contains(rendered, bad) {
					t.Errorf("%s: rendered argv %v carries %q, which vllm-mlx 0.4.1 does not have", tc.name, rendered, bad)
				}
			}
		}
	})

	t.Run("the_surface_check_is_exact_not_prefix_tolerant", func(t *testing.T) {
		// Non-vacuity, and the silent-prefix-match lesson in one place: the scan
		// must reject every option the engine rejects, INCLUDING the one that is a
		// unique abbreviation of an accepted option.
		good := []string{"mlx-community/Qwen3-0.6B-4bit", "--port", "8000", "--max-kv-size", "4096", "--max-num-seqs", "4", "--continuous-batching"}
		if _, err := scanEngineArgv(good); err != nil {
			t.Fatalf("scanEngineArgv(%v) error = %v, want nil — the check rejects an argv the engine accepts", good, err)
		}
		for _, bad := range absentFlags {
			argv := append(append([]string{}, good...), bad, "x")
			if _, err := scanEngineArgv(argv); err == nil {
				t.Errorf("scanEngineArgv accepted %q, which vllm-mlx 0.4.1 does not have — the surface check is vacuous", bad)
			}
		}
		if _, ok := measuredSurface["--models-config"]; !ok {
			t.Fatal("--models-config is missing from the measured surface; the prefix case below proves nothing without it")
		}
		if _, err := scanEngineArgv([]string{"--model", "x"}); err == nil {
			t.Error("scanEngineArgv accepted --model as a prefix of --models-config; argparse would bind it silently and this check must not")
		}
	})

	t.Run("the_model_is_the_one_positional_after_serve", func(t *testing.T) {
		entry := entrypointArgv(t)
		serve := slices.Index(entry, "serve")
		for _, tc := range surfaceCases() {
			t.Run(tc.name, func(t *testing.T) {
				rendered, caller := splitRendered(t, tc.model)
				argv := append(append(append([]string{}, entry[serve+1:]...), rendered...), caller...)
				positionals, err := scanEngineArgv(argv)
				if err != nil {
					t.Fatalf("composed argv %v: %v", argv, err)
				}
				if len(positionals) != 1 {
					t.Fatalf("composed argv %v has %d positionals %v, want exactly 1 — the image's ENTRYPOINT and the pod args must not both name a model", argv, len(positionals), positionals)
				}
				if positionals[0] != rendered[0] {
					t.Errorf("the positional after serve is %q, want the render's leading argument %q", positionals[0], rendered[0])
				}
			})
		}
	})

	t.Run("a_pinned_revision_renders_the_snapshot_path", func(t *testing.T) {
		cases := []struct {
			model string
			want  string
		}{
			{"mlx-community/Qwen3-0.6B-4bit", hfHomePath + "/hub/models--mlx-community--Qwen3-0.6B-4bit/snapshots/"},
			{"gpt2", hfHomePath + "/hub/models--gpt2/snapshots/"},
		}
		for _, tc := range cases {
			m := newModel()
			m.Spec.Model = tc.model
			rendered, _ := splitRendered(t, m)
			want := tc.want + m.Spec.Revision
			if rendered[0] != want {
				t.Errorf("positional for model=%q revision=%q = %q, want %q", tc.model, m.Spec.Revision, rendered[0], want)
			}
			if strings.Contains(rendered[0], "/refs/") {
				t.Errorf("positional %q resolves through refs/, which a staged cache does not carry — snapshots/<revision> is the only path that exists offline", rendered[0])
			}
		}
	})

	t.Run("an_unpinned_model_renders_the_repository_reference", func(t *testing.T) {
		m := newModel()
		m.Spec.Revision = ""
		rendered, _ := splitRendered(t, m)
		if rendered[0] != m.Spec.Model {
			t.Errorf("positional = %q, want the repository reference %q — an unpinned model must resolve through the hub, not through a path that does not exist yet", rendered[0], m.Spec.Model)
		}
		if strings.Contains(rendered[0], "/snapshots/") {
			t.Errorf("positional = %q, want no snapshot path for an unpinned model", rendered[0])
		}
	})

	t.Run("caller_args_ride_last_and_unfiltered", func(t *testing.T) {
		// The override seam. The caller's args are NOT checked against the
		// measured surface: an operator running a newer engine must be able to
		// pass an option this table does not know, and argparse takes the last
		// occurrence, so they have to come after the derived pins.
		m := newModel()
		m.Spec.Runtime.Args = []string{"--max-kv-size", "4096", "--an-option-this-table-does-not-know"}
		rendered, caller := splitRendered(t, m)
		if !reflect.DeepEqual(caller, m.Spec.Runtime.Args) {
			t.Fatalf("trailing args = %v, want the caller's spec.runtime.args %v verbatim and LAST", caller, m.Spec.Runtime.Args)
		}
		if !slices.Contains(rendered, argContinuousBatching) {
			t.Errorf("rendered argv %v dropped %s", rendered, argContinuousBatching)
		}
	})

	t.Run("a_spec_field_the_engine_cannot_express_is_refused", func(t *testing.T) {
		// A field the operator SET must never be silently dropped: it would serve
		// something other than what was asked for and look like success. The CRD
		// makes spec.distributed representable for exactly this reason, and the
		// same rule applies to a field this engine has no expression for.
		cases := []struct {
			name   string
			mutate func(*mlxv1alpha1.MLXModel)
			want   error
		}{
			{"quantization_has_no_option_on_this_surface", func(m *mlxv1alpha1.MLXModel) { m.Spec.Quantization = "8bit" }, ErrQuantizationUnsupported},
			{"revision_without_a_cache_volume", func(m *mlxv1alpha1.MLXModel) { m.Spec.Cache = nil }, ErrRevisionNeedsCache},
			{"revision_with_a_path_separator", func(m *mlxv1alpha1.MLXModel) { m.Spec.Revision = "refs/pr/1" }, ErrInvalidRevision},
			{"revision_that_climbs_out_of_the_cache", func(m *mlxv1alpha1.MLXModel) { m.Spec.Revision = ".." }, ErrInvalidRevision},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				m := newModel()
				tc.mutate(m)
				objs, err := Render(m, testOptions())
				if !errors.Is(err, tc.want) {
					t.Fatalf("Render() error = %v, want one wrapping %v", err, tc.want)
				}
				if objs != nil {
					t.Errorf("Render() returned %+v alongside an error, want no partial object set", objs)
				}
			})
		}
	})
}
