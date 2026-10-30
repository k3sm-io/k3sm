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
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestRenderSeedsPinnedRevision pins the contract between the render and the
// serving entrypoint for a pinned revision. The render names the revision's
// snapshot path inside the cache volume (the engine has no revision option),
// and the entrypoint fetches that exact revision into the cache when the volume
// has never held it, so a pinned model starts on a fresh volume with no seed
// step. The rendered argv and environment are handed, unchanged, to the real
// k3sm_serve module with only the Hub download faked.
func TestRenderSeedsPinnedRevision(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH; hack/images/mlx-serve/selftest.sh runs the entrypoint checks")
	}

	type seedRun struct {
		Argv  []string          `json:"argv"`
		Model string            `json:"model"`
		Env   map[string]string `json:"env"`
		// Mode is what the faked Hub does: "fetch" lands the requested
		// revision, "resolve" lands a different commit (a branch name resolved
		// to its head), "fail" raises; "present" pre-stages the snapshot and
		// then fails, the restart of a pod with no network.
		Mode string `json:"mode"`
	}
	type seedResult struct {
		Calls  [][]string `json:"calls"`
		Error  string     `json:"error"`
		Exists bool       `json:"exists"`
	}

	render := func(t *testing.T, revision string) seedRun {
		t.Helper()
		m := newModel()
		m.Spec.Revision = revision
		objs, err := Render(m, testOptions())
		if err != nil {
			t.Fatalf("Render() error = %v, want nil", err)
		}
		c := objs.StatefulSet.Spec.Template.Spec.Containers[0]
		env := map[string]string{}
		for _, e := range c.Env {
			env[e.Name] = e.Value
		}
		if env[hfHomeEnv] == "" {
			t.Fatalf("rendered container sets no %s; a cached model must name its cache", hfHomeEnv)
		}
		// The image ENTRYPOINT's own leading argv, then the rendered args, the
		// way the pod starts the module. The model is the first rendered arg.
		argv := append([]string{"serve", "--continuous-batching", "--host", "0.0.0.0", "--port", "8000"}, c.Args...)
		return seedRun{Argv: argv, Model: c.Args[0], Env: env}
	}
	run := func(t *testing.T, runs ...seedRun) []seedResult {
		t.Helper()
		in, err := json.Marshal(runs)
		if err != nil {
			t.Fatal(err)
		}
		dir, err := filepath.Abs(filepath.Join("..", "..", "hack", "images", "mlx-serve"))
		if err != nil {
			t.Fatal(err)
		}
		// -I: no user site, no PYTHON* variables, no script directory on the
		// path; -B: no bytecode written into the repo tree.
		cmd := exec.Command(python, "-I", "-B", "-c", seedDriver, dir, t.TempDir())
		cmd.Stdin = strings.NewReader(string(in))
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("seed driver: %v\n%s", err, exitErr.Stderr)
			}
			t.Fatalf("seed driver: %v", err)
		}
		var results []seedResult
		if err := json.Unmarshal(out, &results); err != nil {
			t.Fatalf("decode driver output %q: %v", out, err)
		}
		if len(results) != len(runs) {
			t.Fatalf("%d driver results for %d runs", len(results), len(runs))
		}
		return results
	}

	const revision = "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567"
	// The cache directory the fetch must land in: the hub cache under the
	// rendered HF_HOME, relative to the pod's working directory, where a native
	// pod's volume mount is materialized (the path-rebase shim does not follow
	// the /var -> /private/var resolution the Hub client applies).
	wantCache := "." + hfHomePath + "/" + hubDir

	t.Run("pinned_fresh_volume_is_fetched", func(t *testing.T) {
		r := render(t, revision)
		r.Mode = "fetch"
		got := run(t, r)[0]
		if got.Error != "" {
			t.Fatalf("seed refused a fresh volume: %s", got.Error)
		}
		want := [][]string{{"mlx-community/Qwen3-0.6B-4bit", revision, wantCache}}
		if !reflect.DeepEqual(got.Calls, want) {
			t.Errorf("downloads = %v, want %v (spec.model at spec.revision into the volume's hub cache)", got.Calls, want)
		}
		if !got.Exists {
			t.Errorf("the rendered snapshot path does not exist after the seed; the engine would not find the weights")
		}
	})

	t.Run("unpinned_is_left_to_the_engine", func(t *testing.T) {
		r := render(t, "")
		r.Mode = "fail"
		got := run(t, r)[0]
		if got.Error != "" || len(got.Calls) != 0 {
			t.Errorf("unpinned model: downloads %v, error %q; want none (the engine downloads the default branch itself)", got.Calls, got.Error)
		}
	})

	t.Run("a_moving_reference_is_refused", func(t *testing.T) {
		r := render(t, "main")
		r.Mode = "resolve"
		got := run(t, r)[0]
		if !strings.Contains(got.Error, "main") || !strings.Contains(got.Error, "commit") {
			t.Errorf("revision main seeded with error %q; want a refusal naming the revision and asking for a commit", got.Error)
		}
	})

	t.Run("fetch_failure_on_a_fresh_volume_is_refused", func(t *testing.T) {
		r := render(t, revision)
		r.Mode = "fail"
		got := run(t, r)[0]
		if !strings.Contains(got.Error, revision) || strings.Contains(got.Error, "Traceback") {
			t.Errorf("failed fetch on a fresh volume: error %q; want a one-line refusal naming the revision", got.Error)
		}
	})

	t.Run("fetch_failure_with_the_snapshot_present_serves_it", func(t *testing.T) {
		r := render(t, revision)
		r.Mode = "present"
		got := run(t, r)[0]
		if got.Error != "" || !got.Exists {
			t.Errorf("staged snapshot with no network: error %q, exists %v; want it served from the volume", got.Error, got.Exists)
		}
	})
}

// seedDriver runs k3sm_serve.seed_pinned_revision (sys.argv[1] is the module's
// directory) once per run in stdin's JSON list, each in its own working
// directory under sys.argv[2] holding the materialized mount point, with the
// Hub download replaced by a fake that lands files the way the Hub client does.
const seedDriver = `
import json, os, sys
sys.path.insert(0, sys.argv[1])
import k3sm_serve as ks

COMMIT = "1111111111111111111111111111111111111111"

def relative(p):
    return "." + p

out = []
for i, run in enumerate(json.load(sys.stdin)):
    cwd = os.path.join(sys.argv[2], str(i))
    os.makedirs(os.path.join(cwd, relative(os.path.dirname(run["env"]["HF_HOME"]))), exist_ok=True)
    os.chdir(cwd)
    calls = []
    mode = run["mode"]

    def download(repo_id, revision, cache_dir):
        calls.append([repo_id, revision, cache_dir])
        if mode in ("fail", "present"):
            raise OSError("hub unreachable")
        landed = COMMIT if mode == "resolve" else revision
        snap = os.path.join(cache_dir, "models--" + repo_id.replace("/", "--"), "snapshots", landed)
        os.makedirs(snap, exist_ok=True)
        with open(os.path.join(snap, "config.json"), "w") as f:
            f.write("{}")
        return snap

    if mode == "present":
        os.makedirs(relative(run["model"]), exist_ok=True)
    res = {"calls": calls, "error": ""}
    try:
        ks.seed_pinned_revision(run["argv"], run["env"], parse=lambda argv: (run["model"], None),
                                download=download, say=lambda line: None)
    except ks.SeedError as e:
        res["error"] = str(e)
    res["exists"] = os.path.isdir(relative(run["model"]))
    out.append(res)
print(json.dumps(out))
`
