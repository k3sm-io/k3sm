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
	"slices"
	"strings"
	"testing"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
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

// TestShardedRanksFetchPinnedSnapshotBeforeEngine pins the same contract for a
// sharded model, whose rank Pods run k3sm_shard instead of the image ENTRYPOINT.
// mlx_lm.server only loads a pinned snapshot path, so a rank that does not fetch
// it first dies on an empty cache. Each rank's rendered command arguments and
// environment go to the real k3sm_shard.main in that rank's own working directory,
// with only the Hub client, name resolution and the engine faked.
func TestShardedRanksFetchPinnedSnapshotBeforeEngine(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not on PATH; hack/images/mlx-serve/selftest.sh runs the entrypoint checks")
	}
	dir, err := filepath.Abs(filepath.Join("..", "..", "hack", "images", "mlx-serve"))
	if err != nil {
		t.Fatal(err)
	}

	type rankRun struct {
		Args []string          `json:"args"`
		Env  map[string]string `json:"env"`
		// Mode is what the faked Hub does; see seedDriver for the meanings.
		Mode string `json:"mode"`
	}
	type rankResult struct {
		Calls  [][]string `json:"calls"`
		Events []string   `json:"events"`
		Status int        `json:"status"`
		Stderr string     `json:"stderr"`
		// Loadable is whether the --model path existed when the engine started.
		Loadable bool `json:"loadable"`
	}

	const repo = "mlx-community/Qwen3-0.6B-4bit"
	const revision = "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567"
	snapshot := hfHomePath + "/" + hubDir + "/models--mlx-community--Qwen3-0.6B-4bit/snapshots/" + revision
	wantCache := "." + hfHomePath + "/" + hubDir

	render := func(t *testing.T, m *mlxv1alpha1.MLXModel, placement Placement) []rankRun {
		t.Helper()
		objs, err := RenderSharded(m, testOptions(), placement)
		if err != nil {
			t.Fatalf("RenderSharded() error = %v", err)
		}
		var runs []rankRun
		for i, pod := range objs.Pods {
			c := pod.Spec.Containers[0]
			if want := []string{shardInterpreter, "-m", shardModule}; !reflect.DeepEqual(c.Command, want) {
				t.Fatalf("rank %d command = %v, want %v: the fetch lives in this module", i, c.Command, want)
			}
			wantClaim := RankCacheClaimName(m.Name, placement.Ranks[i].Node)
			var claim string
			for _, v := range pod.Spec.Volumes {
				if v.Name == cacheVolumeName && v.PersistentVolumeClaim != nil {
					claim = v.PersistentVolumeClaim.ClaimName
				}
			}
			if claim != wantClaim {
				t.Errorf("rank %d cache volume names claim %q, want its own %q", i, claim, wantClaim)
			}
			mounted := false
			for _, vm := range c.VolumeMounts {
				mounted = mounted || (vm.Name == cacheVolumeName && vm.MountPath == CacheMountPath)
			}
			if !mounted {
				t.Errorf("rank %d does not mount its cache at %s: %+v", i, CacheMountPath, c.VolumeMounts)
			}
			env := map[string]string{}
			for _, e := range c.Env {
				env[e.Name] = e.Value
			}
			if env[hfHomeEnv] != hfHomePath {
				t.Errorf("rank %d %s = %q, want %q", i, hfHomeEnv, env[hfHomeEnv], hfHomePath)
			}
			runs = append(runs, rankRun{Args: c.Args, Env: env})
		}
		return runs
	}
	run := func(t *testing.T, runs []rankRun, mode string) []rankResult {
		t.Helper()
		for i := range runs {
			runs[i].Mode = mode
		}
		in, err := json.Marshal(runs)
		if err != nil {
			t.Fatal(err)
		}
		// -I: no user site, no PYTHON* variables, no script directory on the
		// path; -B: no bytecode written into the repo tree.
		cmd := exec.Command(python, "-I", "-B", "-c", shardSeedDriver, dir, t.TempDir())
		cmd.Stdin = strings.NewReader(string(in))
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("shard driver: %v\n%s", err, exitErr.Stderr)
			}
			t.Fatalf("shard driver: %v", err)
		}
		var results []rankResult
		if err := json.Unmarshal(out, &results); err != nil {
			t.Fatalf("decode driver output %q: %v", out, err)
		}
		if len(results) != len(runs) {
			t.Fatalf("%d driver results for %d ranks", len(results), len(runs))
		}
		return results
	}
	pinned := func() *mlxv1alpha1.MLXModel {
		m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, mlxv1alpha1.MLXParallelismTensor)
		m.Spec.Revision = revision
		return m
	}

	t.Run("every_rank_fetches_into_its_own_cache_before_the_engine", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			model     *mlxv1alpha1.MLXModel
			placement Placement
		}{
			{"ring", pinned(), ringPlacement()},
			{"jaccl", func() *mlxv1alpha1.MLXModel {
				m := shardedModel(3, mlxv1alpha1.MLXDistributedBackendJACCL, mlxv1alpha1.MLXParallelismTensor)
				m.Spec.Revision = revision
				return m
			}(), jacclPlacement()},
		} {
			t.Run(tc.name, func(t *testing.T) {
				runs := render(t, tc.model, tc.placement)
				for i, r := range run(t, runs, "fetch") {
					if !slices.Contains(runs[i].Args, snapshot) {
						t.Fatalf("rank %d args %v do not name the snapshot %s", i, runs[i].Args, snapshot)
					}
					if want := [][]string{{repo, revision, wantCache}}; !reflect.DeepEqual(r.Calls, want) {
						t.Errorf("rank %d downloads = %v, want %v", i, r.Calls, want)
					}
					if want := []string{"download", "engine"}; !reflect.DeepEqual(r.Events, want) {
						t.Errorf("rank %d order = %v, want %v", i, r.Events, want)
					}
					if !r.Loadable {
						t.Errorf("rank %d: the engine started without the snapshot in its cache", i)
					}
					if r.Status != 0 {
						t.Errorf("rank %d exit status = %d, stderr %q", i, r.Status, r.Stderr)
					}
				}
			})
		}
	})

	t.Run("unpinned_is_left_to_the_engine", func(t *testing.T) {
		m := pinned()
		m.Spec.Revision = ""
		for i, r := range run(t, render(t, m, ringPlacement()), "fail") {
			if len(r.Calls) != 0 || r.Status != 0 || !reflect.DeepEqual(r.Events, []string{"engine"}) {
				t.Errorf("rank %d: downloads %v, order %v, status %d, stderr %q; want the engine alone", i, r.Calls, r.Events, r.Status, r.Stderr)
			}
		}
	})

	// A failed fetch must not exit 2: on the thunderbolt path the operator reads
	// exit 2 as a refusal to start on the interconnect (lostRanks), and a Hub
	// outage is not an interconnect loss.
	t.Run("fetch_failure_on_a_fresh_cache_ends_the_rank_without_the_refusal_status", func(t *testing.T) {
		for i, r := range run(t, render(t, pinned(), ringPlacement()), "fail") {
			if r.Status != 1 {
				t.Errorf("rank %d exit status = %d, want 1", i, r.Status)
			}
			if slices.Contains(r.Events, "engine") {
				t.Errorf("rank %d started the engine on an empty cache", i)
			}
			if !strings.Contains(r.Stderr, revision) || strings.Contains(r.Stderr, "Traceback") {
				t.Errorf("rank %d stderr = %q, want a one-line refusal naming the revision", i, r.Stderr)
			}
		}
	})

	t.Run("fetch_failure_with_the_snapshot_present_starts_the_engine", func(t *testing.T) {
		for i, r := range run(t, render(t, pinned(), ringPlacement()), "present") {
			if r.Status != 0 || !r.Loadable {
				t.Errorf("rank %d: status %d, loadable %v, stderr %q; want the engine started on the staged snapshot", i, r.Status, r.Loadable, r.Stderr)
			}
		}
	})

	t.Run("a_moving_reference_is_refused", func(t *testing.T) {
		m := pinned()
		m.Spec.Revision = "main"
		for i, r := range run(t, render(t, m, ringPlacement()), "resolve") {
			if r.Status != 1 || slices.Contains(r.Events, "engine") || !strings.Contains(r.Stderr, "commit") {
				t.Errorf("rank %d: status %d, order %v, stderr %q; want a refusal asking for a commit", i, r.Status, r.Events, r.Stderr)
			}
		}
	})
}

// shardSeedDriver runs k3sm_shard.main (sys.argv[1] is the module's directory)
// once per rank in stdin's JSON list, each in its own working directory under
// sys.argv[2] holding the materialized mount point. It replaces the Hub client
// module, the system resolver and serve, and records their order.
const shardSeedDriver = `
import contextlib, io, json, os, socket, sys, types
sys.path.insert(0, sys.argv[1])
import k3sm_shard as ks

COMMIT = "1111111111111111111111111111111111111111"

socket.getaddrinfo = lambda name, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))]

def model_of(args):
    return args[args.index("--model") + 1]

out = []
for i, run in enumerate(json.load(sys.stdin)):
    cwd = os.path.join(sys.argv[2], str(i))
    tmp = os.path.join(cwd, "tmp")
    os.makedirs(tmp)
    env = dict(run["env"], TMPDIR=tmp)
    home = env.get("HF_HOME")
    if home:
        os.makedirs(os.path.join(cwd, "." + os.path.dirname(home)))
    os.chdir(cwd)
    model = model_of(run["args"])
    mode = run["mode"]
    res = {"calls": [], "events": [], "status": None, "stderr": "", "loadable": False}

    def snapshot_download(repo_id, revision=None, cache_dir=None):
        res["calls"].append([repo_id, revision, cache_dir])
        res["events"].append("download")
        if mode in ("fail", "present"):
            raise OSError("hub unreachable")
        landed = COMMIT if mode == "resolve" else revision
        snap = os.path.join(cache_dir, "models--" + repo_id.replace("/", "--"), "snapshots", landed)
        os.makedirs(snap, exist_ok=True)
        return snap

    def serve(child_env, child_argv, served):
        res["events"].append("engine")
        res["loadable"] = os.path.isdir("." + model)

    hub = types.ModuleType("huggingface_hub")
    hub.snapshot_download = snapshot_download
    sys.modules["huggingface_hub"] = hub
    ks.serve = serve
    if mode == "present":
        os.makedirs("." + model)
    os.environ.clear()
    os.environ.update(env)
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(stderr):
        res["status"] = ks.main(list(run["args"]))
    res["stderr"] = stderr.getvalue()
    out.append(res)
print(json.dumps(out))
`
