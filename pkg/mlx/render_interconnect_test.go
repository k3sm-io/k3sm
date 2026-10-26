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
	"net/netip"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/darwin-net/pkg/podnet"
)

// icIndices are the cluster indices of the thunderbolt test nodes. Rank order
// (mac-c, mac-a, mac-b) deliberately differs from index order.
var icIndices = map[string]int{"mac-a": 0, "mac-b": 9, "mac-c": 4}

// slot1 is what the provider attaches to a rank Pod on node: the node's slot-1
// interconnect address, which it exports as K3SM_INTERCONNECT_IP.
func slot1(t *testing.T, node string) netip.Addr {
	t.Helper()
	a, err := netv1alpha1.InterconnectSlotAddress(icIndices[node], netv1alpha1.InterconnectSlotMLXRank)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// thunderboltPlacement is a three-rank ring over one interconnect segment.
func thunderboltPlacement(t *testing.T) Placement {
	t.Helper()
	p := Placement{
		Backend:      mlxv1alpha1.MLXDistributedBackendRing,
		Interconnect: mlxv1alpha1.MLXInterconnectThunderbolt,
		Links:        [][2]string{{"mac-a", "mac-c"}, {"mac-a", "mac-b"}, {"mac-b", "mac-c"}},
	}
	for r, node := range []string{"mac-c", "mac-a", "mac-b"} {
		p.Ranks = append(p.Ranks, RankPlacement{Rank: r, Node: node, InterconnectAddr: slot1(t, node)})
	}
	return p
}

// podEnv returns a rank container's environment as a map.
func podEnv(pod *corev1.Pod) map[string]string {
	env := map[string]string{}
	for _, e := range pod.Spec.Containers[0].Env {
		env[e.Name] = e.Value
	}
	return env
}

// TestShardedHostfileUsesInterconnectAddresses pins this contract.
// On the thunderbolt path every rank Pod opts into the
// thunderbolt Interconnect and carries K3SM_MLX_HOSTS: every rank's slot-1
// address and the collective port, in RANK order. Each rank's own entry equals
// the slot-1 address the provider attaches to it (K3SM_INTERCONNECT_IP), and the
// k3sm-shard entrypoint writes the hostfile from those entries and refuses to
// start when its own entry is not its interconnect address. The serving surface
// (probes, the ClusterIP Service) stays on the pod IP.
func TestShardedHostfileUsesInterconnectAddresses(t *testing.T) {
	m := shardedModel(3, mlxv1alpha1.MLXDistributedBackendRing, "")
	objs, err := RenderSharded(m, testOptions(), thunderboltPlacement(t))
	if err != nil {
		t.Fatalf("RenderSharded: %v", err)
	}
	// Spelled out, not re-derived: 169.254.0.(8*idx + 1 + 1) for mac-c (4),
	// mac-a (0), mac-b (9).
	const wantHosts = "169.254.0.34:29500,169.254.0.2:29500,169.254.0.74:29500"
	for r, pod := range objs.Pods {
		env := podEnv(pod)
		if got := env[envHosts]; got != wantHosts {
			t.Errorf("rank %d %s = %q, want %q", r, envHosts, got, wantHosts)
		}
		own := strings.Split(env[envHosts], ",")[r]
		if host, _, _ := strings.Cut(own, ":"); host != slot1(t, pod.Spec.NodeName).String() {
			t.Errorf("rank %d own hostfile entry %q is not %s's slot-1 address %s (its %s)",
				r, own, pod.Spec.NodeName, slot1(t, pod.Spec.NodeName), podnet.EnvInterconnectIP)
		}
		if got := pod.Annotations[netv1alpha1.AnnotationInterconnects]; got != netv1alpha1.MediumThunderbolt {
			t.Errorf("rank %d %s = %q, want %q", r, netv1alpha1.AnnotationInterconnects, got, netv1alpha1.MediumThunderbolt)
		}
		if got := pod.Annotations[AnnotationInterconnect]; got != string(mlxv1alpha1.MLXInterconnectThunderbolt) {
			t.Errorf("rank %d %s = %q, want thunderbolt", r, AnnotationInterconnect, got)
		}
		if c := pod.Spec.Containers[0]; c.ReadinessProbe != nil && c.ReadinessProbe.HTTPGet.Host != "" {
			t.Errorf("rank %d readiness probe host %q; probes stay on the pod IP", r, c.ReadinessProbe.HTTPGet.Host)
		}
	}
	if got := objs.ClusterIPService.Spec.Selector[LabelRank]; got != "0" {
		t.Errorf("ClusterIP Service selects rank %q; the client endpoint stays rank 0's pod IP", got)
	}

	t.Run("network_path_carries_no_interconnect", func(t *testing.T) {
		nw, err := RenderSharded(shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing, ""), testOptions(), ringPlacement())
		if err != nil {
			t.Fatal(err)
		}
		for r, pod := range nw.Pods {
			if _, ok := podEnv(pod)[envHosts]; ok {
				t.Errorf("rank %d carries %s on the network path", r, envHosts)
			}
			if _, ok := pod.Annotations[netv1alpha1.AnnotationInterconnects]; ok {
				t.Errorf("rank %d opts into an Interconnect on the network path", r)
			}
			if got := pod.Annotations[AnnotationInterconnect]; got != string(mlxv1alpha1.MLXInterconnectNetwork) {
				t.Errorf("rank %d %s = %q, want network", r, AnnotationInterconnect, got)
			}
		}
	})

	t.Run("placement_mismatch_refused", func(t *testing.T) {
		for name, mutate := range map[string]func(*Placement){
			"thunderbolt rank without an address": func(p *Placement) { p.Ranks[1].InterconnectAddr = netip.Addr{} },
			"address outside the interconnect":    func(p *Placement) { p.Ranks[1].InterconnectAddr = netip.MustParseAddr("169.254.1.2") },
			"two ranks on one address":            func(p *Placement) { p.Ranks[1].InterconnectAddr = p.Ranks[0].InterconnectAddr },
			"network rank with an address":        func(p *Placement) { p.Interconnect = mlxv1alpha1.MLXInterconnectNetwork },
			"unresolved path":                     func(p *Placement) { p.Interconnect = mlxv1alpha1.MLXInterconnectAuto },
		} {
			p := thunderboltPlacement(t)
			mutate(&p)
			if _, err := RenderSharded(m, testOptions(), p); !errors.Is(err, ErrPlacementMismatch) {
				t.Errorf("%s: RenderSharded = %v, want ErrPlacementMismatch", name, err)
			}
		}
	})

	t.Run("entrypoint_binds_its_own_interconnect_address", func(t *testing.T) {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Skip("python3 is not on PATH; hack/images/mlx-serve/selftest.sh runs the same entrypoint checks")
		}
		type rankRun struct {
			Env map[string]string `json:"env"`
		}
		var runs []rankRun
		for _, pod := range objs.Pods {
			env := podEnv(pod)
			env["TMPDIR"] = t.TempDir()
			env[podnet.EnvInterconnectIP] = slot1(t, pod.Spec.NodeName).String()
			runs = append(runs, rankRun{Env: env})
		}
		// Rank 1 handed rank 0's address, and rank 2 with no attached address.
		mismatch := podEnv(objs.Pods[1])
		mismatch["TMPDIR"] = t.TempDir()
		mismatch[podnet.EnvInterconnectIP] = slot1(t, objs.Pods[0].Spec.NodeName).String()
		unattached := podEnv(objs.Pods[2])
		unattached["TMPDIR"] = t.TempDir()
		runs = append(runs, rankRun{Env: mismatch}, rankRun{Env: unattached})
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
		cmd := exec.Command(python, "-I", "-B", "-c", shardDriver, dir)
		cmd.Stdin = strings.NewReader(string(in))
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("shard driver: %v\n%s", err, exitErr.Stderr)
			}
			t.Fatalf("shard driver: %v", err)
		}
		var results []struct {
			Hostfile [][]string `json:"hostfile"`
			Error    string     `json:"error"`
			Exit     int        `json:"exit"`
			Log      string     `json:"log"`
		}
		if err := json.Unmarshal(out, &results); err != nil {
			t.Fatalf("decode driver output %q: %v", out, err)
		}
		if len(results) != len(runs) {
			t.Fatalf("%d driver results for %d runs", len(results), len(runs))
		}
		want := [][]string{{"169.254.0.34:29500"}, {"169.254.0.2:29500"}, {"169.254.0.74:29500"}}
		for r := range objs.Pods {
			if results[r].Error != "" || !reflect.DeepEqual(results[r].Hostfile, want) {
				t.Errorf("rank %d: hostfile %v, error %q; want %v", r, results[r].Hostfile, results[r].Error, want)
			}
		}
		if e := results[len(objs.Pods)].Error; !strings.Contains(e, "does not hold") {
			t.Errorf("a rank handed another rank's address started (error %q); it must refuse", e)
		}
		unattachedRun := results[len(objs.Pods)+1]
		if !strings.Contains(unattachedRun.Error, podnet.EnvInterconnectIP) {
			t.Errorf("a rank with no interconnect address started (error %q); it must refuse", unattachedRun.Error)
		}
		// The refusal is a clean, logged exit (status 2, one k3sm-shard line),
		// never a traceback and never an exec.
		if unattachedRun.Exit != 2 || !strings.HasPrefix(unattachedRun.Log, "k3sm-shard: ") || strings.Contains(unattachedRun.Log, "Traceback") {
			t.Errorf("unattached rank main() = exit %d, log %q; want a clean exit 2 with a k3sm-shard line", unattachedRun.Exit, unattachedRun.Log)
		}
	})
}

// shardDriver plans each rank in stdin's JSON list with the real k3sm_shard
// module (sys.argv[1] is its directory) and prints, per run, the hostfile it
// would write or the ShardError it raised. Name resolution fails loudly: the
// thunderbolt path must never resolve a name.
const shardDriver = `
import io, json, os, sys
sys.path.insert(0, sys.argv[1])
import k3sm_shard as ks

def no_lookup(name):
    raise AssertionError("the thunderbolt path resolved " + name)

out = []
for run in json.load(sys.stdin):
    try:
        files, _, _ = ks.plan(run["env"], [], resolver=no_lookup)
        (content,) = files.values()
        res = {"hostfile": json.loads(content), "error": ""}
    except ks.ShardError as e:
        res = {"hostfile": None, "error": str(e)}
    if res["error"]:
        # The entrypoint itself, as the rank runs it: a refusal must exit
        # cleanly with a logged line (it never reaches the exec).
        os.environ.clear()
        os.environ.update(run["env"])
        err, sys.stderr = sys.stderr, io.StringIO()
        try:
            res["exit"] = ks.main([])
        finally:
            res["log"], sys.stderr = sys.stderr.getvalue(), err
    out.append(res)
print(json.dumps(out))
`
