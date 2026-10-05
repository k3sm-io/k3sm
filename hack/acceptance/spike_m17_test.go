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

package acceptance

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// m17SpikeRungs are the rungs hack/spike/m17/run.sh chains. S6 is deliberately
// absent: it is the M17-rdma row, so the M17.0 row can exit 0 on a Thunderbolt 4 rig.
var m17SpikeRungs = []string{"s1", "s2", "s3", "s4", "s5"}

// m17SpikeEnv is the test process's environment with every variable the M17.0
// spike reads removed (K3SM_LAB, K3SM_EVIDENCE and all K3SM_M17_*), then extra
// appended, plus a PATH whose first entry holds ssh and scp stand-ins that record
// any call in a marker file. A developer who exported a rig's host variables can
// therefore never have this test reach a real Mac.
func m17SpikeEnv(t *testing.T, extra ...string) ([]string, string) {
	t.Helper()
	shim := t.TempDir()
	marker := filepath.Join(shim, "called")
	for _, tool := range []string{"ssh", "scp"} {
		body := "#!/bin/sh\necho " + tool + " >>'" + marker + "'\nexit 1\n"
		if err := os.WriteFile(filepath.Join(shim, tool), []byte(body), 0o755); err != nil {
			t.Fatalf("write %s stand-in: %v", tool, err)
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "K3SM_LAB" || name == "K3SM_EVIDENCE" || strings.HasPrefix(name, "K3SM_M17_") || name == "PATH" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	return append(env, extra...), marker
}

// runM17Spike runs one spike script and returns its exit code and combined output.
func runM17Spike(t *testing.T, env []string, script string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("run %s %v: %v", script, args, err)
	return -1, ""
}

func assertNoHostContacted(t *testing.T, marker string) {
	t.Helper()
	if b, err := os.ReadFile(marker); err == nil {
		t.Errorf("the script called %s; it must refuse before contacting any host", strings.TrimSpace(string(b)))
	}
}

// TestM17SpikePlanNeedsNoHost pins the review contract of the M17.0 ladder:
// `run.sh --plan` is parsed before any host requirement, so it exits 0 on a machine
// with no rig, no cable and no host variables, contacts nothing, and lists S1–S5 —
// each with its verdict criteria and its pre-decided halt — and not S6.
func TestM17SpikePlanNeedsNoHost(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "hack", "spike", "m17")
	env, marker := m17SpikeEnv(t)

	code, out := runM17Spike(t, env, filepath.Join(dir, "run.sh"), "--plan")
	if code != 0 {
		t.Fatalf("run.sh --plan with no host variables: exit %d, want 0\n%s", code, out)
	}
	for _, r := range m17SpikeRungs {
		head := "spike " + strings.ToUpper(r) + " — PLAN ONLY"
		if !strings.Contains(out, head) {
			t.Errorf("run.sh --plan does not print %q", head)
		}
	}
	for _, want := range []string{"verdict criteria", "halt and pre-decided substitution"} {
		if n := strings.Count(out, want); n != len(m17SpikeRungs) {
			t.Errorf("run.sh --plan prints %q %d times, want once per rung (%d)", want, n, len(m17SpikeRungs))
		}
	}
	if strings.Contains(out, "spike S6") {
		t.Error("run.sh --plan lists S6; S6 belongs to the M17-rdma row, not M17.0")
	}
	assertNoHostContacted(t, marker)

	for _, r := range m17SpikeRungs {
		code, out := runM17Spike(t, env, filepath.Join(dir, r+".sh"), "--plan")
		if code != 0 {
			t.Errorf("%s.sh --plan: exit %d, want 0\n%s", r, code, out)
		}
	}
	assertNoHostContacted(t, marker)
}

// TestM17SpikeRungsRefuseWithoutLabAndHosts pins the refusal half of the spike's
// exit contract for every rung: without K3SM_LAB=1 a rung REFUSES (non-zero: it
// never ran, so it is never a green), and under K3SM_LAB=1 a missing host or
// evidence variable is a FAIL (non-zero) naming what is missing, never a PENDING.
// Neither path may contact a host. run.sh's own K3SM_LAB-unset PENDING (exit 0) is
// TestLabSkeletonHonesty's to pin; its K3SM_LAB=1-without-hosts FAIL is pinned here.
func TestM17SpikeRungsRefuseWithoutLabAndHosts(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "hack", "spike", "m17")
	evidence := t.TempDir()
	cases := []struct {
		name  string
		extra []string
		want  string
	}{
		{"no K3SM_LAB", nil, "REFUSED"},
		{"no K3SM_LAB, hosts set", []string{"K3SM_M17_SERVER=server.invalid", "K3SM_M17_WORKER=worker.invalid", "K3SM_EVIDENCE=" + evidence}, "REFUSED"},
		{"K3SM_LAB=1, no hosts", []string{"K3SM_LAB=1"}, "K3SM_M17_SERVER"},
		{"K3SM_LAB=1, no worker", []string{"K3SM_LAB=1", "K3SM_M17_SERVER=server.invalid", "K3SM_EVIDENCE=" + evidence}, "K3SM_M17_WORKER"},
		{"K3SM_LAB=1, no evidence", []string{"K3SM_LAB=1", "K3SM_M17_SERVER=server.invalid", "K3SM_M17_WORKER=worker.invalid"}, "K3SM_EVIDENCE"},
	}
	for _, r := range m17SpikeRungs {
		for _, tc := range cases {
			t.Run(r+"/"+tc.name, func(t *testing.T) {
				env, marker := m17SpikeEnv(t, tc.extra...)
				code, out := runM17Spike(t, env, filepath.Join(dir, r+".sh"))
				if code == 0 {
					t.Errorf("%s.sh (%s): exit 0 — a rung that did not run must never report a pass\n%s", r, tc.name, out)
				}
				if !strings.Contains(out, tc.want) {
					t.Errorf("%s.sh (%s): output does not name %q\n%s", r, tc.name, tc.want, out)
				}
				assertNoHostContacted(t, marker)
			})
		}
	}

	t.Run("run.sh/K3SM_LAB=1, no hosts", func(t *testing.T) {
		env, marker := m17SpikeEnv(t, "K3SM_LAB=1")
		code, out := runM17Spike(t, env, filepath.Join(dir, "run.sh"))
		if code != 1 {
			t.Errorf("run.sh under K3SM_LAB=1 with no hosts: exit %d, want 1 (a FAIL, never a PENDING)\n%s", code, out)
		}
		assertNoHostContacted(t, marker)
	})
}
