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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const interconnectSpikeRow = "M17-interconnect-spike"

// interconnectSpikeEnv is the test process's environment with every variable the
// interconnect spike reads removed (K3SM_LAB, PEER_SSH, EVIDENCE_DIR and all
// K3SM_INTERCONNECT_*), then extra appended, plus a PATH whose first entry holds ssh,
// scp and sudo stand-ins that record any call in a marker file. A developer who
// exported a rig's variables can therefore never have this test reach a real Mac or
// change the host it runs on.
func interconnectSpikeEnv(t *testing.T, extra ...string) ([]string, string) {
	t.Helper()
	shim := t.TempDir()
	marker := filepath.Join(shim, "called")
	for _, tool := range []string{"ssh", "scp", "sudo"} {
		body := "#!/bin/sh\necho " + tool + " >>'" + marker + "'\nexit 1\n"
		if err := os.WriteFile(filepath.Join(shim, tool), []byte(body), 0o755); err != nil {
			t.Fatalf("write %s stand-in: %v", tool, err)
		}
	}
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		switch {
		case name == "K3SM_LAB", name == "PEER_SSH", name == "EVIDENCE_DIR", name == "PATH",
			strings.HasPrefix(name, "K3SM_INTERCONNECT_"):
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PATH="+shim+string(os.PathListSeparator)+os.Getenv("PATH"))
	return append(env, extra...), marker
}

// interconnectSpikeGate returns the row's gate path, asserting the row's shape: a
// manual lab row on two cabled Macs whose script is the real spike (skeleton:false),
// so TestLabSkeletonHonesty does not cover it and this file must.
func interconnectSpikeGate(t *testing.T) string {
	t.Helper()
	row, ok := loadGateRows(t)[interconnectSpikeRow]
	if !ok {
		t.Fatalf("phases.json declares no %s row", interconnectSpikeRow)
	}
	if row.Gate != "hack/lab/m17-interconnect-spike.sh" {
		t.Errorf("%s gate = %q, want hack/lab/m17-interconnect-spike.sh", interconnectSpikeRow, row.Gate)
	}
	if row.Tier != "lab" || !row.Manual || row.Skeleton {
		t.Errorf("%s: tier=%q manual=%v skeleton=%v, want lab, true, false", interconnectSpikeRow, row.Tier, row.Manual, row.Skeleton)
	}
	if strings.Join(row.Requires, ",") != "two-macs,thunderbolt-cable" {
		t.Errorf("%s requires %v, want [two-macs thunderbolt-cable]", interconnectSpikeRow, row.Requires)
	}
	return filepath.Join(repoRoot(t), filepath.FromSlash(row.Gate))
}

// TestInterconnectSpikePlanNeedsNoHost pins the review contract: `--plan` is parsed
// before any host requirement, exits 0 with no rig and no variables, contacts
// nothing, and lists the three address forms in their pre-decided order, the
// RECORDED rungs, and Q2 and Q3.
func TestInterconnectSpikePlanNeedsNoHost(t *testing.T) {
	gate := interconnectSpikeGate(t)
	env, marker := interconnectSpikeEnv(t)

	code, out := runM17Spike(t, env, gate, "--plan")
	if code != 0 {
		t.Fatalf("--plan with no variables: exit %d, want 0\n%s", code, out)
	}
	last := -1
	for _, form := range []string{"form A", "form B", "form C"} {
		i := strings.Index(out, form)
		if i < 0 {
			t.Errorf("--plan does not list %q", form)
			continue
		}
		if i < last {
			t.Errorf("--plan lists %q out of the pre-decided order A, B, C", form)
		}
		last = i
	}
	for _, want := range []string{"PLAN ONLY", "RECORDED rungs", "unplug", "shim dial", "mlx ring", "Q2", "Q3", "0 PASS", "1 FAIL", "2 RECORDED"} {
		if !strings.Contains(out, want) {
			t.Errorf("--plan does not print %q", want)
		}
	}
	assertNoHostContacted(t, marker)
}

// TestInterconnectSpikeRefusals pins the rest of the exit contract: with K3SM_LAB
// unset the gate exits 0 saying PENDING (a skip, not a pass); under K3SM_LAB=1 a
// missing variable, a relative evidence path or an evidence path inside a git tree
// is a FAIL (exit 1) naming the problem, never a PENDING; an unknown argument is
// refused. No path may contact a host, and a refused evidence path is never created.
func TestInterconnectSpikeRefusals(t *testing.T) {
	gate := interconnectSpikeGate(t)
	evidence := filepath.Join(t.TempDir(), "evidence")
	inRepo := filepath.Join(repoRoot(t), "hack", "acceptance", "interconnect-evidence-must-not-exist")

	cases := []struct {
		name  string
		args  []string
		extra []string
		code  int
		want  string
	}{
		{"no K3SM_LAB", nil, nil, 0, "PENDING"},
		{"no K3SM_LAB, variables set", nil, []string{"PEER_SSH=peer.invalid", "EVIDENCE_DIR=" + evidence}, 0, "NOT a pass"},
		{"K3SM_LAB=1, nothing set", nil, []string{"K3SM_LAB=1"}, 1, "PEER_SSH"},
		{"K3SM_LAB=1, no evidence", nil, []string{"K3SM_LAB=1", "PEER_SSH=peer.invalid"}, 1, "EVIDENCE_DIR"},
		{"K3SM_LAB=1, no peer", nil, []string{"K3SM_LAB=1", "EVIDENCE_DIR=" + evidence}, 1, "PEER_SSH"},
		{"K3SM_LAB=1, relative evidence", nil, []string{"K3SM_LAB=1", "PEER_SSH=peer.invalid", "EVIDENCE_DIR=evidence"}, 1, "absolute"},
		{"K3SM_LAB=1, evidence in a git tree", nil, []string{"K3SM_LAB=1", "PEER_SSH=peer.invalid", "EVIDENCE_DIR=" + inRepo}, 1, "git work tree"},
		{"K3SM_LAB=1, too few runs", nil, []string{"K3SM_LAB=1", "PEER_SSH=peer.invalid", "EVIDENCE_DIR=" + evidence, "K3SM_INTERCONNECT_RUNS=3"}, 1, ">= 5 runs"},
		{"unknown argument", []string{"--not-a-flag"}, nil, 1, "unknown argument"},
		{"--form with a bad value", []string{"--form", "D"}, nil, 1, "--form must be A, B or C"},
		{"--form= with a bad value", []string{"--form=a"}, nil, 1, "--form must be A, B or C"},
		{"--form with no value", []string{"--form"}, nil, 1, "--form needs a value"},
		{"--plan with a bad --form", []string{"--plan", "--form", "X"}, nil, 1, "--form must be A, B or C"},
		{"--form B, no K3SM_LAB", []string{"--form", "B"}, nil, 0, "PENDING"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, marker := interconnectSpikeEnv(t, tc.extra...)
			code, out := runM17Spike(t, env, gate, tc.args...)
			if code != tc.code {
				t.Errorf("exit %d, want %d\n%s", code, tc.code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output does not name %q\n%s", tc.want, out)
			}
			if tc.code == 0 && !strings.Contains(out, "NOT a pass") {
				t.Errorf("a PENDING exit 0 must say it is NOT a pass\n%s", out)
			}
			assertNoHostContacted(t, marker)
		})
	}
	if _, err := os.Stat(inRepo); err == nil {
		_ = os.RemoveAll(inRepo)
		t.Errorf("a refused in-repository evidence path was created: %s", inRepo)
	}
	if _, err := os.Stat(evidence); err == nil {
		t.Errorf("a refused run created the evidence directory %s", evidence)
	}
}

// TestInterconnectSpikePlanSingleForm pins --form: with --plan it lists only the
// chosen form, says a FAIL on it is final, and contacts nothing; the flag is parsed
// in either order and in its --form=X spelling.
func TestInterconnectSpikePlanSingleForm(t *testing.T) {
	gate := interconnectSpikeGate(t)
	for _, args := range [][]string{{"--plan", "--form", "B"}, {"--form", "B", "--plan"}, {"--plan", "--form=B"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			env, marker := interconnectSpikeEnv(t)
			code, out := runM17Spike(t, env, gate, args...)
			if code != 0 {
				t.Fatalf("exit %d, want 0\n%s", code, out)
			}
			if !strings.Contains(out, "form B") {
				t.Errorf("does not list form B\n%s", out)
			}
			for _, other := range []string{"form A", "form C"} {
				if strings.Contains(out, other) {
					t.Errorf("lists %q although --form B was given\n%s", other, out)
				}
			}
			if !strings.Contains(out, "no fallthrough") {
				t.Errorf("does not say a FAIL on the chosen form is final (no fallthrough)\n%s", out)
			}
			assertNoHostContacted(t, marker)
		})
	}
}
