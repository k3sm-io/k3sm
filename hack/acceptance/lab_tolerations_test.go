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
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// B570 — lab harness pods tolerate the VK node taint k3sm.io/provider and nothing
// else, so a NoExecute taint another workload's controller put on a lab node
// evicts them mid-leg. hack/lab/lib/tolerations.sh renders every lab pod's
// tolerations: the provider entry plus one Exists toleration per key the operator
// names in K3SM_LAB_TOLERATE_KEYS. The tests below run the real helper and the
// real adopting scripts under /bin/bash (the macOS bash 3.2 the rig runs), never a
// re-implementation.

const (
	tolerationsLib  = "hack/lab/lib/tolerations.sh"
	labBash         = "/bin/bash"
	tolerateKeysEnv = "K3SM_LAB_TOLERATE_KEYS"
)

// tolerationsDriver calls every rendering function of the helper once, so one
// golden file pins the YAML (default and empty provider effect), the JSON and the
// run-log header for one value of K3SM_LAB_TOLERATE_KEYS.
const tolerationsDriver = `set -u
. "$1"
lab_tolerations_yaml
lab_tolerations_yaml ""
lab_tolerations_json
lab_tolerations_json ""
lab_tolerations_header
`

// labEnv is a scrubbed environment: a fixed PATH whose first entry holds kubectl,
// ssh, scp and sudo stand-ins that record any call in a marker file, plus extra.
// Nothing from the developer's shell (a rig's KUBECONFIG, an exported
// K3SM_LAB_TOLERATE_KEYS) reaches the script.
func labEnv(t *testing.T, extra ...string) ([]string, string) {
	t.Helper()
	shim := t.TempDir()
	marker := filepath.Join(shim, "called")
	for _, tool := range []string{"kubectl", "ssh", "scp", "sudo"} {
		body := "#!/bin/sh\necho " + tool + " >>'" + marker + "'\nexit 1\n"
		if err := os.WriteFile(filepath.Join(shim, tool), []byte(body), 0o755); err != nil {
			t.Fatalf("write %s stand-in: %v", tool, err)
		}
	}
	env := []string{"PATH=" + shim + ":/usr/bin:/bin", "HOME=" + t.TempDir(), "TMPDIR=" + t.TempDir()}
	return append(env, extra...), marker
}

// runLabBash runs /bin/bash with args and env, returning the exit code, stdout and
// stderr separately (an error row must print nothing on stdout).
func runLabBash(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(labBash, args...)
	cmd.Env = env
	cmd.Dir = repoRoot(t)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("run %s %v: %v", labBash, args, err)
	return -1, "", ""
}

func requireLabBash(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(labBash); err != nil {
		t.Skipf("%s is absent (%v); the lab helper targets the system bash", labBash, err)
	}
}

// TestLabHarnessTolerateKeys is the B570 gate. It pins the helper's output for
// every shape of K3SM_LAB_TOLERATE_KEYS against golden files, its refusal of every
// key that is not a Kubernetes qualified name (exit 2, nothing on stdout), and,
// for each adopting lab script, that the pod manifests the script would apply
// carry both operator keys and the provider entry exactly once, so a script that
// reverts to a hard-coded tolerations line reds the gate.
func TestLabHarnessTolerateKeys(t *testing.T) {
	requireLabBash(t)
	lib := filepath.Join(repoRoot(t), filepath.FromSlash(tolerationsLib))

	t.Run("golden", func(t *testing.T) {
		cases := []struct {
			name   string
			keys   *string
			golden string
		}{
			{"unset", nil, "unset.golden"},
			{"empty", strPtr(""), "empty.golden"},
			{"all spaces", strPtr("   "), "spaces.golden"},
			{"one key", strPtr("estate.example.com/off"), "one-key.golden"},
			{"two keys", strPtr("  estate.example.com/off   example.com/lab_hold.v2 "), "two-keys.golden"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var extra []string
				if tc.keys != nil {
					extra = append(extra, tolerateKeysEnv+"="+*tc.keys)
				}
				env, _ := labEnv(t, extra...)
				code, stdout, stderr := runLabBash(t, env, "-c", tolerationsDriver, "driver", lib)
				if code != 0 {
					t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
				}
				want, err := os.ReadFile(filepath.Join("testdata", "lab-tolerations", tc.golden))
				if err != nil {
					t.Fatalf("read golden: %v", err)
				}
				if stdout != string(want) {
					t.Errorf("output differs from testdata/lab-tolerations/%s\ngot:\n%s\nwant:\n%s", tc.golden, stdout, want)
				}
				if stderr != "" {
					t.Errorf("stderr = %q, want empty", stderr)
				}
			})
		}
	})

	t.Run("invalid keys", func(t *testing.T) {
		cases := []struct{ name, keys string }{
			{"two slashes", "a/b/c"},
			{"64-char name", strings.Repeat("a", 64)},
			{"254-char prefix", strings.Repeat("a", 254) + "/x"},
			{"leading dash", "-estate-off"},
			{"uppercase prefix", "Estate.example.com/off"},
			{"trailing slash", "estate.example.com/"},
			{"asterisk", "*"},
			{"bad key after a good one", "estate.example.com/off a/b/c"},
		}
		for _, tc := range cases {
			for _, fn := range []string{"lab_tolerations_yaml", "lab_tolerations_json", "lab_tolerations_header"} {
				t.Run(tc.name+"/"+fn, func(t *testing.T) {
					env, _ := labEnv(t, tolerateKeysEnv+"="+tc.keys)
					code, stdout, stderr := runLabBash(t, env, "-c", "set -u\n. \"$1\"\n"+fn, "driver", lib)
					if code != 2 {
						t.Errorf("exit %d, want 2 (stdout %q, stderr %q)", code, stdout, stderr)
					}
					if stdout != "" {
						t.Errorf("stdout = %q, want nothing for an invalid key", stdout)
					}
					if !strings.Contains(stderr, "usage:") {
						t.Errorf("stderr = %q, want a usage error", stderr)
					}
				})
			}
		}
	})

	// Each adopting script prints the pod manifests it would apply under
	// K3SM_LAB_PRINT_MANIFESTS=1 and exits before any kubectl or ssh. K3SM_LAB=1
	// is set so a script that lost its print mode stops at its lab preflight (a
	// missing variable, the kubectl/ssh stand-ins) instead of booting b416's
	// integration-tier server; K3SM_WORKDIR keeps any such run inside a temp dir.
	const keyA, keyB = "estate.example.com/off", "example.com/lab-hold"
	scripts := []struct {
		script   string
		pods     int    // tolerations lines the script renders (one per pod site)
		provider string // the provider entry, in the script's own effect spelling
	}{
		{"hack/lab/b416.sh", 1, "{key: k3sm.io/provider, operator: Exists}"},
		{"hack/lab/B46.sh", 2, "{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}"},
		{"hack/lab/m11.sh", 5, "{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}"},
		{"hack/lab/m17-interconnect.sh", 2, "{key: k3sm.io/provider, operator: Exists, effect: NoSchedule}"},
	}
	for _, sc := range scripts {
		t.Run("render/"+filepath.Base(sc.script), func(t *testing.T) {
			env, marker := labEnv(t, "K3SM_LAB_PRINT_MANIFESTS=1", "K3SM_LAB=1", "K3SM_WORKDIR="+t.TempDir(),
				tolerateKeysEnv+"="+keyA+" "+keyB)
			code, stdout, stderr := runLabBash(t, env, filepath.Join(repoRoot(t), filepath.FromSlash(sc.script)))
			if code != 0 {
				t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			assertNoHostContacted(t, marker)
			if !strings.Contains(stdout, "tolerate_keys: "+keyA+" "+keyB+"\n") {
				t.Errorf("no 'tolerate_keys: %s %s' header line in:\n%s", keyA, keyB, stdout)
			}
			var lines []string
			for _, l := range strings.Split(stdout, "\n") {
				if strings.Contains(l, "tolerations:") {
					lines = append(lines, l)
				}
			}
			if len(lines) != sc.pods {
				t.Fatalf("%d tolerations lines rendered, want %d (one per pod site):\n%s", len(lines), sc.pods, stdout)
			}
			for _, l := range lines {
				if n := strings.Count(l, "k3sm.io/provider"); n != 1 {
					t.Errorf("provider entry appears %d times, want 1: %s", n, l)
				}
				for _, want := range []string{sc.provider, "{key: " + keyA + ", operator: Exists}", "{key: " + keyB + ", operator: Exists}"} {
					if !strings.Contains(l, want) {
						t.Errorf("tolerations line lacks %q: %s", want, l)
					}
				}
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// providerTolerationRE matches a k3sm.io/provider toleration written out by hand:
// the flow form ({key: k3sm.io/provider, ...}), the block form (- key:
// k3sm.io/provider) and the JSON form ("key": "k3sm.io/provider").
var providerTolerationRE = regexp.MustCompile(`key"?\s*:\s*"?k3sm\.io/provider`)

// sourcesTolerationsRE matches a script sourcing the helper.
var sourcesTolerationsRE = regexp.MustCompile(`(?m)^\s*(\.|source)\s+\S*lib/tolerations\.sh`)

// labTolerationAllowlist names the scripts that still hard-code the provider
// toleration, each with the reason it has not adopted the helper yet.
var labTolerationAllowlist = map[string]string{
	"hack/acceptance/B124.sh": "acceptance gate with flow-YAML tolerations; adoption is a separate change",
	"hack/acceptance/B234.sh": "acceptance gate with flow-YAML tolerations; adoption is a separate change",
	"hack/acceptance/B243.sh": "acceptance gate with flow-YAML tolerations; adoption is a separate change",
	"hack/acceptance/B264.sh": "acceptance gate with flow-YAML tolerations; adoption is a separate change",
	"hack/acceptance/B29.sh":  "acceptance gate with flow-YAML tolerations; adoption is a separate change",
	"hack/acceptance/B282.sh": "block-YAML heredoc tolerations; the helper renders a flow sequence",
	"hack/acceptance/B299.sh": "builds its pod as JSON; adopting lab_tolerations_json is a separate change",
}

// TestLabTolerationsUseHelper is the static guard: a lab or acceptance script that
// writes a k3sm.io/provider toleration by hand must source the helper (so its pods
// honour K3SM_LAB_TOLERATE_KEYS) or be named in labTolerationAllowlist with a
// reason. An allowlist entry that no longer matches anything is stale and fails.
func TestLabTolerationsUseHelper(t *testing.T) {
	root := repoRoot(t)
	var scripts []string
	err := filepath.WalkDir(filepath.Join(root, "hack", "lab"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".sh") {
			scripts = append(scripts, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk hack/lab: %v", err)
	}
	acc, err := filepath.Glob(filepath.Join(root, "hack", "acceptance", "*.sh"))
	if err != nil {
		t.Fatalf("glob hack/acceptance: %v", err)
	}
	scripts = append(scripts, acc...)
	sort.Strings(scripts)

	hardcoded := map[string]bool{}
	for _, p := range scripts {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("rel %s: %v", p, err)
		}
		rel = filepath.ToSlash(rel)
		if rel == tolerationsLib {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !providerTolerationRE.Match(b) {
			continue
		}
		hardcoded[rel] = true
		if sourcesTolerationsRE.Match(b) {
			continue
		}
		if _, ok := labTolerationAllowlist[rel]; ok {
			continue
		}
		t.Errorf("%s writes a k3sm.io/provider toleration by hand: source %s and render it with lab_tolerations_yaml (or _json), or add an allowlist entry with a reason", rel, tolerationsLib)
	}
	for rel := range labTolerationAllowlist {
		if !hardcoded[rel] {
			t.Errorf("allowlist entry %s matches no hand-written provider toleration; remove it", rel)
		}
	}
}
