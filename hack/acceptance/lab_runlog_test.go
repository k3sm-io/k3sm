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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// B575 — the run-log header and verdict functions live in one sourced library,
// hack/lab/lib/runlog.sh. Before it, hack/lab/m17-interconnect.sh read the four
// function bodies out of hack/lab/m11.sh with sed and evaluated them, so moving
// text inside m11.sh could break another ladder.

const runlogLib = "hack/lab/lib/runlog.sh"

// runlogFuncs are the functions only runlogLib may define.
var runlogFuncs = []string{"emit_run_log_header", "emit_run_log_verdict", "artifact_sha256", "repo_git_sha"}

// runlogDriver sources the tolerations helper ($1) and the run-log library ($2)
// with the variables a lab script sets, then calls every function once. The
// artifact is $3; REPO_ROOT is $4.
const runlogDriver = `set -u
. "$1"
. "$2"
GATE_NAME="M11-lab"
MODE="full"
REPO_ROOT="$4"
K3SM_ARTIFACT="$3"
emit_run_log_header "FAIL (provisional; the final result line below is the verdict, and a log that ends here did not finish)"
emit_run_log_verdict PASS
K3SM_RC_TAG="v0.0.0-rc.1" artifact_sha256
K3SM_ARTIFACT="" artifact_sha256
K3SM_ARTIFACT="$3.absent" artifact_sha256
for r in apis runtimed darwin-net k3sm; do repo_git_sha "$r"; done
`

// runlogStubs writes date and git stand-ins so the header is deterministic: date
// prints a fixed instant, and git prints a fixed commit named after the repo
// directory it is asked about.
func runlogStubs(t *testing.T, dir string) {
	t.Helper()
	stubs := map[string]string{
		"date": "#!/bin/sh\necho 2026-10-15T12:00:00Z\n",
		"git": "#!/bin/sh\n" +
			"[ \"$1\" = -C ] || exit 2\n" +
			"case \"$(basename \"$2\")\" in\n" +
			"apis) echo 1111111111111111111111111111111111111111 ;;\n" +
			"runtimed) echo 2222222222222222222222222222222222222222 ;;\n" +
			"k3sm) echo 4444444444444444444444444444444444444444 ;;\n" +
			"*) exit 128 ;;\n" +
			"esac\n",
	}
	for name, body := range stubs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write %s stand-in: %v", name, err)
		}
	}
}

// runlogDefRE matches a definition of one of runlogFuncs; runlogExtractRE
// matches a script reading one out of another file by its definition line (a
// sed/awk/grep address such as /^emit_run_log_header() {$/) or calling the old
// load_header loader.
var (
	runlogDefRE     = regexp.MustCompile(`(?m)^\s*(function\s+)?(` + strings.Join(runlogFuncs, "|") + `)\s*\(\)`)
	runlogExtractRE = regexp.MustCompile(`[/'"^](` + strings.Join(runlogFuncs, "|") + `)\s*\(\)|\bload_header\b`)
)

// sourcesRunlogRE matches a script sourcing runlogLib.
var sourcesRunlogRE = regexp.MustCompile(`(?m)^\s*(\.|source)\s+\S*lib/runlog\.sh`)

// runlogAllowlist names the lab scripts that still define their own copies, each
// with the reason.
var runlogAllowlist = map[string]string{
	"hack/lab/B46.sh": "its header differs (mode leg-<n>, an evidence_dir line, a fixed provisional result); adopting the library changes its log, a separate change",
}

// TestLabRunLogHeaderHelpersAreShared is the B575 gate. It renders a run-log
// header through the library under /bin/bash (the macOS bash 3.2 the rig runs)
// against a golden file, and fails when a hack/lab script other than the library
// defines or text-extracts those functions.
func TestLabRunLogHeaderHelpersAreShared(t *testing.T) {
	root := repoRoot(t)

	t.Run("golden", func(t *testing.T) {
		requireLabBash(t)
		env, marker := labEnv(t)
		bin := strings.TrimPrefix(env[0], "PATH=")
		bin = bin[:strings.Index(bin, ":")]
		runlogStubs(t, bin)

		// REPO_ROOT's siblings: apis, runtimed and k3sm are checked out (a .git
		// entry), darwin-net is absent, so both repo_git_sha branches render.
		ws := t.TempDir()
		for _, r := range []string{"apis", "runtimed", "k3sm"} {
			if err := os.MkdirAll(filepath.Join(ws, r, ".git"), 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", r, err)
			}
		}
		artifact, err := filepath.Abs(filepath.Join("testdata", "lab-runlog", "artifact.bin"))
		if err != nil {
			t.Fatalf("abs artifact: %v", err)
		}
		code, stdout, stderr := runLabBash(t, env, "-c", runlogDriver, "driver",
			filepath.Join(root, filepath.FromSlash(tolerationsLib)),
			filepath.Join(root, filepath.FromSlash(runlogLib)),
			artifact, filepath.Join(ws, "k3sm"))
		if code != 0 {
			t.Fatalf("exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		assertNoHostContacted(t, marker)
		want, err := os.ReadFile(filepath.Join("testdata", "lab-runlog", "header.golden"))
		if err != nil {
			t.Fatalf("read golden: %v", err)
		}
		if stdout != string(want) {
			t.Errorf("output differs from testdata/lab-runlog/header.golden\ngot:\n%s\nwant:\n%s", stdout, want)
		}
		if stderr != "" {
			t.Errorf("stderr = %q, want empty", stderr)
		}
	})

	t.Run("single definition", func(t *testing.T) {
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
		sort.Strings(scripts)
		defines := map[string]bool{}
		for _, p := range scripts {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				t.Fatalf("rel %s: %v", p, err)
			}
			rel = filepath.ToSlash(rel)
			if rel == runlogLib {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			if m := runlogExtractRE.Find(b); m != nil {
				t.Errorf("%s text-extracts a run-log function (%q): source %s instead", rel, m, runlogLib)
			}
			if m := runlogDefRE.Find(b); m != nil {
				defines[rel] = true
				if _, ok := runlogAllowlist[rel]; !ok {
					t.Errorf("%s defines %q: source %s instead, or add an allowlist entry with a reason", rel, strings.TrimSpace(string(m)), runlogLib)
				}
			}
		}
		for rel := range runlogAllowlist {
			if !defines[rel] {
				t.Errorf("allowlist entry %s defines no run-log function; remove it", rel)
			}
		}
	})
}
