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

package testgate

// TestNoUntaggedRealSocketTests is the module-wide gate that keeps real sockets
// out of the unit tier: unit tests fake at seams, and a test that binds or dials a
// kernel socket (loopback included) belongs behind //go:build integration. The
// detector, the exemption rule, the allowlist grammar, and the known limits are
// in realsocket_detector_test.go. A twin of this gate lives in the k3sm.io/darwin-net
// module and is kept in lockstep with this one.
//
// Files that still open real sockets are listed in testdata/realsocket.allow,
// each with a date. The list only shrinks: an entry past its date fails, an entry
// dated more than 183 days out fails, and an entry whose file no longer opens a
// socket fails until it is deleted.

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// realSocketModule is the module this gate guards.
const realSocketModule = "k3sm.io/k3sm"

// TestNoUntaggedRealSocketTests fails on every untagged real-socket test file not
// on the allowlist, and on every allowlist entry that is expired, too far out,
// stale, malformed, or duplicated, reporting them all at once.
func TestNoUntaggedRealSocketTests(t *testing.T) {
	t.Parallel()

	root := realSocketModuleRoot(t)
	findings, err := runRealSocketGate(root, filepath.Join(root, "internal", "testgate", "testdata", "realsocket.allow"), realSocketNow())
	if err != nil {
		t.Fatalf("real-socket gate: %v", err)
	}
	if len(findings) > 0 {
		t.Fatalf("real-socket gate: %d finding(s):\n\t%s", len(findings), strings.Join(findings, "\n\t"))
	}
}

// realSocketModuleRoot walks up from the working directory to the go.mod and
// asserts it declares realSocketModule, so the gate never scans some other tree.
func realSocketModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		f, err := os.Open(filepath.Join(dir, "go.mod"))
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if mod, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "module "); ok {
					if got := strings.TrimSpace(mod); got != realSocketModule {
						t.Fatalf("go.mod at %s declares module %q, want %q", dir, got, realSocketModule)
					}
					return dir
				}
			}
			t.Fatalf("go.mod at %s declares no module", dir)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory")
		}
		dir = parent
	}
}

// TestRealSocketExemptTagsMatchCI holds realSocketExemptTags equal to the tag set
// of hack/ci.sh's tag-vet loop (`for tag in ...; do`), so the tiers this gate
// exempts and the tiers the module vets cannot drift apart. It fails closed: a
// missing or ambiguous loop line is a failure, not a skip.
func TestRealSocketExemptTagsMatchCI(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(realSocketModuleRoot(t), "hack", "ci.sh"))
	if err != nil {
		t.Fatalf("read hack/ci.sh: %v", err)
	}
	var loops [][]string
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "for tag in ")
		if !ok {
			continue
		}
		list, ok := strings.CutSuffix(strings.TrimSpace(rest), "; do")
		if !ok {
			continue
		}
		loops = append(loops, strings.Fields(list))
	}
	if len(loops) != 1 {
		t.Fatalf("hack/ci.sh has %d `for tag in ...; do` lines, want exactly 1 (the tag-vet loop)", len(loops))
	}
	got := slices.Sorted(slices.Values(loops[0]))
	want := slices.Sorted(slices.Values(realSocketExemptTags))
	if !slices.Equal(got, want) {
		t.Fatalf("hack/ci.sh vets tags %v but realSocketExemptTags is %v: a tagged tier must be both vetted and exempt", got, want)
	}
}
