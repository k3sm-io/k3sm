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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// B168 — every repo's hack/ci.sh guards its Go stages on `go list ./...`. The
// original guard tested only whether the OUTPUT was empty:
//
//	if [ -n "$(CGO_ENABLED=$CGO go list ./... 2>/dev/null)" ]; then ... fi
//
// which cannot distinguish the case it was written for — a repo with no Go
// packages yet — from `go list` FAILING (broken go.mod, unresolvable dependency,
// bad GOWORK, absent toolchain). In the failure case the 2>/dev/null swallowed
// the reason, vet/build/test were skipped, and the script still printed
// "OK: <repo> ci green": a fail-open gate, the B165 class.
//
// The fix keys on go list's EXIT STATUS instead, which splits three outcomes the
// old guard collapsed into two. All three are pinned below, because the obvious
// over-correction — capturing `2>&1` so the reason is not lost — folds go list's
// "matched no packages" WARNING into the captured value and makes a genuinely
// package-less module look populated, trading the fail-open for a false positive:
//
//	exit != 0                  -> hard error, with go list's stderr shown
//	exit 0, empty stdout       -> the legitimate quiet skip
//	exit 0, non-empty stdout   -> run gofmt/vet/build/test
//
// Every case runs the real, shipped hack/ci.sh of every repo it can reach — never
// a re-implementation of the guard, which would prove nothing about what ships.
//
// Mechanics: the repo's own hack/ci.sh is invoked with its $0 inside a throwaway
// sandbox (ci.sh does `cd "$(dirname "$0")/.."`, which does not resolve symlinks,
// so a hack/ of symlinks back into the real repo lands the script in the sandbox
// with its real helpers). The sandbox holds only the fixture, so the guard is
// reached and the stages it guards have nothing real to do. GOWORK=off keeps the
// sandbox module from being rejected for sitting outside the Go workspace, which
// would confound the verdicts. No real repo is read for anything but its scripts,
// and none is written to.

// ciGuardRepos are the repo directory names whose hack/ci.sh carry this guard.
// Only k3sm is guaranteed present (it is this module); the siblings are checked
// opportunistically, since they are independent git repos checked out next to
// k3sm in the workspace and in a lane, but need not be.
var ciGuardRepos = []string{"k3sm", "apis", "runtimed", "darwin-net"}

const (
	// skipLine is the substring every repo's legitimate no-Go-packages branch prints.
	skipLine = "no Go packages yet — skipping vet/build/test"
	// failLine is the substring the fixed guard prints when go list exits non-zero.
	failLine = "go list ./... failed"
)

// ciScripts resolves the reachable hack/ci.sh paths, keyed by repo name. k3sm's
// own is required; a missing sibling is skipped rather than fatal.
func ciScripts(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)          // .../<workspace-or-lane>/k3sm
	parent := filepath.Dir(root) // the workspace or lane directory
	self := filepath.Base(root)
	found := map[string]string{}
	for _, name := range ciGuardRepos {
		dir := root
		if name != self {
			dir = filepath.Join(parent, name)
		}
		p := filepath.Join(dir, "hack", "ci.sh")
		if _, err := os.Stat(p); err == nil {
			found[name] = p
		}
	}
	if _, ok := found[self]; !ok {
		t.Fatalf("ciScripts: this repo's own hack/ci.sh not found under %s", root)
	}
	return found
}

// sandboxCI builds a throwaway repo whose hack/ entries symlink to the real
// repo's, writes the fixture files into it, runs the sandbox hack/ci.sh, and
// returns the combined output plus whether the script exited zero. An empty
// goMod writes no go.mod at all.
func sandboxCI(t *testing.T, realScript, goMod string, extra map[string]string) (out string, ok bool) {
	t.Helper()
	realHack := filepath.Dir(realScript)

	sandbox := t.TempDir()
	hack := filepath.Join(sandbox, "hack")
	if err := os.Mkdir(hack, 0o755); err != nil {
		t.Fatalf("mkdir sandbox hack: %v", err)
	}
	entries, err := os.ReadDir(realHack)
	if err != nil {
		t.Fatalf("read %s: %v", realHack, err)
	}
	for _, e := range entries {
		if err := os.Symlink(filepath.Join(realHack, e.Name()), filepath.Join(hack, e.Name())); err != nil {
			t.Fatalf("symlink %s: %v", e.Name(), err)
		}
	}
	files := map[string]string{}
	for rel, b := range extra {
		files[rel] = b
	}
	if goMod != "" {
		files["go.mod"] = goMod
	}
	for rel, b := range files {
		full := filepath.Join(sandbox, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(b), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	// The script must be invoked by its SANDBOX path — ci.sh derives its repo root
	// from $0, and dirname does not resolve the symlink.
	cmd := exec.Command("/usr/bin/env", "bash", filepath.Join(hack, "ci.sh"))
	cmd.Dir = sandbox
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	done := make(chan struct{})
	var raw []byte
	var runErr error
	go func() {
		raw, runErr = cmd.CombinedOutput()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Minute):
		t.Fatalf("sandbox run of %s did not finish within 3m", realScript)
	}
	return string(raw), runErr == nil
}

const (
	// goModOK is a valid module. With no .go files beside it, `go list ./...`
	// exits 0 with EMPTY stdout and a "matched no packages" warning on stderr.
	goModOK = "module k3sm.io/ci-guard-selftest\n\ngo 1.25\n"
	// goModBroken carries an unparseable directive, so `go list` cannot even read
	// the module and exits non-zero.
	goModBroken = "module k3sm.io/ci-guard-selftest\n\ngo 1.25\n\nthis is not a valid go.mod directive\n"
)

// licensed renders a gofmt-clean Go file carrying the repo's Apache header. The
// header must be present verbatim: hack/verify-boilerplate.sh runs BEFORE the
// guard, so a header-less fixture would be rejected first and the guard would
// never be reached — quietly making the test vacuous.
func licensed(t *testing.T, realScript, body string) string {
	t.Helper()
	hdr, err := os.ReadFile(filepath.Join(filepath.Dir(realScript), "boilerplate", "boilerplate.go.txt"))
	if err != nil {
		t.Fatalf("read boilerplate header: %v", err)
	}
	return strings.TrimRight(string(hdr), "\n") + "\n\n" + body
}

// TestCIGuardFailsWhenGoListErrors is the B168 regression: a hack/ci.sh whose
// `go list ./...` cannot enumerate the module must exit NON-ZERO and say why. It
// must NOT take the no-Go-packages branch — doing so is what let the old guard
// report green over a Go gate that never ran.
func TestCIGuardFailsWhenGoListErrors(t *testing.T) {
	cases := []struct {
		name    string
		goMod   string
		extra   func(t *testing.T, script string) map[string]string
		wantErr string // a fragment of go list's own stderr that must be surfaced
	}{
		{
			// The module cannot be parsed. `go mod tidy` fails on this too, so the
			// OLD script also went red here — but incidentally, three stages later,
			// with vet/build/test silently skipped and the true reason discarded.
			name:    "go.mod parse error",
			goMod:   goModBroken,
			wantErr: "unknown directive",
		},
		{
			// No module at all — `go list ./...` exits 1. Distinct from the
			// package-less module below, which exits 0 and is a legitimate skip.
			name:    "no go.mod at all",
			goMod:   "",
			wantErr: "does not contain main module",
		},
		{
			// The module parses; `go list` then fails LOADING PACKAGES. `go mod
			// tidy` is untroubled by it, so this is the fixture that pins the
			// headline of B168: under the old guard all four scripts printed
			// "OK: <repo> ci green" and exited ZERO, having run no Go stage at all.
			name:  "conflicting package names in one directory",
			goMod: goModOK,
			extra: func(t *testing.T, script string) map[string]string {
				return map[string]string{
					"zzconflict/a.go": licensed(t, script, "package alpha\n"),
					"zzconflict/b.go": licensed(t, script, "package beta\n"),
				}
			},
			wantErr: "found packages alpha",
		},
	}

	for name, script := range ciScripts(t) {
		for _, tc := range cases {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				var extra map[string]string
				if tc.extra != nil {
					extra = tc.extra(t, script)
				}
				out, ok := sandboxCI(t, script, tc.goMod, extra)
				if ok {
					t.Errorf("%s exited ZERO though `go list` failed — the fail-open is back:\n%s", script, out)
				}
				if !strings.Contains(out, failLine) {
					t.Errorf("%s did not report the go list failure (want %q):\n%s", script, failLine, out)
				}
				if strings.Contains(out, skipLine) {
					t.Errorf("%s took the no-Go-packages branch on a FAILING go list:\n%s", script, out)
				}
				// The captured stderr must reach the operator: "failed" with the
				// reason swallowed is the same dead end as the old 2>/dev/null.
				if !strings.Contains(out, tc.wantErr) {
					t.Errorf("%s did not surface go list's stderr (want %q):\n%s", script, tc.wantErr, out)
				}
			})
		}
	}
}

// TestCIGuardSkipsWhenNoGoPackages pins the case the guard was written for, and
// the one an over-correction breaks: a module that genuinely has no Go packages
// (`go list` exits ZERO with empty stdout, plus a "matched no packages" warning
// on STDERR — apis was such a repo early on) must still take the quiet skip. A
// guard that captured stderr into the same value would see that warning, judge
// the module populated, and run the Go stages over nothing.
//
// Only the guard's branch is asserted, not the script's exit status: the stages
// AFTER the guard (go mod tidy's no-diff check, k3sm's genproto replace check,
// the apis buf stages) legitimately fail against an empty sandbox and are not
// what this test is about.
func TestCIGuardSkipsWhenNoGoPackages(t *testing.T) {
	for name, script := range ciScripts(t) {
		t.Run(name, func(t *testing.T) {
			out, _ := sandboxCI(t, script, goModOK, nil)
			if !strings.Contains(out, skipLine) {
				t.Errorf("%s did not take the no-Go-packages skip (want %q):\n%s", script, skipLine, out)
			}
			if strings.Contains(out, failLine) {
				t.Errorf("%s reported a go list failure for a clean package-less module:\n%s", script, out)
			}
		})
	}
}

// TestCIGuardRunsWhenPackagesExist pins the third outcome: a healthy module must
// actually REACH gofmt/vet/build/test. Without it the whole guard could be made
// to "pass" the two tests above by failing or skipping unconditionally.
//
// Exit status is again not asserted, for the same reason as the skip test — the
// repo-specific stages after the Go block do not apply to a sandbox module.
func TestCIGuardRunsWhenPackagesExist(t *testing.T) {
	for name, script := range ciScripts(t) {
		t.Run(name, func(t *testing.T) {
			extra := map[string]string{
				"zzpkg/zz.go": licensed(t, script, "package zzpkg\n\n// Answer is here only so the package is non-empty.\nfunc Answer() int { return 42 }\n"),
			}
			out, _ := sandboxCI(t, script, goModOK, extra)
			for _, stage := range []string{"] go vet", "] go build", "] go test"} {
				if !strings.Contains(out, stage) {
					t.Errorf("%s did not reach the %q stage for a healthy module:\n%s", script, stage, out)
				}
			}
			if strings.Contains(out, skipLine) {
				t.Errorf("%s skipped the Go stages for a module that HAS packages:\n%s", script, out)
			}
			if strings.Contains(out, failLine) {
				t.Errorf("%s reported a go list failure for a healthy module:\n%s", script, out)
			}
		})
	}
}
