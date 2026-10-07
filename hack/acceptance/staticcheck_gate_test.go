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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestK3smCIGateRunsPinnedStaticcheck proves that hack/ci.sh runs exactly the
// staticcheck version docs/GO-STANDARDS.md pins, over non-test code, and goes RED
// rather than silently skipping or silently using another version.
//
// A different staticcheck reports different findings, so an unpinned stage lets
// the gate's verdict depend on whichever binary the host happens to have. The
// pin therefore lives in one documented place (GO-STANDARDS.md §Commit gates)
// and one constant (STATICCHECK_VERSION in ci.sh), and this test holds them equal.
//
// Static subtests read only this repo's own hack/ci.sh and docs/GO-STANDARDS.md:
//
//	pin_equals_go_standards  GO-STANDARDS.md carries exactly one install pin, and
//	                         ci.sh defines STATICCHECK_VERSION once, equal to it
//	no_literal_pin_in_ci     no `staticcheck@<digits>` literal in ci.sh, so the
//	                         install hint cannot drift from the constant
//	scope_is_non_test        the stage runs `-tests=false ./...`
//
// Behavioural subtests run the real, shipped ci.sh in the same symlink sandbox
// the go-list guard tests use (see ci_guard_test.go), with a zzpkg fixture so the
// Go block, and therefore the stage, is actually reached. The environment is
// replaced wholesale: PATH is a directory of links to only the tools ci.sh needs
// (plus, per case, a fake staticcheck), GOPATH and GOMODCACHE are empty temp
// dirs. No network and no real staticcheck are needed, and the result does not
// depend on whether the host has one installed.
//
//	absent_tool_is_red   no staticcheck anywhere: non-zero exit, install hint
//	wrong_version_is_red a fake reporting another version: non-zero exit, both
//	                     versions named, and the fake never asked to lint
//	pinned_version_runs  a fake reporting the pin: invoked with -tests=false ./...
//	                     after the vet/build/test stages
//
// Against the ci.sh preceding the pinned stage, pin_equals_go_standards,
// no_literal_pin_in_ci and wrong_version_is_red are red (it had no constant,
// carried the version as a literal in its hint, and ran any staticcheck it found).
func TestK3smCIGateRunsPinnedStaticcheck(t *testing.T) {
	root := repoRoot(t)
	script := filepath.Join(root, "hack", "ci.sh")
	ciRaw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("read ci.sh: %v", err)
	}
	ci := string(ciRaw)
	stdRaw, err := os.ReadFile(filepath.Join(root, "docs", "GO-STANDARDS.md"))
	if err != nil {
		t.Fatalf("read docs/GO-STANDARDS.md: %v", err)
	}
	pin, pinErr := parseStaticcheckPin(string(stdRaw))

	t.Run("pin_equals_go_standards", func(t *testing.T) {
		parseCases := []struct {
			name    string
			doc     string
			want    string
			wantErr bool
		}{
			{name: "one pin", doc: "x `go install honnef.co/go/tools/cmd/staticcheck@2026.2.1`. y", want: "2026.2.1"},
			{name: "no pin", doc: "go install honnef.co/go/tools/cmd/staticcheck", wantErr: true},
			{name: "two pins", doc: "honnef.co/go/tools/cmd/staticcheck@2026.2.1 and honnef.co/go/tools/cmd/staticcheck@2025.1", wantErr: true},
			{name: "two equal pins", doc: "honnef.co/go/tools/cmd/staticcheck@2026.2.1 honnef.co/go/tools/cmd/staticcheck@2026.2.1", wantErr: true},
		}
		for _, pc := range parseCases {
			got, err := parseStaticcheckPin(pc.doc)
			if pc.wantErr {
				if err == nil {
					t.Errorf("parse %q: accepted %q, want rejection", pc.name, got)
				}
				continue
			}
			if err != nil || got != pc.want {
				t.Errorf("parse %q: got %q, %v; want %q", pc.name, got, err, pc.want)
			}
		}

		if pinErr != nil {
			t.Fatalf("docs/GO-STANDARDS.md: %v", pinErr)
		}
		defs := regexp.MustCompile(`(?m)^STATICCHECK_VERSION=(\S+)`).FindAllStringSubmatch(ci, -1)
		if len(defs) != 1 {
			t.Fatalf("ci.sh defines STATICCHECK_VERSION %d times, want exactly 1", len(defs))
		}
		if got := strings.Trim(defs[0][1], `"'`); got != pin {
			t.Errorf("ci.sh STATICCHECK_VERSION=%s, docs/GO-STANDARDS.md pins %s", got, pin)
		}
	})

	t.Run("no_literal_pin_in_ci", func(t *testing.T) {
		if m := regexp.MustCompile(`staticcheck@[0-9][^\s)"]*`).FindAllString(ci, -1); len(m) > 0 {
			t.Errorf("ci.sh carries literal pin(s) %q; build the hint from STATICCHECK_VERSION", m)
		}
	})

	t.Run("scope_is_non_test", func(t *testing.T) {
		if !strings.Contains(ci, "-tests=false ./...") {
			t.Errorf("ci.sh does not run staticcheck with -tests=false ./...")
		}
	})

	if pinErr != nil {
		t.Fatalf("behavioural cases need the documented pin: %v", pinErr)
	}

	cases := []struct {
		name        string
		versionLine string // the fake's `-version` output; "" = no staticcheck at all
		wantRed     bool   // the script must exit non-zero
		wantOut     []string
		wantMarker  bool
	}{
		{
			name:    "absent_tool_is_red",
			wantRed: true,
			wantOut: []string{"not installed", "staticcheck@" + pin},
		},
		{
			name:        "wrong_version_is_red",
			versionLine: "staticcheck 2025.1 (0.6.0)",
			wantRed:     true,
			wantOut:     []string{"2025.1", pin},
		},
		{
			// Exit status is not asserted: the stages after the Go block
			// (go mod tidy's no-diff check, the genproto replace) legitimately
			// fail against the sandbox module.
			name:        "pinned_version_runs",
			versionLine: "staticcheck " + pin + " (0.8.1)",
			wantOut:     []string{"] staticcheck"},
			wantMarker:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "staticcheck-argv")
			env := staticcheckSandboxEnv(t, tc.versionLine, marker)
			extra := map[string]string{
				"zzpkg/zz.go": licensed(t, script, "package zzpkg\n\n// Answer is here only so the package is non-empty.\nfunc Answer() int { return 42 }\n"),
			}
			out, ok := sandboxCIEnv(t, script, goModOK, extra, env)

			if tc.wantRed && ok {
				t.Errorf("ci.sh exited zero, want RED:\n%s", out)
			}
			for _, w := range tc.wantOut {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			// The stage must come after vet/build/test, so a host tool problem
			// never stops those from running.
			sc := strings.Index(out, "] staticcheck")
			if sc < 0 {
				t.Fatalf("staticcheck stage never reached:\n%s", out)
			}
			for _, stage := range []string{"] go vet", "] go build", "] go test"} {
				if i := strings.Index(out, stage); i < 0 || i > sc {
					t.Errorf("stage %q not run before the staticcheck stage:\n%s", stage, out)
				}
			}

			argv, err := os.ReadFile(marker)
			switch {
			case tc.wantMarker && err != nil:
				t.Errorf("the pinned staticcheck was never run to lint (no marker): %v\n%s", err, out)
			case tc.wantMarker && !strings.Contains(string(argv), "-tests=false ./..."):
				t.Errorf("staticcheck ran with %q, want -tests=false ./...", strings.TrimSpace(string(argv)))
			case !tc.wantMarker && err == nil:
				t.Errorf("a non-pinned staticcheck was run to lint with %q:\n%s", strings.TrimSpace(string(argv)), out)
			}
		})
	}
}

// staticcheckPinRE matches the documented install pin. One regex, shared by the
// table cases and the real document, so the rejection the table proves is the
// rejection the real check applies.
var staticcheckPinRE = regexp.MustCompile("honnef\\.co/go/tools/cmd/staticcheck@([0-9][^\\s`'\")]*[0-9A-Za-z])")

// parseStaticcheckPin returns the single staticcheck version pinned in doc. Zero
// or more than one pin is an error: two pins, even equal ones, leave the reader
// unsure which one the gate follows.
func parseStaticcheckPin(doc string) (string, error) {
	m := staticcheckPinRE.FindAllStringSubmatch(doc, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("want exactly one honnef.co/go/tools/cmd/staticcheck@<version> pin, found %d", len(m))
	}
	return m[0][1], nil
}

// staticcheckSandboxEnv builds the full environment for a behavioural case.
// PATH holds links to only the tools ci.sh runs, plus a fake staticcheck when
// versionLine is set; GOPATH and GOMODCACHE are empty, so no host staticcheck
// is reachable by either of the stage's lookups. The fake prints versionLine
// for -version and records any other invocation's argv in marker.
func staticcheckSandboxEnv(t *testing.T, versionLine, marker string) []string {
	t.Helper()
	bin := t.TempDir()
	tools := []struct {
		name     string
		required bool
	}{
		{"bash", true}, {"env", true}, {"dirname", true}, {"go", true}, {"gofmt", true},
		{"git", true}, {"python3", true}, {"grep", true}, {"mktemp", true}, {"rm", true},
		{"cat", true},
		// The cgo toolchain, when the host has one (ci.sh builds CGO_ENABLED=1).
		{"cc", false}, {"clang", false}, {"xcrun", false},
	}
	for _, tl := range tools {
		tool := tl.name
		p, err := exec.LookPath(tool)
		if err != nil {
			if tl.required {
				t.Fatalf("ci.sh needs %s on PATH: %v", tool, err)
			}
			continue
		}
		if !filepath.IsAbs(p) {
			if p, err = filepath.Abs(p); err != nil {
				t.Fatalf("abs %s: %v", tool, err)
			}
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatalf("link %s: %v", tool, err)
		}
	}
	if versionLine != "" {
		fake := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo '%s'; exit 0; fi\nprintf '%%s\\n' \"$*\" > '%s'\nexit 0\n", versionLine, marker)
		if err := os.WriteFile(filepath.Join(bin, "staticcheck"), []byte(fake), 0o755); err != nil {
			t.Fatalf("write fake staticcheck: %v", err)
		}
	}

	goEnv := func(key string) string {
		out, err := exec.Command("go", "env", key).Output()
		if err != nil {
			t.Fatalf("go env %s: %v", key, err)
		}
		return strings.TrimSpace(string(out))
	}
	gopath := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home dir: %v", err)
	}
	return []string{
		"PATH=" + bin,
		"HOME=" + home,
		"TMPDIR=" + os.TempDir(),
		"GOROOT=" + goEnv("GOROOT"),
		"GOCACHE=" + goEnv("GOCACHE"),
		"GOPATH=" + gopath,
		"GOMODCACHE=" + filepath.Join(gopath, "pkg", "mod"),
		"GOWORK=off",
		"GOFLAGS=",
		"GOTOOLCHAIN=local",
		"GOPROXY=off",
	}
}
