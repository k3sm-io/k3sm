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

// Package testresults_test drives hack/lib/testresults.go (a //go:build ignore
// program) as a built binary over planted go test -json streams and registries.
package testresults_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
	buildOut  []byte
)

func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "testresults-bin-")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "testresults")
		cmd := exec.Command("go", "build", "-o", binPath, "testresults.go")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		buildOut, buildErr = cmd.CombinedOutput()
	})
	if buildErr != nil {
		t.Fatalf("build testresults.go: %v\n%s", buildErr, buildOut)
	}
	return binPath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if binPath != "" {
		_ = os.RemoveAll(filepath.Dir(binPath)) // best-effort cleanup of the temp build dir
	}
	os.Exit(code)
}

const (
	pkg   = "k3sm.io/apis/net/v1"
	other = "k3sm.io/apis/storage/v1"
	sig   = "read udp 127.0.0.1: i/o timeout"
	today = "2026-10-30"
)

func ev(action, pkg, test, output string) string {
	m := map[string]string{"Action": action, "Package": pkg}
	if test != "" {
		m["Test"] = test
	}
	if output != "" {
		m["Output"] = output
	}
	b, _ := json.Marshal(m) // a map of strings always marshals
	return string(b)
}

func stream(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func entryFor(test string) string {
	return test + `  sig="` + sig + `"  owner=maintainers  filed=2026-10-20  deadline=2026-11-20  fix=#1  reason="port collision"` + "\n"
}

var (
	green = stream(
		ev("run", pkg, "TestOK", ""),
		ev("pass", pkg, "TestOK", ""),
		ev("output", pkg, "", "ok  \t"+pkg+"\t0.1s\n"),
		ev("pass", pkg, "", ""))
	flake = stream(
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "    x_test.go:9: "+sig+"\n"),
		ev("output", pkg, "TestFlake", "--- FAIL: TestFlake (0.01s)\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("output", pkg, "", "FAIL\t"+pkg+"\t0.1s\n"),
		ev("fail", pkg, "", ""))
	race = stream(
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "WARNING: DATA RACE\n"+sig+"\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("fail", pkg, "", ""))
	subFlake = stream(
		ev("run", pkg, "TestParent", ""),
		ev("run", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent/a", sig+"\n"),
		ev("fail", pkg, "TestParent/a", ""),
		ev("pass", pkg, "TestParent/b", ""),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	nestedFlake = stream(
		ev("output", pkg, "TestTop/mid/leaf", sig+"\n"),
		ev("fail", pkg, "TestTop/mid/leaf", ""),
		ev("fail", pkg, "TestTop/mid", ""),
		ev("fail", pkg, "TestTop", ""),
		ev("fail", pkg, "", ""))
	parentOnly = stream(
		ev("output", pkg, "TestParent", sig+"\n"),
		ev("pass", pkg, "TestParent/a", ""),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	parentOwnFail = stream(
		ev("run", pkg, "TestParent", ""),
		ev("output", pkg, "TestParent", "=== RUN   TestParent\n"),
		ev("output", pkg, "TestParent", "    x_test.go:12: parent setup broke\n"),
		ev("run", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent/a", "=== RUN   TestParent/a\n"),
		ev("output", pkg, "TestParent/a", sig+"\n"),
		ev("output", pkg, "TestParent/a", "    --- FAIL: TestParent/a (0.00s)\n"),
		ev("fail", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	parentFramingOnly = stream(
		ev("run", pkg, "TestParent", ""),
		ev("output", pkg, "TestParent", "=== RUN   TestParent\n"),
		ev("run", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent/a", "=== RUN   TestParent/a\n"),
		ev("output", pkg, "TestParent/a", sig+"\n"),
		ev("output", pkg, "TestParent/a", "    --- FAIL: TestParent/a (0.00s)\n"),
		ev("fail", pkg, "TestParent/a", ""),
		ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"),
		ev("fail", pkg, "TestParent", ""),
		ev("fail", pkg, "", ""))
	pkgFail = stream(
		ev("output", pkg, "", "panic: init\n"),
		ev("fail", pkg, "", ""))
	noResult = stream(
		ev("run", pkg, "TestHang", ""),
		ev("output", pkg, "TestHang", "=== RUN TestHang\n"))
	buildFail = `{"ImportPath":"k3sm.io/apis/net/v1 [k3sm.io/apis/net/v1.test]","Action":"build-output","Output":"x.go:1: syntax error\n"}` + "\n" +
		`{"ImportPath":"k3sm.io/apis/net/v1 [k3sm.io/apis/net/v1.test]","Action":"build-fail"}` + "\n" +
		ev("fail", pkg, "", "") + "\n"
)

func TestTestResults(t *testing.T) {
	bin := binary(t)
	cases := []struct {
		name     string
		registry string // "" writes an empty file; "-" writes none
		input    string
		args     []string
		want     int
		wantOut  string
	}{
		{name: "green run, empty registry", input: green, args: []string{"-tier", "fast"}, want: 0, wantOut: "ok"},
		{name: "missing registry is empty", registry: "-", input: green, args: []string{"-tier", "full"}, want: 0},
		{name: "unlisted failure reds", input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestFlake: failed"},
		{name: "failing-test summary names the test", input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "--- FAIL: TestFlake"},
		{name: "quarantined flake is excused in the fast tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast"}, want: 3, wantOut: "QUARANTINED " + pkg + "::TestFlake"},
		{name: "affected is the fast tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "affected"}, want: 3},
		{name: "quarantined flake reds in the full tier", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "full"}, want: 1, wantOut: "the full tier reds on it"},
		{name: "quarantined flake in an edited package reds", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", pkg}, want: 1, wantOut: "edits " + pkg + " directly"},
		{name: "another edited package does not matter", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", other}, want: 3},
		{name: "signature mismatch reds", registry: strings.Replace(entryFor(pkg+"::TestFlake"), sig, "connection reset by peer", 1), input: flake, args: []string{"-tier", "fast"}, want: 1, wantOut: "does not match the recorded signature"},
		{name: "race reds even when listed", registry: entryFor(pkg + "::TestFlake"), input: race, args: []string{"-tier", "fast"}, want: 1, wantOut: "race or sanitizer report"},
		{name: "expired entry reds", registry: entryFor(pkg + "::TestFlake"), input: flake, args: []string{"-tier", "fast", "-today", "2026-11-21"}, want: 1, wantOut: "quarantine expired"},
		{name: "expired entry reds a green run", registry: entryFor(pkg + "::TestFlake"), input: green, args: []string{"-tier", "fast", "-today", "2026-11-21"}, want: 1},
		{name: "malformed line reds a green run", registry: pkg + "::TestX sig=\"x\"\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED registry: line 1"},
		{name: "unclosed quote reds", registry: pkg + "::TestX sig=\"" + sig + "\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "unparseable"},
		{name: "unknown key reds", registry: strings.TrimSuffix(entryFor(pkg+"::TestX"), "\n") + " extra=1\n", input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "unknown key"},
		{name: "short signature reds", registry: strings.Replace(entryFor(pkg+"::TestX"), sig, "timeout", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "shorter than 12"},
		{name: "race signature is refused", registry: strings.Replace(entryFor(pkg+"::TestX"), sig, "WARNING: DATA RACE here", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "refused"},
		{name: "trust surface is refused", registry: entryFor("k3sm.io/k3sm/pkg/certs::TestRotate"), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "can never be quarantined"},
		{name: "deadline before filed reds", registry: strings.Replace(entryFor(pkg+"::TestX"), "deadline=2026-11-20", "deadline=2026-10-01", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "before filed"},
		{name: "duplicate id reds", registry: entryFor(pkg+"::TestX") + entryFor(pkg+"::TestX"), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "already listed"},
		{name: "eleven entries red", registry: elevenEntries(), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "at most 10"},
		{name: "comments and blank lines are ignored", registry: "# header\n\n" + strings.TrimSuffix(entryFor(pkg+"::TestFlake"), "\n") + "  # trailing\n", input: flake, args: []string{"-tier", "fast"}, want: 3},
		{name: "unlisted parent of a quarantined subtest is excused", registry: entryFor(pkg + "::TestParent/a"), input: subFlake, args: []string{"-tier", "fast"}, want: 3, wantOut: "failed only through quarantined subtests"},
		{name: "nested unlisted parents are excused", registry: entryFor(pkg + "::TestTop/mid/leaf"), input: nestedFlake, args: []string{"-tier", "fast"}, want: 3},
		{name: "a listed parent covers no subtest", registry: entryFor(pkg + "::TestParent"), input: subFlake, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestParent/a: failed"},
		{name: "a parent failing with no failing subtest reds", registry: entryFor(pkg + "::TestParent/a"), input: parentOnly, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestParent: failed"},
		{name: "parent rule does not apply in the full tier", registry: entryFor(pkg + "::TestParent/a"), input: subFlake, args: []string{"-tier", "full"}, want: 1},
		{name: "an unlisted parent with its own failure line reds", registry: entryFor(pkg + "::TestParent/a"), input: parentOwnFail, args: []string{"-tier", "fast"}, want: 1, wantOut: "RED " + pkg + "::TestParent: failed"},
		{name: "an unlisted parent with only harness framing is excused", registry: entryFor(pkg + "::TestParent/a"), input: parentFramingOnly, args: []string{"-tier", "fast"}, want: 3, wantOut: "failed only through quarantined subtests"},
		{name: "a parent whose output repeats its subtest's lines is excused", registry: entryFor(pkg + "::TestParent/a"), input: strings.Replace(parentFramingOnly,
			ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"),
			ev("output", pkg, "TestParent", sig+"\n")+"\n"+ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"), 1), args: []string{"-tier", "fast"}, want: 3},
		{name: "an unlisted parent with a race report of its own reds", registry: entryFor(pkg + "::TestParent/a"), input: strings.Replace(parentFramingOnly,
			ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"),
			ev("output", pkg, "TestParent", "WARNING: DATA RACE\n")+"\n"+ev("output", pkg, "TestParent", "--- FAIL: TestParent (0.01s)\n"), 1), args: []string{"-tier", "fast"}, want: 1, wantOut: "race or sanitizer report"},
		{name: "a sig naming a different test is accepted", registry: strings.Replace(entryFor(pkg+"::TestX"), sig, "--- FAIL: TestOtherThing", 1), input: green, args: []string{"-tier", "fast"}, want: 0},
		{name: "a sig equal to the test id is refused", registry: strings.Replace(entryFor(pkg+"::TestFlake"), sig, pkg+"::TestFlake", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "harness"},
		{name: "a sig inside the test id is refused", registry: strings.Replace(entryFor(pkg+"::TestFlakeOverLoopback"), sig, "TestFlakeOverLoop", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "harness"},
		{name: "a sig that is the RUN line is refused", registry: strings.Replace(entryFor(pkg+"::TestFlake"), sig, "=== RUN   TestFlake", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "harness"},
		{name: "a sig that is the FAIL line is refused", registry: strings.Replace(entryFor(pkg+"::TestFlake"), sig, "--- FAIL: TestFlake (0.01s)", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "harness"},
		{name: "a sig that is a subtest FAIL line is refused", registry: strings.Replace(entryFor(pkg+"::TestParent/a"), sig, "--- FAIL: TestParent/a", 1), input: green, args: []string{"-tier", "fast"}, want: 1, wantOut: "harness"},
		{name: "package failure outside a test reds", input: pkgFail, args: []string{"-tier", "fast"}, want: 1, wantOut: pkg + "::(package)"},
		{name: "a build failure reds", input: buildFail, args: []string{"-tier", "fast"}, want: 1, wantOut: "::(build)"},
		{name: "a test with no result reds", input: noResult, args: []string{"-tier", "fast"}, want: 1, wantOut: "no result"},
		{name: "a non-JSON line reds", input: green + "FAIL something\n", args: []string{"-tier", "fast"}, want: 1, wantOut: "not JSON"},
		{name: "an empty stream reds", input: "", args: []string{"-tier", "fast"}, want: 1, wantOut: "holds no results"},
		{name: "no tier is a usage error", input: green, want: 2},
		{name: "an unknown tier is a usage error", input: green, args: []string{"-tier", "medium"}, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { runCase(t, bin, tc.registry, tc.input, tc.args, tc.want, tc.wantOut) })
	}
}

// TestQuarantineNeverExcusesAPackageRace pins that a race or sanitizer report in a
// package's output outside any test reds, whatever the registry excuses.
func TestQuarantineNeverExcusesAPackageRace(t *testing.T) {
	bin := binary(t)
	pkgRace := func(pkgAction string) string {
		return stream(
			ev("run", pkg, "TestFlake", ""),
			ev("output", pkg, "TestFlake", "    x_test.go:9: "+sig+"\n"),
			ev("output", pkg, "TestFlake", "--- FAIL: TestFlake (0.01s)\n"),
			ev("fail", pkg, "TestFlake", ""),
			ev("output", pkg, "", "==================\nWARNING: DATA RACE\nWrite at 0x00c000 by goroutine 7:\n"),
			ev("output", pkg, "", "FAIL\t"+pkg+"\t0.1s\n"),
			ev(pkgAction, pkg, "", ""))
	}
	cases := []struct {
		name, registry, input string
		want                  int
		wantOut               string
	}{
		{name: "a package race beside a quarantined failure reds", registry: entryFor(pkg + "::TestFlake"), input: pkgRace("fail"), want: 1, wantOut: pkg + "::(package)"},
		{name: "the red names the race", registry: entryFor(pkg + "::TestFlake"), input: pkgRace("fail"), want: 1, wantOut: "race or sanitizer report"},
		{name: "a package race reds even when the package passes", registry: entryFor(pkg + "::TestFlake"), input: pkgRace("pass"), want: 1, wantOut: pkg + "::(package)"},
		{name: "a sanitizer report in package output reds", registry: entryFor(pkg + "::TestFlake"), input: strings.Replace(pkgRace("fail"), "WARNING: DATA RACE", "ERROR: AddressSanitizer: heap-use-after-free", 1), want: 1, wantOut: pkg + "::(package)"},
		{name: "a package race with every test passing reds", registry: "", input: stream(
			ev("run", pkg, "TestOK", ""),
			ev("pass", pkg, "TestOK", ""),
			ev("output", pkg, "", "WARNING: DATA RACE\n"),
			ev("pass", pkg, "", "")), want: 1, wantOut: pkg + "::(package)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runCase(t, bin, tc.registry, tc.input, []string{"-tier", "fast"}, tc.want, tc.wantOut)
		})
	}
}

// runCase writes the registry ("-" writes none), runs the binary over input, and
// checks the exit status and an output substring.
func runCase(t *testing.T, bin, registry, input string, extra []string, want int, wantOut string) {
	t.Helper()
	dir := t.TempDir()
	reg := filepath.Join(dir, "quarantine.txt")
	if registry != "-" {
		if err := os.WriteFile(reg, []byte(registry), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := append([]string{"-registry", reg, "-today", today}, extra...)
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	got := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run: %v", err)
		}
		got = ee.ExitCode()
	}
	if got != want {
		t.Fatalf("exit %d, want %d\n%s", got, want, out.String())
	}
	if wantOut != "" && !strings.Contains(out.String(), wantOut) {
		t.Fatalf("output lacks %q\n%s", wantOut, out.String())
	}
}

func elevenEntries() string {
	var b strings.Builder
	for i := 0; i < 11; i++ {
		b.WriteString(entryFor(pkg + "::TestN" + string(rune('A'+i))))
	}
	return b.String()
}

// TestCommittedRegistryIsValid keeps the repository's own registry parseable.
func TestCommittedRegistryIsValid(t *testing.T) {
	cmd := exec.Command(binary(t), "-registry", "../quarantine.txt", "-tier", "full")
	cmd.Stdin = strings.NewReader(green)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("committed registry: %v\n%s", err, out)
	}
}

// corpusDir is the quarantine corpus shared with the other copy of these rules:
// each case is a go test -json stream, a registry, and the expected verdicts.
const corpusDir = "testdata/quarantine-corpus"

// corpusCase is one case's expected.json.
type corpusCase struct {
	Description string            `json:"description"`
	Tier        string            `json:"tier"`
	Today       string            `json:"today"`
	Edited      []string          `json:"edited"`
	Tests       map[string]string `json:"tests"`
	Verdict     string            `json:"verdict"`
	// Diverges records, per implementation ("go" or "python"), a known
	// disagreement listed in DISAGREEMENTS.md: that implementation's actual
	// verdicts, which its test pins until the disagreement is resolved.
	Diverges map[string]struct {
		Verdict string            `json:"verdict"`
		Tests   map[string]string `json:"tests"`
		Note    string            `json:"note"`
	} `json:"diverges"`
}

// resultLineRE matches a per-result report line: RED or QUARANTINED, the test
// id (which may hold a space in a build ImportPath), then the reason.
var resultLineRE = regexp.MustCompile(`^(RED|QUARANTINED) (.+?::\S*): (.*)$`)

// corpusVerdicts reads the report: the per-test verdicts for every test named in
// a result line. An expired entry's line is about the registry, not a result.
func corpusVerdicts(out string) map[string]string {
	got := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "RED registry:") || strings.HasPrefix(l, "RED test stream:") {
			continue
		}
		m := resultLineRE.FindStringSubmatch(l)
		if m == nil || strings.HasPrefix(m[3], "quarantine expired") {
			continue
		}
		v := "failed"
		if m[1] == "QUARANTINED" {
			v = "excused"
		}
		got[m[2]] = v
	}
	return got
}

// TestFailEchoesOnlyTheFailingRun pins the echo under -count=2: a repeated failure
// prints each run's output once, so the first run's lines do not appear again.
func TestFailEchoesOnlyTheFailingRun(t *testing.T) {
	input := stream(
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "first run line\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("run", pkg, "TestFlake", ""),
		ev("output", pkg, "TestFlake", "second run line\n"),
		ev("fail", pkg, "TestFlake", ""),
		ev("fail", pkg, "", ""))
	cmd := exec.Command(binary(t), "-registry", filepath.Join(t.TempDir(), "absent"), "-tier", "full", "-today", today)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("run: %v, want exit 1\n%s", err, out)
	}
	for _, line := range []string{"first run line\n", "second run line\n"} {
		if n := bytes.Count(out, []byte(line)); n != 1 {
			t.Errorf("%q printed %d times, want once\n%s", line, n, out)
		}
	}
}

// TestGeneratedCorpusStreams keeps the generated corpus streams honest: it reruns
// the generator under testdata/gen against real go test -json and reds when a
// committed stream.jsonl differs from what the generator writes.
func TestGeneratedCorpusStreams(t *testing.T) {
	cmd := exec.Command("go", "run", "./testdata/gen", "-check")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated corpus streams drifted (%v):\n%s", err, out)
	}
}

// TestQuarantineCorpusParity runs every shared corpus case through this copy of
// the rules and checks the overall verdict and each test's verdict.
func TestQuarantineCorpusParity(t *testing.T) {
	bin := binary(t)
	dirs, err := os.ReadDir(corpusDir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		n++
		dir := filepath.Join(corpusDir, d.Name())
		t.Run(d.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			var c corpusCase
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("expected.json: %v", err)
			}
			wantVerdict, wantTests := c.Verdict, c.Tests
			if dv, ok := c.Diverges["go"]; ok {
				t.Logf("known disagreement (DISAGREEMENTS.md): %s", dv.Note)
				wantVerdict, wantTests = dv.Verdict, dv.Tests
			}
			stream, err := os.Open(filepath.Join(dir, "stream.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			args := append([]string{"-registry", filepath.Join(dir, "quarantine.txt"), "-tier", c.Tier, "-today", c.Today}, c.Edited...)
			cmd := exec.Command(bin, args...)
			cmd.Stdin = stream
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			code := 0
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("run: %v", err)
				}
				code = ee.ExitCode()
			}
			verdict := map[int]string{0: "green", 1: "red", 3: "excused"}[code]
			if verdict != wantVerdict {
				t.Errorf("verdict %q (exit %d), want %q\n%s", verdict, code, wantVerdict, out.String())
			}
			got := corpusVerdicts(out.String())
			ids := make([]string, 0, len(wantTests))
			for id := range wantTests {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				g := got[id]
				if g == "" {
					g = "passed"
				}
				if g != wantTests[id] {
					t.Errorf("%s: %s, want %s", id, g, wantTests[id])
				}
				delete(got, id)
			}
			for id, v := range got {
				t.Errorf("%s: %s, but expected.json does not name it", id, v)
			}
			if t.Failed() {
				t.Logf("report:\n%s", out.String())
			}
		})
	}
	if n < 7 {
		t.Fatalf("corpus holds %d cases; at least 7 are required", n)
	}
}
