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

// Command gen writes the stream.jsonl of the quarantine corpus cases that are
// real go test -json output rather than hand-built streams. For each case it
// copies fixtures/<case>/x_test.go into a throwaway module named k3sm.io/apis
// (as package net/v1, the package every corpus case names), runs
// `go test -json -count=N` there, and normalizes the stream: durations become
// 0.00s, and only the fields the readers parse are kept (Action, Package,
// ImportPath, Test, Output), so Time, Elapsed and OutputType do not churn it.
//
// Usage, from apis/hack/lib:
//
//	go run ./testdata/gen          # rewrite the generated streams
//	go run ./testdata/gen -check   # exit 1 if a committed stream differs
//
// TestGeneratedCorpusStreams in hack/lib/testresults_test.go runs -check.
// go test -json never emits an === NAME line as output: test2json reads it to
// attribute what follows and drops it. PAUSE and CONT lines are emitted.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// goDirective is the throwaway module's go line; it matches apis/go.mod.
const goDirective = "1.26.0"

// genCase is one generated corpus case.
type genCase struct {
	name  string
	count int      // the go test -count value
	needs []string // output prefixes the stream must carry, or the case misses its point
}

var cases = []genCase{
	{name: "repeated-fail-then-skip", count: 2},
	{name: "repeated-pass-fail-pass", count: 3},
	{name: "repeated-subtest-fail-then-pass", count: 2, needs: []string{"=== PAUSE ", "=== CONT "}},
	{name: "parent-failnow-no-output", count: 2},
}

// event keeps the fields the readers parse, in the corpus's key order.
type event struct {
	Action     string `json:"Action"`
	Package    string `json:"Package,omitempty"`
	ImportPath string `json:"ImportPath,omitempty"`
	Test       string `json:"Test,omitempty"`
	Output     string `json:"Output,omitempty"`
}

var (
	durationRE = regexp.MustCompile(`\(\d+(?:\.\d+)?s\)`)
	pkgTimeRE  = regexp.MustCompile(`\t\d+(?:\.\d+)?s\n$`)
)

func main() {
	check := flag.Bool("check", false, "compare the committed streams instead of writing them")
	corpus := flag.String("corpus", "testdata/quarantine-corpus", "the corpus directory")
	fixtures := flag.String("fixtures", "testdata/gen/fixtures", "the fixture directory")
	flag.Parse()
	drift := false
	for _, c := range cases {
		got, err := generate(c, filepath.Join(*fixtures, c.name, "x_test.go"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen %s: %v\n", c.name, err)
			os.Exit(2)
		}
		path := filepath.Join(*corpus, c.name, "stream.jsonl")
		if !*check {
			if err := os.WriteFile(path, got, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "gen %s: %v\n", c.name, err)
				os.Exit(2)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen %s: %v\n", c.name, err)
			os.Exit(2)
		}
		if d := firstDiff(want, got); d != "" {
			fmt.Printf("DRIFT %s: %s\n", path, d)
			drift = true
		}
	}
	if drift {
		fmt.Println("regenerate with: (cd hack/lib && go run ./testdata/gen)")
		os.Exit(1)
	}
}

// generate runs one case's fixture under go test -json and returns the
// normalized stream.
func generate(c genCase, fixture string) ([]byte, error) {
	src, err := os.ReadFile(fixture)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "quarantine-corpus-gen-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir) // best-effort cleanup of the throwaway module
	if err := os.MkdirAll(filepath.Join(dir, "net", "v1"), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module k3sm.io/apis\n\ngo "+goDirective+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "net", "v1", "x_test.go"), src, 0o644); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "test", "-json", fmt.Sprintf("-count=%d", c.count), "./net/v1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	var ee *exec.ExitError
	if err != nil && !(errors.As(err, &ee) && ee.ExitCode() == 1) {
		return nil, fmt.Errorf("go test: %v\n%s", err, stderr.String())
	}
	var out bytes.Buffer
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("go test emitted a non-JSON line %q: %v", line, err)
		}
		e.Output = durationRE.ReplaceAllString(e.Output, "(0.00s)")
		if e.Test == "" {
			e.Output = pkgTimeRE.ReplaceAllString(e.Output, "\t0.00s\n")
		}
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		out.Write(b)
		out.WriteByte('\n')
	}
	for _, n := range c.needs {
		if !strings.Contains(out.String(), `"Output":"`+n) {
			return nil, fmt.Errorf("the stream carries no %q line", n)
		}
	}
	return out.Bytes(), nil
}

// firstDiff describes the first line where the committed and generated streams
// differ, or returns "" when they are equal.
func firstDiff(want, got []byte) string {
	if bytes.Equal(want, got) {
		return ""
	}
	w, g := strings.Split(string(want), "\n"), strings.Split(string(got), "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			return fmt.Sprintf("line %d is %q, the generator writes %q", i+1, wl, gl)
		}
	}
	return "the streams differ"
}
