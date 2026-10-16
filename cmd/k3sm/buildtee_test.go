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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/buildledger"
)

// loggedRecord is a started record with a log, for the tee tests.
func loggedRecord(t *testing.T) *buildRecord {
	t.Helper()
	l := buildledger.New(filepath.Join(t.TempDir(), "builds"))
	tr := startBuildRecord(l, buildOptions{tag: "a:v1", platforms: []string{"darwin/arm64"}})
	if !tr.started || tr.log == nil {
		t.Fatal("the record or its log was not created")
	}
	return tr
}

// TestEngineBuildxWithoutATerminalIsAPlainCopy pins the non-terminal path:
// buildx's stderr reaches the process's stderr byte for byte, exactly as it
// did before builds kept logs, and the log gets the same text with terminal
// control removed.
func TestEngineBuildxWithoutATerminalIsAPlainCopy(t *testing.T) {
	var stderr bytes.Buffer
	oldErr, oldTerm := processStderr, stderrTerminal
	processStderr = &stderr
	stderrTerminal = func() *os.File { return nil }
	t.Cleanup(func() { processStderr, stderrTerminal = oldErr, oldTerm })

	tr := loggedRecord(t)
	var stdout bytes.Buffer
	out := tr.tee(&stdout)
	if out.(*teeOutput).term != nil {
		t.Fatal("a non-terminal stderr chose the pseudo-terminal path")
	}
	script := filepath.Join(t.TempDir(), "fake-buildx")
	body := "#!/bin/sh\nprintf 'digest\\n'\nprintf '\\033[32m#1 DONE\\033[0m\\r\\n' >&2\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runEngineBuildx(t.Context(), script, nil, nil, out); err != nil {
		t.Fatal(err)
	}
	if err := tr.log.Close(); err != nil {
		t.Fatal(err)
	}
	if stderr.String() != "\x1b[32m#1 DONE\x1b[0m\r\n" {
		t.Errorf("stderr = %q, want buildx's bytes unchanged", stderr.String())
	}
	if stdout.String() != "digest\n" {
		t.Errorf("stdout = %q", stdout.String())
	}
	data, err := os.ReadFile(tr.ledger.LogPath(tr.rec.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "#1 DONE\n") || strings.ContainsAny(string(data), "\x1b\r") {
		t.Errorf("log = %q, want the text without control sequences", data)
	}
}

// TestBuildTeeChoosesThePseudoTerminalOnATerminal: a terminal stderr is
// carried to the engine path, which runs buildx on a pseudo-terminal.
func TestBuildTeeChoosesThePseudoTerminalOnATerminal(t *testing.T) {
	fake, err := os.CreateTemp(t.TempDir(), "tty")
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	old := stderrTerminal
	stderrTerminal = func() *os.File { return fake }
	t.Cleanup(func() { stderrTerminal = old })
	out := loggedRecord(t).tee(&bytes.Buffer{})
	if tt := out.(*teeOutput); tt.term != fake || tt.log == nil {
		t.Errorf("tee = %+v, want the terminal and the log input carried", tt)
	}
}
