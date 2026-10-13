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

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParsePrintDisabled pins the read-back across the two value spellings
// launchctl has printed, and refuses output it cannot classify.
func TestParsePrintDisabled(t *testing.T) {
	const words = "disabled services = {\n\t\"com.apple.ftpd\" => disabled\n\t\"io.k3sm.netd\" => disabled\n\t\"io.k3sm.server\" => enabled\n}\n"
	const bools = "disabled services = {\n\t\"io.k3sm.netd\" => true\n\t\"io.k3sm.server\" => false\n}\n"
	for _, tc := range []struct {
		name, out, label string
		want             bool
		wantErr          bool
	}{
		{"disabled word", words, NetdLabel, true, false},
		{"enabled word", words, ServerLabel, false, false},
		{"true is disabled", bools, NetdLabel, true, false},
		{"false is enabled", bools, ServerLabel, false, false},
		{"absent has no override", words, AgentLabel, false, false},
		{"a label that only prefixes another does not match", "disabled services = {\n\t\"io.k3sm.netd2\" => disabled\n}\n", NetdLabel, false, false},
		{"an unknown value is an error", "disabled services = {\n\t\"io.k3sm.netd\" => maybe\n}\n", NetdLabel, false, true},
		{"output with no block is an error", "Usage: launchctl print-disabled <domain-target>\n", NetdLabel, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePrintDisabled(tc.out, tc.label)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Errorf("parsePrintDisabled = %v, %v; want %v, error %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// TestReadVMHostRecords reads runtimed's vm reap store shape, skipping what is
// not a usable record and never following a symlink.
func TestReadVMHostRecords(t *testing.T) {
	root := t.TempDir()
	if recs, err := readVMHostRecords(root); err != nil || len(recs) != 0 {
		t.Fatalf("absent store = %v, %v; want none", recs, err)
	}
	store := filepath.Join(root, "vmreap")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(store, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The exact shape runtimed writes (sandbox.vmProcRecord).
	write("601.json", `{"podId":"linux","pgid":601,"startUnixNano":22,"agentSocket":"/x/agent.sock","runDir":"/x"}`)
	write("1.json", `{"podId":"bad","pgid":1,"startUnixNano":5}`)
	write("junk.json", `not json`)
	write("602.json.tmp", `{"podId":"tmp","pgid":602,"startUnixNano":7}`)
	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, []byte(`{"podId":"evil","pgid":777,"startUnixNano":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store, "777.json")); err != nil {
		t.Fatal(err)
	}
	recs, err := readVMHostRecords(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0] != (VMHostRecord{PodID: "linux", Pgid: 601, StartUnixNano: 22}) {
		t.Errorf("records = %+v, want only the well-formed 601", recs)
	}
}

// TestLifecycleIdentity pins the closed actor set and the reason cleaning.
func TestLifecycleIdentity(t *testing.T) {
	if _, _, err := lifecycleIdentity("root", "x"); err == nil {
		t.Error("an actor outside user/auto was accepted")
	}
	_, reason, err := lifecycleIdentity(ActorAuto, "line\nforged=1\t"+strings.Repeat("x", 300))
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(reason, "\n\t") || len([]rune(reason)) != maxReasonLen {
		t.Errorf("reason not cleaned: %q (%d runes)", reason, len([]rune(reason)))
	}
}
