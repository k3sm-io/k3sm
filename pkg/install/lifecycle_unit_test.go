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
	"slices"
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

// TestReadVMHostRecords reads runtimed's vm reap store shape, trusting only a
// store and records owned by an allowed uid, not group/world-writable and not
// symlinks: an untrusted record is listed as rejected and never parsed.
func TestReadVMHostRecords(t *testing.T) {
	me := []uint32{uint32(os.Geteuid())}
	root := t.TempDir()
	if st, err := readVMHostRecords(root, me); err != nil || len(st.Records)+len(st.Rejected) != 0 {
		t.Fatalf("absent store = %+v, %v; want none", st, err)
	}
	store := filepath.Join(root, "vmreap")
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string, mode os.FileMode) {
		p := filepath.Join(store, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	// The exact shape runtimed writes (sandbox.vmProcRecord).
	write("601.json", `{"podId":"linux","pgid":601,"startUnixNano":22,"agentSocket":"/x/agent.sock","runDir":"/x"}`, 0o600)
	write("1.json", `{"podId":"bad","pgid":1,"startUnixNano":5}`, 0o600)
	write("junk.json", `not json`, 0o600)
	write("602.json.tmp", `{"podId":"tmp","pgid":602,"startUnixNano":7}`, 0o600)
	write("603.json", `{"podId":"forged","pgid":603,"startUnixNano":7}`, 0o666)
	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, []byte(`{"podId":"evil","pgid":777,"startUnixNano":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(store, "777.json")); err != nil {
		t.Fatal(err)
	}
	st, err := readVMHostRecords(root, me)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Records) != 1 || st.Records[0] != (VMHostRecord{PodID: "linux", Pgid: 601, StartUnixNano: 22}) {
		t.Errorf("records = %+v, want only the well-formed trusted 601", st.Records)
	}
	if !slices.Equal(st.Rejected, []string{"603.json", "777.json"}) {
		t.Errorf("rejected = %q, want the world-writable and the symlinked record", st.Rejected)
	}
	// A store owned by another uid is not read at all.
	if _, err := readVMHostRecords(root, []uint32{uint32(os.Geteuid()) + 1}); err == nil {
		t.Error("a store owned by an untrusted uid was read")
	}
	// Nor is a world-writable store.
	if err := os.Chmod(store, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := readVMHostRecords(root, me); err == nil {
		t.Error("a world-writable store was read")
	}
	// Nor a symlinked one.
	other := t.TempDir()
	if err := os.Symlink(store, filepath.Join(other, "vmreap")); err != nil {
		t.Fatal(err)
	}
	if _, err := readVMHostRecords(other, me); err == nil {
		t.Error("a symlinked store was read")
	}
}

// TestProcargsExecPath pins the kern.procargs2 parse: argc, then the path.
func TestProcargsExecPath(t *testing.T) {
	raw := append([]byte{2, 0, 0, 0}, []byte("/Library/k3sm/k3sm-vmhost\x00\x00k3sm-vmhost\x00")...)
	if got, err := procargsExecPath(raw); err != nil || got != "/Library/k3sm/k3sm-vmhost" {
		t.Errorf("procargsExecPath = %q, %v", got, err)
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0}, {1, 0, 0, 0, 0}} {
		if _, err := procargsExecPath(bad); err == nil {
			t.Errorf("procargsExecPath(%v) accepted a buffer with no path", bad)
		}
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
