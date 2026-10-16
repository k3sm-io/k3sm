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

package status

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestUpdateRowFrom pins the update row's verdicts over a record: every node
// current is ok, any behind node warns naming it, and an error, a stale record
// or a node with no k3sm version is unknown.
func TestUpdateRowFrom(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Minute)
	nodes := func(states ...string) []UpdateNode {
		var out []UpdateNode
		for i, s := range states {
			out = append(out, UpdateNode{Name: string(rune('a' + i)), Version: "v1.37.1+k3sm.0.1." + string(rune('0'+i)), State: s})
		}
		return out
	}
	cases := []struct {
		name   string
		rec    UpdateRecord
		state  RowState
		sev    Severity
		detail string
		remedy string
	}{
		{"every node current", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: nodes(UpdateCurrent, UpdateCurrent)},
			StateOK, SeverityOK, "every node runs the latest release, k3sm v0.2.0", ""},
		{"one behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: nodes(UpdateCurrent, UpdateBehind)},
			StateBehind, SeverityWarn, "behind: b (v1.37.1+k3sm.0.1.1)", UpdateUpgradeRemedy},
		{"no nodes, binary behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.1.7", InstalledState: UpdateBehind},
			StateBehind, SeverityWarn, "this Mac (0.1.7)", UpdateUpgradeRemedy},
		{"no nodes, binary current", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.2.0", InstalledState: UpdateCurrent},
			StateOK, SeverityOK, "this Mac runs the latest release", ""},
		{"a node with no k3sm version", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: nodes(UpdateCurrent, UpdateUnknown)},
			StateUnknown, SeverityUnknown, "no k3sm version reported by: b", ""},
		{"github unreachable", UpdateRecord{CheckedAt: fresh, Error: "resolve the latest release: dial tcp: lookup github.com: no such host\nsecond line"},
			StateUnknown, SeverityUnknown, "could not check for an update: resolve the latest release: dial tcp: lookup github.com: no such host", UpdateCheckRemedy},
		{"stale", UpdateRecord{CheckedAt: now.Add(-25 * time.Hour), Latest: "v0.2.0", Nodes: nodes(UpdateCurrent)},
			StateUnknown, SeverityUnknown, "ran 25h0m0s ago", UpdateCheckRemedy},
		{"no release", UpdateRecord{CheckedAt: fresh},
			StateUnknown, SeverityUnknown, "found no release", UpdateCheckRemedy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := UpdateRowFrom(tc.rec, now)
			if r.Name != RowUpdate || r.State != tc.state || r.Severity != tc.sev {
				t.Fatalf("row = %s %s/%s, want %s/%s (%s)", r.Name, r.State, r.Severity, tc.state, tc.sev, r.Detail)
			}
			if !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("detail %q does not contain %q", r.Detail, tc.detail)
			}
			if r.Remedy != tc.remedy {
				t.Errorf("remedy %q, want %q", r.Remedy, tc.remedy)
			}
		})
	}
	if !advisory("server", RowUpdate) {
		t.Error("the update row must be advisory: a newer release does not degrade a cluster")
	}
}

// TestUpdateRowReadsTheRecord pins the read: an absent record and an
// unparseable one are unknown with the check as the remedy, an unreadable one
// asks for sudo, and a readable one renders through UpdateRowFrom.
func TestUpdateRowReadsTheRecord(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := "/var/lib/k3sm/server"
	path := UpdatePath(wd)
	if path != "/var/lib/k3sm/server/status/update.json" {
		t.Fatalf("UpdatePath = %s", path)
	}
	good, err := json.Marshal(UpdateRecord{CheckedAt: now, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "a", Version: "v1.37.1+k3sm.0.2.0", State: UpdateCurrent}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		fs     fakeFS
		state  RowState
		remedy string
	}{
		{"absent", fakeFS{}, StateUnknown, UpdateCheckRemedy},
		{"unreadable", fakeFS{unreadable: map[string]bool{path: true}}, StateUnknown, "sudo k3sm status"},
		{"unparseable", fakeFS{contents: map[string][]byte{path: []byte("{")}}, StateUnknown, UpdateCheckRemedy},
		{"current", fakeFS{contents: map[string][]byte{path: good}}, StateOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{FS: tc.fs, Paths: Paths{WorkDir: wd}}
			r, ok := c.updateRow(now)
			if !ok {
				t.Fatal("no update row")
			}
			if r.State != tc.state || r.Remedy != tc.remedy || r.Wide["record"] != path {
				t.Errorf("row = %+v, want state %s remedy %q", r, tc.state, tc.remedy)
			}
		})
	}
	if _, ok := (Collector{FS: fakeFS{}}).updateRow(now); ok {
		t.Error("a collector with no work dir has an update row")
	}
}
