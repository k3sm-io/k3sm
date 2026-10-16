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

	"k3sm.io/k3sm/pkg/version"
)

// nodeAt is a node whose kubelet reports k3sm release rel, stored with state
// (which the row must ignore).
func nodeAt(name, rel, state string) UpdateNode {
	return UpdateNode{Name: name, Version: version.Info{KubeVersion: "v1.37.1", Version: rel}.NodeVersion(), State: state}
}

// TestUpdateRowFrom pins the update row's verdicts over a record: every node
// current is ok, any behind node warns naming it with the install remedy, a
// node newer than the latest release is ahead with no remedy, and an error, a
// stale record or a node with no tagged release is unknown. The stored state
// words are never trusted: each case stores the wrong one.
func TestUpdateRowFrom(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Minute)
	cases := []struct {
		name   string
		rec    UpdateRecord
		state  RowState
		sev    Severity
		detail string
		remedy string
	}{
		{"every node current", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateBehind), nodeAt("b", "v0.2.0", UpdateBehind)}},
			StateOK, SeverityOK, "every node runs the latest release, k3sm v0.2.0", ""},
		{"one behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateBehind), nodeAt("b", "0.1.7", UpdateCurrent)}},
			StateBehind, SeverityWarn, "behind: b (v1.37.1+k3sm.0.1.7)", UpdateUpgradeRemedy},
		{"one behind, one ahead", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.3.0", UpdateCurrent), nodeAt("b", "0.1.7", UpdateCurrent)}},
			StateBehind, SeverityWarn, "behind: b (v1.37.1+k3sm.0.1.7); newer than the latest release: a (v1.37.1+k3sm.0.3.0)", UpdateUpgradeRemedy},
		{"ahead", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent), nodeAt("b", "0.2.1-rc.1", UpdateBehind)}},
			StateAhead, SeverityOK, "newer than the latest release: b (v1.37.1+k3sm.0.2.1-rc.1)", ""},
		{"no nodes, binary behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.1.7", InstalledState: UpdateCurrent},
			StateBehind, SeverityWarn, "this Mac (0.1.7)", UpdateUpgradeRemedy},
		{"no nodes, binary current", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.2.0", InstalledState: UpdateBehind},
			StateOK, SeverityOK, "this Mac runs the latest release", ""},
		{"no nodes, dirty binary", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.2.0", InstalledDirty: true},
			StateUnknown, SeverityUnknown, "no tagged k3sm release reported by: this Mac", ""},
		{"no nodes, dev binary", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "dev"},
			StateUnknown, SeverityUnknown, "no tagged k3sm release reported by: this Mac", ""},
		{"a node with no k3sm version", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent), {Name: "b", Version: "v1.37.1", State: UpdateCurrent}}},
			StateUnknown, SeverityUnknown, "no tagged k3sm release reported by: b", ""},
		{"github unreachable", UpdateRecord{CheckedAt: fresh, Error: "resolve the latest release: dial tcp: lookup github.com: no such host\nsecond line"},
			StateUnknown, SeverityUnknown, "could not check for an update: resolve the latest release: dial tcp: lookup github.com: no such host", UpdateCheckRemedy},
		{"error with control characters", UpdateRecord{CheckedAt: fresh, Error: "bad \x1b[31mred\u202e reversed"},
			StateUnknown, SeverityUnknown, "could not check for an update: bad [31mred reversed", UpdateCheckRemedy},
		{"stale", UpdateRecord{CheckedAt: now.Add(-25 * time.Hour), Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}},
			StateUnknown, SeverityUnknown, "ran 25h0m0s ago", UpdateCheckRemedy},
		{"dated in the future", UpdateRecord{CheckedAt: now.Add(time.Hour), Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}},
			StateUnknown, SeverityUnknown, "no update check is recorded", UpdateCheckRemedy},
		{"within the clock slack", UpdateRecord{CheckedAt: now.Add(4 * time.Minute), Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}},
			StateOK, SeverityOK, "every node runs", ""},
		{"no release", UpdateRecord{CheckedAt: fresh},
			StateUnknown, SeverityUnknown, "found no release", UpdateCheckRemedy},
		{"unusable latest tag", UpdateRecord{CheckedAt: fresh, Latest: "v1;rm -rf"},
			StateUnknown, SeverityUnknown, "not valid: unusable latest tag", UpdateCheckRemedy},
		{"unusable node version", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "a", Version: "v1\x1b[2J", State: UpdateCurrent}}},
			StateUnknown, SeverityUnknown, "not valid: node version", UpdateCheckRemedy},
		{"node name is not a resource name", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "A B", Version: "v1.37.1+k3sm.0.2.0", State: UpdateCurrent}}},
			StateUnknown, SeverityUnknown, "not valid: node name", UpdateCheckRemedy},
		{"unknown stored node state", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "a", Version: "v1.37.1+k3sm.0.2.0", State: "fine"}}},
			StateUnknown, SeverityUnknown, "not valid: node state", UpdateCheckRemedy},
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
			for _, s := range append([]string{r.Detail}, wideValues(r)...) {
				if strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f || c == 0x202e }) {
					t.Errorf("row text %q carries a control character", s)
				}
			}
		})
	}
	if !advisory("server", RowUpdate) {
		t.Error("the update row must be advisory: a newer release does not degrade a cluster")
	}
}

// wideValues lists a row's Wide values.
func wideValues(r Row) []string {
	var out []string
	for _, v := range r.Wide {
		out = append(out, v)
	}
	return out
}

// TestClipText pins the strip and the clip.
func TestClipText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                 "plain",
		"a\nb\tc\x1b[0m\u200fd": "abc[0md",
		"abcdefghij":            "abcde...",
		"\xff\xfeok":            "ok",
		"ééé":                   "éé...",
	} {
		max := 64
		if in == "abcdefghij" {
			max = 5
		}
		if in == "ééé" {
			max = 5
		}
		if got := ClipText(in, max); got != want {
			t.Errorf("ClipText(%q, %d) = %q, want %q", in, max, got, want)
		}
	}
}

// TestUpdateRowReadsTheRecord pins the read: an absent record and an
// unparseable one are unknown with the check as the remedy, an unreadable one
// asks for sudo, and a readable one renders through UpdateRowFrom.
func TestUpdateRowReadsTheRecord(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	wd := "/var/lib/k3sm/server"
	path := UpdatePath(wd)
	if path != "/var/lib/k3sm/status/update.json" {
		t.Fatalf("UpdatePath = %s, want the user-readable status directory", path)
	}
	good, err := json.Marshal(UpdateRecord{CheckedAt: now, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "a", Version: "v1.37.1+k3sm.0.2.0", State: UpdateCurrent}}})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := json.Marshal(UpdateRecord{CheckedAt: now.Add(-48 * time.Hour), Latest: "v0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	const user, service = 501, 250
	cases := []struct {
		name   string
		fs     fakeFS
		euid   int
		state  RowState
		remedy string
	}{
		{"absent, as a user", fakeFS{}, user, StateUnknown, UpdateCheckRemedy},
		{"absent, as root", fakeFS{}, 0, StateUnknown, UpdateCheckRemedyWritable},
		{"absent, as the service user", fakeFS{}, service, StateUnknown, UpdateCheckRemedyWritable},
		{"stale, as a user", fakeFS{contents: map[string][]byte{path: stale}}, user, StateUnknown, UpdateCheckRemedy},
		{"stale, as root", fakeFS{contents: map[string][]byte{path: stale}}, 0, StateUnknown, UpdateCheckRemedyWritable},
		{"unreadable", fakeFS{unreadable: map[string]bool{path: true}}, user, StateUnknown, "sudo k3sm status"},
		{"unparseable", fakeFS{contents: map[string][]byte{path: []byte("{")}}, user, StateUnknown, UpdateCheckRemedy},
		{"current, as a user", fakeFS{contents: map[string][]byte{path: good}}, user, StateOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Collector{FS: tc.fs, Paths: Paths{WorkDir: wd}, EUID: tc.euid, ServiceUID: service}
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
