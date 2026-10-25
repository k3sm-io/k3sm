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
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

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
			r, ok := c.updateRow(now, nil, false)
			if !ok {
				t.Fatal("no update row")
			}
			if r.State != tc.state || r.Remedy != tc.remedy || r.Wide["record"] != path {
				t.Errorf("row = %+v, want state %s remedy %q", r, tc.state, tc.remedy)
			}
		})
	}
	if _, ok := (Collector{FS: fakeFS{}}).updateRow(now, nil, false); ok {
		t.Error("a collector with no work dir has an update row")
	}
}

// TestUpdateRowRolling pins the row while a managed update is in progress: a
// fresh roll is `rolling` (severity ok, no remedy) with the phase and the
// current node in the detail and wide.phase / wide.node, ahead of a behind
// cluster or a failed check; a stale roll falls back to the check's verdict;
// a roll of the wrong shape invalidates the record.
func TestUpdateRowRolling(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	behind := UpdateRecord{CheckedAt: now.Add(-time.Hour), Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("node-b", "0.1.7", UpdateCurrent)}}
	roll := func(at time.Time, node, nodePhase string) *UpdateRoll {
		return &UpdateRoll{ObservedAt: at, Version: "v0.2.0", Phase: "Rolling", Node: node, NodePhase: nodePhase}
	}
	for _, tc := range []struct {
		name       string
		rec        UpdateRecord
		state      RowState
		detail     string
		phase, nd  string
		withRemedy bool
	}{
		{"rolling a node", func() UpdateRecord {
			r := behind
			r.Roll = roll(now.Add(-time.Minute), "node-b", "Installing")
			return r
		}(),
			StateRolling, "updating the cluster to k3sm v0.2.0: Rolling, node node-b Installing", "Rolling", "node-b", false},
		{"pending, no check recorded", UpdateRecord{Roll: &UpdateRoll{ObservedAt: now, Version: "v0.2.0"}},
			StateRolling, "updating the cluster to k3sm v0.2.0: Pending", "Pending", "", false},
		{"check failed", func() UpdateRecord {
			r := behind
			r.Error, r.Roll = "dial tcp: refused", roll(now, "node-b", "Downloading")
			return r
		}(), StateRolling, "node node-b Downloading", "Rolling", "node-b", false},
		{"stale roll", func() UpdateRecord {
			r := behind
			r.Roll = roll(now.Add(-UpdateRollStaleAfter-time.Second), "node-b", "Installing")
			return r
		}(),
			StateBehind, "behind: node-b", "", "", true},
		{"bad node name", func() UpdateRecord { r := behind; r.Roll = roll(now, "Bad Node", "Installing"); return r }(),
			StateUnknown, "roll", "", "", true},
		{"bad phase", func() UpdateRecord { r := behind; r.Roll = roll(now, "node-b", "Installing\x1b[2J"); return r }(),
			StateUnknown, "roll", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := UpdateRowFrom(tc.rec, now)
			if r.State != tc.state || !strings.Contains(r.Detail, tc.detail) || r.Wide["phase"] != tc.phase || r.Wide["node"] != tc.nd || (r.Remedy != "") != tc.withRemedy {
				t.Errorf("row = %+v", r)
			}
			if tc.state == StateRolling && (r.Severity != SeverityOK || r.Wide["target"] != "v0.2.0") {
				t.Errorf("rolling row = %+v", r)
			}
		})
	}
}

// TestUpdateRowCarriesLatestDuringARollAndOnAgents pins the latest release in
// the two places the row used to drop it. A rolling row carries wide.latest
// beside wide.target when the check found one. A worker Mac's report carries
// a read-only update row from the latest a server publishes on its Node (read
// through the node list the worker already takes): the cluster verdict with
// wide.latest and no refresh remedy. Only a control-plane Node's annotations
// count, a value of the wrong shape is skipped, and when the list is not there
// to read the row is unknown and says why.
func TestUpdateRowCarriesLatestDuringARollAndOnAgents(t *testing.T) {
	t.Parallel()
	now := goldenTime

	t.Run("a rolling row carries the latest release", func(t *testing.T) {
		rec := UpdateRecord{CheckedAt: now.Add(-time.Hour), Latest: "v0.2.1", Nodes: []UpdateNode{nodeAt("node-b", "0.1.7", UpdateBehind)},
			Roll: &UpdateRoll{ObservedAt: now, Version: "v0.2.0", Phase: "Rolling", Node: "node-b", NodePhase: "Installing"}}
		r := UpdateRowFrom(rec, now)
		if r.State != StateRolling || r.Wide["latest"] != "v0.2.1" || r.Wide["target"] != "v0.2.0" {
			t.Errorf("rolling row = %+v, want wide.latest v0.2.1 beside wide.target v0.2.0", r)
		}
		rec.Latest = ""
		if r := UpdateRowFrom(rec, now); r.State != StateRolling || r.Wide["latest"] != "" {
			t.Errorf("rolling row with no check = %+v, want no wide.latest", r)
		}
	})

	server := func(name, latest, checked string) corev1.Node {
		n := workerNode(name, "v1.37.1+k3sm.0.2.0")
		n.Labels = map[string]string{controlPlaneNodeLabel: ""}
		n.Annotations = map[string]string{NodeReleaseLatestAnnotation: latest, NodeReleaseCheckedAnnotation: checked}
		return n
	}
	checked := now.Add(-time.Hour).Format(time.RFC3339)
	pub := UpdateAnnotations(UpdateRecord{CheckedAt: now.Add(-time.Hour), Latest: "v0.2.0"})
	if pub[NodeReleaseLatestAnnotation] != "v0.2.0" || pub[NodeReleaseCheckedAnnotation] != checked {
		t.Fatalf("UpdateAnnotations = %v", pub)
	}
	if UpdateAnnotations(UpdateRecord{CheckedAt: now, Latest: "v0.2.0", Error: "dial tcp: refused"}) != nil {
		t.Error("a failed check publishes annotations")
	}

	worker := func(t *testing.T, kube Kube) Row {
		t.Helper()
		p := agentPaths(t.TempDir())
		fsys := withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, now.Add(90*24*time.Hour))
		c := agentCollector(t, p, fsys)
		if kube != nil {
			c.Kube = kube
		}
		rep := c.Collect(context.Background())
		r, ok := rep.Row(RowUpdate)
		if !ok {
			t.Fatalf("a worker's report has no update row\n%s", Render(rep, Style{}))
		}
		return r
	}
	cluster := func(nodes ...corev1.Node) fakeKube {
		k := healthyKube()
		k.nodes = append(k.nodes, nodes...)
		return k
	}
	forged := workerNode("rogue", "v1.37.1+k3sm.0.2.0")
	forged.Annotations = map[string]string{NodeReleaseLatestAnnotation: "v9.9.9", NodeReleaseCheckedAnnotation: now.Format(time.RFC3339)}

	for _, tc := range []struct {
		name          string
		kube          Kube
		state         RowState
		latest, rec   string
		detail        string
		remedyAllowed bool
	}{
		{"behind, from the server's Node", cluster(server("node-a", "v0.2.0", checked), workerNode("node-b", "v1.37.1+k3sm.0.1.7")),
			StateBehind, "v0.2.0", "node/node-a", "behind: node-b", true},
		{"the newest check wins", cluster(server("node-a", "v0.1.0", now.Add(-48*time.Hour).Format(time.RFC3339)), server("node-c", "v0.2.0", checked)),
			StateUnknown, "v0.2.0", "node/node-c", "no tagged k3sm release reported by: my-mac", false},
		{"a worker's own annotation is not the server's", cluster(forged),
			StateUnknown, "", "", "no server has published an update check yet", false},
		{"a value of the wrong shape is skipped", cluster(server("node-a", "v0.2.0;rm", checked)),
			StateUnknown, "", "", "no server has published", false},
		{"the apiserver does not answer", fakeKube{rawErr: map[string]error{"/readyz": errors.New("connection refused")}, server: "https://100.64.0.1:6444", tls: "ca pinned"},
			StateUnknown, "", "", "cannot read the latest release the server recorded: the apiserver does not answer", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := worker(t, tc.kube)
			if r.State != tc.state || r.Wide["latest"] != tc.latest || r.Wide["record"] != tc.rec || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("row = %+v, want state %s latest %q record %q detail ~%q", r, tc.state, tc.latest, tc.rec, tc.detail)
			}
			if r.Remedy == UpdateCheckRemedy || r.Remedy == UpdateCheckRemedyWritable || (!tc.remedyAllowed && r.Remedy != "") {
				t.Errorf("remedy = %q; a worker cannot refresh the server's record", r.Remedy)
			}
		})
	}

	t.Run("the node list refused", func(t *testing.T) {
		r := Collector{Kube: healthyKube()}.agentUpdateRow(true, nil, errors.New(`nodes is forbidden: User "system:node:node-b" cannot list resource "nodes"`), now)
		if r.State != StateUnknown || !strings.Contains(r.Detail, "cannot read the latest release the server recorded: nodes is forbidden") {
			t.Errorf("row = %+v", r)
		}
	})
	t.Run("no cluster client", func(t *testing.T) {
		r := Collector{EUID: 501}.agentUpdateRow(false, nil, nil, now)
		if r.State != StateUnknown || !strings.Contains(r.Detail, "no cluster client") || r.Remedy != "sudo k3sm status" {
			t.Errorf("row = %+v", r)
		}
	})
}

// TestReleaseStatePseudoVersionRanksByCore pins how a Go pseudo-version (a
// build of an untagged commit) compares with the latest release: by its core
// and prerelease in semver order, so v0.1.8-0.<stamp>-<rev> is ahead of
// v0.1.7, behind v0.1.8 (its core, not yet tagged when it was built) and
// behind v0.1.9, and the row says it is an untagged build. A dirty build stays
// unknown, in either spelling.
func TestReleaseStatePseudoVersionRanksByCore(t *testing.T) {
	const pseudo = "v0.1.8-0.20261025152241-96fbff948562"
	cases := []struct {
		have, latest string
		state        string
		untaggedOf   string
	}{
		{pseudo, "v0.1.7", UpdateAhead, "0.1.8"},
		{pseudo, "v0.1.8", UpdateBehind, "0.1.8"},
		{pseudo, "v0.1.8-rc.1", UpdateBehind, "0.1.8"},
		{pseudo, "v0.1.9", UpdateBehind, "0.1.8"},
		{"v0.1.6-0.20261025152241-96fbff948562", "v0.1.7", UpdateBehind, "0.1.6"},
		{pseudo + "+dirty", "v0.1.7", UpdateUnknown, ""},
		{"0.1.8-0.20261025152241-96fbff948562.dirty", "v0.1.7", UpdateUnknown, ""},
		{"dev", "v0.1.7", UpdateUnknown, ""},
		{"v0.1.7", "v0.1.7", UpdateCurrent, ""},
		{pseudo, pseudo, UpdateUnknown, ""},
	}
	for _, tc := range cases {
		if got := ReleaseState(tc.have, tc.latest); got != tc.state {
			t.Errorf("ReleaseState(%q, %q) = %s, want %s", tc.have, tc.latest, got, tc.state)
		}
		if got, of := BuildState(tc.have, tc.latest); got != tc.state || of != tc.untaggedOf {
			t.Errorf("BuildState(%q, %q) = %s, %q; want %s, %q", tc.have, tc.latest, got, of, tc.state, tc.untaggedOf)
		}
	}
	node := version.Info{KubeVersion: "v1.37.1", Version: pseudo}.NodeVersion()
	if got := NodeReleaseState(node, "v0.1.7"); got != UpdateAhead {
		t.Errorf("NodeReleaseState(%q, v0.1.7) = %s, want ahead", node, got)
	}
	dirty := version.Info{KubeVersion: "v1.37.1", Version: pseudo, Dirty: true}.NodeVersion()
	if got := NodeReleaseState(dirty, "v0.1.7"); got != UpdateUnknown {
		t.Errorf("NodeReleaseState(%q, v0.1.7) = %s, want unknown", dirty, got)
	}

	now := time.Date(2026, 10, 25, 16, 0, 0, 0, time.UTC)
	fresh := now.Add(-10 * time.Minute)
	for _, tc := range []struct {
		name   string
		rec    UpdateRecord
		state  RowState
		detail string
	}{
		{"nodes ahead", UpdateRecord{CheckedAt: fresh, Latest: "v0.1.7", Nodes: []UpdateNode{nodeAt("a", pseudo, UpdateUnknown), nodeAt("b", pseudo, UpdateUnknown)}},
			StateAhead, "newer than the latest release: a (untagged build of 0.1.8), b (untagged build of 0.1.8)"},
		{"node behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.1.7", Nodes: []UpdateNode{nodeAt("a", "v0.1.6-0.20261025152241-96fbff948562", UpdateUnknown)}},
			StateBehind, "behind: a (untagged build of 0.1.6)"},
		{"this Mac ahead", UpdateRecord{CheckedAt: fresh, Latest: "v0.1.7", Installed: pseudo, InstalledState: UpdateUnknown},
			StateAhead, "this Mac (untagged build of 0.1.8)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := UpdateRowFrom(tc.rec, now)
			if r.State != tc.state || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("row = %s %q, want %s containing %q", r.State, r.Detail, tc.state, tc.detail)
			}
		})
	}
}

// TestUpdateRowRederivesFromTheRunningVersion pins that the row does not
// replay the verdict the record was written with: a record an older binary
// left (every node and the binary on v0.1.7, the latest) reads against the
// binary that runs now and the live node list this report took, so after an
// in-place install of an untagged build the row says ahead. The record's
// latest release and check time stay as recorded. With no live node list the
// recorded nodes stay, re-ranked; with no nodes at all the running binary is
// the fact.
func TestUpdateRowRederivesFromTheRunningVersion(t *testing.T) {
	now := time.Date(2026, 10, 25, 16, 0, 0, 0, time.UTC)
	checked := now.Add(-20 * time.Minute)
	const pseudo = "v0.1.8-0.20261025152241-96fbff948562"
	wd := "/var/lib/k3sm/server"
	path := UpdatePath(wd)
	old := UpdateRecord{CheckedAt: checked, Latest: "v0.1.7", Published: "2026-10-05T00:00:00Z", Installed: "v0.1.7", InstalledState: UpdateCurrent,
		Nodes: []UpdateNode{nodeAt("a", "0.1.7", UpdateCurrent), nodeAt("b", "0.1.7", UpdateCurrent)}}
	noNodes := old
	noNodes.Nodes = nil
	running := version.Info{KubeVersion: "v1.37.1", Version: pseudo}
	liveNode := func(name string) corev1.Node {
		n := readyNode(name)
		n.Status.NodeInfo.KubeletVersion = running.NodeVersion()
		return n
	}
	live := []corev1.Node{liveNode("b"), liveNode("a")}
	for _, tc := range []struct {
		name   string
		rec    UpdateRecord
		ver    version.Info
		live   []corev1.Node
		liveOK bool
		state  RowState
		detail string
	}{
		{"live nodes on the new build", old, running, live, true, StateAhead,
			"k3sm v0.1.7 is the latest; newer than the latest release: a (untagged build of 0.1.8), b (untagged build of 0.1.8)"},
		{"node list not read keeps the recorded nodes", old, running, nil, false, StateOK, "every node runs the latest release, k3sm v0.1.7"},
		{"no nodes, the running binary", noNodes, running, nil, false, StateAhead, "this Mac (untagged build of 0.1.8)"},
		{"no nodes, a dirty running binary", noNodes, version.Info{Version: pseudo, Dirty: true}, nil, false, StateUnknown, "no tagged k3sm release reported by: this Mac"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(tc.rec)
			if err != nil {
				t.Fatal(err)
			}
			c := Collector{FS: fakeFS{contents: map[string][]byte{path: raw}}, Paths: Paths{WorkDir: wd}, EUID: 0, ServiceUID: 250, Version: tc.ver}
			r, ok := c.updateRow(now, tc.live, tc.liveOK)
			if !ok {
				t.Fatal("no update row")
			}
			if r.State != tc.state || !strings.Contains(r.Detail, tc.detail) {
				t.Errorf("row = %s %q, want %s containing %q", r.State, r.Detail, tc.state, tc.detail)
			}
			if r.Wide["latest"] != "v0.1.7" || r.Wide["checked"] != checked.Format(time.RFC3339) {
				t.Errorf("wide = %v, want the recorded latest and check time", r.Wide)
			}
		})
	}
}
