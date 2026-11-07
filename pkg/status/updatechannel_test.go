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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
)

// channelServer is a control-plane Node publishing latest, checked at checked,
// with the channel annotation when channel is not empty.
func channelServer(name, latest, channel string, checked time.Time) corev1.Node {
	n := workerNode(name, "v1.37.1+k3sm.0.2.0")
	n.Labels = map[string]string{controlPlaneNodeLabel: ""}
	n.Annotations = map[string]string{
		NodeReleaseLatestAnnotation:  latest,
		NodeReleaseCheckedAnnotation: checked.UTC().Format(time.RFC3339),
	}
	if channel != "" {
		n.Annotations[updatesv1alpha1.AnnotationReleaseChannel] = channel
	}
	return n
}

// countingNodes is a node lister that counts its lists.
type countingNodes struct {
	fakeKube
	lists *int
}

func (k countingNodes) Nodes(ctx context.Context) ([]corev1.Node, error) {
	*k.lists++
	return k.fakeKube.Nodes(ctx)
}

// channelWorkerRow is a worker Mac's update row over kube.
func channelWorkerRow(t *testing.T, kube Kube) Row {
	t.Helper()
	p := agentPaths(t.TempDir())
	c := agentCollector(t, p, withCredential(t, agentInstalledFS(p), p.AgentCredentialDir, goldenTime.Add(90*24*time.Hour)))
	c.Kube = kube
	r, ok := c.Collect(context.Background()).Row(RowUpdate)
	if !ok {
		t.Fatal("a worker's report has no update row")
	}
	return r
}

// TestUpdateRowNamesChannelAndKeepsStableDetail pins what the update row and the
// Node say of the release channel. wide.channel is the channel the record's
// result was computed under, on every row a record reaches, the rolling row
// included. On stable the detail is byte-identical to what it was before there
// were channels, and on rc it gains a trailing "; channel rc". The channel and
// the latest release are published as one pair, taken from the record.
func TestUpdateRowNamesChannelAndKeepsStableDetail(t *testing.T) {
	now := goldenTime
	fresh := now.Add(-10 * time.Minute)
	const (
		stable = updatesv1alpha1.UpdateChannelStable
		rc     = updatesv1alpha1.UpdateChannelRC
	)

	details := []struct {
		name   string
		rec    UpdateRecord
		detail string
	}{
		{"every node current", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}},
			"every node runs the latest release, k3sm v0.2.0"},
		{"one behind", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("b", "0.1.7", UpdateBehind)}},
			"k3sm v0.2.0 is available; behind: b (v1.37.1+k3sm.0.1.7)"},
		{"behind and newer", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.3.0", UpdateAhead), nodeAt("b", "0.1.7", UpdateBehind)}},
			"k3sm v0.2.0 is available; behind: b (v1.37.1+k3sm.0.1.7); newer than the latest release: a (v1.37.1+k3sm.0.3.0)"},
		{"ahead", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.3.0", UpdateAhead)}},
			"k3sm v0.2.0 is the latest; newer than the latest release: a (v1.37.1+k3sm.0.3.0)"},
		{"unknown node", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{{Name: "a", Version: "v1.37.1", State: UpdateUnknown}}},
			"k3sm v0.2.0 is the latest; no tagged k3sm release reported by: a"},
		{"this Mac", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Installed: "0.2.0"},
			"this Mac runs the latest release, k3sm v0.2.0"},
		{"stale", UpdateRecord{CheckedAt: now.Add(-25 * time.Hour), Latest: "v0.2.0"},
			"the last update check ran 25h0m0s ago"},
		{"failed check", UpdateRecord{CheckedAt: fresh, Error: "dial tcp: refused"},
			"could not check for an update: dial tcp: refused"},
		{"no release", UpdateRecord{CheckedAt: fresh},
			"the update check found no release"},
		{"rolling", UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Roll: &UpdateRoll{ObservedAt: now, Version: "v0.2.0", Phase: "Rolling", Node: "b", NodePhase: "Installing"}},
			"updating the cluster to k3sm v0.2.0: Rolling, node b Installing"},
	}
	for _, tc := range details {
		t.Run("stable detail is byte-identical/"+tc.name, func(t *testing.T) {
			rec := tc.rec
			rec.Channel = stable
			r := UpdateRowFrom(rec, now)
			if r.Detail != tc.detail {
				t.Errorf("detail = %q, want %q", r.Detail, tc.detail)
			}
			if r.Wide["channel"] != "stable" {
				t.Errorf("wide.channel = %q, want stable", r.Wide["channel"])
			}
		})
		t.Run("rc gains a trailing channel/"+tc.name, func(t *testing.T) {
			rec := tc.rec
			rec.Channel = rc
			r := UpdateRowFrom(rec, now)
			if want := tc.detail + "; channel rc"; r.Detail != want {
				t.Errorf("detail = %q, want %q", r.Detail, want)
			}
			if r.Wide["channel"] != "rc" {
				t.Errorf("wide.channel = %q, want rc", r.Wide["channel"])
			}
			if plain := UpdateRowFrom(tc.rec, now); r.State != plain.State || r.Severity != plain.Severity || r.Remedy != plain.Remedy {
				t.Errorf("rc moved the row: %s/%s %q, stable reads %s/%s %q", r.State, r.Severity, r.Remedy, plain.State, plain.Severity, plain.Remedy)
			}
			if alertOf(r) != alertOf(UpdateRowFrom(tc.rec, now)) {
				t.Errorf("rc changed which alert the row carries: %q", r.Detail)
			}
		})
	}

	t.Run("the rolling row names the channel of a record with no latest", func(t *testing.T) {
		r := UpdateRowFrom(UpdateRecord{Channel: rc, Roll: &UpdateRoll{ObservedAt: now, Version: "v0.3.0-rc.2"}}, now)
		if r.State != StateRolling || r.Wide["channel"] != "rc" || r.Wide["target"] != "v0.3.0-rc.2" {
			t.Errorf("row = %+v", r)
		}
	})

	t.Run("a row with nothing computed names no channel", func(t *testing.T) {
		for name, rec := range map[string]UpdateRecord{
			"a roll before any check":        {Roll: &UpdateRoll{ObservedAt: now, Version: "v0.2.0"}},
			"a check that could not read it": {CheckedAt: fresh, Error: "resolve the latest release: the update channel could not be read"},
			"a record dated in the future":   {CheckedAt: now.Add(time.Hour), Channel: rc, Latest: "v0.2.0"},
			"a record that fails validation": {CheckedAt: fresh, Channel: rc, Latest: "v1;rm"},
		} {
			if r := UpdateRowFrom(rec, now); r.Wide["channel"] != "" || strings.Contains(r.Detail, "channel rc") {
				t.Errorf("%s: row = %+v", name, r)
			}
		}
		c := Collector{Paths: Paths{WorkDir: "/nonexistent"}, FS: fakeFS{}}
		if r, ok := c.updateRow(now, nil, false); !ok || r.Detail != updateMissingDetail || r.Wide["channel"] != "" {
			t.Errorf("no record: row = %+v", r)
		}
	})

	t.Run("an unknown value never reads as a real one", func(t *testing.T) {
		for _, value := range []updatesv1alpha1.UpdateChannel{"beta", "RC", "rc ", "evil\x1b[2J‮"} {
			rec := UpdateRecord{CheckedAt: fresh, Channel: value, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}}
			r := UpdateRowFrom(rec, now)
			if r.Wide["channel"] != "stable" {
				t.Errorf("%q: wide.channel = %q, want stable", value, r.Wide["channel"])
			}
			if !strings.HasPrefix(r.Detail, "every node runs the latest release, k3sm v0.2.0; the server's channel could not be read") {
				t.Errorf("%q: detail %q does not say why", value, r.Detail)
			}
			if strings.ContainsFunc(r.Detail, func(c rune) bool { return c < 0x20 || c == 0x7f || c == 0x202e }) {
				t.Errorf("%q: detail %q carries a control character", value, r.Detail)
			}
			if got := UpdateAnnotations(rec); got != nil {
				t.Errorf("%q: a record with an unknown channel publishes %v", value, got)
			}
		}
		long := UpdateRowFrom(UpdateRecord{CheckedAt: fresh, Channel: updatesv1alpha1.UpdateChannel(strings.Repeat("x", 4096)), Latest: "v0.2.0"}, now)
		if len(long.Detail) > 300 {
			t.Errorf("an unknown value is not clipped: %d bytes", len(long.Detail))
		}
	})

	t.Run("the annotation is the record's channel", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			ch   updatesv1alpha1.UpdateChannel
			want string
		}{
			{"rc", rc, "rc"},
			{"stable", stable, "stable"},
			// A merge patch never removes a key, so a record with no channel
			// names stable rather than leave an older rc beside a new latest.
			{"an older record", "", "stable"},
		} {
			got := UpdateAnnotations(UpdateRecord{CheckedAt: fresh, Channel: tc.ch, Latest: "v0.2.0"})
			if got[updatesv1alpha1.AnnotationReleaseChannel] != tc.want || got[NodeReleaseLatestAnnotation] != "v0.2.0" || len(got) != 3 {
				t.Errorf("%s: UpdateAnnotations = %v", tc.name, got)
			}
		}
	})

	t.Run("a flip then a failed check keeps the old pair together", func(t *testing.T) {
		good := UpdateRecord{CheckedAt: fresh, Channel: rc, Latest: "v0.3.0-rc.2", Nodes: []UpdateNode{nodeAt("a", "0.3.0-rc.2", UpdateCurrent)}}
		pair := UpdateAnnotations(good)
		if pair[updatesv1alpha1.AnnotationReleaseChannel] != "rc" || pair[NodeReleaseLatestAnnotation] != "v0.3.0-rc.2" {
			t.Fatalf("UpdateAnnotations = %v", pair)
		}

		// The operator sets stable, and the check on it fails.
		failed := UpdateRecord{CheckedAt: now, Channel: stable, Error: "dial tcp: refused"}
		if got := UpdateAnnotations(failed); got != nil {
			t.Fatalf("a failed check publishes %v, so the pair could split", got)
		}

		// So the Node still carries the whole of the old pair.
		node := workerNode("studio", "v1.37.1+k3sm.0.3.0-rc.2")
		node.Labels = map[string]string{controlPlaneNodeLabel: ""}
		node.Annotations = pair
		rec, server, ok := PublishedUpdateRecord([]corev1.Node{node})
		if !ok || server != "studio" || rec.Channel != rc || rec.Latest != "v0.3.0-rc.2" {
			t.Fatalf("PublishedUpdateRecord = %+v, %q, %v", rec, server, ok)
		}
		k := healthyKube()
		k.nodes = []corev1.Node{node}
		r := channelWorkerRow(t, k)
		if r.Wide["channel"] != "rc" || r.Wide["latest"] != "v0.3.0-rc.2" || r.Wide["record"] != "node/studio" {
			t.Errorf("the worker's row split the pair: %+v", r)
		}
		if !strings.HasSuffix(r.Detail, "; channel rc") {
			t.Errorf("detail = %q", r.Detail)
		}

		// The server's own row says the check failed, with no release beside the
		// new channel: a candidate never reads as stable.
		s := UpdateRowFrom(failed, now)
		if s.Wide["channel"] != "stable" || s.Wide["latest"] != "" || s.Detail != "could not check for an update: dial tcp: refused" {
			t.Errorf("the server's row = %+v", s)
		}
	})

	t.Run("a failed listing names when the pair was checked", func(t *testing.T) {
		wd := "/var/lib/k3sm/server"
		checked := now.Add(-2 * time.Hour)
		live := []corev1.Node{channelServer("studio", "v0.3.0-rc.1", "rc", checked), workerNode("my-mac", "v1.37.1+k3sm.0.3.0-rc.1")}
		row := func(t *testing.T, rec UpdateRecord, nodes []corev1.Node, liveOK bool) Row {
			t.Helper()
			raw, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			r, ok := Collector{Paths: Paths{WorkDir: wd}, FS: fakeFS{contents: map[string][]byte{UpdatePath(wd): raw}}}.updateRow(now, nodes, liveOK)
			if !ok {
				t.Fatal("no row")
			}
			return r
		}
		failed := UpdateRecord{CheckedAt: now, Channel: rc, Error: "resolve the latest release: list releases: 403"}
		want := "could not check for an update: resolve the latest release: list releases: 403" +
			"; the last good check found k3sm v0.3.0-rc.1 on channel rc, checked " + checked.UTC().Format(time.RFC3339) + "; channel rc"
		if r := row(t, failed, live, true); r.Detail != want || r.State != StateUnknown {
			t.Errorf("row = %+v, want detail %q", r, want)
		}
		if a := alertOf(row(t, failed, live, true)); !strings.Contains(a, "The last update check failed") {
			t.Errorf("alert = %q", a)
		}
		// With no node list there is no pair to name, and the failure still reads.
		if r := row(t, failed, nil, false); r.Detail != "could not check for an update: resolve the latest release: list releases: 403; channel rc" {
			t.Errorf("no node list: detail = %q", r.Detail)
		}
		// A stable check that fails has listed nothing, and its detail stays.
		failed.Channel = stable
		if r := row(t, failed, live, true); r.Detail != "could not check for an update: resolve the latest release: list releases: 403" {
			t.Errorf("stable: detail = %q", r.Detail)
		}
	})

	t.Run("a pair with no channel reads stable", func(t *testing.T) {
		k := healthyKube()
		k.nodes = []corev1.Node{channelServer("studio", "v0.2.0", "", fresh)}
		r := channelWorkerRow(t, k)
		if r.Wide["channel"] != "stable" || r.Wide["latest"] != "v0.2.0" {
			t.Errorf("row = %+v", r)
		}
		if strings.Contains(r.Detail, "channel") {
			t.Errorf("an older server's pair changed the detail: %q", r.Detail)
		}
		rec := UpdateRecord{CheckedAt: fresh, Latest: "v0.2.0", Nodes: []UpdateNode{nodeAt("a", "0.2.0", UpdateCurrent)}}
		if r := UpdateRowFrom(rec, now); r.Wide["channel"] != "stable" || r.Detail != "every node runs the latest release, k3sm v0.2.0" {
			t.Errorf("an older record: row = %+v", r)
		}
	})

	t.Run("the worker does not list on rc", func(t *testing.T) {
		// A report holds no client for the release host at all, so what it can ask
		// is the node list: one read, the pair the row names is from it.
		lists := 0
		k := healthyKube()
		k.nodes = []corev1.Node{channelServer("studio", "v0.3.0-rc.2", "rc", fresh), workerNode("my-mac", "v1.37.1+k3sm.0.3.0-rc.1")}
		r := channelWorkerRow(t, countingNodes{fakeKube: k, lists: &lists})
		if r.Wide["channel"] != "rc" || r.Wide["latest"] != "v0.3.0-rc.2" || r.Wide["record"] != "node/studio" || r.State != StateBehind {
			t.Errorf("row = %+v", r)
		}
		if !strings.HasPrefix(r.Detail, "k3sm v0.3.0-rc.2 is available; behind: my-mac") || !strings.HasSuffix(r.Detail, "; channel rc") {
			t.Errorf("detail = %q", r.Detail)
		}
		if lists != 1 {
			t.Errorf("%d node lists, want the one the report already takes", lists)
		}
	})

	t.Run("only a server's Node names the channel", func(t *testing.T) {
		forged := workerNode("rogue", "v1.37.1+k3sm.0.2.0")
		forged.Annotations = map[string]string{
			NodeReleaseLatestAnnotation:              "v9.9.9-rc.1",
			NodeReleaseCheckedAnnotation:             now.Format(time.RFC3339),
			updatesv1alpha1.AnnotationReleaseChannel: "rc",
		}
		k := healthyKube()
		k.nodes = []corev1.Node{channelServer("studio", "v0.2.0", "stable", fresh), forged}
		if r := channelWorkerRow(t, k); r.Wide["channel"] != "stable" || r.Wide["latest"] != "v0.2.0" || r.Wide["record"] != "node/studio" {
			t.Errorf("row = %+v", r)
		}
	})

	t.Run("a candidate's kubelet version", func(t *testing.T) {
		for _, tc := range []struct {
			name, kubelet, latest string
			state                 RowState
			detail                string
		}{
			{"on the latest candidate", "0.3.0-rc.2", "v0.3.0-rc.2", StateOK, "every node runs the latest release, k3sm v0.3.0-rc.2"},
			{"behind the next candidate", "0.3.0-rc.1", "v0.3.0-rc.2", StateBehind, "k3sm v0.3.0-rc.2 is available; behind: a (v1.37.1+k3sm.0.3.0-rc.1)"},
			{"ranks numerically, not by text", "0.3.0-rc.9", "v0.3.0-rc.10", StateBehind, "k3sm v0.3.0-rc.10 is available; behind: a (v1.37.1+k3sm.0.3.0-rc.9)"},
			{"above a candidate after a withdrawal", "0.3.0-rc.2", "v0.3.0-rc.1", StateAhead, "k3sm v0.3.0-rc.1 is the latest; newer than the latest release: a (v1.37.1+k3sm.0.3.0-rc.2)"},
			{"behind its own final", "0.3.0-rc.2", "v0.3.0", StateBehind, "k3sm v0.3.0 is available; behind: a (v1.37.1+k3sm.0.3.0-rc.2)"},
			{"a final above the next core's candidate is behind it", "0.3.0", "v0.3.1-rc.1", StateBehind, "k3sm v0.3.1-rc.1 is available; behind: a (v1.37.1+k3sm.0.3.0)"},
			{"a final above its own candidate", "0.3.0", "v0.3.0-rc.2", StateAhead, "k3sm v0.3.0-rc.2 is the latest; newer than the latest release: a (v1.37.1+k3sm.0.3.0)"},
			{"left rc on a candidate", "0.3.0-rc.2", "v0.2.3", StateAhead, "k3sm v0.2.3 is the latest; newer than the latest release: a (v1.37.1+k3sm.0.3.0-rc.2)"},
			{"a higher final after leaving rc", "0.3.0-rc.2", "v0.4.0", StateBehind, "k3sm v0.4.0 is available; behind: a (v1.37.1+k3sm.0.3.0-rc.2)"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rec := UpdateRecord{CheckedAt: fresh, Channel: stable, Latest: tc.latest, Nodes: []UpdateNode{nodeAt("a", tc.kubelet, UpdateUnknown)}}
				r := UpdateRowFrom(rec, now)
				if r.State != tc.state || r.Detail != tc.detail {
					t.Errorf("row = %s %q, want %s %q", r.State, r.Detail, tc.state, tc.detail)
				}
			})
		}
		t.Run("a partly moved cluster that left rc", func(t *testing.T) {
			rec := UpdateRecord{CheckedAt: fresh, Channel: stable, Latest: "v0.2.3", Nodes: []UpdateNode{nodeAt("a", "0.3.0-rc.1", UpdateUnknown), nodeAt("b", "0.2.2", UpdateUnknown)}}
			r := UpdateRowFrom(rec, now)
			want := "k3sm v0.2.3 is available; behind: b (v1.37.1+k3sm.0.2.2); newer than the latest release: a (v1.37.1+k3sm.0.3.0-rc.1)"
			if r.State != StateBehind || r.Detail != want {
				t.Errorf("row = %s %q, want behind %q", r.State, r.Detail, want)
			}
		})
	})

	t.Run("the production status decoders are not strict", func(t *testing.T) {
		// A k3sm that predates a record field reads the record, and a report with
		// a wide key it has not heard of, by ignoring what it does not know.
		wd := "/var/lib/k3sm/server"
		raw := []byte(`{"checkedAt":"` + fresh.Format(time.RFC3339) + `","channel":"rc","fromTheFuture":{"a":1},"latest":"v0.2.0"}`)
		r, ok := Collector{Paths: Paths{WorkDir: wd}, FS: fakeFS{contents: map[string][]byte{UpdatePath(wd): raw}}}.updateRow(now, nil, false)
		if !ok || r.Wide["channel"] != "rc" || strings.Contains(r.Detail, "does not parse") {
			t.Errorf("row = %+v", r)
		}
		var old struct {
			Rows []struct {
				Name string            `json:"name"`
				Wide map[string]string `json:"wide"`
			} `json:"rows"`
		}
		encoded, err := json.Marshal(Report{Rows: []Row{UpdateRowFrom(UpdateRecord{CheckedAt: fresh, Channel: rc, Latest: "v0.2.0"}, now)}})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, &old); err != nil || len(old.Rows) != 1 || old.Rows[0].Wide["channel"] != "rc" {
			t.Errorf("a report with wide.channel: %v, %+v", err, old)
		}
	})

	t.Run("the committed app status fixtures equal regenerated output", func(t *testing.T) {
		scenarios := contractScenarios()
		regenerated := func(t *testing.T, base string) []byte {
			t.Helper()
			name := strings.TrimSuffix(base, ".json")
			if alerts, ok := strings.CutPrefix(name, "alerts_json_"); ok {
				sc, known := scenarios[alertsGoldens[alerts]]
				if !known {
					t.Fatalf("%s: no contract scenario", base)
				}
				encoded, err := encodeAlertsJSON(sc.collector(t).CollectAlerts(context.Background()))
				if err != nil {
					t.Fatal(err)
				}
				return encoded
			}
			var report any
			if posture, ok := strings.CutPrefix(name, "status_daemons_json_"); ok {
				sc, known := scenarios[posture]
				if !known {
					t.Fatalf("%s: no contract scenario", base)
				}
				report = sc.collector(t).CollectDaemons()
			} else if posture, ok := strings.CutPrefix(name, "status_json_"); ok {
				sc, known := scenarios[posture]
				if !known {
					t.Fatalf("%s: no contract scenario", base)
				}
				report = sc.collector(t).Collect(context.Background())
			} else {
				t.Fatalf("%s: not a status fixture", base)
			}
			encoded, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			return append(encoded, '\n')
		}

		goldens, err := filepath.Glob(filepath.Join("testdata", "status_*json_*.json"))
		if err != nil || len(goldens) == 0 {
			t.Fatalf("no status goldens: %v", err)
		}
		goldens = append(goldens, filepath.Join("testdata", "alerts_json_degraded.json"))
		for _, path := range goldens {
			base := filepath.Base(path)
			t.Run("the golden/"+base, func(t *testing.T) {
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := regenerated(t, base); !bytes.Equal(got, want) {
					t.Errorf("%s is not what the collectors produce; the app vendors it, so a change here moves the app's copy too", path)
				}
			})
		}

		// The app's copy, where a checkout sits beside this one; its own gate makes
		// the same comparison and a lone clone has nothing to compare with.
		vendored := filepath.Join("..", "..", "..", "app", "Tests", "K3smStatusTests", "Fixtures")
		if _, err := os.Stat(vendored); errors.Is(err, os.ErrNotExist) {
			t.Skip("no app checkout beside this one")
		}
		fixtures, err := filepath.Glob(filepath.Join(vendored, "status_*json_*.json"))
		if err != nil || len(fixtures) == 0 {
			t.Fatalf("no vendored status fixtures under %s: %v", vendored, err)
		}
		more, err := filepath.Glob(filepath.Join(vendored, "alerts_json_*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range append(fixtures, more...) {
			base := filepath.Base(path)
			t.Run("the app's copy/"+base, func(t *testing.T) {
				want, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := regenerated(t, base); !bytes.Equal(got, want) {
					t.Errorf("%s differs from what k3sm produces", path)
				}
			})
		}
	})
}

// alertOf is the cause of the alert a row carries, empty for none.
func alertOf(r Row) string {
	if a := updateAlert(r); a != nil {
		return a.Cause
	}
	return ""
}
