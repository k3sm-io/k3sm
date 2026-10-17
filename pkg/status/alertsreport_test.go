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
	"strings"
	"testing"
)

// TestAlertsCutsOnlyTheRowsThatNeedAttention drives every contract posture's
// full report through Alerts and checks the cut: the verdict, role and summary
// carried over, exactly the rows with an alert, in report order, and a list
// that encodes as [] (never null) when nothing needs attention.
func TestAlertsCutsOnlyTheRowsThatNeedAttention(t *testing.T) {
	t.Parallel()
	for name, sc := range contractScenarios() {
		t.Run(name, func(t *testing.T) {
			c := sc.collector(t)
			rep := c.Collect(context.Background())
			got := c.CollectAlerts(context.Background())
			if got.Verdict != rep.Verdict || got.Role != rep.Role || got.Summary != rep.Summary || got.SchemaVersion != SchemaVersion {
				t.Fatalf("alerts header %v/%v/%q/%d, report %v/%v/%q/%d", got.Verdict, got.Role, got.Summary, got.SchemaVersion,
					rep.Verdict, rep.Role, rep.Summary, SchemaVersion)
			}
			var want []string
			for _, r := range rep.Rows {
				if NeedsAlert(r) {
					want = append(want, r.Name)
				}
			}
			var names []string
			for _, r := range got.Alerts {
				if r.Alert == nil {
					t.Errorf("%s is in the alerts list without an alert", r.Name)
				}
				names = append(names, r.Name)
			}
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Errorf("alerts rows %v, want the non-ok rows %v", names, want)
			}
			raw, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), `"alerts":[`) {
				t.Errorf("alerts list does not encode as a JSON array: %s", raw)
			}
			text := RenderAlerts(got, Style{})
			if !strings.HasPrefix(text, "k3sm "+got.Verdict.String()+": ") {
				t.Errorf("screen does not start with the verdict line:\n%s", text)
			}
			for _, r := range got.Alerts {
				if !strings.Contains(text, r.Alert.Cause) || !strings.Contains(text, "docs: docs/user/"+r.Alert.Docs) {
					t.Errorf("screen lacks the cause or docs of %s:\n%s", r.Name, text)
				}
			}
		})
	}
}

// TestAlertsNode pins where the node name comes from: the node row's pick,
// then the heartbeat row's, then the short host name.
func TestAlertsNode(t *testing.T) {
	t.Parallel()
	withWide := func(name, node string) Row {
		return Row{Name: name, State: StateReady, Severity: SeverityOK, Wide: map[string]string{"node": node}}
	}
	cases := []struct {
		name     string
		rows     []Row
		hostname string
		want     string
	}{
		{"node row", []Row{withWide(RowNode, "k3sm-mac"), withWide(RowHeartbeat, "other")}, "mac.local", "k3sm-mac"},
		{"heartbeat row", []Row{{Name: RowNode}, withWide(RowHeartbeat, "k3sm-hb")}, "mac.local", "k3sm-hb"},
		{"host name", []Row{{Name: RowNode}}, "mac.local", "mac"},
		{"nothing known", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Alerts(Report{Rows: tc.rows}, tc.hostname).Node; got != tc.want {
				t.Errorf("node %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRenderAlertsHealthy pins the screen when nothing needs attention.
func TestRenderAlertsHealthy(t *testing.T) {
	t.Parallel()
	rows := healthyRows()
	attachAlerts(rows, serverCtx)
	got := RenderAlerts(Alerts(Report{Verdict: VerdictRunning, Summary: "1/1 nodes ready", Rows: rows}, "mac"), Style{})
	want := "k3sm running: 1/1 nodes ready · node mac\n\nNo alerts: nothing on this Mac needs attention.\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

// TestRenderAlertsSteps pins how one alert reads: the row line, the cause, the
// evidence beyond the detail, the numbered steps with the administrator mark,
// and the docs page.
func TestRenderAlertsSteps(t *testing.T) {
	t.Parallel()
	row := Row{Name: RowServer, State: StateStopped, Severity: SeverityFail, Detail: "io.k3sm.server is loaded but not running"}
	row.Alert = &Alert{
		Cause:    "The control-plane daemon is loaded in launchd but not running.",
		Evidence: []string{row.Detail, "last-exit: 1"},
		Fix:      []FixStep{manual("Check the log"), cmd("Restart the daemon", "sudo launchctl kickstart -k system/io.k3sm.server")},
		Docs:     docsDaemon,
		Since:    "2026-09-05T09:30:00Z",
	}
	got := RenderAlerts(AlertsReport{Verdict: VerdictStopped, Summary: "the control plane is not serving", Alerts: []Row{row}}, Style{})
	want := "k3sm stopped: the control plane is not serving\n\n" +
		"    " + pad(RowServer, nameWidth) + " " + pad(string(StateStopped), stateWidth) + " io.k3sm.server is loaded but not running\n" +
		logIndent + "The control-plane daemon is loaded in launchd but not running.\n" +
		logIndent + "since 2026-09-05T09:30:00Z\n" +
		logIndent + "last-exit: 1\n" +
		logIndent + "1. Check the log\n" +
		logIndent + "2. Restart the daemon: sudo launchctl kickstart -k system/io.k3sm.server (administrator)\n" +
		logIndent + "docs: docs/user/troubleshooting.md#a-k3sm-daemon-is-not-running\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}
