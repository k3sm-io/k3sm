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
	"context"
	"encoding/json"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/status"
)

// degradedAlerts is a report with one row that needs attention.
func degradedAlerts() status.AlertsReport {
	return status.AlertsReport{
		SchemaVersion: status.SchemaVersion,
		Verdict:       status.VerdictDegraded,
		Role:          "server",
		Summary:       "1/1 nodes ready; the node resolver is missing",
		Node:          "k3sm-mac",
		Alerts: []status.Row{{
			Name: status.RowNodeResolver, State: status.StateMissing, Severity: status.SeverityWarn,
			Detail: "netd has not published the node resolver entry",
			Remedy: "sudo launchctl kickstart -k system/io.k3sm.netd",
			Alert: &status.Alert{
				Cause:    "netd has not published the node resolver entry, so host processes cannot resolve cluster names.",
				Evidence: []string{"netd has not published the node resolver entry"},
				Fix:      []status.FixStep{{Step: "Restart the daemon", Command: "sudo launchctl kickstart -k system/io.k3sm.netd", NeedsAdmin: true}},
				Docs:     "troubleshooting.md#the-node-resolver-does-not-answer",
			},
		}},
	}
}

// TestAlertsVerb drives `k3sm alerts` through its parsed command line against a
// fake collector: the JSON carries the verdict, the node and the alert object
// under the documented keys, the text names the cause and the fix, the exit
// code is the verdict, and a bad flag or argument is a usage error that never
// collects.
func TestAlertsVerb(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		args     []string
		code     int
		contains []string
		collects bool
	}{
		{"json", []string{"-o", "json"}, status.VerdictDegraded.ExitCode(), []string{
			`"verdict": "degraded"`, `"node": "k3sm-mac"`, `"alerts": [`, `"alert": {`, `"cause": "netd has not published`,
			`"needsAdmin": true`, `"confirm": false`, `"docs": "troubleshooting.md#the-node-resolver-does-not-answer"`, `"schemaVersion": 1`,
		}, true},
		{"text", nil, status.VerdictDegraded.ExitCode(), []string{
			"k3sm degraded: 1/1 nodes ready; the node resolver is missing · node k3sm-mac",
			"so host processes cannot resolve cluster names.",
			"1. Restart the daemon: sudo launchctl kickstart -k system/io.k3sm.netd (administrator)",
			"docs: docs/user/troubleshooting.md#the-node-resolver-does-not-answer",
		}, true},
		{"help", []string{"--help"}, 0, []string{"Usage: k3sm alerts"}, false},
		{"bad format", []string{"-o", "wide"}, exitUsage, nil, false},
		{"positional", []string{"cluster"}, exitUsage, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			collected := false
			collect := func(context.Context) status.AlertsReport { collected = true; return degradedAlerts() }
			code := runAlertsArgs(context.Background(), tc.args, &out, &errOut, collect, func(bool) bool { return false })
			if code != tc.code {
				t.Errorf("exit %d, want %d (stderr %q)", code, tc.code, errOut.String())
			}
			if collected != tc.collects {
				t.Errorf("collected=%v, want %v", collected, tc.collects)
			}
			for _, want := range tc.contains {
				if !strings.Contains(out.String(), want) {
					t.Errorf("output lacks %q:\n%s", want, out.String())
				}
			}
		})
	}
}

// TestAlertsJSONRoundTrips decodes the verb's JSON back into the report type,
// so a key the encoder writes is a key a Go reader reads.
func TestAlertsJSONRoundTrips(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	collect := func(context.Context) status.AlertsReport { return degradedAlerts() }
	if code := runAlertsArgs(context.Background(), []string{"-o", "json"}, &out, &bytes.Buffer{}, collect, func(bool) bool { return false }); code != status.VerdictDegraded.ExitCode() {
		t.Fatalf("exit %d", code)
	}
	dec := json.NewDecoder(&out)
	dec.DisallowUnknownFields()
	var got status.AlertsReport
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Alerts) != 1 || got.Alerts[0].Alert == nil || !got.Alerts[0].Alert.Fix[0].NeedsAdmin {
		t.Errorf("round trip lost the alert: %+v", got.Alerts)
	}
}
