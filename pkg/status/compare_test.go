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
	"testing"
	"time"
)

// TestSameState pins what the stream treats as a change: the row facts and
// the verdict, never the clock.
func TestSameState(t *testing.T) {
	t.Parallel()
	base := func() Report {
		return Report{
			Verdict: VerdictRunning,
			Role:    "server",
			Summary: "1/1 nodes ready",
			Rows: []Row{
				{Name: RowNode, State: StateReady, Severity: SeverityOK, Detail: "1/1 nodes ready"},
				{Name: RowHeartbeat, State: StateOK, Severity: SeverityOK, Detail: "mac: node status posted 12s ago · lease renewed 3s ago", Wide: map[string]string{"leaseAgeSeconds": "3"}},
				{Name: RowRuntimed, State: StateNeedsAdmin, Severity: SeveritySkip, Detail: "the runtime socket is root-only"},
			},
			Timestamp: time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC),
		}
	}
	for _, tc := range []struct {
		name string
		edit func(*Report)
		same bool
	}{
		{"identical", func(*Report) {}, true},
		{"only the timestamp moved", func(r *Report) { r.Timestamp = r.Timestamp.Add(30 * time.Second) }, true},
		{"only the provenance moved", func(r *Report) { r.Version.Commit = "other" }, true},
		{"only an age moved", func(r *Report) {
			r.Rows[1].Detail = "mac: node status posted 1m2s ago · lease renewed 7s ago"
			r.Rows[1].Wide = map[string]string{"leaseAgeSeconds": "7"}
		}, true},
		{"a node went not-ready", func(r *Report) {
			r.Rows[0].State, r.Rows[0].Severity, r.Rows[0].Detail = StateNotReady, SeverityFail, "0/1 nodes ready"
		}, false},
		{"a detail changed", func(r *Report) { r.Rows[0].Detail = "2/2 nodes ready" }, false},
		{"a row appeared", func(r *Report) { r.Rows = append(r.Rows, Row{Name: RowDNS, State: StateOK}) }, false},
		{"the verdict changed", func(r *Report) { r.Verdict = VerdictDegraded }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := base()
			tc.edit(&b)
			if got := SameState(base(), b); got != tc.same {
				t.Errorf("SameState = %v, want %v", got, tc.same)
			}
		})
	}
	t.Run("counted ages mask to the same token", func(t *testing.T) {
		t.Parallel()
		if maskAges("copy (2G, 3 minutes ago)") != maskAges("copy (2G, just now)") {
			t.Error("a counted age and just now differ after masking")
		}
	})
}
