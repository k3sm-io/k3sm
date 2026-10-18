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

import "regexp"

// SameState reports whether two reports say the same thing about the cluster:
// the same verdict, role and summary, and the same rows in the same order with
// the same name, state, severity and detail.
//
// It is what the `k3sm status --watch -o json` stream compares to decide
// whether a re-collect is worth a frame, so it deliberately leaves out
// everything that moves with the clock and nothing else: the timestamp, the
// build provenance, a row's wide columns (which carry ages in seconds) and its
// alert (whose evidence repeats the detail). The other report fields (workers,
// network, the stop marker, the interconnect block) are not compared on their
// own either; each of them is also stated by a row or by the verdict.
//
// A detail is compared with its clock-derived ages masked ("posted 12s ago",
// "ran 3 hours ago"), because the rows that print an age re-derive it from
// the clock on every collect: a heartbeat row whose node posts on time would
// otherwise differ on every collect while nothing about the node changed. A
// change that matters moves the row's state or severity, which are compared
// as they are.
func SameState(a, b Report) bool {
	if a.Verdict != b.Verdict || a.Role != b.Role || maskAges(a.Summary) != maskAges(b.Summary) || len(a.Rows) != len(b.Rows) {
		return false
	}
	for i := range a.Rows {
		x, y := a.Rows[i], b.Rows[i]
		if x.Name != y.Name || x.State != y.State || x.Severity != y.Severity || maskAges(x.Detail) != maskAges(y.Detail) {
			return false
		}
	}
	return true
}

// clockAges matches an age a row derives from the clock: a Go duration
// ("12s", "1h2m3s", "1.5s") or a counted unit ("3 minutes"), followed by
// "ago", or the "just now" a counted age starts as. Every row that prints an
// age prints it in one of those forms.
var clockAges = regexp.MustCompile(`\b(?:\d+(?:\.\d+)?(?:h|ms|m|s|µs|ns))+ ago\b|\b\d+ (?:seconds?|minutes?|hours?|days?) ago\b|\bjust now\b`)

// maskAges replaces every clock-derived age in s with a fixed token.
func maskAges(s string) string {
	return clockAges.ReplaceAllString(s, "<age> ago")
}
