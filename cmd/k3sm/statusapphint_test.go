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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/status"
)

// TestStatusAppHint pins the k3sm.app hint: a fixed line at the end of the
// human output when the app is absent, and never in the JSON.
func TestStatusAppHint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		format   string
		present  bool
		wantHint bool
	}{
		{name: "text, app absent", format: "text", wantHint: true},
		{name: "wide, app absent", format: "wide", wantHint: true},
		{name: "text, app present", format: "text", present: true},
		{name: "json, app absent", format: "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out, errOut bytes.Buffer
			r := testRunner(&out, &errOut, func(context.Context) status.Report { return reportOf(status.VerdictRunning) })
			r.appPresent = func() bool { return tc.present }
			r.run(context.Background(), statusOptions{format: tc.format})
			got := strings.Contains(out.String(), "k3sm.app is not installed")
			if got != tc.wantHint {
				t.Errorf("hint printed = %v, want %v; output:\n%s", got, tc.wantHint, out.String())
			}
			if tc.wantHint && !strings.HasSuffix(out.String(), appHint) {
				t.Errorf("the hint is not the last line:\n%s", out.String())
			}
		})
	}
}
