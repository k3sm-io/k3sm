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
	"errors"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// TestDeveloperModeRow pins the developer-mode row: no row when nothing is at
// the marker path (or no reader is wired), on and invalid with their fixed
// sentences, the installed k3sm's signing in the wide map when it can be
// read, and a running verdict that the row does not move.
func TestDeveloperModeRow(t *testing.T) {
	t.Parallel()
	const bin = "/Library/k3sm/k3sm"
	cases := []struct {
		name       string
		state      install.DeveloperModeState
		nilReader  bool
		team       string
		teamErr    error
		noSigner   bool
		wantRow    bool
		wantState  RowState
		wantDetail string
		wantRemedy string
		wantWide   string // "" = no signing key
	}{
		{name: "no reader wired", nilReader: true},
		{name: "nothing at the marker path", state: install.DeveloperModeAbsent},
		{name: "a valid marker over an ad-hoc k3sm", state: install.DeveloperModeMarkerOn, teamErr: install.ErrNoTeamID,
			wantRow: true, wantState: StateOn, wantDetail: developerModeOnDetail, wantRemedy: developerModeOnRemedy, wantWide: "ad-hoc"},
		{name: "a valid marker over a team-signed k3sm", state: install.DeveloperModeMarkerOn, team: "ABCDE12345",
			wantRow: true, wantState: StateOn, wantDetail: developerModeOnDetail, wantRemedy: developerModeOnRemedy, wantWide: "team ABCDE12345"},
		{name: "an invalid marker", state: install.DeveloperModeInvalid, team: "ABCDE12345",
			wantRow: true, wantState: StateInvalid, wantDetail: developerModeInvalidDetail, wantRemedy: "sudo rm /Library/k3sm.developer-mode", wantWide: "team ABCDE12345"},
		{name: "an unreadable signature leaves the key out", state: install.DeveloperModeMarkerOn, teamErr: errors.New("codesign failed"),
			wantRow: true, wantState: StateOn, wantDetail: developerModeOnDetail, wantRemedy: developerModeOnRemedy},
		{name: "no signature reader leaves the key out", state: install.DeveloperModeMarkerOn, noSigner: true,
			wantRow: true, wantState: StateOn, wantDetail: developerModeOnDetail, wantRemedy: developerModeOnRemedy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{Paths: Paths{Binary: bin}}
			if !tc.nilReader {
				c.DeveloperMode = func() install.DeveloperModeState { return tc.state }
			}
			if !tc.noSigner {
				c.SigningTeamID = func(_ context.Context, path string) (string, error) {
					if path != bin {
						t.Errorf("signature read for %s, want the installed %s", path, bin)
					}
					return tc.team, tc.teamErr
				}
			}
			r, ok := c.developerModeRow(context.Background())
			if ok != tc.wantRow {
				t.Fatalf("row present = %v, want %v (%+v)", ok, tc.wantRow, r)
			}
			if !ok {
				return
			}
			if r.Name != RowDeveloperMode || r.State != tc.wantState || r.Severity != SeverityWarn || r.Detail != tc.wantDetail || r.Remedy != tc.wantRemedy {
				t.Errorf("row = %+v", r)
			}
			if got := r.Wide["signing"]; got != tc.wantWide {
				t.Errorf("wide signing = %q, want %q", got, tc.wantWide)
			}
			if tc.wantWide == "" && r.Wide != nil {
				t.Errorf("wide = %v, want none", r.Wide)
			}
		})
	}

	t.Run("the row does not move a running verdict, and the text shows it", func(t *testing.T) {
		t.Parallel()
		for _, name := range []string{"developer_mode", "developer_mode_invalid"} {
			rep := contractScenarios()[name].collector(t).Collect(context.Background())
			if rep.Verdict != VerdictRunning {
				t.Errorf("%s: verdict %v, want running", name, rep.Verdict)
			}
			if _, ok := rep.Row(RowDeveloperMode); !ok {
				t.Errorf("%s: no developer-mode row", name)
			}
			if text := Render(rep, Style{}); !strings.Contains(text, RowDeveloperMode) {
				t.Errorf("%s: the text report does not show the row:\n%s", name, text)
			}
		}
	})
}
