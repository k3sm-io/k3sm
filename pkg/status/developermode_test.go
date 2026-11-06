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
	"fmt"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/install"
)

// soundMarker is a marker file that passes every check of its own.
var soundMarker = install.OwnedEntry{Kind: install.EntryRegular, Mode: 0o644}

// markerFactsUnder is marker under / and /Library, with the directory named
// bad group-writable.
func markerFactsUnder(marker install.OwnedEntry, bad string) install.DeveloperModeFacts {
	dir := func(name string) install.DeveloperModeAncestor {
		e := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o755}
		if name == bad {
			e.Mode = 0o775
		}
		return install.DeveloperModeAncestor{Entry: e}
	}
	return install.DeveloperModeFacts{Exists: true, Entry: marker, Ancestors: []install.DeveloperModeAncestor{dir("/"), dir("/Library")}}
}

// markerFacts is a read of the marker that judges to state.
func markerFacts(state install.DeveloperModeState) install.DeveloperModeFacts {
	switch state {
	case install.DeveloperModeMarkerOn:
		return markerFactsUnder(soundMarker, "")
	case install.DeveloperModeInvalid:
		return markerFactsUnder(install.OwnedEntry{Kind: install.EntryRegular, Mode: 0o666}, "")
	case install.DeveloperModeUnknown:
		return install.DeveloperModeFacts{Exists: true, Err: errors.New("lstat: permission denied")}
	}
	return install.DeveloperModeFacts{}
}

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
				c.DeveloperMode = func() install.DeveloperModeFacts { return markerFacts(tc.state) }
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

// TestDeveloperModeInvalidRowNamesAncestorCause pins that an invalid marker
// whose cause is a directory above it names that directory in the detail and
// the remedy, and that a marker-file cause keeps the sudo rm remedy.
func TestDeveloperModeInvalidRowNamesAncestorCause(t *testing.T) {
	t.Parallel()
	row := func(dir string) Row {
		f := markerFacts(install.DeveloperModeInvalid)
		if dir != "" {
			f = markerFactsUnder(soundMarker, "/Library")
		}
		c := Collector{DeveloperMode: func() install.DeveloperModeFacts { return f }}
		r, ok := c.developerModeRow(context.Background())
		if !ok {
			t.Fatal("no developer-mode row")
		}
		return r
	}
	r := row("/Library")
	if !strings.Contains(r.Detail, "/Library") || !strings.Contains(r.Remedy, "/Library") || strings.Contains(r.Remedy, "sudo rm") {
		t.Errorf("ancestor row = %+v", r)
	}
	if !strings.Contains(r.Remedy, "removing the marker clears this row but leaves that directory as it is") {
		t.Errorf("ancestor remedy = %q, want it to say what removing the marker does", r.Remedy)
	}
	a := developerModeAlert(r)
	if a == nil {
		t.Fatal("no ancestor alert")
	}
	if !strings.Contains(a.Cause, "A directory above the developer-mode marker") || strings.Contains(a.Cause, "not a root-owned file nobody") {
		t.Errorf("ancestor alert cause = %q", a.Cause)
	}
	if len(a.Fix) != 1 || a.Fix[0].Step != r.Remedy || a.Fix[0].Command != "" {
		t.Errorf("ancestor alert fix = %+v, want the row's remedy as one step by hand", a.Fix)
	}
	r = row("")
	if ma := developerModeAlert(r); ma == nil || len(ma.Fix) != 1 || ma.Fix[0].Command != developerModeInvalidRemedy {
		t.Errorf("marker-file alert = %+v, want the sudo rm step", ma)
	}
	if r.Detail != developerModeInvalidDetail || r.Remedy != developerModeInvalidRemedy {
		t.Errorf("marker-file row = %+v", r)
	}
}

// TestDeveloperModeInvalidDirectoryRemedy pins that a directory at the marker
// path gets a removal command rm accepts, in the row and in the alert; that a
// bad directory above it gets the ancestor remedy instead, because rm -r must
// not be aimed through it; and that a file keeps the plain command.
func TestDeveloperModeInvalidDirectoryRemedy(t *testing.T) {
	t.Parallel()
	const dirRemedy = "sudo rm -r /Library/k3sm.developer-mode"
	dirMarker := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o755}
	for _, tc := range []struct {
		name string
		f    install.DeveloperModeFacts
		want string
		// wantCmd is the alert's command; a remedy done by hand has none.
		wantCmd string
	}{
		{name: "a directory", f: markerFactsUnder(dirMarker, ""), want: dirRemedy, wantCmd: dirRemedy},
		{name: "a file", f: markerFacts(install.DeveloperModeInvalid), want: developerModeInvalidRemedy, wantCmd: developerModeInvalidRemedy},
		{name: "a directory under a bad /Library", f: markerFactsUnder(dirMarker, "/Library"), want: fmt.Sprintf(developerModeAncestorRemedyFmt, "/Library")},
		{name: "a file owned by a user under a bad /Library", f: badRegularMarkerUnderBadLibrary(), want: fmt.Sprintf(developerModeAncestorRemedyFmt, "/Library")},
		{name: "a directory under a bad /", f: markerFactsUnder(dirMarker, "/"), want: fmt.Sprintf(developerModeAncestorRemedyFmt, "/")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{DeveloperMode: func() install.DeveloperModeFacts { return tc.f }}
			r, ok := c.developerModeRow(context.Background())
			if !ok || r.Remedy != tc.want {
				t.Fatalf("row %+v, ok %v; want remedy %q", r, ok, tc.want)
			}
			a := developerModeAlert(r)
			if a == nil || len(a.Fix) != 1 || a.Fix[0].Command != tc.wantCmd {
				t.Fatalf("alert = %+v, want command %q", a, tc.wantCmd)
			}
		})
	}
}

// badRegularMarkerUnderBadLibrary is a regular file that fails by itself, under
// a /Library that fails too.
func badRegularMarkerUnderBadLibrary() install.DeveloperModeFacts {
	good := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o755}
	bad := install.OwnedEntry{Kind: install.EntryDir, Mode: 0o775}
	return install.DeveloperModeFacts{
		Exists:    true,
		Entry:     install.OwnedEntry{Kind: install.EntryRegular, UID: 501, Mode: 0o644},
		Ancestors: []install.DeveloperModeAncestor{{Entry: good}, {Entry: bad}},
	}
}

// TestDeveloperModeRowReadsOneSnapshot pins that a row takes one read of the
// marker, whatever it finds, so its state, cause and remedy describe one moment.
func TestDeveloperModeRowReadsOneSnapshot(t *testing.T) {
	t.Parallel()
	for _, state := range []install.DeveloperModeState{install.DeveloperModeAbsent, install.DeveloperModeMarkerOn, install.DeveloperModeInvalid, install.DeveloperModeUnknown} {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()
			reads := 0
			c := Collector{DeveloperMode: func() install.DeveloperModeFacts {
				reads++
				return markerFacts(state)
			}}
			c.developerModeRow(context.Background())
			if reads != 1 {
				t.Errorf("the row read the marker %d times, want 1", reads)
			}
		})
	}
}

// TestDeveloperModeUnknownRow pins the row of a read that could not see the
// marker path: it is there at warn, it claims neither a marker nor the checks
// staying on, it names no removal, and its remedy can work from the account it
// is written for.
func TestDeveloperModeUnknownRow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		euid       int
		wantRemedy string
		wantCmd    string
	}{
		{name: "an ordinary account reads it again as root", euid: 501, wantRemedy: "sudo k3sm status", wantCmd: "sudo k3sm status"},
		{name: "root looks at the path", euid: 0, wantRemedy: "Check the path and the directories above it with ls -ldO@e /Library/k3sm.developer-mode /Library /"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{EUID: tc.euid, DeveloperMode: func() install.DeveloperModeFacts { return markerFacts(install.DeveloperModeUnknown) }}
			r, ok := c.developerModeRow(context.Background())
			if !ok {
				t.Fatal("no row: an unread marker must not read as absent")
			}
			if r.State != StateUnknown || r.Severity != SeverityWarn || r.Remedy != tc.wantRemedy {
				t.Errorf("row = %+v", r)
			}
			for _, claim := range []string{"marker exists", "stay on", "ignored", "this account"} {
				if strings.Contains(r.Detail, claim) {
					t.Errorf("detail %q claims %q", r.Detail, claim)
				}
			}
			if strings.Contains(r.Remedy, "rm ") {
				t.Errorf("remedy %q removes what it could not read", r.Remedy)
			}
			a := developerModeAlert(r)
			if a == nil || len(a.Fix) != 1 || a.Fix[0].Command != tc.wantCmd {
				t.Fatalf("alert = %+v", a)
			}
			if !strings.Contains(a.Cause, "cannot say whether developer mode is on") || strings.Contains(a.Cause, "this account") {
				t.Errorf("alert cause = %q", a.Cause)
			}
			if tc.wantCmd == "" && a.Fix[0].Step != tc.wantRemedy {
				t.Errorf("alert step = %q, want %q", a.Fix[0].Step, tc.wantRemedy)
			}
		})
	}
}
