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

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDeveloperModeMarkerState pins the marker's lstat discipline: only a
// regular file owned by root, with no group or other write bit and no ACL,
// turns developer mode on; anything else at the path is invalid and counts as
// absent.
func TestDeveloperModeMarkerState(t *testing.T) {
	t.Parallel()
	good := OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	ancestors := []DeveloperModeAncestor{
		{Entry: OwnedEntry{Path: "/", Kind: EntryDir, Mode: 0o755}},
		{Entry: OwnedEntry{Path: "/Library", GID: 80, Kind: EntryDir, Mode: 0o755}},
	}
	with := func(mut func(*OwnedEntry)) DeveloperModeFacts {
		e := good
		mut(&e)
		return DeveloperModeFacts{Exists: true, Entry: e, Ancestors: ancestors}
	}
	cases := []struct {
		name  string
		facts DeveloperModeFacts
		want  DeveloperModeState
	}{
		{name: "nothing there", facts: DeveloperModeFacts{}, want: DeveloperModeAbsent},
		{name: "root:wheel 0644", facts: DeveloperModeFacts{Exists: true, Entry: good, Ancestors: ancestors}, want: DeveloperModeMarkerOn},
		{name: "root:wheel 0644 with no ancestor described", facts: DeveloperModeFacts{Exists: true, Entry: good}, want: DeveloperModeInvalid},
		{name: "root 0600", facts: with(func(e *OwnedEntry) { e.Mode = 0o600 }), want: DeveloperModeMarkerOn},
		{name: "a symlink", facts: with(func(e *OwnedEntry) { e.Kind = EntrySymlink }), want: DeveloperModeInvalid},
		{name: "a directory", facts: with(func(e *OwnedEntry) { e.Kind = EntryDir; e.Mode = 0o755 }), want: DeveloperModeInvalid},
		{name: "a fifo", facts: with(func(e *OwnedEntry) { e.Kind = EntryOther }), want: DeveloperModeInvalid},
		{name: "owned by a user", facts: with(func(e *OwnedEntry) { e.UID = 501 }), want: DeveloperModeInvalid},
		{name: "0666", facts: with(func(e *OwnedEntry) { e.Mode = 0o666 }), want: DeveloperModeInvalid},
		{name: "0664", facts: with(func(e *OwnedEntry) { e.Mode = 0o664 }), want: DeveloperModeInvalid},
		{name: "0646", facts: with(func(e *OwnedEntry) { e.Mode = 0o646 }), want: DeveloperModeInvalid},
		{name: "an ACL", facts: DeveloperModeFacts{Exists: true, Entry: good, HasACL: true, Ancestors: ancestors}, want: DeveloperModeInvalid},
		{name: "a probe that failed", facts: DeveloperModeFacts{Exists: true, Entry: good, Err: errors.New("EIO"), Ancestors: ancestors}, want: DeveloperModeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DeveloperModeMarkerState(tc.facts); got != tc.want {
				t.Errorf("DeveloperModeMarkerState = %s, want %s", got, tc.want)
			}
		})
	}

	t.Run("read through the System seam", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name    string
			entry   *OwnedEntry
			acl     bool
			want    DeveloperModeState
			wantACL bool
		}{
			{name: "absent", want: DeveloperModeAbsent},
			{name: "valid", entry: &good, want: DeveloperModeMarkerOn, wantACL: true},
			{name: "a valid file with an ACL", entry: &good, acl: true, want: DeveloperModeInvalid, wantACL: true},
			{name: "a symlink is described, never followed or probed", entry: &OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntrySymlink, Mode: 0o755}, want: DeveloperModeInvalid},
			{name: "world-writable", entry: &OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o666}, want: DeveloperModeInvalid, wantACL: true},
		} {
			f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{DeveloperModeMarkerPath: tc.acl}}
			seedMarkerAncestors(f)
			if tc.entry != nil {
				f.owners[DeveloperModeMarkerPath] = *tc.entry
			}
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != tc.want {
				t.Errorf("%s: state %s, want %s", tc.name, got, tc.want)
			}
			if probed := slices.Contains(f.calls, "HasACL:"+DeveloperModeMarkerPath); probed != tc.wantACL {
				t.Errorf("%s: ACL probed = %v, want %v (calls %v)", tc.name, probed, tc.wantACL, f.calls)
			}
		}
	})
}

// seedMarkerAncestors gives the fake the directories above the marker as a
// Mac has them: / root:wheel 0755 and /Library root:admin 0755, real
// directories that neither group nor others can write, with no ACL. A test
// that puts a marker on the fake seeds them too, or the marker is invalid.
func seedMarkerAncestors(f *fakeSystem) {
	if f.owners == nil {
		f.owners = map[string]OwnedEntry{}
	}
	f.owners["/"] = OwnedEntry{Path: "/", Kind: EntryDir, Mode: 0o755}
	f.owners["/Library"] = OwnedEntry{Path: "/Library", GID: 80, Kind: EntryDir, Mode: 0o755}
}

// TestDeveloperModeMarkerJudgesAncestors pins that the marker counts only when
// every directory above it, from /, passes the checks the app applies: a real
// directory (not a symlink), owned by root, with no group or other write bit
// and no ACL. A valid marker under a failing ancestor is invalid, so the
// signature checks stay on.
func TestDeveloperModeMarkerJudgesAncestors(t *testing.T) {
	t.Parallel()
	marker := OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	cases := []struct {
		name string
		mut  func(*fakeSystem)
		want DeveloperModeState
	}{
		{name: "root-owned / and /Library", mut: func(*fakeSystem) {}, want: DeveloperModeMarkerOn},
		{name: "/Library writable by group", mut: func(f *fakeSystem) {
			e := f.owners["/Library"]
			e.Mode = 0o775
			f.owners["/Library"] = e
		}, want: DeveloperModeInvalid},
		{name: "/Library writable by others", mut: func(f *fakeSystem) {
			e := f.owners["/Library"]
			e.Mode = 0o757
			f.owners["/Library"] = e
		}, want: DeveloperModeInvalid},
		{name: "/ writable by group", mut: func(f *fakeSystem) {
			e := f.owners["/"]
			e.Mode = 0o775
			f.owners["/"] = e
		}, want: DeveloperModeInvalid},
		{name: "/Library with an ACL", mut: func(f *fakeSystem) { f.acls["/Library"] = true }, want: DeveloperModeInvalid},
		{name: "/ with an ACL", mut: func(f *fakeSystem) { f.acls["/"] = true }, want: DeveloperModeInvalid},
		{name: "/Library owned by a user", mut: func(f *fakeSystem) {
			e := f.owners["/Library"]
			e.UID = 501
			f.owners["/Library"] = e
		}, want: DeveloperModeInvalid},
		{name: "/Library a symlink", mut: func(f *fakeSystem) {
			f.owners["/Library"] = OwnedEntry{Path: "/Library", Kind: EntrySymlink, Mode: 0o755}
		}, want: DeveloperModeInvalid},
		{name: "/Library not a directory", mut: func(f *fakeSystem) {
			f.owners["/Library"] = OwnedEntry{Path: "/Library", Kind: EntryRegular, Mode: 0o644}
		}, want: DeveloperModeInvalid},
		{name: "/Library that cannot be described", mut: func(f *fakeSystem) { delete(f.owners, "/Library") }, want: DeveloperModeInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{DeveloperModeMarkerPath: marker}, acls: map[string]bool{}}
			seedMarkerAncestors(f)
			tc.mut(f)
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != tc.want {
				t.Errorf("ReadDeveloperModeState = %s, want %s (calls %v)", got, tc.want, f.calls)
			}
		})
	}

	t.Run("an absent marker is absent whatever its ancestors", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{"/Library": true}}
		seedMarkerAncestors(f)
		if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeAbsent {
			t.Errorf("ReadDeveloperModeState = %s, want %s", got, DeveloperModeAbsent)
		}
	})
}

// TestParseDeveloperMode pins the accepted values: exactly on or off.
func TestParseDeveloperMode(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]DeveloperMode{"on": DeveloperModeOn, "off": DeveloperModeOff} {
		if got, err := ParseDeveloperMode(in); err != nil || got != want {
			t.Errorf("ParseDeveloperMode(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ON", "On", " on", "yes", "true", "1"} {
		if _, err := ParseDeveloperMode(bad); err == nil {
			t.Errorf("ParseDeveloperMode(%q) accepted", bad)
		}
	}
}

// markerContent is the one line the marker carries.
var markerContent = regexp.MustCompile(`^developer mode enabled by k3sm install on \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\n$`)

// TestDeveloperModeMarkerOnInstall pins what an install does with the marker:
// on writes it root:wheel 0644 through the temp-and-rename seam before the
// install root is swapped, and a failed install leaves it; off removes it
// without following a symlink; not passed keeps it with a Warn saying why,
// unless the k3sm being installed carries a Developer ID team signature, which
// removes it with an Info line. An install from a staging directory needs the
// whole tree team-signed instead (TestDeveloperModeOffNeedsTheWholeTree).
func TestDeveloperModeMarkerOnInstall(t *testing.T) {
	t.Parallel()
	const src = "/tmp/k3sm"
	marker := OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	writeCall := "WriteRootOnlyFile:" + DeveloperModeMarkerPath + ":0644"
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	teamSigned := fakeSigner{ids: map[string]string{src: testTeamID}}
	adHoc := fakeSigner{errs: map[string]error{src: ErrNoTeamID}}
	appleDevelopment := fakeSigner{ids: map[string]string{src: testTeamID}, notDevID: map[string]bool{src: true}}

	cases := []struct {
		name       string
		mode       DeveloperMode
		signer     TeamIDReader
		onDisk     *OwnedEntry
		swapErr    error
		wantWrite  bool
		wantRemove bool
		wantInfo   bool
		// wantKeepWarn is the Warn a no-flag install logs when it keeps a
		// marker it could have turned off.
		wantKeepWarn bool
		// wantInvalidInfo is the Info line for an invalid marker a signed
		// install removed; wantIgnoredWarn the Warn for one it kept.
		wantInvalidInfo bool
		wantIgnoredWarn bool
	}{
		{name: "on writes the marker", mode: DeveloperModeOn, wantWrite: true},
		{name: "on writes the marker over a team-signed build", mode: DeveloperModeOn, signer: teamSigned, wantWrite: true},
		{name: "on writes the marker and a failed install leaves it", mode: DeveloperModeOn, swapErr: errors.New("EIO"), wantWrite: true},
		{name: "off removes the marker", mode: DeveloperModeOff, onDisk: &marker, wantRemove: true},
		{name: "off removes a symlink at the path, never its target", mode: DeveloperModeOff,
			onDisk: &OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntrySymlink, Mode: 0o755}, wantRemove: true},
		{name: "not passed keeps the marker", onDisk: &marker},
		{name: "not passed keeps the marker over an ad-hoc build", signer: adHoc, onDisk: &marker, wantKeepWarn: true},
		{name: "not passed keeps the marker over an Apple Development build", signer: appleDevelopment, onDisk: &marker, wantKeepWarn: true},
		{name: "a team-signed install without the flag removes the marker", signer: teamSigned, onDisk: &marker, wantRemove: true, wantInfo: true},
		{name: "a team-signed install without the flag removes an invalid marker", signer: teamSigned,
			onDisk: &OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o666}, wantRemove: true, wantInvalidInfo: true},
		{name: "an ad-hoc install without the flag keeps an invalid marker and says it is ignored", signer: adHoc,
			onDisk: &OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o666}, wantIgnoredWarn: true},
		{name: "a team-signed install with nothing there removes nothing", signer: teamSigned},
		{name: "off keeps the marker when the swap fails", mode: DeveloperModeOff, onDisk: &marker, swapErr: errors.New("EIO")},
		{name: "a team-signed install keeps the marker when the swap fails", signer: teamSigned, onDisk: &marker, swapErr: errors.New("EIO")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}, swapErr: tc.swapErr}
			if tc.onDisk != nil {
				seedMarkerAncestors(f)
				f.owners[DeveloperModeMarkerPath] = *tc.onDisk
				f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
			}
			var logs strings.Builder
			cfg := Config{BinarySource: src, TargetUser: "alice", Logger: slog.New(slog.NewTextHandler(&logs, nil))}
			cfg.DeveloperMode = tc.mode
			cfg.Signer = tc.signer
			err := Install(context.Background(), f, cfg)
			if (err != nil) != (tc.swapErr != nil) {
				t.Fatalf("Install = %v, want failure %v", err, tc.swapErr != nil)
			}
			wrote := slices.Index(f.calls, writeCall)
			if (wrote >= 0) != tc.wantWrite {
				t.Fatalf("marker written = %v, want %v; calls %v", wrote >= 0, tc.wantWrite, f.calls)
			}
			if tc.wantWrite {
				swap := slices.IndexFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "SwapInstallRoot:") })
				if swap < 0 || wrote > swap {
					t.Errorf("the marker was written at call %d, the install root swapped at %d: want it before the swap", wrote, swap)
				}
				if !markerContent.Match(f.files[DeveloperModeMarkerPath]) {
					t.Errorf("marker content %q is not the one fixed line", f.files[DeveloperModeMarkerPath])
				}
				if lock := slices.Index(f.calls, "LockInstall:/Library/k3sm.lock"); lock < 0 || lock > wrote {
					t.Errorf("the marker was written before the install lock was taken: %v", f.calls)
				}
			}
			removed := slices.Contains(f.calls, removeCall)
			if removed != tc.wantRemove {
				t.Errorf("marker removed = %v, want %v; calls %v", removed, tc.wantRemove, f.calls)
			}
			if tc.wantRemove {
				if _, ok := f.files[DeveloperModeMarkerPath]; ok {
					t.Error("the marker is still there")
				}
				swap := slices.IndexFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "SwapInstallRoot:") })
				if at := slices.Index(f.calls, removeCall); swap < 0 || at < swap {
					t.Errorf("the marker was removed at call %d, the install root swapped at %d: want it after the swap", at, swap)
				}
			} else if tc.onDisk != nil {
				if _, ok := f.files[DeveloperModeMarkerPath]; !ok {
					t.Error("the marker was removed")
				}
			}
			info := strings.Contains(logs.String(), "level=INFO") && strings.Contains(logs.String(), `"developer mode turned off by a signed install"`)
			if tc.wantInfo && !strings.Contains(logs.String(), "team-id="+testTeamID) {
				t.Errorf("the turned-off line does not name the team %s; logs:\n%s", testTeamID, logs.String())
			}
			if info != tc.wantInfo {
				t.Errorf("the turned-off Info line logged = %v, want %v; logs:\n%s", info, tc.wantInfo, logs.String())
			}
			invalidInfo := strings.Contains(logs.String(), "level=INFO") && strings.Contains(logs.String(), `"removed an invalid developer-mode marker by a signed install"`)
			if invalidInfo != tc.wantInvalidInfo {
				t.Errorf("the removed-invalid Info line logged = %v, want %v; logs:\n%s", invalidInfo, tc.wantInvalidInfo, logs.String())
			}
			ignoredWarn := strings.Contains(logs.String(), "level=WARN") && strings.Contains(logs.String(), `"ignored invalid marker:`)
			if ignoredWarn != tc.wantIgnoredWarn {
				t.Errorf("the ignored-invalid Warn logged = %v, want %v; logs:\n%s", ignoredWarn, tc.wantIgnoredWarn, logs.String())
			}
			keepWarn := strings.Contains(logs.String(), "level=WARN") && strings.Contains(logs.String(), `"developer mode stays on`)
			if keepWarn != tc.wantKeepWarn {
				t.Errorf("the stays-on Warn logged = %v, want %v; logs:\n%s", keepWarn, tc.wantKeepWarn, logs.String())
			}
		})
	}

	t.Run("the signature verdicts and the docs", pinPlainInstallSignature)

	t.Run("a plain install with no flag and no Signer never looks at the marker", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{}
		if err := Install(context.Background(), f, Config{BinarySource: src, TargetUser: "alice"}); err != nil {
			t.Fatal(err)
		}
		for _, c := range f.calls {
			if strings.Contains(c, "developer-mode") {
				t.Errorf("the install touched the marker: %s", c)
			}
		}
	})

	t.Run("an unknown mode is refused before any system call", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{}
		cfg := Config{BinarySource: src, TargetUser: "alice"}
		cfg.DeveloperMode = "maybe"
		if err := Install(context.Background(), f, cfg); err == nil {
			t.Fatal("Install accepted DeveloperMode \"maybe\"")
		}
		if len(f.calls) != 0 {
			t.Errorf("system calls before the refusal: %v", f.calls)
		}
	})
}

// TestDeveloperModeMarkerSeams pins the two write seams: the marker is
// written root:wheel 0644 through WriteRootOnlyFile (temp-and-rename, so a
// symlink at the path is replaced and not followed) and removed through
// RemoveEntry (unlink relative to the held parent, never following).
func TestDeveloperModeMarkerSeams(t *testing.T) {
	t.Parallel()
	f := &fakeSystem{}
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	if err := WriteDeveloperModeMarker(f, DeveloperModeMarkerPath, now); err != nil {
		t.Fatal(err)
	}
	if want := "developer mode enabled by k3sm install on 2026-10-31T12:00:00Z\n"; string(f.files[DeveloperModeMarkerPath]) != want {
		t.Errorf("content %q, want %q", f.files[DeveloperModeMarkerPath], want)
	}
	if err := RemoveDeveloperModeMarker(f, DeveloperModeMarkerPath); err != nil {
		t.Fatal(err)
	}
	want := []string{"WriteRootOnlyFile:/Library/k3sm.developer-mode:0644", "RemoveEntry:/Library:k3sm.developer-mode"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls %v, want %v", f.calls, want)
	}
	if _, ok := f.files[DeveloperModeMarkerPath]; ok {
		t.Error("the marker survived its removal")
	}
}

// TestUninstallRemovesTheDeveloperModeMarker pins the manifest entry: uninstall
// removes the marker, by a remove that unlinks a symlink rather than following
// it, and does not require it to exist.
func TestUninstallRemovesTheDeveloperModeMarker(t *testing.T) {
	t.Parallel()
	var found []artifact
	for _, a := range artifactManifest(Config{}) {
		if a.path == DeveloperModeMarkerPath {
			found = append(found, a)
		}
	}
	if len(found) != 1 || found[0].kind != kindFile || found[0].disp != dispRemove || found[0].assertExists {
		t.Fatalf("manifest entries for the marker = %+v, want one removed file not asserted to exist", found)
	}
	f := &fakeSystem{}
	if err := Uninstall(context.Background(), f, Config{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.calls, "RemoveAll:"+DeveloperModeMarkerPath) {
		t.Errorf("uninstall did not remove the marker: %v", f.calls)
	}
}

// TestDeveloperModeClearedByAnyDeveloperIDTeam pins which signatures turn
// developer mode off on a plain install without the flag: a Developer ID
// Application signature of any team does, including a team other than the
// one that signs releases, because removing the marker only turns the
// signature checks back on. An ad-hoc or unsigned k3sm, or one whose
// signature cannot be read, keeps the marker.
func TestDeveloperModeClearedByAnyDeveloperIDTeam(t *testing.T) {
	t.Parallel()
	const (
		src       = "/tmp/k3sm"
		otherTeam = "ZYXWV98765"
	)
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	cases := []struct {
		name       string
		signer     fakeSigner
		wantRemove bool
		wantTeam   string
	}{
		{name: "the release team's Developer ID clears it", signer: fakeSigner{ids: map[string]string{src: testTeamID}}, wantRemove: true, wantTeam: testTeamID},
		{name: "another team's Developer ID clears it", signer: fakeSigner{ids: map[string]string{src: otherTeam}}, wantRemove: true, wantTeam: otherTeam},
		{name: "an ad-hoc signature keeps it", signer: fakeSigner{errs: map[string]error{src: ErrNoTeamID}}},
		{name: "an unsigned binary keeps it", signer: fakeSigner{errs: map[string]error{src: fmt.Errorf("%s: code object is not signed at all: %w", src, ErrNoTeamID)}}},
		{name: "an unreadable binary keeps it", signer: fakeSigner{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
			var logs strings.Builder
			cfg := Config{BinarySource: src, TargetUser: "alice", Logger: slog.New(slog.NewTextHandler(&logs, nil))}
			cfg.Signer = tc.signer
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install = %v", err)
			}
			if removed := slices.Contains(f.calls, removeCall); removed != tc.wantRemove {
				t.Fatalf("marker removed = %v, want %v; logs:\n%s", removed, tc.wantRemove, logs.String())
			}
			_, kept := f.files[DeveloperModeMarkerPath]
			if kept == tc.wantRemove {
				t.Errorf("marker still there = %v, want %v", kept, !tc.wantRemove)
			}
			if tc.wantRemove && !strings.Contains(logs.String(), "team-id="+tc.wantTeam) {
				t.Errorf("the turned-off line does not name team %s; logs:\n%s", tc.wantTeam, logs.String())
			}
		})
	}
}

// TestDeveloperModeKeptWhenDeveloperIDVerificationFails pins the fail-closed
// direction of the strict Developer ID check: when it cannot run (an error,
// as for a tampered binary) or says no, a no-flag install keeps the marker.
func TestDeveloperModeKeptWhenDeveloperIDVerificationFails(t *testing.T) {
	t.Parallel()
	const src = "/tmp/k3sm"
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	cases := []struct {
		name   string
		signer fakeSigner
	}{
		{name: "strict verification returns an error",
			signer: fakeSigner{ids: map[string]string{src: testTeamID}, devIDErrs: map[string]error{src: errors.New("codesign: a sealed resource is missing or invalid")}}},
		{name: "a readable team whose strict verification returns false",
			signer: fakeSigner{ids: map[string]string{src: testTeamID}, notDevID: map[string]bool{src: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"))
			var logs strings.Builder
			cfg := Config{BinarySource: src, TargetUser: "alice", Logger: slog.New(slog.NewTextHandler(&logs, nil))}
			cfg.Signer = tc.signer
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatalf("Install = %v", err)
			}
			if slices.Contains(f.calls, removeCall) {
				t.Errorf("the marker was removed; calls %v", f.calls)
			}
			if _, ok := f.files[DeveloperModeMarkerPath]; !ok {
				t.Error("the marker is gone")
			}
			if !strings.Contains(logs.String(), "developer mode stays on") {
				t.Errorf("no stays-on Warn; logs:\n%s", logs.String())
			}
		})
	}
}

// TestDeveloperModeMarkerDroppedAsTheSwapCommits pins when an install that
// turns developer mode off removes the marker: right after the swap commits
// and before the daemons are wired and restarted on the new tree, so the
// app's root steps never read developer mode as on beside a signed tree. A
// revert puts the marker back as it was, so the rolled-back build stays in
// developer mode, and a removal that fails still finishes the install before
// it is reported.
func TestDeveloperModeMarkerDroppedAsTheSwapCommits(t *testing.T) {
	shrinkRestartBudgets(t)
	const content = "developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	putMarker := func(f *fakeSystem, mode fs.FileMode) {
		seedMarkerAncestors(f)
		f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: mode}
		f.putFile(DeveloperModeMarkerPath, []byte(content))
		if f.modes == nil {
			f.modes = map[string]fs.FileMode{}
		}
		f.modes[DeveloperModeMarkerPath] = mode
	}

	for _, tc := range []struct {
		name string
		mode DeveloperMode
		sign TeamIDReader
	}{
		{name: "off", mode: DeveloperModeOff},
		{name: "a team-signed install", sign: fakeSigner{ids: map[string]string{"/tmp/k3sm": testTeamID}}},
	} {
		t.Run(tc.name+" removes it before the wiring", func(t *testing.T) {
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			putMarker(f, 0o644)
			cfg := stageCfg()
			cfg.DeveloperMode, cfg.Signer = tc.mode, tc.sign
			if err := Install(context.Background(), f, cfg); err != nil {
				t.Fatal(err)
			}
			swap := slices.IndexFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "SwapInstallRoot:") })
			removed := slices.Index(f.calls, removeCall)
			if swap < 0 || removed < swap {
				t.Fatalf("the marker was removed at call %d, the swap at %d: want it after the swap", removed, swap)
			}
			for _, c := range f.calls[swap+1 : removed] {
				if !strings.Contains(c, "developer-mode") && c != "Owner:/" && c != "Owner:/Library" && c != "HasACL:/" && c != "HasACL:/Library" {
					t.Errorf("call %q ran between the swap and the marker removal; want the removal first", c)
				}
			}
		})
	}

	t.Run("a revert restores the marker as it was", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, stageCfg()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		putMarker(f, 0o600)
		f.putLoaded(NetdLabel, ServerLabel)
		f.calls = nil
		f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125: Domain does not support specified action"))
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		err := Install(context.Background(), f, cfg)
		if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
			t.Fatalf("Install = %v, want the rollback", err)
		}
		removed := slices.Index(f.calls, removeCall)
		restored := slices.Index(f.calls, "WriteRootOnlyFile:"+DeveloperModeMarkerPath+":0600")
		if removed < 0 || restored < removed {
			t.Fatalf("removed at call %d, restored at %d: want a removal then a restore; calls %v", removed, restored, f.calls)
		}
		if got := string(f.files[DeveloperModeMarkerPath]); got != content {
			t.Errorf("restored content %q, want %q", got, content)
		}
		if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeMarkerOn {
			t.Errorf("after the revert the marker reads %s, want %s", got, DeveloperModeMarkerOn)
		}
	})

	t.Run("a removal that fails finishes the install, then says so", func(t *testing.T) {
		f := &fakeSystem{owners: map[string]OwnedEntry{}, removeEntryErrs: map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}}
		putMarker(f, 0o644)
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		err := Install(context.Background(), f, cfg)
		if err == nil || !strings.Contains(err.Error(), "k3sm install --developer-mode off") {
			t.Fatalf("Install = %v, want the removal failure naming k3sm install --developer-mode off", err)
		}
		removed := slices.Index(f.calls, removeCall)
		if removed < 0 {
			t.Fatalf("the removal was not attempted; calls %v", f.calls)
		}
		// Step 5, after the removal: the admin kubeconfig, then the server
		// arguments record that names it.
		for _, want := range []string{"WriteUserKubeconfig:alice", "WriteServerArgsRecord:"} {
			if !slices.ContainsFunc(f.calls[removed:], func(c string) bool { return strings.HasPrefix(c, want) }) {
				t.Errorf("the install stopped before %s; calls after the removal %v", want, f.calls[removed:])
			}
		}
	})

	t.Run("a later failure keeps the removal error beside it", func(t *testing.T) {
		f := &fakeSystem{owners: map[string]OwnedEntry{}, removeEntryErrs: map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}, kubeconfigErr: errors.New("home is read-only")}
		putMarker(f, 0o644)
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install succeeded with the kubeconfig write failing")
		}
		for _, want := range []string{"write admin kubeconfig for alice: home is read-only", "k3sm install --developer-mode off"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
	})
}
