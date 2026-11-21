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
	"slices"
	"strings"
	"testing"
)

// requireMarkerOn fails the test unless the marker a fixture seeded reads on
// through the production reader, so a seed that silently reads invalid (an
// ancestor left out, a mode slip) cannot pass a presence-only test. It leaves
// f.calls as it found them, so a test asserting on the calls sees none of its
// reads.
func requireMarkerOn(t *testing.T, f *fakeSystem) {
	t.Helper()
	n := len(f.calls)
	got := ReadDeveloperModeState(f, DeveloperModeMarkerPath)
	f.calls = f.calls[:n]
	if got != DeveloperModeMarkerOn {
		t.Fatalf("the seeded developer-mode marker reads %s, want %s", got, DeveloperModeMarkerOn)
	}
}

// TestDeveloperModeMarkerAncestorACLProbeFails pins the fail-closed reading of
// an ACL probe that cannot run: when / or /Library, or the marker itself,
// cannot be probed, the marker does not read on, so a probe error never leaves
// the signature checks off: a directory that cannot be probed makes it invalid,
// and a marker that cannot be probed makes it unknown.
func TestDeveloperModeMarkerAncestorACLProbeFails(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path string
		want       DeveloperModeState
	}{
		{"the root directory", "/", DeveloperModeInvalid},
		{"the Library directory", "/Library", DeveloperModeInvalid},
		{"the marker itself", DeveloperModeMarkerPath, DeveloperModeUnknown},
	} {
		path := tc.path
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			requireMarkerOn(t, f)
			f.hasACLErrs = map[string]error{path: errors.New("acl_get_link_np: EIO")}
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != tc.want {
				t.Errorf("ReadDeveloperModeState = %s, want %s (calls %v)", got, tc.want, f.calls)
			}
			if !slices.Contains(f.calls, "HasACL:"+path) {
				t.Errorf("the ACL of %s was never probed: %v", path, f.calls)
			}
		})
	}
}

// TestDeveloperModeInvalidMarkerNotRestoredOnRevert pins that a revert puts
// back only a marker that read on: a symlink, a group-writable file and a
// file with an ACL at the marker path are removed by a team-signed install
// and stay gone when the install root is rolled back, so a rollback never
// turns an invalid marker into a valid one.
func TestDeveloperModeInvalidMarkerNotRestoredOnRevert(t *testing.T) {
	const content = "developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	for _, tc := range []struct {
		name string
		kind EntryKind
		mode fs.FileMode
		acl  bool
	}{
		{name: "a symlink", kind: EntrySymlink, mode: 0o755},
		{name: "a group-writable file", kind: EntryRegular, mode: 0o664},
		{name: "a file with an ACL", kind: EntryRegular, mode: 0o644, acl: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSystem(t)
			if err := Install(context.Background(), f, stageCfg(t)); err != nil {
				t.Fatalf("first Install: %v", err)
			}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: tc.kind, Mode: tc.mode}
			f.putFile(DeveloperModeMarkerPath, []byte(content))
			f.modes = map[string]fs.FileMode{DeveloperModeMarkerPath: tc.mode}
			f.acls = map[string]bool{DeveloperModeMarkerPath: tc.acl}
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeInvalid {
				t.Fatalf("the seeded marker reads %s, want %s", got, DeveloperModeInvalid)
			}
			f.putLoaded(NetdLabel, ServerLabel)
			f.calls = nil
			// A bootstrap error that is not transient fails on the first
			// attempt, so the revert runs without waiting on any budget.
			f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125: Domain does not support specified action"))
			cfg := stageCfg(t)
			cfg.Signer = fakeSigner{ids: map[string]string{"/tmp/k3sm": testTeamID}}
			err := Install(context.Background(), f, cfg)
			if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
				t.Fatalf("Install = %v, want the rollback", err)
			}
			if !slices.Contains(f.calls, removeCall) {
				t.Fatalf("the invalid marker was not removed; calls %v", f.calls)
			}
			if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "WriteRootOnlyFile:"+DeveloperModeMarkerPath) }) {
				t.Errorf("the revert re-created an invalid marker; calls %v", f.calls)
			}
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeAbsent {
				t.Errorf("after the revert the marker reads %s, want %s", got, DeveloperModeAbsent)
			}
		})
	}
}

// TestDeveloperModeValidMarkerRestoredOnPlainInstallRevert pins the revert of
// a team-signed plain install (plainInstallTeam) over a valid marker: the
// install removes it as the swap commits, the bootstrap fails, and the revert
// puts it back with its bytes once the previous tree is live again and before
// any daemon is restarted on it, so the rolled-back build stays in developer
// mode.
func TestDeveloperModeValidMarkerRestoredOnPlainInstallRevert(t *testing.T) {
	const content = "developer mode enabled by k3sm install on 2026-10-31T00:00:00Z\n"
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"
	restoreCall := "WriteRootOnlyFile:" + DeveloperModeMarkerPath + ":0644"
	f := newFakeSystem(t)
	if err := Install(context.Background(), f, stageCfg(t)); err != nil {
		t.Fatalf("first Install: %v", err)
	}
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	f.putFile(DeveloperModeMarkerPath, []byte(content))
	f.modes = map[string]fs.FileMode{DeveloperModeMarkerPath: 0o644}
	requireMarkerOn(t, f)
	f.putLoaded(NetdLabel, ServerLabel)
	f.calls = nil
	// A bootstrap error that is not transient fails on the first attempt, so
	// the revert runs without waiting on any budget.
	f.putBootstrapAlways(NetdLabel, errors.New("Bootstrap failed: 125: Domain does not support specified action"))
	cfg := stageCfg(t)
	cfg.Signer = fakeSigner{ids: map[string]string{"/tmp/k3sm": testTeamID}}
	err := Install(context.Background(), f, cfg)
	if err == nil || !strings.Contains(err.Error(), "rolled back to the previous install root") {
		t.Fatalf("Install = %v, want the rollback", err)
	}
	publish, revert := -1, -1
	for i, c := range f.calls {
		if strings.HasPrefix(c, "SwapInstallRoot:") {
			if publish < 0 {
				publish = i
			} else if revert < 0 {
				revert = i
			}
		}
	}
	removed := slices.Index(f.calls, removeCall)
	restored := slices.Index(f.calls, restoreCall)
	if publish < 0 || revert < 0 {
		t.Fatalf("publish swap at %d, reverse swap at %d: want both; calls %v", publish, revert, f.calls)
	}
	if removed < publish || removed > revert {
		t.Errorf("the marker was removed at call %d, want between the swap (%d) and the revert (%d)", removed, publish, revert)
	}
	if restored < revert {
		t.Fatalf("the marker was restored at call %d, want after the reverse swap at %d; calls %v", restored, revert, f.calls)
	}
	for _, c := range f.calls[revert+1 : restored] {
		for _, p := range []string{"Bootstrap:", "Bootout:", "Kickstart:", "Enable:"} {
			if strings.HasPrefix(c, p) {
				t.Errorf("call %q ran between the reverse swap and the restore; want the marker back before any daemon restarts", c)
			}
		}
	}
	if got := string(f.files[DeveloperModeMarkerPath]); got != content {
		t.Errorf("restored content %q, want %q", got, content)
	}
	if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeMarkerOn {
		t.Errorf("after the revert the marker reads %s, want %s", got, DeveloperModeMarkerOn)
	}
}

// TestDeveloperModeMarkerAncestorsGuards pins the refusals of markerAncestors
// and how they read: a root that is not absolute, a marker whose parent is
// not under the root (above it, beside it, or reached through ..) is an
// error, and the facts built on it make the marker unknown, never on.
func TestDeveloperModeMarkerAncestorsGuards(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, root, path string
		want             []string
	}{
		{name: "the real marker", root: "/", path: DeveloperModeMarkerPath, want: []string{"/", "/Library"}},
		{name: "a marker in the root", root: "/", path: "/k3sm.developer-mode", want: []string{"/"}},
		{name: "a .. that stays under the root", root: "/", path: "/Library/sub/../k3sm.developer-mode", want: []string{"/", "/Library"}},
		{name: "a relative root", root: "Library", path: "Library/k3sm.developer-mode"},
		{name: "a relative root above a nested marker", root: "Library", path: "Library/sub/k3sm.developer-mode"},
		{name: "a relative marker", root: "/", path: "Library/k3sm.developer-mode"},
		{name: "a marker above the root", root: "/Library/sub", path: "/Library/k3sm.developer-mode"},
		{name: "a marker outside the root", root: "/Library", path: "/etc/k3sm.developer-mode"},
		{name: "a marker beside a root it shares a prefix with", root: "/Lib", path: "/Library/k3sm.developer-mode"},
		{name: "a .. path out of the root", root: "/Library", path: "/Library/../etc/k3sm.developer-mode"},
		{name: "a .. path out of the root from a nested directory", root: "/Library/sub", path: "/Library/sub/../../k3sm.developer-mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := markerAncestors(tc.root, tc.path)
			if tc.want != nil {
				if err != nil || !slices.Equal(got, tc.want) {
					t.Fatalf("markerAncestors(%q, %q) = %v, %v; want %v", tc.root, tc.path, got, err, tc.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("markerAncestors(%q, %q) = %v, want a refusal", tc.root, tc.path, got)
			}
			f := &fakeSystem{owners: map[string]OwnedEntry{tc.path: {Path: tc.path, Kind: EntryRegular, Mode: 0o644}}, acls: map[string]bool{}}
			seedMarkerAncestors(f)
			facts := readDeveloperModeFacts(f, tc.root, tc.path)
			if facts.Err == nil || len(facts.Ancestors) != 0 {
				t.Errorf("facts = %+v, want the refusal and no ancestor read", facts)
			}
			if st := developerModeState(facts, 0); st != DeveloperModeUnknown {
				t.Errorf("the marker reads %s, want %s", st, DeveloperModeUnknown)
			}
		})
	}
}

// removeFailsOnce is the fake with the marker's first removal failing, so the
// retry is what removes it.
type removeFailsOnce struct {
	*fakeSystem
	failed bool
}

func (s *removeFailsOnce) RemoveEntry(dir, name string) error {
	if !s.failed && dir+"/"+name == DeveloperModeMarkerPath {
		s.failed = true
		s.calls = append(s.calls, "RemoveEntry:"+dir+":"+name)
		return fmt.Errorf("remove %s in %s: EBUSY", name, dir)
	}
	return s.fakeSystem.RemoveEntry(dir, name)
}

// restoreWriteFails is the fake with every root-only write failing, so the
// restore cannot put the marker back.
type restoreWriteFails struct{ *fakeSystem }

func (s *restoreWriteFails) WriteRootOnlyFile(path string, _ []byte, mode fs.FileMode) error {
	s.calls = append(s.calls, fmt.Sprintf("WriteRootOnlyFile:%s:%#o", path, mode))
	return errors.New("rename: EROFS")
}

// validMarkerFake is a fake holding a valid marker, asserted to read on.
func validMarkerFake(t *testing.T) *fakeSystem {
	t.Helper()
	f := (&fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}).rootedIn(t)
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
	f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-11-01T00:00:00Z\n"))
	f.modes = map[string]fs.FileMode{DeveloperModeMarkerPath: 0o644}
	requireMarkerOn(t, f)
	return f
}

// TestDeveloperModeMarkerDropPaths pins drop's branches one at a time: a
// removal that fails once and then succeeds removes the marker and keeps the
// copy without handing anything to nobody; a read error is returned joined
// with a disown that also failed, so neither is lost; and a read error beside
// a disown that worked is returned alone.
func TestDeveloperModeMarkerDropPaths(t *testing.T) {
	t.Parallel()
	removeCall := "RemoveEntry:/Library:k3sm.developer-mode"

	t.Run("a removal that succeeds on the retry", func(t *testing.T) {
		t.Parallel()
		f := validMarkerFake(t)
		sys := &removeFailsOnce{fakeSystem: f}
		r := &markerRemoval{path: DeveloperModeMarkerPath, team: testTeamID}
		if err := r.drop(sys, Config{}.withDefaults()); err != nil {
			t.Fatalf("drop = %v, want nil", err)
		}
		if n := countCalls(f, removeCall); n != 2 {
			t.Errorf("the removal was attempted %d times, want 2", n)
		}
		if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "Chown:") }) {
			t.Errorf("the marker was handed to nobody after a removal that succeeded; calls %v", f.calls)
		}
		if !r.removed || r.saved == nil || r.stillOn() {
			t.Errorf("removed %v, saved %q, stillOn %v; want removed with the copy kept", r.removed, r.saved, r.stillOn())
		}
		if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeAbsent {
			t.Errorf("the marker reads %s, want %s", got, DeveloperModeAbsent)
		}
	})

	for _, tc := range []struct {
		name     string
		chownErr error
		want     []string
		stuck    bool
	}{
		{name: "a read error joined with a disown that failed", chownErr: errors.New("EACCES"), want: []string{"EIO", "EPERM", "EACCES", "sudo chflags nouchg"}, stuck: true},
		{name: "a read error beside a disown that worked", want: []string{"EIO"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := validMarkerFake(t)
			f.readModeErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EIO")}
			f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
			if tc.chownErr != nil {
				f.chownErrs = map[string]error{DeveloperModeMarkerPath: tc.chownErr}
			}
			r := &markerRemoval{path: DeveloperModeMarkerPath, team: testTeamID}
			err := r.drop(f, Config{}.withDefaults())
			if err == nil {
				t.Fatal("drop = nil, want the read error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("drop = %q, does not carry %q", err, w)
				}
			}
			if !tc.stuck && strings.Contains(err.Error(), "EPERM") {
				t.Errorf("drop = %q, want only the read error once the marker reads invalid", err)
			}
			if r.stillOn() != tc.stuck || r.removed || r.saved != nil {
				t.Errorf("stillOn %v, removed %v, saved %q; want stillOn %v, nothing removed or kept", r.stillOn(), r.removed, r.saved, tc.stuck)
			}
		})
	}
}

// TestDeveloperModeMarkerRestoreWriteFails pins a restore whose root-only
// write fails: it is logged at Warn with the remedy, nothing claims the marker
// is back, and the marker stays absent, which leaves developer mode off.
func TestDeveloperModeMarkerRestoreWriteFails(t *testing.T) {
	t.Parallel()
	f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
	seedMarkerAncestors(f)
	var logs strings.Builder
	cfg := Config{}.withDefaults()
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	r := &markerRemoval{path: DeveloperModeMarkerPath, removed: true, saved: []byte("x\n"), savedMode: 0o644}
	r.restore(&restoreWriteFails{fakeSystem: f}, cfg)
	if !slices.Contains(f.calls, "WriteRootOnlyFile:"+DeveloperModeMarkerPath+":0644") {
		t.Fatalf("restore did not try the write; calls %v", f.calls)
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "could not be restored") || !strings.Contains(out, "EROFS") {
		t.Errorf("the failed restore is not logged at Warn with its cause; logs:\n%s", out)
	}
	for _, bad := range []string{"restored the developer-mode marker", "the restored developer-mode marker reads"} {
		if strings.Contains(out, bad) {
			t.Errorf("the log claims a restore that failed (%q); logs:\n%s", bad, out)
		}
	}
	if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeAbsent {
		t.Errorf("the marker reads %s, want %s", got, DeveloperModeAbsent)
	}
}
