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
	"io/fs"
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
// cannot be probed, the marker reads invalid, so a probe error never leaves
// the signature checks off.
func TestDeveloperModeMarkerAncestorACLProbeFails(t *testing.T) {
	t.Parallel()
	for name, path := range map[string]string{
		"the root directory":    "/",
		"the Library directory": "/Library",
		"the marker itself":     DeveloperModeMarkerPath,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
			requireMarkerOn(t, f)
			f.hasACLErrs = map[string]error{path: errors.New("acl_get_link_np: EIO")}
			if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeInvalid {
				t.Errorf("ReadDeveloperModeState = %s, want %s (calls %v)", got, DeveloperModeInvalid, f.calls)
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
			f := &fakeSystem{}
			if err := Install(context.Background(), f, stageCfg()); err != nil {
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
			cfg := stageCfg()
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
