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

package keystore

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// interruptAfterListing runs rm-scope of uid 1001 stopped at its first
// take, after the judged key was listed: the directory stays, its key
// listed, as an interrupted run leaves it.
func interruptAfterListing(t *testing.T, s *FileStore) {
	t.Helper()
	saved := rmTakeDir
	rmTakeDir = func(int) error { return unix.EIO }
	defer func() { rmTakeDir = saved }()
	if _, err := s.RemoveScope(t.Context(), 1001); !Committed(err) {
		t.Fatalf("run 1, stopped at the take after listing: %v, want committed", err)
	}
}

// mustRename renames from to to.
func mustRename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

// wantNewestRefused checks that rm-scope's result is not exit 0, says the
// floor shows activity after the listed key, offers no command, and that
// the live scope at live is untouched (before).
func wantNewestRefused(t *testing.T, res RemoveScopeResult, err error, live string, before []string) {
	t.Helper()
	if err == nil || !Committed(err) {
		t.Fatalf("rm-scope over a listed key at the name, the live scope away: %v (recorded %v), want committed, not exit 0", err, res.Recorded)
	}
	msg := err.Error()
	for _, want := range []string{"shows activity of this uid after the listed key", "cannot confirm that the uid's current scope is the one removed", "moved away from its name"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "sudo") {
		t.Errorf("the error %q offers a command", msg)
	}
	checkRmScopeCommands(t, msg)
	if after := treeNames(t, live); !slices.Equal(before, after) {
		t.Fatalf("the live scope holds %v, want %v untouched", after, before)
	}
}

// Case (i): the uid's scope K0 was removed and listed; the tree-writer
// kept a copy of its scope.key; the uid's next put minted K1 through the
// real store, which wrote K1's floor lines. With K1 renamed away and a
// directory holding the K0 copy at the name, the judge opens K0, finds it
// listed and removes the decoy, but the floor holds lines of the uid past
// K0's listing, so the result is not exit 0, and K1 is untouched.
func TestRmScopeDecoyOfListedKeyIsNotExitZero(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	k0, err := os.ReadFile(filepath.Join(dir, scopeKeyName))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
		t.Fatalf("the first removal (K0): %v, recorded %v", err, res.Recorded)
	}
	userPut(t, userScope(t, s, 1001), "user/1001/y", "y") // mints K1
	away := filepath.Join(filepath.Dir(dir), "away")
	mustRename(t, dir, away)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, scopeKeyName), k0, fileMode); err != nil {
		t.Fatal(err)
	}
	before := treeNames(t, away)
	res, err := s.RemoveScope(t.Context(), 1001)
	wantNewestRefused(t, res, err, away, before)
	if !strings.Contains(err.Error(), "written after that key was listed") {
		t.Errorf("the error %q does not say the line was written after the listing", err)
	}
}

// Case (ii): an interrupted run left a root-owned directory holding K0,
// listed; the tree-writer parked it aside, the uid's next put minted K1,
// and the writer put the leftover back with K1 renamed away. The rerun
// finishes the leftover, but the floor's later lines refuse exit 0.
func TestRmScopeParkedLeftoverIsNotExitZero(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	interruptAfterListing(t, s)
	parked := filepath.Join(server, "parked")
	mustRename(t, dir, parked)
	userPut(t, userScope(t, s, 1001), "user/1001/y", "y") // mints K1
	away := filepath.Join(server, "away")
	mustRename(t, dir, away)
	mustRename(t, parked, dir)
	before := treeNames(t, away)
	asTakenRerun(t, s, dir)
	res, err := s.RemoveScope(t.Context(), 1001)
	wantNewestRefused(t, res, err, away, before)
}

// A genuine rerun of an interrupted run, with no line of the uid in the
// floor after the listing, still exits 0, on the judged path (the service
// user's directory) and on the taken path (root's leftover).
func TestRmScopeGenuineRerunStillExitsZero(t *testing.T) {
	for _, taken := range []bool{false, true} {
		name := "judged"
		if taken {
			name = "taken"
		}
		t.Run(name, func(t *testing.T) {
			if taken && asRoot() {
				t.Skip("the seam's other service uid makes the store's own directories foreign as root")
			}
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			interruptAfterListing(t, s)
			if taken {
				asTakenRerun(t, s, dir)
			}
			if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
				t.Fatalf("the rerun: %v, recorded %v; want exit 0", err, res.Recorded)
			}
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
		})
	}
}

// A floor rebuilt since the listing is another file than the one the
// recorded position belongs to: every line of the uid in it counts as
// later. The rebuild drops the listed scope's own lines (they start before
// the recorded offset), so with no newer scope the rerun still exits 0;
// with a scope minted into the rebuilt floor, it does not.
func TestRmScopeRebuiltFloorCountsEveryLine(t *testing.T) {
	for _, newer := range []bool{false, true} {
		name := "no newer scope"
		if newer {
			name = "newer scope"
		}
		t.Run(name, func(t *testing.T) {
			if !newer && runtime.GOOS != "darwin" {
				t.Skip("without a birth time the floor identity is not whole, and rebuild drops nothing")
			}
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			interruptAfterListing(t, s)
			parked := filepath.Join(server, "parked")
			mustRename(t, dir, parked)
			if _, err := s.RebuildFloor(t.Context(), &attrRecorder{}); err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			if newer {
				userPut(t, userScope(t, s, 1001), "user/1001/y", "y") // mints K1
				away := filepath.Join(server, "away")
				mustRename(t, dir, away)
				mustRename(t, parked, dir)
				before := treeNames(t, away)
				res, err := s.RemoveScope(t.Context(), 1001)
				wantNewestRefused(t, res, err, away, before)
				if !strings.Contains(err.Error(), "is not the file the listing recorded") {
					t.Errorf("the error %q does not say the floor is another file", err)
				}
				return
			}
			mustRename(t, parked, dir)
			if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
				t.Fatalf("the rerun after a rebuild with no newer scope: %v, recorded %v; want exit 0", err, res.Recorded)
			}
		})
	}
}

// A floor that cannot be opened or judged never yields exit 0.
func TestRmScopeUnjudgedFloorIsNotExitZero(t *testing.T) {
	s, _, _ := fileLogScope(t)
	setSeam(t, &rmFloorOpen, func(*FileStore, int, string) (*oldLog, error) { return nil, unix.EIO })
	res, err := s.RemoveScope(t.Context(), 1001)
	if err == nil || !Committed(err) || !strings.Contains(err.Error(), "could not be opened or judged") {
		t.Fatalf("rm-scope with an unreadable floor: %v (recorded %v), want committed, saying the floor could not be judged", err, res.Recorded)
	}
}
