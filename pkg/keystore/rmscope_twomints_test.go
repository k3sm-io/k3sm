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
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// mintAway moves uid 1001's scope directory to a new name under server and
// mints a fresh scope at the name through the real store: the second mint
// appends a second sequence-1 delivery-record line of the uid. It returns
// the moved directory and its names.
func mintAway(t *testing.T, s *FileStore, server, away string) (string, []string) {
	t.Helper()
	dir := scopeDir(server, "1001")
	moved := filepath.Join(filepath.Dir(dir), away)
	mustRename(t, dir, moved)
	userPut(t, userScope(t, s, 1001), "user/1001/"+away, "v") // mints a fresh scope
	return moved, treeNames(t, moved)
}

// wantCreatedTwice checks that rm-scope's result is not exit 0, says the
// floor shows the uid's scope created more than once since its last
// listing, that the scope at the name is removed and listed (keys listed
// for 1001 in all), and that the moved scope is untouched.
func wantCreatedTwice(t *testing.T, s *FileStore, server string, res RemoveScopeResult, err error, keys int, moved string, before []string) {
	t.Helper()
	if err == nil || !Committed(err) {
		t.Fatalf("rm-scope after two mints since the last listing: %v (recorded %v), want committed, not exit 0", err, res.Recorded)
	}
	msg := err.Error()
	for _, want := range []string{"created more than once since its last listing", "another scope of this uid may be held away from its name", "rm-scope removed and listed the one at the name"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error %q does not say %q", msg, want)
		}
	}
	if strings.Contains(msg, "sudo") {
		t.Errorf("the error %q offers a command", msg)
	}
	checkRmScopeCommands(t, msg)
	if !res.Recorded {
		t.Error("the scope at the name is not reported listed")
	}
	if _, err := os.Lstat(scopeDir(server, "1001")); !os.IsNotExist(err) {
		t.Fatalf("the scope at the name is still there: %v", err)
	}
	if n := readRecord(t, s).count(1001); n != keys {
		t.Fatalf("the record lists %d keys of 1001, want %d", n, keys)
	}
	if after := treeNames(t, moved); !slices.Equal(before, after) {
		t.Fatalf("the moved scope holds %v, want %v untouched", after, before)
	}
}

// K_a is minted, its directory moved away, and K_b minted at the name with
// no listing between: the floor holds two creation lines of the uid, so
// rm-scope removes and lists K_b but does not exit 0, and K_a stays.
func TestRmScopeTwoMintsSinceListingIsNotExitZero(t *testing.T) {
	s, server, _ := fileLogScope(t)
	moved, before := mintAway(t, s, server, "away")
	res, err := s.RemoveScope(t.Context(), 1001)
	wantCreatedTwice(t, s, server, res, err, 1, moved, before)
}

// One mint since the last listing is the judged scope's own: exit 0,
// whether the uid was never listed or an earlier removal was listed.
func TestRmScopeOneMintSinceListingExitsZero(t *testing.T) {
	for _, earlier := range []bool{false, true} {
		name := "never listed"
		if earlier {
			name = "after a listed removal"
		}
		t.Run(name, func(t *testing.T) {
			if earlier && runtime.GOOS != "darwin" {
				t.Skip("without a birth time the floor identity is not whole, and the whole floor counts")
			}
			s, _, _ := fileLogScope(t)
			want := 1
			if earlier {
				if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
					t.Fatalf("the first removal: %v, recorded %v; want exit 0", err, res.Recorded)
				}
				userPut(t, userScope(t, s, 1001), "user/1001/y", "y") // mints K1
				want = 2
			}
			if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
				t.Fatalf("rm-scope after one mint since the last listing: %v, recorded %v; want exit 0", err, res.Recorded)
			}
			if n := readRecord(t, s).count(1001); n != want {
				t.Fatalf("the record lists %d keys of 1001, want %d", n, want)
			}
		})
	}
}

// After a listed removal, two mints (the first moved away) are counted
// from that listing: not exit 0.
func TestRmScopeTwoMintsAfterListedRemovalIsNotExitZero(t *testing.T) {
	s, server, _ := fileLogScope(t)
	if res, err := s.RemoveScope(t.Context(), 1001); err != nil || !res.Recorded {
		t.Fatalf("the first removal: %v, recorded %v; want exit 0", err, res.Recorded)
	}
	userPut(t, userScope(t, s, 1001), "user/1001/y", "y") // mints K1
	moved, before := mintAway(t, s, server, "away")       // mints K2
	res, err := s.RemoveScope(t.Context(), 1001)
	wantCreatedTwice(t, s, server, res, err, 2, moved, before)
}

// A torn or over-long hostile line appended just before the second mint's
// delivery-record line, in the window between the mint's floor read and
// its append, does not hide that line: the writer leads every append with a
// newline, so the fragment is a damaged line of its own and the creation
// line still parses and counts.
func TestRmScopeHostileLineBeforeMintDoesNotHideIt(t *testing.T) {
	long := append([]byte("\nuser/1002 .deliveries "), bytes.Repeat([]byte("a"), 2*maxLogLine)...)
	for name, hostile := range map[string][]byte{
		"torn":      []byte("\nuser/1002 .deliveries 00"),
		"over-long": long,
	} {
		t.Run(name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			moved := filepath.Join(filepath.Dir(dir), "away")
			mustRename(t, dir, moved)
			before := treeNames(t, moved)
			// The hostile bytes land between the mint's floor read and its
			// append, as a racing writer's would, so the mint is not
			// refused for them.
			fl := s.userFloor.(*fileFloorLog).log
			fl.write = func(f *os.File, b []byte) (int, error) {
				fl.write = nil
				appendLogBytes(t, s, userFloorLogName, hostile)
				return f.Write(b)
			}
			// The put mints K_b; the over-long line, which no key can be
			// read from, then refuses the entry's own floor line, after the
			// mint is done.
			_, perr := userScope(t, s, 1001).Put(t.Context(), "user/1001/y", KindOpaque, []byte("y"))
			fl.write = nil
			if perr != nil && !Committed(perr) {
				t.Fatalf("the put that mints K_b: %v", perr)
			}
			if _, err := os.Lstat(filepath.Join(dir, scopeKeyName)); err != nil {
				t.Fatalf("K_b was not minted at the name: %v", err)
			}
			res, err := s.RemoveScope(t.Context(), 1001)
			wantCreatedTwice(t, s, server, res, err, 1, moved, before)
		})
	}
}
