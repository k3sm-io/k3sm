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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// setMode sets path's mode exactly, past the umask.
func setMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// markerReadDenied is a fake on which one path cannot be read from this
// account, the way a directory it cannot search hides what is below it.
type markerReadDenied struct {
	*fakeSystem
	err error
}

func (s markerReadDenied) Owner(path string) (OwnedEntry, error) {
	if path == DeveloperModeMarkerPath {
		s.calls = append(s.calls, "Owner:"+path)
		return OwnedEntry{}, fmt.Errorf("lstat %s: %w", path, s.err)
	}
	return s.fakeSystem.Owner(path)
}

// TestDeveloperModeUnreadableParentIsNotAMarkerFault pins that a read which
// could not see the marker is unknown, never an invalid marker with a remedy
// aimed at a file that may not exist, and never absent: the same denied read
// hides a marker and an empty path alike, so it cannot be told apart from
// either. It names no directory, because no directory above the marker failed
// a check: a root-owned 0700 parent is sound, and root reads a marker below it
// as on.
func TestDeveloperModeUnreadableParentIsNotAMarkerFault(t *testing.T) {
	t.Parallel()
	const root0700 = fs.FileMode(0o700)

	assertUnknown := func(t *testing.T, f DeveloperModeFacts, path string) {
		t.Helper()
		if !errors.Is(f.Err, fs.ErrPermission) {
			t.Fatalf("facts err = %v, want a permission error", f.Err)
		}
		if got := DeveloperModeMarkerState(f); got != DeveloperModeUnknown {
			t.Errorf("state %s, want %s", got, DeveloperModeUnknown)
		}
		if got := DeveloperModeAncestorCause(f, path); got != "" {
			t.Errorf("ancestor cause %q, want none: no directory failed a check", got)
		}
		if DeveloperModeMarkerIsDir(f) {
			t.Error("an unread path reads as a directory")
		}
	}

	for _, tc := range []struct {
		name   string
		marker bool
		want   DeveloperModeState
	}{
		{name: "nothing at the path", want: DeveloperModeAbsent},
		{name: "a marker at the path", marker: true, want: DeveloperModeMarkerOn},
	} {
		t.Run("a parent of mode 000 on disk, "+tc.name, func(t *testing.T) {
			t.Parallel()
			if os.Geteuid() == 0 {
				t.Skip("root searches a directory of mode 000")
			}
			root := t.TempDir()
			setMode(t, root, 0o755)
			lib := filepath.Join(root, "Library")
			if err := os.Mkdir(lib, 0o755); err != nil {
				t.Fatal(err)
			}
			setMode(t, lib, 0o755)
			marker := filepath.Join(lib, "k3sm.developer-mode")
			if tc.marker {
				if err := os.WriteFile(marker, []byte("x\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				setMode(t, marker, 0o644)
			}
			setMode(t, lib, 0)
			t.Cleanup(func() { _ = os.Chmod(lib, 0o755) })

			sys := NewDarwinSystem()
			f := readDeveloperModeFacts(sys, root, marker)
			if !errors.Is(f.Err, fs.ErrPermission) {
				t.Fatalf("facts err = %v, want a permission error", f.Err)
			}
			if got := developerModeState(f, os.Getuid()); got != DeveloperModeUnknown {
				t.Errorf("state %s, want %s", got, DeveloperModeUnknown)
			}

			// The same tree, once the parent can be searched, is what the denied
			// read was hiding: the read did not see it either way.
			setMode(t, lib, 0o755)
			want := tc.want
			if _, err := pathHasACL(root); err != nil && tc.marker {
				want = DeveloperModeUnknown // a build without cgo reads no ACL
			}
			if got := developerModeState(readDeveloperModeFacts(sys, root, marker), os.Getuid()); got != want {
				t.Errorf("state with the parent searchable %s, want %s", got, want)
			}
		})
	}

	t.Run("a root-owned 0700 parent an account cannot search", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
		seedMarkerAncestors(f)
		f.owners["/Library"] = OwnedEntry{Path: "/Library", Kind: EntryDir, Mode: root0700}
		assertUnknown(t, ReadDeveloperModeFacts(markerReadDenied{f, fs.ErrPermission}, DeveloperModeMarkerPath), DeveloperModeMarkerPath)

		// Root, which can search it, reads a marker there as on: the denied
		// account has no ground to say the checks stay on.
		f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryRegular, Mode: 0o644}
		if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeMarkerOn {
			t.Errorf("root reads %s under a 0700 parent, want %s", got, DeveloperModeMarkerOn)
		}
	})

	t.Run("a marker whose lstat fails for another reason", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
		seedMarkerAncestors(f)
		if got := ReadDeveloperModeState(markerReadDenied{f, errors.New("EIO")}, DeveloperModeMarkerPath); got != DeveloperModeUnknown {
			t.Errorf("state %s, want %s", got, DeveloperModeUnknown)
		}
	})
}

// TestDeveloperModeUnknownKeepsTheChecksOn pins the fail-closed reading of an
// unknown marker: it never turns developer mode on, a change between the two
// reads still refuses the install, an install that cannot clear it says it
// could not be read, and a removal keeps no copy to restore.
func TestDeveloperModeUnknownKeepsTheChecksOn(t *testing.T) {
	t.Parallel()
	const src = "/tmp/k3sm"
	signedCfg := func(signer TeamIDReader, logs *strings.Builder) Config {
		cfg := Config{BinarySource: src, TargetUser: "alice"}
		cfg.Signer = signer
		if logs != nil {
			cfg.Logger = slog.New(slog.NewTextHandler(logs, nil))
		}
		return cfg.withDefaults()
	}

	t.Run("it does not turn developer mode on", func(t *testing.T) {
		t.Parallel()
		o := DeveloperModeOptions{markerState: func() DeveloperModeState { return DeveloperModeUnknown }}
		if o.developerModeOn() {
			t.Error("an unknown marker turned developer mode on")
		}
		if o.preLockMarker != DeveloperModeUnknown {
			t.Errorf("the pre-lock read is %q, want %s", o.preLockMarker, DeveloperModeUnknown)
		}
	})

	t.Run("a marker unknown before the lock and on after it refuses the install", func(t *testing.T) {
		t.Parallel()
		f := validMarkerFake(t)
		cfg := signedCfg(fakeSigner{errs: map[string]error{src: ErrNoTeamID}}, nil)
		cfg.preLockMarker = DeveloperModeUnknown
		if _, err := applyDeveloperMode(context.Background(), f, cfg); !errors.Is(err, ErrDeveloperModeChanged) {
			t.Fatalf("applyDeveloperMode = %v, want %v", err, ErrDeveloperModeChanged)
		}
	})

	t.Run("an ad-hoc install keeps it and says it could not be read", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
		seedMarkerAncestors(f)
		var logs strings.Builder
		cfg := signedCfg(fakeSigner{errs: map[string]error{src: ErrNoTeamID}}, &logs)
		r, err := applyDeveloperMode(context.Background(), markerReadDenied{f, errors.New("EIO")}, cfg)
		if err != nil || r != nil {
			t.Fatalf("applyDeveloperMode = %+v, %v; want nothing to remove", r, err)
		}
		if !strings.Contains(logs.String(), "could not be read") || strings.Contains(logs.String(), "developer mode stays on") {
			t.Errorf("log = %q, want the unread marker named and no claim that the mode is on", logs.String())
		}
	})

	t.Run("a team-signed install removes it and keeps no copy", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
		seedMarkerAncestors(f)
		sys := markerReadDenied{f, errors.New("EIO")}
		var logs strings.Builder
		cfg := signedCfg(fakeSigner{ids: map[string]string{src: testTeamID}}, &logs)
		r, err := applyDeveloperMode(context.Background(), sys, cfg)
		if err != nil || r == nil {
			t.Fatalf("applyDeveloperMode = %+v, %v; want a removal", r, err)
		}
		if err := r.drop(sys, cfg); err != nil {
			t.Fatalf("drop = %v", err)
		}
		if !r.removed || r.saved != nil {
			t.Errorf("removed %v, saved %q; want removed with no copy", r.removed, r.saved)
		}
		if !strings.Contains(logs.String(), "removed a developer-mode marker that could not be read") {
			t.Errorf("log = %q, want the removal to say the marker could not be read", logs.String())
		}
		for _, claim := range []string{"developer mode turned off", "invalid"} {
			if strings.Contains(logs.String(), claim) {
				t.Errorf("log = %q claims %q of a marker it could not read", logs.String(), claim)
			}
		}
		r.restore(sys, cfg)
		if slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "WriteRootOnlyFile:"+DeveloperModeMarkerPath) }) {
			t.Errorf("a marker that could not be read was restored: %v", f.calls)
		}
	})

	t.Run("a removal and a disown that fail on an unread marker count as still on", func(t *testing.T) {
		t.Parallel()
		f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
		seedMarkerAncestors(f)
		f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
		r := &markerRemoval{path: DeveloperModeMarkerPath, team: testTeamID, unread: true}
		err := r.drop(markerReadDenied{f, errors.New("EIO")}, Config{}.withDefaults())
		if err == nil || !r.stillOn() {
			t.Fatalf("drop = %v, stillOn %v; want the install reverted", err, r.stillOn())
		}
		if !strings.Contains(err.Error(), "may still be on") {
			t.Errorf("drop = %q, want it to say the mode may still be on", err)
		}
	})
}

// TestDeveloperModeMarkerIsDir pins the one fact the row's remedy turns on: a
// directory at the path, seen by a read that worked.
func TestDeveloperModeMarkerIsDir(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		f    DeveloperModeFacts
		want bool
	}{
		{"a directory", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntryDir}}, true},
		{"a regular file", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntryRegular}}, false},
		{"a symlink", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntrySymlink}}, false},
		{"nothing there", DeveloperModeFacts{}, false},
		{"a failed read", DeveloperModeFacts{Exists: true, Entry: OwnedEntry{Kind: EntryDir}, Err: errors.New("EIO")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := DeveloperModeMarkerIsDir(tc.f); got != tc.want {
				t.Errorf("DeveloperModeMarkerIsDir = %v, want %v", got, tc.want)
			}
		})
	}
	f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: EntryDir, Mode: 0o755}
	if !DeveloperModeMarkerIsDir(ReadDeveloperModeFacts(f, DeveloperModeMarkerPath)) {
		t.Error("a directory at the path does not read as one")
	}
}

// TestDeveloperModeNonRegularMarkerReadsItsAncestors pins that a marker that is
// not a regular file still has the directories above it read, so a bad one is
// named, and that a probe of them that fails, which is every ACL probe in a
// build without cgo, is a read that failed rather than a directory to repair.
func TestDeveloperModeNonRegularMarkerReadsItsAncestors(t *testing.T) {
	t.Parallel()
	for _, kind := range []EntryKind{EntryDir, EntrySymlink, EntryOther} {
		seed := func() *fakeSystem {
			f := &fakeSystem{owners: map[string]OwnedEntry{}, acls: map[string]bool{}}
			seedMarkerAncestors(f)
			f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: kind, Mode: 0o755}
			return f
		}
		t.Run(fmt.Sprintf("kind %v under a bad directory", kind), func(t *testing.T) {
			t.Parallel()
			f := seed()
			f.owners["/Library"] = OwnedEntry{Path: "/Library", Kind: EntryDir, Mode: 0o775}
			facts := ReadDeveloperModeFacts(f, DeveloperModeMarkerPath)
			if got := DeveloperModeMarkerState(facts); got != DeveloperModeInvalid {
				t.Errorf("state %s, want %s", got, DeveloperModeInvalid)
			}
			if got := DeveloperModeAncestorCause(facts, DeveloperModeMarkerPath); got != "/Library" {
				t.Errorf("cause %q, want /Library", got)
			}
		})
		t.Run(fmt.Sprintf("kind %v under sound directories", kind), func(t *testing.T) {
			t.Parallel()
			facts := ReadDeveloperModeFacts(seed(), DeveloperModeMarkerPath)
			if got := DeveloperModeMarkerState(facts); got != DeveloperModeInvalid {
				t.Errorf("state %s, want %s", got, DeveloperModeInvalid)
			}
			if got := DeveloperModeAncestorCause(facts, DeveloperModeMarkerPath); got != "" {
				t.Errorf("cause %q, want none", got)
			}
		})
		t.Run(fmt.Sprintf("kind %v with every ACL probe failing", kind), func(t *testing.T) {
			t.Parallel()
			f := seed()
			noCgo := errors.New("this k3sm was built without cgo")
			f.hasACLErrs = map[string]error{"/": noCgo, "/Library": noCgo}
			facts := ReadDeveloperModeFacts(f, DeveloperModeMarkerPath)
			if got := DeveloperModeMarkerState(facts); got != DeveloperModeUnknown {
				t.Errorf("state %s, want %s", got, DeveloperModeUnknown)
			}
			if got := DeveloperModeAncestorCause(facts, DeveloperModeMarkerPath); got != "" {
				t.Errorf("cause %q, want none: / was not found at fault", got)
			}
			if DeveloperModeMarkerIsDir(facts) {
				t.Error("a read that failed offers a directory removal")
			}
		})
	}
}

// TestDeveloperModeDisownReportsWhatItProved pins the log of a marker that was
// handed to nobody and then could not be read: it says the handover happened
// and that the rest is inferred, and does not state the outcome as read.
func TestDeveloperModeDisownReportsWhatItProved(t *testing.T) {
	t.Parallel()
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	putUnclearableMarker(t, f, EntryRegular)
	f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
	var logs strings.Builder
	cfg := Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))}.withDefaults()
	r := &markerRemoval{path: DeveloperModeMarkerPath}
	if err := r.drop(&rereadFailsAfterChown{fakeSystem: f}, cfg); err != nil {
		t.Fatalf("drop = %v, want nil", err)
	}
	if r.stillOn() {
		t.Error("a marker handed to nobody counts as still on")
	}
	for _, want := range []string{"handed to nobody", "inferred from the handover and not confirmed"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log = %q, want %q", logs.String(), want)
		}
	}
	if strings.Contains(logs.String(), "reads unknown") {
		t.Errorf("log = %q states an outcome the read did not show", logs.String())
	}
}
