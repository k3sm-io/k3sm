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
	"slices"
	"strings"
	"testing"
)

const unclearableMarkerRemove = "RemoveEntry:/Library:k3sm.developer-mode"

// putUnclearableMarker puts a valid developer-mode marker on the fake, with
// the directories above it, as kind.
func putUnclearableMarker(f *fakeSystem, kind EntryKind) {
	seedMarkerAncestors(f)
	f.owners[DeveloperModeMarkerPath] = OwnedEntry{Path: DeveloperModeMarkerPath, Kind: kind, Mode: 0o644}
	if kind == EntryRegular {
		f.putFile(DeveloperModeMarkerPath, []byte("developer mode enabled by k3sm install on 2026-11-01T00:00:00Z\n"))
		if f.modes == nil {
			f.modes = map[string]fs.FileMode{}
		}
		f.modes[DeveloperModeMarkerPath] = 0o644
	}
}

// startedOnTheNewTree lists the calls between the publish swap and the
// reverse swap (or the end) that wire or start a daemon: none may run on the
// new tree while the marker still reads on.
func startedOnTheNewTree(calls []string) (publish, revert int, started []string) {
	publish, revert = -1, -1
	for i, c := range calls {
		if strings.HasPrefix(c, "SwapInstallRoot:") {
			if publish < 0 {
				publish = i
			} else if revert < 0 {
				revert = i
			}
		}
	}
	if publish < 0 {
		return publish, revert, nil
	}
	end := len(calls)
	if revert >= 0 {
		end = revert
	}
	for _, c := range calls[publish+1 : end] {
		for _, p := range []string{"Bootstrap:", "Kickstart:", "Enable:", "Bootout:", "WriteLaunchDaemon:", "EnsureSymlink:", "WriteUserKubeconfig:"} {
			if strings.HasPrefix(c, p) {
				started = append(started, c)
			}
		}
	}
	return publish, revert, started
}

// TestDeveloperModeMarkerUnclearableRevertsTheSwap pins the fail-closed
// branch: a marker that can be neither removed (twice) nor handed to nobody
// still reads on, so the signed tree must not run beside it. On an upgrade the
// swap is reverted, the previous tree and its marker are live again, nothing
// is wired or restarted on the new tree, and the error names the remedy. On a
// first install there is nothing to revert to, so the install stops before
// anything is wired or restarted.
func TestDeveloperModeMarkerUnclearableRevertsTheSwap(t *testing.T) {
	shrinkRestartBudgets(t)
	stuck := func(f *fakeSystem) {
		f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
		f.chownErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
	}

	t.Run("an upgrade reverts the swap and restarts nothing on the new tree", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, stageCfg()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		putUnclearableMarker(f, EntryRegular)
		stuck(f)
		f.putLoaded(NetdLabel, ServerLabel)
		f.calls = nil
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install succeeded beside a marker that still reads on")
		}
		for _, want := range []string{"k3sm install --developer-mode off", "rolled back to the previous install root"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
		if n := countCalls(f, unclearableMarkerRemove); n != 2 {
			t.Errorf("the removal was attempted %d times, want 2", n)
		}
		publish, revert, started := startedOnTheNewTree(f.calls)
		if publish < 0 || revert < 0 {
			t.Fatalf("publish swap at %d, reverse swap at %d: want both; calls %v", publish, revert, f.calls)
		}
		if !strings.HasSuffix(f.calls[revert], ":swap") {
			t.Errorf("the reverse swap was %q, want an exchange with the previous tree", f.calls[revert])
		}
		if len(started) > 0 {
			t.Errorf("wired or started on the new tree before the revert: %v", started)
		}
		if removed := slices.Index(f.calls, unclearableMarkerRemove); removed < publish || removed > revert {
			t.Errorf("the removal ran at call %d, want between the swap (%d) and the revert (%d)", removed, publish, revert)
		}
		if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeMarkerOn {
			t.Errorf("after the revert the marker reads %s, want %s beside the previous tree", got, DeveloperModeMarkerOn)
		}
	})

	t.Run("a first install stops before anything is wired or restarted", func(t *testing.T) {
		f := &fakeSystem{owners: map[string]OwnedEntry{}}
		putUnclearableMarker(f, EntryRegular)
		stuck(f)
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		err := Install(context.Background(), f, cfg)
		if err == nil {
			t.Fatal("Install succeeded beside a marker that still reads on")
		}
		for _, want := range []string{"k3sm install --developer-mode off", "first install"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
		publish, revert, started := startedOnTheNewTree(f.calls)
		if publish < 0 {
			t.Fatalf("no publish swap; calls %v", f.calls)
		}
		if revert >= 0 {
			t.Errorf("a first install swapped again at call %d (%s); want the new tree left with nothing started", revert, f.calls[revert])
		}
		if len(started) > 0 {
			t.Errorf("wired or started on the new tree: %v", started)
		}
	})
}

// rereadFailsAfterChown is the fake with the marker's lstat failing once the
// disown's Chown has gone through, so the re-read cannot confirm the marker.
type rereadFailsAfterChown struct {
	*fakeSystem
	chowned bool
}

func (s *rereadFailsAfterChown) Chown(path string, uid, gid int) error {
	err := s.fakeSystem.Chown(path, uid, gid)
	if err == nil && path == DeveloperModeMarkerPath {
		s.chowned = true
	}
	return err
}

func (s *rereadFailsAfterChown) Owner(path string) (OwnedEntry, error) {
	if s.chowned && path == DeveloperModeMarkerPath {
		s.calls = append(s.calls, "Owner:"+path)
		return OwnedEntry{}, fmt.Errorf("lstat %s: EIO", path)
	}
	return s.fakeSystem.Owner(path)
}

// TestDeveloperModeMarkerUnclearableEdgeCases pins the two disown outcomes
// that do not leave the marker reading on, so the install proceeds on the new
// tree: a Chown that succeeds with a re-read that then errors (the marker
// reads invalid, which never turns developer mode on), and a marker that is
// not a regular file whose removal fails (never handed to nobody, and invalid
// already).
func TestDeveloperModeMarkerUnclearableEdgeCases(t *testing.T) {
	shrinkRestartBudgets(t)
	for _, tc := range []struct {
		name string
		kind EntryKind
		sys  func(*fakeSystem) System
		// chown says the disown hands the marker to nobody.
		chown bool
	}{
		{
			name:  "a chown that succeeds and a re-read that errors",
			kind:  EntryRegular,
			sys:   func(f *fakeSystem) System { return &rereadFailsAfterChown{fakeSystem: f} },
			chown: true,
		},
		{
			name: "a non-regular marker whose removal fails",
			kind: EntryDir,
			sys:  func(f *fakeSystem) System { return f },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeSystem{owners: map[string]OwnedEntry{}}
			putUnclearableMarker(f, tc.kind)
			f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
			cfg := stageCfg()
			cfg.DeveloperMode = DeveloperModeOff
			if err := Install(context.Background(), tc.sys(f), cfg); err != nil {
				t.Fatalf("Install = %v, want success with the marker reading invalid", err)
			}
			if n := countCalls(f, unclearableMarkerRemove); n != 2 {
				t.Errorf("the removal was attempted %d times, want 2", n)
			}
			chowned := slices.ContainsFunc(f.calls, func(c string) bool { return strings.HasPrefix(c, "Chown:"+DeveloperModeMarkerPath+":") })
			if chowned != tc.chown {
				t.Errorf("the marker was handed to nobody: %v, want %v; calls %v", chowned, tc.chown, f.calls)
			}
			if got := ReadDeveloperModeState(tc.sys(f), DeveloperModeMarkerPath); got == DeveloperModeMarkerOn {
				t.Errorf("the marker reads %s after the install", got)
			}
			if n := len(slices.DeleteFunc(slices.Clone(f.calls), func(c string) bool { return !strings.HasPrefix(c, "SwapInstallRoot:") })); n != 1 {
				t.Errorf("the install swapped %d times, want the publish alone", n)
			}
			if !slices.Contains(f.calls, "WriteUserKubeconfig:alice") {
				t.Error("the install stopped before step 5")
			}
		})
	}
}
