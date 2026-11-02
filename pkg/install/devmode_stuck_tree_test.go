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
	"strings"
	"testing"
)

// failingSwap is the fake with every SwapInstallRoot or MoveInstallRootAside
// after the first n failing: the publish goes through and the reverse swap
// (or the move aside) does not.
type failingSwap struct {
	*fakeSystem
	n int
}

func (s *failingSwap) SwapInstallRoot(staging, live string) (bool, error) {
	if s.n <= 0 {
		s.calls = append(s.calls, "SwapInstallRoot:"+staging+"<->"+live+":failed")
		return false, errors.New("EIO")
	}
	s.n--
	return s.fakeSystem.SwapInstallRoot(staging, live)
}

func (s *failingSwap) MoveInstallRootAside(live, aside string) error {
	if s.n <= 0 {
		s.calls = append(s.calls, "MoveInstallRootAside:"+live+"->"+aside+":failed")
		return errors.New("EIO")
	}
	s.n--
	return s.fakeSystem.MoveInstallRootAside(live, aside)
}

// stuckMarker makes the marker on f impossible to remove or hand to nobody.
func stuckMarker(t *testing.T, f *fakeSystem) {
	t.Helper()
	putUnclearableMarker(t, f, EntryRegular)
	f.removeEntryErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
	f.chownErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EPERM")}
}

// TestDeveloperModeStuckMarkerLeavesNoSignedTree pins what an install does
// when the developer-mode marker can be neither removed nor handed to nobody,
// so it still reads on and k3sm.app's root steps would skip the signature
// check of the installed CLI. A first install moves its new tree out of the
// install root, and a rollback that fails says that developer mode is still
// on beside the new tree. Every error names the likely blocker, not
// `k3sm install --developer-mode off`, which runs the removal that failed.
func TestDeveloperModeStuckMarkerLeavesNoSignedTree(t *testing.T) {
	shrinkRestartBudgets(t)
	offCfg := func() Config {
		cfg := stageCfg()
		cfg.DeveloperMode = DeveloperModeOff
		return cfg
	}
	live, staging := DefaultInstallDir, DefaultInstallDir+installSwapSuffix

	t.Run("a first install moves the new tree out of the install root", func(t *testing.T) {
		f := &fakeSystem{owners: map[string]OwnedEntry{}}
		stuckMarker(t, f)
		err := Install(context.Background(), f, offCfg())
		if err == nil {
			t.Fatal("Install succeeded beside a marker that still reads on")
		}
		for _, want := range []string{"first install", "moved from the install root " + live, "sudo chflags nouchg " + DeveloperModeMarkerPath} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
		if f.dirExists(live) {
			t.Errorf("the install root %s still holds a tree beside the stuck marker", live)
		}
		if !f.dirExists(staging) {
			t.Errorf("the new tree is not at %s, where the next install removes it", staging)
		}
		if _, _, started := startedOnTheNewTree(f.calls); len(started) > 0 {
			t.Errorf("wired or started on the new tree: %v", started)
		}
	})

	t.Run("a first install whose move aside fails says the tree is still there", func(t *testing.T) {
		f := &fakeSystem{owners: map[string]OwnedEntry{}}
		stuckMarker(t, f)
		err := Install(context.Background(), &failingSwap{fakeSystem: f, n: 1}, offCfg())
		if err == nil {
			t.Fatal("Install succeeded beside a marker that still reads on")
		}
		for _, want := range []string{"so it is still there beside the developer-mode marker " + DeveloperModeMarkerPath, "sudo rm -rf " + live} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
	})

	t.Run("a failed rollback says developer mode is still on", func(t *testing.T) {
		f := &fakeSystem{}
		if err := Install(context.Background(), f, stageCfg()); err != nil {
			t.Fatalf("first Install: %v", err)
		}
		stuckMarker(t, f)
		f.putLoaded(NetdLabel, ServerLabel)
		f.calls = nil
		err := Install(context.Background(), &failingSwap{fakeSystem: f, n: 1}, offCfg())
		if err == nil {
			t.Fatal("Install succeeded beside a marker that still reads on")
		}
		for _, want := range []string{
			"ROLLBACK FAILED",
			"DEVELOPER MODE IS STILL ON",
			"the developer-mode marker " + DeveloperModeMarkerPath + " is beside the new tree",
			"plists name paths inside it",
			"sudo chflags nouchg " + DeveloperModeMarkerPath,
			"ls -lO@e " + DeveloperModeMarkerPath,
			"a system-immutable flag (schg): `sudo chflags noschg " + DeveloperModeMarkerPath + "`, or Recovery if the securelevel is raised",
			"a deny-delete ACL: `sudo chmod -N " + DeveloperModeMarkerPath + "`",
			"`sudo launchctl bootout system/<label>` and `sudo launchctl disable system/<label>`",
			"a stop-gap until the marker is cleared and the install is re-run",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not carry %q", err, want)
			}
		}
		if strings.Contains(err.Error(), "run k3sm install --developer-mode off") {
			t.Errorf("error %q names the command that just failed as the remedy", err)
		}
	})
}

// TestInstallReportsUnreadableMarkerBesideKubeconfigError pins the join at
// the admin kubeconfig step: a valid marker that could not be read to keep a
// copy (and was removed anyway) and a kubeconfig write that then fails are
// both reported.
func TestInstallReportsUnreadableMarkerBesideKubeconfigError(t *testing.T) {
	shrinkRestartBudgets(t)
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	putUnclearableMarker(t, f, EntryRegular)
	f.readModeErrs = map[string]error{DeveloperModeMarkerPath: errors.New("EIO reading the marker")}
	f.kubeconfigErr = errors.New("home directory is read-only")
	cfg := stageCfg()
	cfg.DeveloperMode = DeveloperModeOff
	err := Install(context.Background(), f, cfg)
	if err == nil {
		t.Fatal("Install succeeded with the kubeconfig write failing")
	}
	for _, want := range []string{"could not be read to keep a copy", "EIO reading the marker", "home directory is read-only"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
	if got := ReadDeveloperModeState(f, DeveloperModeMarkerPath); got != DeveloperModeAbsent {
		t.Errorf("the marker reads %s, want it removed", got)
	}
}

// TestDeveloperModeStuckMarkerWithdrawIsOneWay pins that a first install's
// withdraw never swaps: with the staging path occupied it refuses, the new
// tree stays at the install root, nothing from the staging path reaches it,
// and the error says the tree is still beside the marker.
func TestDeveloperModeStuckMarkerWithdrawIsOneWay(t *testing.T) {
	shrinkRestartBudgets(t)
	live, staging := DefaultInstallDir, DefaultInstallDir+installSwapSuffix
	planted := staging + "/planted"
	f := &fakeSystem{owners: map[string]OwnedEntry{}}
	stuckMarker(f)
	f.calls = nil
	occupy := &occupyAfterPublish{fakeSystem: f, path: planted}
	cfg := stageCfg()
	cfg.DeveloperMode = DeveloperModeOff
	err := Install(context.Background(), occupy, cfg)
	if err == nil {
		t.Fatal("Install succeeded beside a marker that still reads on")
	}
	for _, want := range []string{"so it is still there beside the developer-mode marker " + DeveloperModeMarkerPath, "sudo rm -rf " + live} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not carry %q", err, want)
		}
	}
	if !f.dirExists(live) {
		t.Errorf("the install root %s lost the new tree", live)
	}
	if _, ok := f.tree[live+"/planted"]; ok {
		t.Errorf("what occupied %s was put at the install root", staging)
	}
	if _, ok := f.tree[planted]; !ok {
		t.Errorf("what occupied %s was moved", staging)
	}
}

// occupyAfterPublish is the fake with something put at the staging path the
// moment the publish has renamed the staged tree away from it.
type occupyAfterPublish struct {
	*fakeSystem
	path string
}

func (s *occupyAfterPublish) SwapInstallRoot(staging, live string) (bool, error) {
	previous, err := s.fakeSystem.SwapInstallRoot(staging, live)
	if err == nil && !previous {
		if s.tree == nil {
			s.tree = map[string]string{}
		}
		s.tree[s.path] = "/elsewhere/planted"
	}
	return previous, err
}
