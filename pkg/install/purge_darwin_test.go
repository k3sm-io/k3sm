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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"k8s.io/client-go/tools/clientcmd"

	"k3sm.io/k3sm/pkg/dataroot"
)

// purgeFixture builds a real tree under a t.TempDir(): a marker, nested
// directories and files, and two symlinks that point OUTSIDE the tree (one at
// a file, one at a directory holding a file). It returns the root and the two
// outside targets.
func purgeFixture(t *testing.T) (root, outsideFile, outsideDir string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "k3sm")
	outsideFile = filepath.Join(base, "precious.txt")
	outsideDir = filepath.Join(base, "precious")
	for _, d := range []string{root, filepath.Join(root, "server", "db"), filepath.Join(root, "pods", "a", "b"), outsideDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		dataroot.MarkerPath(root):                       string(dataroot.MarkerContent(root)),
		filepath.Join(root, "server", "db", "state.db"): "SQLite format 3",
		filepath.Join(root, "pods", "a", "b", "log"):    "hello",
		outsideFile:                         "keep me",
		filepath.Join(outsideDir, "inside"): "keep me too",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outsideFile, filepath.Join(root, "pods", "a", "to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(root, "server", "to-dir")); err != nil {
		t.Fatal(err)
	}
	return root, outsideFile, outsideDir
}

// identity is root's (dev, ino), what the guard would have handed PurgeTree.
func identity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return statDev(&st), st.Ino
}

func realDev(_ string, st *unix.Stat_t) uint64 { return statDev(st) }

// TestPurgeTreeRemovesTheTreeButNotSymlinkTargets is the real-filesystem gate
// for the walk: the whole tree goes, each symlink in it is unlinked, and what
// the symlinks point at outside the tree survives untouched.
func TestPurgeTreeRemovesTheTreeButNotSymlinkTargets(t *testing.T) {
	root, outsideFile, outsideDir := purgeFixture(t)
	dev, ino := identity(t, root)
	if err := purgeTree(root, dev, ino, realDev); err != nil {
		t.Fatalf("purgeTree: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("root still there after purge: %v", err)
	}
	for _, p := range []string{outsideFile, filepath.Join(outsideDir, "inside")} {
		if b, err := os.ReadFile(p); err != nil || !strings.HasPrefix(string(b), "keep me") {
			t.Fatalf("symlink target %s was touched: %q, %v", p, b, err)
		}
	}
}

// TestPurgeTreeClearsAnImmutableFlag proves the EPERM retry: a file the owner
// marked immutable (uchg) is unflagged and removed rather than left behind.
func TestPurgeTreeClearsAnImmutableFlag(t *testing.T) {
	root, _, _ := purgeFixture(t)
	locked := filepath.Join(root, "server", "db", "state.db")
	if err := unix.Chflags(locked, unix.UF_IMMUTABLE); err != nil {
		t.Skipf("cannot set uchg here: %v", err)
	}
	dev, ino := identity(t, root)
	if err := purgeTree(root, dev, ino, realDev); err != nil {
		_ = unix.Chflags(locked, 0) // let t.TempDir clean up
		t.Fatalf("purgeTree: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("root still there after purge: %v", err)
	}
}

// TestPurgeTreeNeverEntersAnotherDevice describes a mount point inside the tree
// through the injected device lookup: the walk must not enter it, must report
// it, and must keep the marker and the root so a re-run is still authorized.
func TestPurgeTreeNeverEntersAnotherDevice(t *testing.T) {
	root, _, _ := purgeFixture(t)
	mnt := filepath.Join(root, "pods", "a")
	devOf := func(path string, st *unix.Stat_t) uint64 {
		if path == mnt {
			return 999
		}
		return statDev(st)
	}
	dev, ino := identity(t, root)
	err := purgeTree(root, dev, ino, devOf)
	if err == nil || !strings.Contains(err.Error(), mnt) {
		t.Fatalf("purgeTree = %v, want an error naming %s", err, mnt)
	}
	for _, p := range []string{filepath.Join(mnt, "b", "log"), dataroot.MarkerPath(root)} {
		if _, err := os.Lstat(p); err != nil {
			t.Fatalf("%s was removed across the mount or before the end: %v", p, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "server")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the rest of the tree should still be purged: %v", err)
	}
}

// TestPurgeTreeRefusesASwappedRoot proves the TOCTOU bind: a root that is not
// the (dev, ino) the guard approved is not touched at all.
func TestPurgeTreeRefusesASwappedRoot(t *testing.T) {
	root, _, _ := purgeFixture(t)
	dev, ino := identity(t, root)
	if err := purgeTree(root, dev, ino+1, realDev); err == nil {
		t.Fatal("purgeTree of a different inode succeeded")
	}
	if _, err := os.Lstat(filepath.Join(root, "server", "db", "state.db")); err != nil {
		t.Fatalf("a refused purge removed something: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err := purgeTree(link, dev, ino, realDev); err == nil {
		t.Fatal("purgeTree through a symlinked root succeeded")
	}
}

// TestPurgeLaunchctlListAndDsclParsing pins the two text parsers the darwin
// System reads launchd and the directory service through.
func TestPurgeLaunchctlListAndDsclParsing(t *testing.T) {
	out := []byte("PID\tStatus\tLabel\n-\t0\tcom.apple.foo\n123\t0\tio.k3sm.server\n-\t78\tio.k3sm.netd\n")
	got := parseLaunchctlList(out, purgeLabelPrefix)
	if strings.Join(got, ",") != "io.k3sm.netd,io.k3sm.server" {
		t.Fatalf("labels = %v", got)
	}
	if v := parseDsclAttr([]byte("RealName:\n k3sm service user\n"), "RealName"); v != serviceUserRealName {
		t.Fatalf("RealName = %q", v)
	}
	if v := parseDsclAttr([]byte("UserShell: /usr/bin/false\n"), "UserShell"); v != serviceUserShell {
		t.Fatalf("UserShell = %q", v)
	}
	// IsHidden is outside dscl's standard attribute set and reads back with
	// the native prefix; an absent attribute reads back as "No such key".
	if v := parseDsclAttr([]byte("dsAttrTypeNative:IsHidden: 1\n"), "IsHidden"); v != serviceUserHidden {
		t.Fatalf("IsHidden = %q, want %q", v, serviceUserHidden)
	}
	if v := parseDsclAttr([]byte("No such key: IsHidden\n"), "IsHidden"); v != "" {
		t.Fatalf("absent IsHidden = %q, want empty", v)
	}
}

// TestReviveServiceUser pins what an install does to an account it adopts:
// one a purge left disabled gets the install RealName and IsHidden back (the
// dscl -create calls, in order), and any other account is left alone.
func TestReviveServiceUser(t *testing.T) {
	current := ServiceUserRecord{Exists: true, UID: 271, RealName: serviceUserRealName, Shell: serviceUserShell, Home: DefaultDataRoot, Hidden: true}
	disabled := current
	disabled.RealName = serviceUserDisabledRealName
	legacy := current
	legacy.RealName, legacy.Hidden = DefaultServiceUser, false
	for _, tc := range []struct {
		name string
		rec  ServiceUserRecord
		want []string
	}{
		{name: "the account a purge left disabled", rec: disabled, want: []string{"RealName=" + serviceUserRealName, "IsHidden=" + serviceUserHidden}},
		{name: "the current shape", rec: current},
		{name: "a legacy account", rec: legacy},
		{name: "no account", rec: ServiceUserRecord{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			err := reviveServiceUser(tc.rec, func(attr, value string) error {
				got = append(got, attr+"="+value)
				return nil
			})
			if err != nil {
				t.Fatalf("reviveServiceUser: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("dscl -create calls = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("a failed dscl -create is the install's error", func(t *testing.T) {
		boom := errors.New("boom")
		if err := reviveServiceUser(disabled, func(string, string) error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("reviveServiceUser = %v, want boom", err)
		}
	})
	t.Run("the restored record passes the purge identity check", func(t *testing.T) {
		for _, rec := range []ServiceUserRecord{current, disabled} {
			if err := checkServiceUser(DefaultServiceUser, rec, DefaultDataRoot); err != nil {
				t.Fatalf("checkServiceUser(%q) = %v, want accepted", rec.RealName, err)
			}
		}
	})
}

// TestPurgeKubeconfigFileKeepsOwnerModeAndOtherEntries runs the real removal
// against a t.TempDir() home: the k3sm context goes, the other cluster stays,
// and the file keeps its mode. A symlinked ~/.kube is refused untouched.
func TestPurgeKubeconfigFileKeepsOwnerModeAndOtherEntries(t *testing.T) {
	home := t.TempDir()
	kube := filepath.Join(home, ".kube")
	if err := os.Mkdir(kube, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(kube, "config")
	if err := os.WriteFile(path, kubeFixture(t, true), 0o640); err != nil {
		t.Fatal(err)
	}
	if removed, err := removeUserKubeconfigContext(home); err != nil || !removed {
		t.Fatalf("remove = %v, %v; want removed", removed, err)
	}
	// Once more: the context is gone, so nothing is reported removed.
	if removed, err := removeUserKubeconfigContext(home); err != nil || removed {
		t.Fatalf("second remove = %v, %v; want nothing removed", removed, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode after = %v (%v), want 0640", fi, err)
	}
	b, _ := os.ReadFile(path)
	cfg, err := clientcmd.Load(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Contexts[adminContextName]; ok {
		t.Fatal("k3sm context survived")
	}
	if _, ok := cfg.Contexts["work"]; !ok {
		t.Fatal("the user's own context was removed")
	}

	// Absent ~/.kube: a no-op.
	if removed, err := removeUserKubeconfigContext(t.TempDir()); err != nil || removed {
		t.Fatalf("absent ~/.kube = %v, %v; want a no-op", removed, err)
	}
	// Symlinked ~/.kube: refused, the target untouched.
	evil := t.TempDir()
	if err := os.Symlink(kube, filepath.Join(evil, ".kube")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, kubeFixture(t, true), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := removeUserKubeconfigContext(evil); !errors.Is(err, errSymlinkRefused) {
		t.Fatalf("symlinked ~/.kube = %v, want errSymlinkRefused", err)
	}
	if b2, _ := os.ReadFile(path); string(b2) != string(kubeFixture(t, true)) {
		t.Fatal("a refused removal changed the file")
	}
}

// TestPurgeLivePIDsSkipsZombies proves a zombie is neither counted as a
// survivor nor killed, and that the two sysctl lists are merged without
// duplicates.
func TestPurgeLivePIDsSkipsZombies(t *testing.T) {
	proc := func(pid int32, stat int8) unix.KinfoProc {
		var p unix.KinfoProc
		p.Proc.P_pid, p.Proc.P_stat = pid, stat
		return p
	}
	got := livePIDs([]unix.KinfoProc{proc(300, 2), proc(200, procStateZombie), proc(300, 2), proc(100, 3), proc(0, 2)})
	if len(got) != 2 || got[0] != 100 || got[1] != 300 {
		t.Fatalf("livePIDs = %v, want [100 300]", got)
	}
}
