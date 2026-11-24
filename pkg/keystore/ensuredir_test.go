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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// TestEnsureDir: the server's start creates the store directory with the
// first put's own helper (the service user's, dirMode), a later put and
// the store lock then use it, and an existing directory is judged as an
// open judges it: one at a wider mode or another owner is refused and left
// as it is.
func TestEnsureDir(t *testing.T) {
	t.Run("a missing directory is created as a first put creates it", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := s.CheckDir(); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("CheckDir before EnsureDir = %v, want fs.ErrNotExist", err)
		}
		if err := s.EnsureDir(); err != nil {
			t.Fatalf("EnsureDir: %v", err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if !fi.IsDir() || fi.Mode().Perm() != dirMode || st.Uid != s.uid {
			t.Fatalf("%s: dir %v mode %04o uid %d; want a directory at %04o owned by %d", dir, fi.IsDir(), fi.Mode().Perm(), st.Uid, dirMode, s.uid)
		}
		if err := s.CheckDir(); err != nil {
			t.Fatalf("CheckDir after EnsureDir = %v", err)
		}
		// The store lock, which the server's log reopen takes, now opens.
		_, done, err := s.openLocked(context.Background(), false, true)
		if err != nil {
			t.Fatalf("the store lock after EnsureDir: %v", err)
		}
		done()
		// A second EnsureDir and a first put both find it and use it.
		if err := s.EnsureDir(); err != nil {
			t.Fatalf("a second EnsureDir: %v", err)
		}
		mustPut(t, s, "a", KindOpaque, []byte("v"))
	})

	t.Run("a directory at a wider mode is refused, not repaired", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		giveToService(t, dir)
		err := s.EnsureDir()
		if err == nil || !strings.Contains(err.Error(), "grants more than") {
			t.Fatalf("EnsureDir over a 0755 directory = %v, want the open's mode refusal", err)
		}
		if cerr := s.CheckDir(); cerr == nil || cerr.Error() != err.Error() {
			t.Fatalf("CheckDir = %v, want EnsureDir's refusal %v", cerr, err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Fatalf("the refused directory's mode is %04o after EnsureDir, want it left at 0755", fi.Mode().Perm())
		}
	})

	t.Run("a directory of another owner is refused, not repaired", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, dirMode); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		owner := fi.Sys().(*syscall.Stat_t).Uid
		if owner == s.uid {
			// Run as the service user's stand-in: judge it as another uid's.
			s.uid = owner + 1
		}
		err = s.EnsureDir()
		if err == nil || !strings.Contains(err.Error(), "owned by uid") {
			t.Fatalf("EnsureDir over another owner's directory = %v, want the open's owner refusal", err)
		}
		after, lerr := os.Lstat(dir)
		if lerr != nil {
			t.Fatal(lerr)
		}
		if after.Sys().(*syscall.Stat_t).Uid != owner || after.Mode().Perm() != dirMode {
			t.Fatal("the refused directory was changed")
		}
	})
}

// TestEnsureDirClassifiesRefusals: EnsureDir marks a persistent refusal of
// an existing directory (its mode or owner) as StoreDirRefused; a directory
// it cannot open (EACCES) as StoreDirDenied, and as StoreDirRace too when
// its owner is root or the service user (as one root has made and not yet
// handed over), never when it is a third uid's; and a directory it has just
// made that a racing put already writes in (ErrCorrupt, not empty) as
// StoreDirRace alone. The text is the open's.
func TestEnsureDirClassifiesRefusals(t *testing.T) {
	t.Run("a wider mode is a refusal", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		giveToService(t, dir)
		err := s.EnsureDir()
		if !StoreDirRefused(err) || StoreDirRace(err) || StoreDirDenied(err) || !strings.Contains(err.Error(), "grants more than") {
			t.Fatalf("EnsureDir = %v: refused %v race %v, want a refusal", err, StoreDirRefused(err), StoreDirRace(err))
		}
	})
	t.Run("a directory it cannot open is the race", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		err := s.EnsureDir()
		if !errors.Is(err, fs.ErrPermission) || !StoreDirDenied(err) || !StoreDirRace(err) || StoreDirRefused(err) {
			t.Fatalf("EnsureDir = %v: refused %v denied %v race %v, want denied and the race", err, StoreDirRefused(err), StoreDirDenied(err), StoreDirRace(err))
		}
	})
	t.Run("a third uid's directory it cannot open is denied, never the race", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		owner := fi.Sys().(*syscall.Stat_t).Uid
		if owner == 0 {
			t.Skip("run as root: the directory is root's, which the race may be")
		}
		// The service uid made other than the directory's owner, which is
		// not root either: a third uid's directory.
		s.uid = owner + 1
		err = s.EnsureDir()
		if !errors.Is(err, fs.ErrPermission) || !StoreDirDenied(err) || StoreDirRace(err) || StoreDirRefused(err) {
			t.Fatalf("EnsureDir = %v: refused %v denied %v race %v, want denied and not the race", err, StoreDirRefused(err), StoreDirDenied(err), StoreDirRace(err))
		}
	})
	t.Run("a parent that denies the walk is denied, never the race", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			mk   bool
		}{{"with the directory there", true}, {"with no directory yet", false}} {
			t.Run(tt.name, func(t *testing.T) {
				s, server := newTestStore(t)
				if tt.mk {
					if err := os.Mkdir(filepath.Join(server, "keystore"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(server, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(server, 0o700) })
				err := s.EnsureDir()
				d, ok := StoreDirDenial(err)
				if !StoreDirDenied(err) || StoreDirRace(err) || StoreDirRefused(err) || !ok || d.Cause != DeniedParent || d.Path != server || d.Unreachable {
					t.Fatalf("EnsureDir = %v: denied %v race %v denial %+v, want the parent %s, not the race", err, StoreDirDenied(err), StoreDirRace(err), d, server)
				}
			})
		}
	})
	t.Run("a new directory a put already writes in is the race", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		s.dirMade = func(string) {
			if err := os.WriteFile(filepath.Join(dir, "planted"), nil, 0o600); err != nil {
				t.Error(err)
			}
		}
		err := s.EnsureDir()
		if !errors.Is(err, ErrCorrupt) || !StoreDirRace(err) || StoreDirRefused(err) || StoreDirDenied(err) || !strings.Contains(err.Error(), "not empty") {
			t.Fatalf("EnsureDir = %v: refused %v race %v, want the race", err, StoreDirRefused(err), StoreDirRace(err))
		}
	})
	t.Run("a nil error is neither", func(t *testing.T) {
		if StoreDirRefused(nil) || StoreDirRace(nil) || StoreDirDenied(nil) {
			t.Fatal("nil classified")
		}
	})
}

// TestEnsureDirSyncsParentOfExistingDir: when the store directory already
// exists, as when a racing root put made it first, EnsureDir still fsyncs
// server/, so the name it then works under is durable; a failed fsync is
// its error.
func TestEnsureDirSyncsParentOfExistingDir(t *testing.T) {
	s, server := newTestStore(t)
	dir := filepath.Join(server, "keystore")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	giveToService(t, dir)
	var synced []string
	setSyncDir(t, func(root *os.Root) error {
		synced = append(synced, root.Name())
		return fsyncDir(root)
	})
	if err := s.EnsureDir(); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if !slices.Contains(synced, server) {
		t.Fatalf("synced %q; want the parent %s of the existing directory", synced, server)
	}
	boom := errors.New("fsync failed")
	setSyncDir(t, func(*os.Root) error { return boom })
	if err := s.EnsureDir(); !errors.Is(err, boom) {
		t.Fatalf("EnsureDir with a failing fsync = %v, want it", err)
	}
}

// TestMkdirAtExistingSyncFailureKeepsErrExist: when mkdirAt finds the name
// existing and the parent's fsync then fails, its error carries both, so
// a caller still tells an existing name (fs.ErrExist) from another failure
// and still sees the sync's.
func TestMkdirAtExistingSyncFailureKeepsErrExist(t *testing.T) {
	s, server := newTestStore(t)
	if err := os.Mkdir(filepath.Join(server, "keystore"), 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.OpenRoot(server)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	errSync := errors.New("injected fsync failure")
	setSyncDir(t, func(*os.Root) error { return errSync })
	_, err = s.mkdirAt(parent, "keystore")
	if !errors.Is(err, fs.ErrExist) || !errors.Is(err, errSync) {
		t.Fatalf("mkdirAt over an existing name with a failed sync: %v, want both fs.ErrExist and the sync's error", err)
	}
	// A caller that goes on under an existing name does not take it as one.
	if err := s.EnsureDir(); !errors.Is(err, errSync) {
		t.Fatalf("EnsureDir over an existing directory with a failed sync: %v, want the sync's error", err)
	}
}
