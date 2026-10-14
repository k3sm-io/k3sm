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
	"testing"

	"golang.org/x/sys/unix"
)

// TestDarwinStagingFSOnDisk pins the real seam's no-follow behaviour in a
// scratch directory: lstat describes a symlink, the walk does not descend
// through one, the token read refuses a symlink and a fifo, and unlink
// removes a link rather than its target.
func TestDarwinStagingFSOnDisk(t *testing.T) {
	t.Parallel()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "deep"), 0o755); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(dir, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(stage, "join-token")
	if err := os.WriteFile(token, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(stage, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(stage, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sfs := NewDarwinStagingFS()

	e, err := sfs.Lstat(link)
	if err != nil || e.Mode&fs.ModeSymlink == 0 {
		t.Errorf("Lstat(link) = %+v, %v, want a symlink described", e, err)
	}
	if e, err := sfs.Lstat(stage); err != nil || e.UID != uint32(os.Getuid()) || e.Mode.Perm() != 0o700 || e.Dev == 0 {
		t.Errorf("Lstat(stage) = %+v, %v", e, err)
	}

	entries, err := sfs.WalkNoFollow(stage)
	if err != nil {
		t.Fatalf("WalkNoFollow: %v", err)
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, e.Path)
	}
	slices.Sort(paths)
	if want := []string{fifo, token, link}; !slices.Equal(paths, want) {
		t.Errorf("WalkNoFollow = %v, want %v (and nothing through the link)", paths, want)
	}

	raw, te, err := sfs.ReadTokenFile(token)
	if err != nil || string(raw) != "tok\n" || te.Nlink != 1 || te.Mode.Perm() != 0o600 {
		t.Errorf("ReadTokenFile(regular) = %q, %+v, %v", raw, te, err)
	}
	for _, p := range []string{link, fifo} {
		if _, _, err := sfs.ReadTokenFile(p); !errors.Is(err, ErrNotRegularFile) {
			t.Errorf("ReadTokenFile(%s) = %v, want ErrNotRegularFile", filepath.Base(p), err)
		}
	}

	if err := sfs.RemoveFile(link); err != nil {
		t.Fatalf("RemoveFile(link): %v", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("RemoveFile followed the link: %v", err)
	}
	if err := sfs.RemoveFile(link); err != nil {
		t.Errorf("RemoveFile of an absent path = %v, want nil", err)
	}

	if _, err := sfs.BinaryVersion(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("BinaryVersion(missing) = %v, want fs.ErrNotExist", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := sfs.BinaryVersion(self); err != nil || v == "" {
		t.Errorf("BinaryVersion(test binary) = %q, %v, want a version string", v, err)
	}
}

// TestCodesignTeamIDMissing pins the absent-file contract without running
// codesign on anything.
func TestCodesignTeamIDMissing(t *testing.T) {
	t.Parallel()
	if _, err := (CodesignTeamID{}).TeamID(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("TeamID(missing) = %v, want fs.ErrNotExist", err)
	}
}
