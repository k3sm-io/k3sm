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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// addACL gives the file at p an extended ACL entry, as chmod +a does.
func addACL(t *testing.T, p string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow read", p).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
}

// cloneSource is a 0600 file holding "one\ntwo\n" with the extended
// attribute com.k3sm.probe, open read-only, in a fresh directory open at
// the returned descriptor.
func cloneSource(t *testing.T) (*os.File, int, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "log")
	if err := os.WriteFile(src, []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(src, "com.k3sm.probe", []byte("x"), 0); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	nad, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(nad) })
	return f, nad, dir
}

// withDecoratedClone makes cloneFileAt clone, then give the clone the
// extended attribute com.k3sm.planted and an extended ACL, so the clone
// carries both whatever the volume copies; it skips on a volume that
// refuses clonefile.
func withDecoratedClone(t *testing.T, dir string) {
	t.Helper()
	prev := cloneFileAt
	cloneFileAt = func(src, d int, name string) error {
		if err := prev(src, d, name); err != nil {
			return err
		}
		p := filepath.Join(dir, name)
		if err := unix.Setxattr(p, "com.k3sm.planted", []byte("y"), 0); err != nil {
			t.Fatalf("setxattr on the clone: %v", err)
		}
		addACL(t, p)
		return nil
	}
	t.Cleanup(func() { cloneFileAt = prev })
}

// The cloned archive keeps none of what the source's owner could set: every
// extended attribute is removed and any ACL with it, and the archive then
// passes the logs' flags-and-ACL judge.
func TestCloneArchiveStripsXattrsAndACL(t *testing.T) {
	f, nad, dir := cloneSource(t)
	withDecoratedClone(t, dir)
	err := cloneArchive(&oldLog{f: f, size: 8}, nad, "one")
	if errors.Is(err, errCloneRefused) {
		t.Skipf("this volume refuses clonefile: %v", err)
	}
	if err != nil {
		t.Fatalf("cloneArchive: %v", err)
	}
	fd, err := unix.Open(filepath.Join(dir, "one"), unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if names, err := listXattrs(fd); err != nil || len(names) != 0 {
		t.Fatalf("the archive carries extended attributes %q (%v), want none", names, err)
	}
	if acl, err := fdHasACL(fd); err != nil || acl {
		t.Fatalf("the archive has an ACL %v (%v), want none", acl, err)
	}
	if err := judgeFlagsACL(fd, fdFlags); err != nil {
		t.Fatalf("the archive fails the logs' judge: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "one")); err != nil || string(b) != "one\ntwo\n" {
		t.Fatalf("the archive holds %q (%v)", b, err)
	}
}

// An extended attribute on the clone that cannot be removed, as a
// protected system attribute cannot, does not refuse rotate: the clone is
// discarded and the archive is a copy, which carries no extended
// attribute, holds the whole log at open and is the caller's 0600.
func TestCloneArchiveProtectedXattr(t *testing.T) {
	f, nad, dir := cloneSource(t)
	withDecoratedClone(t, dir)
	var cloned bool
	prevClone := cloneFileAt
	cloneFileAt = func(src, d int, name string) error {
		err := prevClone(src, d, name)
		cloned = err == nil
		return err
	}
	prev := fremovexattr
	var refused bool
	fremovexattr = func(fd int, name string) error {
		if name == "com.k3sm.planted" {
			refused = true
			return unix.EPERM
		}
		return prev(fd, name)
	}
	volumeSpace = func(int) (int64, int64, error) { return 1 << 40, 1 << 40, nil }
	t.Cleanup(func() { cloneFileAt = prevClone; fremovexattr = prev; volumeSpace = defaultVolumeSpace })
	if err := archiveLog(&oldLog{f: f, size: 8}, nad, "one"); err != nil {
		t.Fatalf("archiving with an unremovable attribute on the clone: %v, want the copy", err)
	}
	if !cloned {
		t.Skip("this volume refuses clonefile; the copy path is tested elsewhere")
	}
	if !refused {
		t.Fatal("the attribute removal was never tried")
	}
	p := filepath.Join(dir, "one")
	if b, err := os.ReadFile(p); err != nil || string(b) != "one\ntwo\n" {
		t.Fatalf("the archive holds %q (%v), want the whole log at open", b, err)
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if names, err := listXattrs(fd); err != nil || len(names) != 0 {
		t.Fatalf("the archive carries extended attributes %q (%v), want none", names, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o7777 != logMode || statFlags(&st) != 0 || st.Nlink != 1 {
		t.Fatalf("the archive is uid %d mode %04o flags %#x nlink %d, want the caller's 0600, unflagged, one link", st.Uid, st.Mode&0o7777, statFlags(&st), st.Nlink)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "log,one" {
		t.Fatalf("the directory holds %q, want only the log and its archive: no clone left behind", names)
	}
}

// An ACL left on the clone (its removal a no-op) fails the logs' judge, so
// the clone is refused.
func TestCloneArchiveRefusesRemainingACL(t *testing.T) {
	f, nad, dir := cloneSource(t)
	withDecoratedClone(t, dir)
	prev := removeACL
	removeACL = func(int) error { return nil }
	t.Cleanup(func() { removeACL = prev })
	err := cloneArchive(&oldLog{f: f, size: 8}, nad, "one")
	if errors.Is(err, errCloneRefused) {
		t.Skipf("this volume refuses clonefile: %v", err)
	}
	if !errors.Is(err, errLogUntrusted) || !strings.Contains(err.Error(), "extended ACL") {
		t.Fatalf("cloneArchive with an ACL left: %v, want the judge's ACL refusal", err)
	}
}

// judgeArchives reads each archive's ACL on its own descriptor: an archive
// with an extended ACL refuses the rotate, as its directory's does.
func TestJudgeArchiveRefusesACL(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, auditArchiveName(1))
	if err := os.WriteFile(p, []byte("x\n"), logMode); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	s := &FileStore{floorUID: os.Geteuid()}
	present, err := s.judgeArchives(fd)
	if err != nil || !present[1] {
		t.Fatalf("an archive with no ACL: present %v, %v; want it judged present", present[1], err)
	}
	addACL(t, p)
	if _, err := s.judgeArchives(fd); !errors.Is(err, errLogUntrusted) || !strings.Contains(err.Error(), "extended ACL") || !strings.Contains(err.Error(), "chmod -N") {
		t.Fatalf("an archive with an ACL: %v, want a refusal naming the ACL and chmod -N", err)
	}
}
