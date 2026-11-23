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

// An extended attribute that cannot be removed refuses the clone, naming
// it: none is skipped.
func TestCloneArchiveRefusesUnremovableXattr(t *testing.T) {
	f, nad, dir := cloneSource(t)
	withDecoratedClone(t, dir)
	prev := fremovexattr
	fremovexattr = func(fd int, name string) error {
		if name == "com.k3sm.planted" {
			return unix.EPERM
		}
		return prev(fd, name)
	}
	t.Cleanup(func() { fremovexattr = prev })
	err := cloneArchive(&oldLog{f: f, size: 8}, nad, "one")
	if errors.Is(err, errCloneRefused) {
		t.Skipf("this volume refuses clonefile: %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), `remove the extended attribute "com.k3sm.planted"`) || !errors.Is(err, unix.EPERM) {
		t.Fatalf("cloneArchive with an unremovable attribute: %v, want a refusal naming it", err)
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
