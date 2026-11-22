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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The helper-process environment: set, the test binary runs the defeat
// list as the service user against defeatFileEnv's file, in a directory of
// the kind defeatDirEnv names.
const (
	defeatFileEnv = "K3SM_TEST_DEFEAT_FILE"
	defeatDirEnv  = "K3SM_TEST_DEFEAT_DIR"
	// The directory kinds: root's at 0755, where a refusal of a name
	// operation is the directory's (EACCES), and the service user's at
	// 0700, where only the flag can refuse it (EPERM).
	defeatDirRoot    = "root"
	defeatDirService = "service"
)

// The bytes the parent writes, the line the child appends through O_APPEND,
// and the line its seek-then-write must append at the end.
const (
	defeatFirst  = "first\n"
	defeatSecond = "second\n"
	defeatSeeked = "seeked\n"
)

// TestAppendOnlyDefeatListAsServiceUser (U50) runs the defeat list
// (docs/design/keystore.md § "The user-scope floor") as the service user
// against each flagged log: the parent, root, makes the log the service
// user's at 0600 with SF_APPEND set, in a root-owned 0755 directory and in a
// service-owned 0700 one, and re-runs this test binary as a child with the
// service uid and gid, which attempts each defeat and asserts it fails with
// EPERM exactly (EACCES for a name operation the root-owned directory
// refuses), the bytes unchanged, while an O_APPEND write still lands. The
// parent then checks the bytes and the flag. Root-only and darwin-only.
func TestAppendOnlyDefeatListAsServiceUser(t *testing.T) {
	if p := os.Getenv(defeatFileEnv); p != "" {
		defeatChild(t, p, os.Getenv(defeatDirEnv))
		return
	}
	if !asRoot() {
		t.Skip("root-only: SF_APPEND can only be set by root, and the child runs as the service user")
	}
	uid, gid := serviceIDs(t)
	base, err := os.MkdirTemp("/private/tmp", "k3sm-defeat-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	var flaggedFiles []string
	t.Cleanup(func() {
		for _, p := range flaggedFiles {
			_ = unix.Chflags(p, 0) // so the tree can be removed
		}
		_ = os.RemoveAll(base)
	})
	bin := filepath.Join(base, "keystore.test")
	copyExecutable(t, bin)

	for _, kind := range []string{defeatDirRoot, defeatDirService} {
		for _, name := range []string{userFloorLogName, auditLogName} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				dir := filepath.Join(base, kind+"-"+name)
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if kind == defeatDirService {
					if err := os.Chown(dir, int(uid), int(gid)); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				p := filepath.Join(dir, name)
				other := filepath.Join(dir, "other")
				for _, f := range []string{p, other} {
					if err := os.WriteFile(f, []byte(defeatFirst), logMode); err != nil {
						t.Fatal(err)
					}
					if err := os.Chown(f, int(uid), int(gid)); err != nil {
						t.Fatal(err)
					}
				}
				if err := unix.Chflags(p, sfAppend); err != nil {
					t.Fatalf("chflags sappnd: %v", err)
				}
				// A clone may carry the flag too.
				flaggedFiles = append(flaggedFiles, p, filepath.Join(dir, "clone"))

				cmd := exec.Command(bin, "-test.run=^TestAppendOnlyDefeatListAsServiceUser$", "-test.v", "-test.count=1")
				cmd.Dir = base
				cmd.Env = append(os.Environ(), defeatFileEnv+"="+p, defeatDirEnv+"="+kind)
				cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
				out, err := cmd.CombinedOutput()
				t.Logf("child as uid %d:\n%s", uid, out)
				if err != nil {
					t.Fatalf("the defeat list as the service user: %v (a defeat that succeeded is a design finding)", err)
				}
				b, err := os.ReadFile(p)
				if want := defeatFirst + defeatSecond + defeatSeeked; err != nil || string(b) != want {
					t.Fatalf("after the child the log holds %q (%v), want %q", b, err, want)
				}
				var st unix.Stat_t
				if err := unix.Stat(p, &st); err != nil {
					t.Fatal(err)
				}
				if st.Flags&sfAppend == 0 {
					t.Fatal("the child cleared SF_APPEND")
				}
			})
		}
	}
}

// copyExecutable copies the running test binary to dst at 0755, so the
// child, as the service user, can execute it from a directory it can reach.
func copyExecutable(t *testing.T, dst string) {
	t.Helper()
	src, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }() // read-only
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close() // the copy already failed
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// defeatChild is the child's half, running as the service user: it
// appends through O_APPEND, then attempts each defeat against p and asserts
// the refusal and the bytes after it.
func defeatChild(t *testing.T, p, kind string) {
	if uint32(os.Geteuid()) == 0 {
		t.Fatal("the defeat-list child runs as root; it must run as the service user")
	}
	dir := filepath.Dir(p)
	other := filepath.Join(dir, "other")
	want := defeatFirst
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open O_APPEND as the service user: %v", err)
	}
	defer func() { _ = f.Close() }() // the child's descriptor
	if _, err := f.Write([]byte(defeatSecond)); err != nil {
		t.Fatalf("O_APPEND write as the service user: %v", err)
	}
	want += defeatSecond
	fd := int(f.Fd())
	rw, err := unix.Open(p, unix.O_RDWR|unix.O_APPEND, 0)
	if err != nil {
		t.Fatalf("open O_RDWR|O_APPEND as the owner: %v", err)
	}
	defer func() { _ = unix.Close(rw) }() // the child's descriptor

	// dirOp marks a name operation: in the root-owned directory the
	// directory refuses it first (EACCES); in the service user's own
	// directory only the flag can (EPERM).
	for _, a := range []struct {
		name    string
		dirOp   bool
		attempt func() error
	}{
		{"chflags nosappnd by descriptor (Fchflags)", false, func() error { return unix.Fchflags(fd, 0) }},
		{"chflags nosappnd by path", false, func() error { return unix.Chflags(p, 0) }},
		{"owner fchmod", false, func() error { return unix.Fchmod(fd, 0o644) }},
		{"owner chmod by path", false, func() error { return unix.Chmod(p, 0o644) }},
		{"F_SETFL clearing O_APPEND", false, func() error {
			fl, err := unix.FcntlInt(uintptr(rw), unix.F_GETFL, 0)
			if err != nil {
				return err
			}
			_, err = unix.FcntlInt(uintptr(rw), unix.F_SETFL, fl&^unix.O_APPEND)
			return err
		}},
		{"pwrite at offset 0 after the F_SETFL attempt", false, func() error {
			_, err := unix.Pwrite(rw, []byte("XXXXX"), 0)
			return err
		}},
		{"pwrite at offset 3", false, func() error {
			_, err := unix.Pwrite(rw, []byte("XXXXX"), 3)
			return err
		}},
		{"ftruncate", false, func() error { return unix.Ftruncate(fd, 0) }},
		{"truncate by path", false, func() error { return unix.Truncate(p, 0) }},
		{"O_TRUNC open", false, func() error { return openClose(p, unix.O_WRONLY|unix.O_TRUNC) }},
		{"a second O_TRUNC open with O_APPEND", false, func() error { return openClose(p, unix.O_WRONLY|unix.O_APPEND|unix.O_TRUNC) }},
		{"mmap MAP_SHARED|PROT_WRITE", false, func() error {
			b, err := unix.Mmap(rw, 0, len(want), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
			if err == nil {
				_ = unix.Munmap(b) // the mapping itself is the failure
			}
			return err
		}},
		{"F_PUNCHHOLE", false, func() error {
			ph := fpunchhole{offset: 0, length: int64(len(want))}
			if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(rw), unix.F_PUNCHHOLE, uintptr(unsafe.Pointer(&ph))); errno != 0 {
				return errno
			}
			return nil
		}},
		{"exchangedata", false, func() error { return unix.Exchangedata(other, p, 0) }},
		{"link to a new name", true, func() error { return unix.Link(p, filepath.Join(dir, "linked")) }},
		{"fclonefileat then rename over the original", true, func() error {
			clone := "clone"
			if err := unix.Fclonefileat(fd, unix.AT_FDCWD, filepath.Join(dir, clone), 0); err != nil {
				return err
			}
			defer func() { _ = unix.Unlink(filepath.Join(dir, clone)) }() // the clone is not the log
			return unix.Rename(filepath.Join(dir, clone), p)
		}},
		{"renamex_np RENAME_SWAP", true, func() error { return unix.RenamexNp(other, p, unix.RENAME_SWAP) }},
		{"rename over the original", true, func() error { return unix.Rename(other, p) }},
		{"rename away", true, func() error { return unix.Rename(p, filepath.Join(dir, "renamed")) }},
		{"unlink", true, func() error { return unix.Unlink(p) }},
	} {
		t.Run(a.name, func(t *testing.T) {
			wantErr := unix.EPERM
			if a.dirOp && kind == defeatDirRoot {
				wantErr = unix.EACCES
			}
			if err := a.attempt(); !errors.Is(err, wantErr) {
				t.Errorf("%s of a flagged log as the service user in the %s directory: %v, want %v", a.name, kind, err, wantErr)
			}
			if b, err := os.ReadFile(p); err != nil || string(b) != want {
				t.Fatalf("after the %s attempt the log holds %q (%v), want %q", a.name, b, err, want)
			}
		})
	}
	// An ACL write: x/sys/unix exposes no ACL call (acl_set_fd is libc's),
	// and this package does not use cgo, so it is not attempted here.
	t.Log("not attempted: an ACL write, which x/sys/unix gives no access to")

	// Seek to 0 and write: O_APPEND puts the bytes at the end.
	if _, err := unix.Seek(rw, 0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(rw, []byte(defeatSeeked)); err != nil {
		t.Fatalf("seek-then-write through O_APPEND: %v", err)
	}
	want += defeatSeeked
	if b, err := os.ReadFile(p); err != nil || string(b) != want {
		t.Fatalf("after seek-then-write the log holds %q (%v), want %q at the end", b, err, want)
	}
}

// openClose opens p with flag and closes it at once: the open itself is
// the attempt.
func openClose(p string, flag int) error {
	fd, err := unix.Open(p, flag, 0)
	if err == nil {
		_ = unix.Close(fd) // the open itself is the failure
	}
	return err
}
