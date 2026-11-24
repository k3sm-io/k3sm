//go:build integration

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
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// u104SockEnv carries the socket path to the service-uid child.
const u104SockEnv = "K3SM_U104_SOCK"

// U104, root-run: install's keystore step makes keystore-sock/ root:wheel
// 0755 in a data root of root's in another group (staff), with a real
// chown; with a root-owned socket at keys.sock (as
// launchd makes it), a process running as the service uid cannot unlink it
// or rename a socket of its own over it, and once the name is gone (the
// server not running) it cannot bind one there either: each gets EACCES.
// Non-root it skips, and the root-run row fails on a SKIP. It binds a real
// socket and runs as root, so it is in the integration tier, which --root
// builds with -tags integration. It runs install's keystore step with the
// real euid source and file-attribute writer, which TestMain replaces with
// stubs that panic.
func TestSocketDirRootOwnedServiceUIDCannotBind(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-run (U104): run as root through hack/acceptance/keystore.sh --root")
	}
	uid, gid := instServiceIDs(t)
	setSeam(t, &euidSeam, os.Geteuid)
	setSeam[fileAttrWriter](t, &fileAttrSeam, realFileAttrWriter{})
	// A short base: a unix socket path is at most 104 bytes.
	base, err := os.MkdirTemp("/private/tmp", "k3sm-u104-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
		_ = os.RemoveAll(base)
	})
	root := filepath.Join(base, "data")
	own := filepath.Join(base, "own")
	for _, d := range []string{base, root, own} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(d, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(own, uid, gid); err != nil {
		t.Fatal(err)
	}
	// BSD mkdir would hand keystore-sock/ this group; install chowns the
	// directory it creates to wheel.
	if err := os.Chown(root, 0, 20); err != nil {
		t.Fatal(err)
	}
	if err := ensureKeystoreFiles(root, uid, gid, 0); err != nil {
		t.Fatalf("the keystore step: %v", err)
	}
	var st unix.Stat_t
	dir := filepath.Join(root, keystorepaths.SockDir)
	if err := unix.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o755 || st.Uid != 0 || st.Gid != 0 {
		t.Fatalf("keystore-sock/: mode %#o owner %d:%d, want a root:wheel 0755 directory", st.Mode, st.Uid, st.Gid)
	}
	sock := keystorepaths.SocketPath(root)
	ln, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(ln) }() // the stand-in for launchd's socket
	if err := unix.Bind(ln, &unix.SockaddrUnix{Name: sock}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(ln, 8); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, KeystoreSocketMode); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(base, "install.test")
	copyTestBinary(t, bin)
	child := func(phase string) {
		t.Helper()
		cmd := exec.Command(bin, "-test.run=^TestU104ServiceUIDChild$", "-test.v", "-test.count=1")
		cmd.Dir = own
		cmd.Env = append(os.Environ(), u104SockEnv+"="+sock, "K3SM_U104_PHASE="+phase, "K3SM_U104_OWN="+own)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		out, err := cmd.CombinedOutput()
		t.Logf("child as uid %d (%s):\n%s", uid, phase, out)
		if err != nil {
			t.Fatalf("as the service user (%s): %v", phase, err)
		}
	}
	child("present")
	if err := unix.Lstat(sock, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 {
		t.Fatalf("keys.sock after the child: %+v, %v; want root's socket still there", st, err)
	}
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	child("absent")
	if _, err := os.Lstat(sock); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("keys.sock after the bind attempt: %v; want nothing", err)
	}
}

// TestU104ServiceUIDChild is TestSocketDirRootOwnedServiceUIDCannotBind's
// child, run as the service user; it skips unless that test started it.
func TestU104ServiceUIDChild(t *testing.T) {
	sock := os.Getenv(u104SockEnv)
	if sock == "" {
		t.Skip("the child of TestSocketDirRootOwnedServiceUIDCannotBind")
	}
	bind := func(path string) error {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(fd) }() // a probe
		return unix.Bind(fd, &unix.SockaddrUnix{Name: path})
	}
	switch os.Getenv("K3SM_U104_PHASE") {
	case "present":
		if err := unix.Unlink(sock); !errors.Is(err, unix.EACCES) {
			t.Errorf("unlink keys.sock: %v, want EACCES", err)
		}
		mine := filepath.Join(os.Getenv("K3SM_U104_OWN"), "mine.sock")
		if err := bind(mine); err != nil {
			t.Fatal(err)
		}
		if err := unix.Rename(mine, sock); !errors.Is(err, unix.EACCES) {
			t.Errorf("rename a socket over keys.sock: %v, want EACCES", err)
		}
	case "absent":
		if err := bind(sock); !errors.Is(err, unix.EACCES) {
			t.Errorf("bind keys.sock: %v, want EACCES", err)
		}
	default:
		t.Fatal("no phase")
	}
}

// copyTestBinary copies this test binary to dst, 0755, so the service-uid
// child can run it from a directory it can reach.
func copyTestBinary(t *testing.T, dst string) {
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
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
