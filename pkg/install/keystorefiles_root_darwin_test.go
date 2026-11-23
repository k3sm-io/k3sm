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
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// The root-run half of install's log creation (docs/design/keystore.md §
// "The swap", install's procedure; row U90): run as root with the real
// file-attribute writer and SF_APPEND set for real; non-root it skips, and
// the root-run row fails on a SKIP. Every failure names the hook, the
// operation, the route, the errno got and wanted, and the error install
// returned.

// instAttack is what the service user writes through a descriptor it
// should not be able to write through; it must never reach a live log.
const instAttack = "HELD-DESCRIPTOR-WRITE\n"

// instFloorData is the existing floor log's content in the fixture that
// has one.
const instFloorData = "an existing floor line\n"

// instRoot is the fixture: a root-owned 0755 data root holding
// keystore-logs/ (root's 0755) and, when existing, keystore-logs/floor/
// with a judged floor log; the service user, holding from before install
// a descriptor on keystore-logs/ and, when existing, one on floor/ and an
// O_APPEND one on the floor log; root's descriptor on the data root and
// on a directory the service user owns, on the same volume, into which its
// probes try to link.
type instRoot struct {
	t        *testing.T
	root     string
	dfd      int
	own      int
	svcUID   int
	svcGID   int
	links    int
	existing bool
	// The service user's held descriptors, -1 when not held.
	heldLogs, heldDir, heldLog int
	floorIno                   uint64
}

// instServiceIDs is the service user the root run uses: K3SM_KEYSTORE_TEST_UID
// and K3SM_KEYSTORE_TEST_GID, or the local user _k3sm; with neither the
// test skips.
func instServiceIDs(t *testing.T) (int, int) {
	t.Helper()
	u, uok := os.LookupEnv("K3SM_KEYSTORE_TEST_UID")
	g, gok := os.LookupEnv("K3SM_KEYSTORE_TEST_GID")
	if !uok || !gok {
		su, err := user.Lookup("_k3sm")
		if err != nil {
			t.Skipf("root-run needs a service user: set K3SM_KEYSTORE_TEST_UID and K3SM_KEYSTORE_TEST_GID, or create _k3sm (%v)", err)
		}
		u, g = su.Uid, su.Gid
	}
	uid, err := strconv.Atoi(u)
	if err != nil || uid == 0 {
		t.Fatalf("the service uid %q is not a non-zero number", u)
	}
	gid, err := strconv.Atoi(g)
	if err != nil {
		t.Fatalf("the service gid %q is not a number", g)
	}
	return uid, gid
}

func newInstRoot(t *testing.T, existing bool) *instRoot {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-run (U90): run as root through hack/acceptance/keystore.sh --root")
	}
	r := &instRoot{t: t, dfd: -1, own: -1, existing: existing, heldLogs: -1, heldDir: -1, heldLog: -1}
	r.svcUID, r.svcGID = instServiceIDs(t)
	base := t.TempDir()
	r.root = filepath.Join(base, "data")
	own := filepath.Join(base, "service-own")
	for _, d := range []string{r.root, own, filepath.Join(r.root, keystore.LogsDirName)} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(own, r.svcUID, r.svcGID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
	})
	if existing {
		d := filepath.Join(r.root, keystore.LogsDirName, keystore.FloorDirName)
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(d, keystore.UserFloorLogName)
		if err := os.WriteFile(p, []byte(instFloorData), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, r.svcUID, r.svcGID); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := unix.Chflags(p, unix.SF_APPEND); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatal(err)
		}
		r.floorIno = st.Ino
	}
	var err error
	if r.dfd, err = unix.Open(r.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		t.Fatal(err)
	}
	if r.own, err = unix.Open(own, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		t.Fatal(err)
	}
	err = r.asService(func() error {
		dirFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		var err error
		if r.heldLogs, err = unix.Openat(r.dfd, keystore.LogsDirName, dirFlags, 0); err != nil {
			return err
		}
		if !existing {
			return nil
		}
		if r.heldDir, err = unix.Openat(r.heldLogs, keystore.FloorDirName, dirFlags, 0); err != nil {
			return err
		}
		r.heldLog, err = unix.Openat(r.heldDir, keystore.UserFloorLogName, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return err
	})
	if err != nil {
		t.Fatalf("the service user cannot take its descriptors before install: %v", err)
	}
	t.Cleanup(func() {
		for _, fd := range []int{r.dfd, r.own, r.heldLogs, r.heldDir, r.heldLog} {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	})
	setSeam(t, &euidSeam, func() int { return 0 })
	return r
}

// asService runs probe on a fresh OS thread that has taken the service
// user's identity (settid); the thread is never handed back.
func (r *instRoot) asService(probe func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(r.svcUID), uintptr(r.svcGID), 0); errno != 0 {
			errc <- fmt.Errorf("settid to the service user: %w", errno)
			return
		}
		errc <- probe()
	}()
	return <-errc
}

// instLogs are the two logs, with their paths from keystore-logs/.
var instLogs = []string{keystore.UserFloorLogName, keystore.AuditLogName}

func instRel(name string) string { return filepath.Join(keystore.LogDirOf(name), name) }

// instWant is the errno the service user's attempt on path under dirfd
// wants, as root reads the same path through the same descriptor: ENOENT
// for an absent name, EACCES when a directory on the way is closed to it
// (keystore-staging/), EPERM on a flagged file, and 0, with the reason, for
// an unflagged file it can reach.
func (r *instRoot) instWant(dirfd int, path string) (unix.Errno, string) {
	if first, _, ok := strings.Cut(path, "/"); ok && first == keystore.StagingDirName {
		var dst unix.Stat_t
		if err := unix.Fstatat(dirfd, first, &dst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return unix.ENOENT, first + " absent"
		}
		if dst.Mode&0o001 == 0 {
			return unix.EACCES, fmt.Sprintf("%s mode %04o", first, dst.Mode&0o7777)
		}
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, path, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		var e unix.Errno
		if errors.As(err, &e) {
			return e, fmt.Sprintf("root's fstatat: %v", e)
		}
		return unix.ENOENT, err.Error()
	}
	state := fmt.Sprintf("uid %d mode %04o flags %#x nlink %d", st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	if st.Flags&unix.SF_APPEND != 0 {
		return unix.EPERM, state
	}
	return 0, state + ": an unflagged log the service user can reach"
}

// expect returns a failure line unless err is the errno want (0: success).
func instExpect(at, op, route string, err error, want unix.Errno, state string) []string {
	var got unix.Errno
	switch {
	case err == nil && want == 0:
		return nil
	case err == nil:
		return []string{fmt.Sprintf("%s: the service user's %s %s SUCCEEDED; want errno %d (%v) (state: %s)", at, op, route, int(want), want, state)}
	case !errors.As(err, &got):
		return []string{fmt.Sprintf("%s: the service user's %s %s: %v, not an errno; want %d (%v) (state: %s)", at, op, route, err, int(want), want, state)}
	case got != want || want == 0:
		return []string{fmt.Sprintf("%s: the service user's %s %s: errno %d (%v), want %d (%v) (state: %s)", at, op, route, int(got), got, int(want), want, state)}
	}
	return nil
}

// probeAll is one hook's attempts and checks: each canonical log that
// exists judged (the service user's 0600, SF_APPEND alone, one link,
// empty when install made it, the floor's old content when it was
// there); by path, open(O_WRONLY), open(O_WRONLY|O_TRUNC) and link() into
// its own directory of each log, in keystore-logs/ and in staging; through
// the held descriptor on keystore-logs/ openat of each log for write; and,
// with the existing floor, F_SETFL clearing O_APPEND, pwrite and ftruncate
// through the held floor descriptor and openat through the held floor/
// descriptor. It returns every failure.
func (r *instRoot) probeAll(at string) []string {
	out := r.checkLogs(at + ", before the attempts")
	for _, n := range instLogs {
		paths := []string{
			filepath.Join(keystore.LogsDirName, instRel(n)),
			filepath.Join(keystore.StagingDirName, keystore.LogDirOf(n)+".new", n),
		}
		for _, p := range paths {
			for _, op := range []string{"open(O_WRONLY)", "open(O_WRONLY|O_TRUNC)", "link()"} {
				want, state := r.instWant(r.dfd, p)
				err := r.asService(func() error {
					if op == "link()" {
						r.links++
						return unix.Linkat(r.dfd, p, r.own, fmt.Sprintf("alias-%d", r.links), 0)
					}
					flag := unix.O_WRONLY
					if op == "open(O_WRONLY|O_TRUNC)" {
						flag |= unix.O_TRUNC
					}
					fd, err := unix.Openat(r.dfd, p, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
					if err == nil {
						_ = unix.Close(fd)
					}
					return err
				})
				out = append(out, instExpect(at, op, "by path "+p+" through the data root", err, want, state)...)
			}
		}
		out = append(out, r.openHeld(at, r.heldLogs, instRel(n), "through the descriptor held on "+keystore.LogsDirName+"/")...)
	}
	if r.existing {
		out = append(out, r.openHeld(at, r.heldDir, keystore.UserFloorLogName, "through the descriptor held on "+keystore.FloorDirName+"/")...)
		var fst unix.Stat_t
		if err := unix.Fstat(r.heldLog, &fst); err != nil {
			out = append(out, fmt.Sprintf("%s: fstat the held floor descriptor: %v", at, err))
		} else {
			route := fmt.Sprintf("through the O_APPEND descriptor held on the floor log (flags %#x)", fst.Flags)
			err := r.asService(func() error {
				fl, err := unix.FcntlInt(uintptr(r.heldLog), unix.F_GETFL, 0)
				if err != nil {
					return err
				}
				_, err = unix.FcntlInt(uintptr(r.heldLog), unix.F_SETFL, fl&^unix.O_APPEND)
				return err
			})
			// Flagged, the F_SETFL clearing O_APPEND is EPERM too
			// (keystore's TestAppendOnlyFlagHoldsAsRoot).
			out = append(out, instExpect(at, "fcntl(F_SETFL) clearing O_APPEND", route, err, unix.EPERM, "")...)
			err = r.asService(func() error {
				_, err := unix.Pwrite(r.heldLog, []byte(instAttack), 0)
				return err
			})
			out = append(out, instExpect(at, "pwrite at offset 0", route, err, unix.EPERM, "")...)
			err = r.asService(func() error { return unix.Ftruncate(r.heldLog, 0) })
			out = append(out, instExpect(at, "ftruncate to 0", route, err, unix.EPERM, "")...)
		}
	}
	return append(out, r.checkLogs(at+", after the attempts")...)
}

// openHeld is the service user's openat(O_WRONLY) and pwrite of path
// through the held directory descriptor dirfd.
func (r *instRoot) openHeld(at string, dirfd int, path, route string) []string {
	want, state := r.instWant(dirfd, path)
	err := r.asService(func() error {
		fd, err := unix.Openat(dirfd, path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(fd) }()
		_, err = unix.Pwrite(fd, []byte(instAttack), 0)
		return err
	})
	return instExpect(at, "openat(O_WRONLY) and pwrite of "+path, route, err, want, state)
}

// checkLogs judges each canonical log present by path: a regular file,
// the service user's 0600, SF_APPEND alone, one link, holding nothing (a
// log install made) or the existing floor's content, the same inode.
func (r *instRoot) checkLogs(at string) []string {
	var out []string
	for _, n := range instLogs {
		p := filepath.Join(r.root, keystore.LogsDirName, instRel(n))
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); errors.Is(err, unix.ENOENT) {
			if r.existing && n == keystore.UserFloorLogName {
				out = append(out, fmt.Sprintf("%s: the existing floor log is gone", at))
			}
			continue
		} else if err != nil {
			out = append(out, fmt.Sprintf("%s: lstat %s: %v", at, instRel(n), err))
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != r.svcUID || st.Mode&0o7777 != 0o600 || st.Flags != unix.SF_APPEND {
			out = append(out, fmt.Sprintf("%s: %s is type %#o uid %d mode %04o flags %#x nlink %d; want the service user's 0600, SF_APPEND alone, one link", at, instRel(n), st.Mode&unix.S_IFMT, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink))
		}
		b, err := os.ReadFile(p)
		want := ""
		if r.existing && n == keystore.UserFloorLogName {
			want = instFloorData
			if st.Ino != r.floorIno {
				out = append(out, fmt.Sprintf("%s: the existing floor log is inode %d, was %d", at, st.Ino, r.floorIno))
			}
		}
		if err != nil || string(b) != want {
			out = append(out, fmt.Sprintf("%s: %s holds %q (%v); want %q", at, instRel(n), b, err, want))
		}
	}
	return out
}

// instProbeAttrs is the real file-attribute writer and step seam with a
// hook before each call and step.
type instProbeAttrs struct {
	before func(label string) error
}

func (p *instProbeAttrs) hook(label string) error {
	if p.before == nil {
		return nil
	}
	return p.before(label)
}

func (p *instProbeAttrs) Fchown(fd, uid, gid int) error {
	if err := p.hook(fmt.Sprintf("before fchown(%d) of %s", uid, fdName(fd))); err != nil {
		return err
	}
	return unix.Fchown(fd, uid, gid)
}

func (p *instProbeAttrs) Fchmod(fd int, mode uint32) error {
	if err := p.hook(fmt.Sprintf("before fchmod(%#o) of %s", mode, fdName(fd))); err != nil {
		return err
	}
	return unix.Fchmod(fd, mode)
}

func (p *instProbeAttrs) Fchflags(fd, flags int) error {
	if err := p.hook(fmt.Sprintf("before fchflags(%#x) of %s", flags, fdName(fd))); err != nil {
		return err
	}
	return unix.Fchflags(fd, flags)
}

func (p *instProbeAttrs) BeforeSwapStep(step string) error {
	return p.hook("before the step " + step)
}

// run runs the keystore step with probes at every hook point, crashing at
// the crashAt-th (from 0) when crashAt >= 0, and returns the hook labels,
// the probe failures and install's error.
func (r *instRoot) run(crashAt int) ([]string, []string, error) {
	var labels, fails []string
	fails = append(fails, r.probeAll("before install")...)
	p := &instProbeAttrs{before: func(label string) error {
		n := len(labels)
		labels = append(labels, label)
		fails = append(fails, r.probeAll(fmt.Sprintf("hook %d (%s)", n, label))...)
		if n == crashAt {
			return errors.New("crashed here (the test's hook)")
		}
		return nil
	}}
	old := fileAttrSeam
	fileAttrSeam = p
	err := ensureKeystoreFiles(r.root, r.svcUID, r.svcGID, 0)
	fileAttrSeam = old
	fails = append(fails, r.probeAll("after install")...)
	return labels, fails, err
}

// checkDone checks what a finished keystore step leaves: both logs judged
// (checkLogs) and present, and no staging directory.
func (r *instRoot) checkDone(what string, err error) {
	r.t.Helper()
	for _, f := range r.checkLogs(what) {
		r.t.Errorf("%s (install: %v)", f, err)
	}
	for _, n := range instLogs {
		if _, serr := os.Lstat(filepath.Join(r.root, keystore.LogsDirName, instRel(n))); serr != nil {
			r.t.Errorf("%s: %s missing: %v (install: %v)", what, instRel(n), serr, err)
		}
	}
	var dst unix.Stat_t
	if serr := unix.Fstatat(r.dfd, keystore.StagingDirName, &dst, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(serr, unix.ENOENT) {
		r.t.Errorf("%s: %s left: %v (install: %v)", what, keystore.StagingDirName, serr, err)
	}
}

// TestKeystoreLogCreationRefusesServiceUserAtEveryStep is install's half
// of U90, root-run: install creates each missing log's directory in
// keystore-staging/, its log flagged before it is reachable, and places it
// with RENAME_EXCL. With no log present, and with the floor log present
// (the service user then holding an O_APPEND descriptor on it and one on
// floor/), and a descriptor on keystore-logs/ held from before install,
// before every hook point (each attribute call and each step: create,
// rename, fsync) and after, the service user's open(O_WRONLY),
// open(O_WRONLY|O_TRUNC) and link() into its own directory of each log,
// in keystore-logs/ and in staging, its openat for write through each held
// directory descriptor, and F_SETFL clearing O_APPEND then pwrite and
// ftruncate through the held log descriptor, each fail with the errno the
// state gives (EACCES behind staging, EPERM on a flagged file, ENOENT on
// an absent name). Every log present at a hook is judged and holds what it
// should. Install stopped at each hook point in turn and rerun ends with
// both logs judged and no staging directory.
func TestKeystoreLogCreationRefusesServiceUserAtEveryStep(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "no log"
		if existing {
			name = "the floor log present"
		}
		var labels []string
		t.Run(name+"/every step", func(t *testing.T) {
			r := newInstRoot(t, existing)
			l, fails, err := r.run(-1)
			for _, f := range fails {
				t.Errorf("%s (install: %v)", f, err)
			}
			if err != nil {
				t.Fatalf("install: %v; hooks: %v", err, l)
			}
			r.checkDone("install", err)
			labels = l
		})
		for i := range labels {
			t.Run(fmt.Sprintf("%s/crash at hook %d", name, i), func(t *testing.T) {
				r := newInstRoot(t, existing)
				l, fails, err := r.run(i)
				for _, f := range fails {
					t.Errorf("crash at hook %d: %s (install: %v)", i, f, err)
				}
				if err == nil {
					t.Fatalf("install crashed at hook %d (%s) reported success; hooks: %v", i, labels[i], l)
				}
				_, fails, rerr := r.run(-1)
				for _, f := range fails {
					t.Errorf("the rerun after a crash at hook %d (%s): %s (install: %v)", i, labels[i], f, rerr)
				}
				if rerr != nil {
					t.Fatalf("the rerun after a crash at hook %d (%s): %v; the crashed run: %v", i, labels[i], rerr, err)
				}
				r.checkDone(fmt.Sprintf("the rerun after a crash at hook %d (%s)", i, labels[i]), rerr)
			})
		}
	}
}
