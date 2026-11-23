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
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// The root-run half of install's log creation (docs/design/keystore.md §
// "The swap", install's procedure; row U90): run as root with the real
// file-attribute writer and SF_APPEND set for real; non-root it skips, and
// the root-run row fails on a SKIP. Every failure names the step, the
// operation, the errno and the error install returned.

// instRoot is the fixture: a root-owned 0755 data root, the service user,
// root's descriptor on the data root and on a directory the service user
// owns, on the same volume, into which its probes try to link.
type instRoot struct {
	t       *testing.T
	root    string
	dfd     int
	own     int
	svcUID  int
	svcGID  int
	links   int
	preGate int
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

func newInstRoot(t *testing.T) *instRoot {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root-run (U90): run as root through hack/acceptance/keystore.sh --root")
	}
	r := &instRoot{t: t, dfd: -1, own: -1, preGate: -1}
	r.svcUID, r.svcGID = instServiceIDs(t)
	base := t.TempDir()
	r.root = filepath.Join(base, "data")
	own := filepath.Join(base, "service-own")
	for _, d := range []string{r.root, own} {
		if err := os.Mkdir(d, 0o755); err != nil {
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
		_ = os.Chmod(filepath.Join(r.root, keystore.LogsDirName), 0o755)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type()&fs.ModeSymlink == 0 {
				_ = unix.Chflags(p, 0)
			}
			return nil
		})
	})
	var err error
	if r.dfd, err = unix.Open(r.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		t.Fatal(err)
	}
	if r.own, err = unix.Open(own, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(r.dfd)
		_ = unix.Close(r.own)
		if r.preGate >= 0 {
			_ = unix.Close(r.preGate)
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

// instTargets are the names the service user attacks: both logs in
// keystore-logs/ and in keystore-staging/.
var instTargets = func() [][2]string {
	var out [][2]string
	for _, d := range []string{keystore.LogsDirName, keystore.StagingDirName} {
		for _, n := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
			out = append(out, [2]string{d, n})
		}
	}
	return out
}()

// want is the errno the service user's attempt on dir/name must fail
// with as root sees the tree now: ENOENT for an absent directory or name,
// EACCES behind a directory closed to it, EPERM on a flagged file; 0, with
// the reason, for an unflagged file it can reach.
func (r *instRoot) want(dir, name string) (unix.Errno, string) {
	var dst, st unix.Stat_t
	if err := unix.Fstatat(r.dfd, dir, &dst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.ENOENT, dir + " absent"
	}
	if dst.Mode&0o001 == 0 {
		return unix.EACCES, fmt.Sprintf("%s mode %04o", dir, dst.Mode&0o7777)
	}
	if err := unix.Fstatat(r.dfd, dir+"/"+name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unix.ENOENT, fmt.Sprintf("%s mode %04o, %s absent", dir, dst.Mode&0o7777, name)
	}
	state := fmt.Sprintf("%s mode %04o; %s uid %d mode %04o flags %#x nlink %d", dir, dst.Mode&0o7777, name, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	if st.Flags&unix.SF_APPEND != 0 {
		return unix.EPERM, state
	}
	return 0, state + ": an unflagged log the service user can reach"
}

// probeAll makes the service user try open(O_WRONLY), open(O_WRONLY|O_TRUNC)
// and link() into its own directory on every target, through the data
// root and, for keystore-logs/, through the descriptor it opened while the
// gate was open; it returns each attempt that succeeded, failed with
// another errno, or changed a byte.
func (r *instRoot) probeAll(at string) []string {
	var out []string
	if r.preGate < 0 {
		var dst unix.Stat_t
		if unix.Fstatat(r.dfd, keystore.LogsDirName, &dst, 0) == nil && dst.Mode&0o7777 == 0o755 {
			_ = r.asService(func() error {
				fd, err := unix.Openat(r.dfd, keystore.LogsDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err == nil {
					r.preGate = fd
				}
				return err
			})
		}
	}
	for _, tg := range instTargets {
		dir, name := tg[0], tg[1]
		before, _ := os.ReadFile(filepath.Join(r.root, dir, name))
		type route struct {
			how   string
			dirfd int
			path  string
		}
		routes := []route{{"through the data root", r.dfd, dir + "/" + name}}
		if dir == keystore.LogsDirName && r.preGate >= 0 {
			routes = append(routes, route{"through the descriptor on keystore-logs/ opened before the gate closed", r.preGate, name})
		}
		for _, rt := range routes {
			for _, op := range []string{"open(O_WRONLY)", "open(O_WRONLY|O_TRUNC)", "link()"} {
				want, state := r.want(dir, name)
				err := r.asService(func() error {
					switch op {
					case "link()":
						r.links++
						return unix.Linkat(rt.dirfd, rt.path, r.own, fmt.Sprintf("alias-%d", r.links), 0)
					default:
						flag := unix.O_WRONLY
						if op == "open(O_WRONLY|O_TRUNC)" {
							flag |= unix.O_TRUNC
						}
						fd, err := unix.Openat(rt.dirfd, rt.path, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
						if err == nil {
							_ = unix.Close(fd)
						}
						return err
					}
				})
				var got unix.Errno
				switch {
				case err == nil:
					out = append(out, fmt.Sprintf("%s: the service user's %s of %s/%s %s SUCCEEDED; want %v (state: %s)", at, op, dir, name, rt.how, want, state))
				case !errors.As(err, &got):
					out = append(out, fmt.Sprintf("%s: the service user's %s of %s/%s %s: %v (state: %s)", at, op, dir, name, rt.how, err, state))
				case want == 0 || got != want:
					out = append(out, fmt.Sprintf("%s: the service user's %s of %s/%s %s: errno %d (%v), want %d (%v) (state: %s)", at, op, dir, name, rt.how, int(got), got, int(want), want, state))
				}
			}
		}
		if after, _ := os.ReadFile(filepath.Join(r.root, dir, name)); string(after) != string(before) {
			out = append(out, fmt.Sprintf("%s: the service user's attempts changed %s/%s: %q, was %q", at, dir, name, after, before))
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

// checkDone checks what a finished keystore step leaves: both logs the
// service user's 0600, SF_APPEND alone, one link; the gate open; no
// staging directory.
func (r *instRoot) checkDone(what string, err error) {
	r.t.Helper()
	for _, n := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		var st unix.Stat_t
		if serr := unix.Fstatat(r.dfd, keystore.LogsDirName+"/"+n, &st, unix.AT_SYMLINK_NOFOLLOW); serr != nil {
			r.t.Errorf("%s: stat %s: %v (install: %v)", what, n, serr, err)
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != r.svcUID || st.Mode&0o7777 != 0o600 || st.Flags != unix.SF_APPEND {
			r.t.Errorf("%s: %s is uid %d mode %04o flags %#x nlink %d; want the service user's 0600, SF_APPEND alone, one link (install: %v)", what, n, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink, err)
		}
	}
	var dst unix.Stat_t
	if serr := unix.Fstatat(r.dfd, keystore.LogsDirName, &dst, 0); serr != nil || dst.Mode&0o7777 != 0o755 {
		r.t.Errorf("%s: %s mode %04o (%v); want the gate open (install: %v)", what, keystore.LogsDirName, dst.Mode&0o7777, serr, err)
	}
	if serr := unix.Fstatat(r.dfd, keystore.StagingDirName, &dst, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(serr, unix.ENOENT) {
		r.t.Errorf("%s: %s left: %v (install: %v)", what, keystore.StagingDirName, serr, err)
	}
}

// TestKeystoreLogCreationRefusesServiceUserAtEveryStep is install's half
// of U90, root-run: before every step of the keystore step (each attribute
// call and each step the step seam names: create, rename, fsync) and
// after, the service user's open(O_WRONLY), open(O_WRONLY|O_TRUNC) and
// link() into its own directory of each log, in keystore-logs/ and in
// keystore-staging/, through the data root and through a descriptor on
// keystore-logs/ opened while the gate was open, each fail with the errno
// the state gives (EACCES, EPERM or ENOENT), and no byte changes. Both
// logs end judged with one link and the gate open. Install stopped at each
// hook point in turn and rerun ends the same way.
func TestKeystoreLogCreationRefusesServiceUserAtEveryStep(t *testing.T) {
	var labels []string
	t.Run("every step", func(t *testing.T) {
		r := newInstRoot(t)
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
		t.Run(fmt.Sprintf("crash at hook %d", i), func(t *testing.T) {
			r := newInstRoot(t)
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
