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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// The root-run rows of the maintenance verbs floor --rebuild and audit
// --rotate (docs/design/keystore.md § "The swap"): U68, U90 and U118. Each
// runs only as root, through hack/acceptance/keystore.sh --root, with the
// real file-attribute writer and SF_APPEND set for real; non-root it skips,
// and the root-run row fails on a SKIP. Every failure names the step, the
// operation, the route, the errno got and wanted, and the verb's exit code
// and full stderr, so a root run's log alone says what went wrong.

// keysSFAppend is SF_APPEND, the system append-only file flag.
const keysSFAppend = 0x00040000

// The names the verbs use in the data root.
const (
	keysMarkerName = keystore.MaintenanceMarkerName
	keysStagingDir = keystore.StagingDirName
	keysLogsDir    = keystore.LogsDirName
)

// keysAttack is what the service user writes through a descriptor it
// should not be able to write through; it must never reach a live log.
const keysAttack = "HELD-DESCRIPTOR-WRITE\n"

// keysFloorGarbage is a line of the old floor that does not parse: the
// rebuild drops it and exits 4, listing it.
const keysFloorGarbage = "not a floor line\n"

// keysMaintVerb is one maintenance verb: its arguments, the log it swaps
// and the exit code its uncrashed run gives on the fixture (the fixture's
// floor holds a line that does not parse, so the rebuild exits 4).
type keysMaintVerb struct {
	name string
	args []string
	log  string
	code int
}

// dir is the log's directory in keystore-logs/.
func (v keysMaintVerb) dir() string { return keystore.LogDirOf(v.log) }

// rel is the canonical log's path from the data root.
func (v keysMaintVerb) rel() string { return filepath.Join(keysLogsDir, v.dir(), v.log) }

var keysMaintVerbs = []keysMaintVerb{
	{"floor-rebuild", []string{"floor", "--rebuild"}, keystore.UserFloorLogName, keysCommitted},
	{"audit-rotate", []string{"audit", "--rotate"}, keystore.AuditLogName, keysOK},
}

// other is the other maintenance verb.
func (v keysMaintVerb) other() keysMaintVerb {
	if v.log == keystore.UserFloorLogName {
		return keysMaintVerbs[1]
	}
	return keysMaintVerbs[0]
}

// keysRootMaint is a root-run maintenance fixture: a harness whose store
// has an entry, its data root root's 0755 as deployed, keystore-logs/ and
// its floor/ and audit/ root's 0755, each holding its log, the service
// user's 0600 and flagged (the floor holding one line that does not
// parse, the audit log one line), and root's descriptors on the data root
// and on a directory the service user owns, on the same volume, into which
// its probes try to link.
type keysRootMaint struct {
	t      *testing.T
	h      *keysHarness
	root   string
	dfd    *os.File
	own    *os.File
	svcUID uint32
	svcGID uint32
	links  int
}

func keysMaintRoot(t *testing.T, row string) *keysRootMaint {
	t.Helper()
	if !keysAsRoot() {
		t.Skip("root-run (" + row + "): run as root through hack/acceptance/keystore.sh --root")
	}
	h := newKeysHarness(t)
	h.put("system/api-token", []byte("tok"))
	m := &keysRootMaint{t: t, h: h, root: h.cfg.DataRoot}
	m.svcUID, m.svcGID = keysServiceIDs(t)
	own := filepath.Join(filepath.Dir(m.root), "service-own")
	// Registered after the harness's temp dirs, so it runs before their
	// removal, which a flagged file would refuse.
	t.Cleanup(func() { keysUnflagAll(m.root); keysUnflagAll(own) })
	if err := os.Chmod(m.root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{keysLogsDir, filepath.Join(keysLogsDir, keystore.FloorDirName), filepath.Join(keysLogsDir, keystore.AuditDirName)} {
		p := filepath.Join(m.root, d)
		if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	m.placeLog(keystore.UserFloorLogName, keysFloorGarbage, true, true)
	m.placeLog(keystore.AuditLogName, "", true, true)
	// An audit line, so the audit log holds bytes the swap must keep.
	h.mustRun(keysOK, "list")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(own, int(m.svcUID), int(m.svcGID)); err != nil {
		t.Fatal(err)
	}
	var err error
	if m.dfd, err = os.Open(m.root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.dfd.Close() })
	if m.own, err = os.Open(own); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.own.Close() })
	h.attrs = realFileAttrWriter{}
	return m
}

// logPath is the log name's canonical path.
func (m *keysRootMaint) logPath(name string) string {
	return filepath.Join(m.root, keysLogsDir, keystore.LogDirOf(name), name)
}

// placeLog creates the log name in its directory holding data, mode 0600,
// the service user's when service and root's otherwise (owner first),
// flagged when flag (flag last).
func (m *keysRootMaint) placeLog(name, data string, service, flag bool) {
	m.t.Helper()
	p := m.logPath(name)
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		m.t.Fatal(err)
	}
	uid, gid := 0, 0
	if service {
		uid, gid = int(m.svcUID), int(m.svcGID)
	}
	if err := os.Chown(p, uid, gid); err != nil {
		m.t.Fatal(err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		m.t.Fatal(err)
	}
	if flag {
		if err := unix.Chflags(p, keysSFAppend); err != nil {
			m.t.Fatal(err)
		}
	}
}

// keysUnflagAll clears the flags of every file under root, so the tree
// can be removed.
func keysUnflagAll(root string) {
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink == 0 {
			_ = unix.Chflags(p, 0)
		}
		return nil
	})
}

// keysFileState is what a refusal must leave as it was: a name's type,
// owner, mode, flags, inode and link count, and a regular file's bytes or
// a symlink's target.
type keysFileState struct {
	typ, mode     uint16
	uid           uint32
	flags         uint32
	ino           uint64
	nlink         uint16
	data, symlink string
}

// snapshot is the state of every name under keystore-logs/, never
// following a symlink, and of the marker and keystore-staging/ in the data
// root, keyed by the path from the data root.
func (m *keysRootMaint) snapshot() map[string]keysFileState {
	m.t.Helper()
	out := map[string]keysFileState{}
	for _, n := range []string{keysMarkerName, keysStagingDir} {
		if _, err := os.Lstat(filepath.Join(m.root, n)); err == nil {
			out[n] = keysState(m.t, filepath.Join(m.root, n))
		}
	}
	_ = filepath.WalkDir(filepath.Join(m.root, keysLogsDir), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(m.root, p)
		out[rel] = keysState(m.t, p)
		return nil
	})
	return out
}

func keysState(t *testing.T, p string) keysFileState {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	s := keysFileState{typ: st.Mode & unix.S_IFMT, mode: st.Mode & 0o7777, uid: st.Uid, flags: st.Flags, ino: st.Ino, nlink: st.Nlink}
	switch s.typ {
	case unix.S_IFREG:
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s.data = string(b)
	case unix.S_IFLNK:
		l, err := os.Readlink(p)
		if err != nil {
			t.Fatal(err)
		}
		s.symlink = l
	}
	return s
}

// asService runs probe on a fresh OS thread that has taken the service
// user's identity (settid). The thread is never handed back: a goroutine
// that exits locked to its thread takes the thread with it, so no other
// goroutine runs as the service user.
func (m *keysRootMaint) asService(probe func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if _, _, errno := syscall.Syscall(syscall.SYS_SETTID, uintptr(m.svcUID), uintptr(m.svcGID), 0); errno != 0 {
			errc <- fmt.Errorf("settid to the service user %d:%d: %w", m.svcUID, m.svcGID, errno)
			return
		}
		errc <- probe()
	}()
	return <-errc
}

// keysHeld is what a process running as the service user holds from
// before the verb: an O_APPEND descriptor on the old log, a descriptor on
// the log's live directory, and one on keystore-logs/.
type keysHeld struct {
	log, dir, logs int
}

// hold opens v's held descriptors as the service user.
func (m *keysRootMaint) hold(v keysMaintVerb) keysHeld {
	m.t.Helper()
	h := keysHeld{log: -1, dir: -1, logs: -1}
	err := m.asService(func() error {
		var err error
		dirFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if h.logs, err = unix.Openat(int(m.dfd.Fd()), keysLogsDir, dirFlags, 0); err != nil {
			return fmt.Errorf("open %s: %w", keysLogsDir, err)
		}
		if h.dir, err = unix.Openat(h.logs, v.dir(), dirFlags, 0); err != nil {
			return fmt.Errorf("open %s/%s: %w", keysLogsDir, v.dir(), err)
		}
		if h.log, err = unix.Openat(h.dir, v.log, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); err != nil {
			return fmt.Errorf("open %s O_APPEND: %w", v.rel(), err)
		}
		return nil
	})
	if err != nil {
		m.t.Fatalf("the service user cannot take its descriptors before the verb: %v", err)
	}
	m.t.Cleanup(func() {
		for _, fd := range []int{h.log, h.dir, h.logs} {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		}
	})
	return h
}

// keysStepAttrs is the real file-attribute writer and the step seam: it
// records each attribute call and each step, and runs before before each
// step; an error from it fails the step, as a crash there would leave it.
type keysStepAttrs struct {
	t      *testing.T
	before func(step string) error
	events []keysAttrEvent
}

// keysAttrEvent is one attribute call, with the file's state just before
// it, or one step (call "step <name>").
type keysAttrEvent struct {
	call  string
	arg   int
	ino   uint64
	uid   uint32
	flags uint32
}

func (p *keysStepAttrs) do(call string, fd, arg int, f func() error) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		p.t.Errorf("fstat before %s: %v", call, err)
		return err
	}
	p.events = append(p.events, keysAttrEvent{call: call, arg: arg, ino: st.Ino, uid: st.Uid, flags: st.Flags})
	return f()
}

func (p *keysStepAttrs) Fchown(fd, uid, gid int) error {
	return p.do("fchown", fd, uid, func() error { return unix.Fchown(fd, uid, gid) })
}

func (p *keysStepAttrs) Fchmod(fd int, mode uint32) error {
	return p.do("fchmod", fd, int(mode), func() error { return unix.Fchmod(fd, mode) })
}

func (p *keysStepAttrs) Fchflags(fd, flags int) error {
	return p.do("fchflags", fd, flags, func() error { return unix.Fchflags(fd, flags) })
}

func (p *keysStepAttrs) BeforeSwapStep(step string) error {
	p.events = append(p.events, keysAttrEvent{call: "step " + step})
	if p.before != nil {
		return p.before(step)
	}
	return nil
}

// index is the position of the event call (on inode ino, when ino is not
// 0) in the events, or -1.
func (p *keysStepAttrs) index(call string, ino uint64) int {
	return slices.IndexFunc(p.events, func(e keysAttrEvent) bool {
		return e.call == call && (ino == 0 || e.ino == ino)
	})
}

// keysSwapRun is one probed run of a verb.
type keysSwapRun struct {
	m     *keysRootMaint
	v     keysMaintVerb
	held  keysHeld
	attrs *keysStepAttrs
	// oldIno and oldData are the canonical log before the verb.
	oldIno  uint64
	oldData string
	// newIno is the new log's inode once the marker names it, wrote its
	// content as root read it in staging at the swap step, and appended
	// what the service user appended to it legitimately.
	newIno   uint64
	wrote    string
	haveNew  bool
	appended []string
	// appendNew makes the service user append through O_APPEND to the new
	// canonical log at every hook after the swap.
	appendNew bool
	steps     []string
	crashed   string
	failures  []string
	code      int
	stdout    string
	stderr    string
}

func (r *keysSwapRun) failf(format string, args ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, args...))
}

// report fails the test with every failure the run's probes found, each
// with the verb's exit code and full stderr.
func (r *keysSwapRun) report(t *testing.T, what string) {
	t.Helper()
	for _, f := range r.failures {
		t.Errorf("%s: %s\nverb exit %d, stderr:\n%s", what, f, r.code, r.stderr)
	}
}

// runProbed runs v with the held descriptors and the probes before every
// step in keystore.SwapSteps and after the verb. crashAt, when not empty,
// makes that step fail, as a crash there would.
func (m *keysRootMaint) runProbed(v keysMaintVerb, crashAt string, appendNew bool) *keysSwapRun {
	m.t.Helper()
	st := keysState(m.t, m.logPath(v.log))
	r := &keysSwapRun{m: m, v: v, held: m.hold(v), oldIno: st.ino, oldData: st.data, appendNew: appendNew}
	r.attrs = &keysStepAttrs{t: m.t}
	r.attrs.before = func(step string) error {
		r.steps = append(r.steps, step)
		r.probe(step)
		if step == crashAt {
			r.crashed = step
			return errors.New("crashed here (the test's hook)")
		}
		return nil
	}
	m.h.attrs = r.attrs
	r.code = m.h.run(v.args...)
	r.stdout, r.stderr = m.h.stdout.String(), m.h.stderr.String()
	m.h.attrs = realFileAttrWriter{}
	r.probe("after the verb")
	if crashAt != "" && r.crashed == "" {
		r.failf("the step %s was never reached; steps reached: %v", crashAt, r.steps)
	}
	return r
}

// probe is one hook's work: the canonical log judged; at the swap step the
// staged log read; the service user's attacks, by path and through each
// held descriptor, each checked against the errno the tree's state wants;
// the legitimate append, when asked; and the canonical log judged again.
func (r *keysSwapRun) probe(step string) {
	at := "step " + step
	if step == "after the verb" {
		at = step
	}
	r.checkCanonical(at + ", before the attempts")
	if step == "swap" {
		r.readStaged(at)
	}
	r.byPath(at)
	r.throughHeld(at)
	if r.appendNew && step != "after the verb" && r.haveNew && r.liveIno() == r.newIno {
		line := fmt.Sprintf("appended through O_APPEND at %s\n", at)
		err := r.m.asService(func() error {
			fd, err := unix.Openat(int(r.m.dfd.Fd()), r.v.rel(), unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			_, err = unix.Write(fd, []byte(line))
			return err
		})
		if err != nil {
			r.failf("%s: open(O_WRONLY|O_APPEND) and write of %s by path: %v, want success", at, r.v.rel(), err)
		} else {
			r.appended = append(r.appended, line)
		}
	}
	r.checkCanonical(at + ", after the attempts")
}

// liveIno is the canonical log's inode now, or 0.
func (r *keysSwapRun) liveIno() uint64 {
	var st unix.Stat_t
	if unix.Lstat(r.m.logPath(r.v.log), &st) != nil {
		return 0
	}
	return st.Ino
}

// readStaged reads, as root, the new log the verb staged: what it wrote.
func (r *keysSwapRun) readStaged(at string) {
	p := filepath.Join(r.m.root, keysStagingDir, r.v.dir()+".new", r.v.log)
	b, err := os.ReadFile(p)
	if err != nil {
		r.failf("%s: read the staged %s as root: %v", at, p, err)
		return
	}
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		r.failf("%s: stat the staged %s: %v", at, p, err)
		return
	}
	r.newIno, r.wrote, r.haveNew = st.Ino, string(b), true
	if st.Flags != keysSFAppend || st.Uid != r.m.svcUID || st.Mode&0o7777 != 0o600 || st.Nlink != 1 {
		r.failf("%s: the staged %s is uid %d mode %04o flags %#x nlink %d before it is reachable; want the service user's 0600, SF_APPEND alone, one link", at, r.v.log, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	}
	if r.v.log == keystore.AuditLogName && r.wrote != "" {
		r.failf("%s: the staged audit log holds %q; want it empty", at, r.wrote)
	}
}

// checkCanonical judges the canonical log by path: a regular file, flags
// exactly SF_APPEND, the service user's, 0600, one link, and either the
// old log with its whole old content or the new one with what the verb
// wrote and the legitimate appends.
func (r *keysSwapRun) checkCanonical(at string) {
	p := r.m.logPath(r.v.log)
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		r.failf("%s: lstat the canonical %s: %v", at, r.v.rel(), err)
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Flags != keysSFAppend || st.Uid != r.m.svcUID || st.Mode&0o7777 != 0o600 || st.Nlink != 1 {
		r.failf("%s: the canonical %s is type %#o uid %d mode %04o flags %#x nlink %d; want a regular file, the service user's 0600, SF_APPEND alone, one link", at, r.v.rel(), st.Mode&unix.S_IFMT, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		r.failf("%s: read the canonical %s: %v", at, r.v.rel(), err)
		return
	}
	got := string(b)
	// After the verb, the audit log holds the verb's own audit line too,
	// in whichever log is live.
	if strings.HasPrefix(at, "after the verb") && r.v.log == keystore.AuditLogName {
		if i := strings.LastIndex(strings.TrimSuffix(got, "\n"), "\n"); strings.HasSuffix(got, "\n") {
			got = got[:i+1]
		}
	}
	if strings.Contains(got, keysAttack) {
		r.failf("%s: the canonical %s holds the held descriptors' write %q: %q", at, r.v.rel(), keysAttack, got)
	}
	switch {
	case st.Ino == r.oldIno:
		if got != r.oldData {
			r.failf("%s: the canonical %s is the old log holding %q; want its whole old content %q", at, r.v.rel(), got, r.oldData)
		}
	case r.haveNew && st.Ino == r.newIno:
		want := r.wrote + strings.Join(r.appended, "")
		if got != want {
			r.failf("%s: the canonical %s is the new log holding %q; want what the verb wrote %q and the service user's appends %q", at, r.v.rel(), got, r.wrote, r.appended)
		}
	default:
		r.failf("%s: the canonical %s is inode %d, neither the old log (%d) nor the staged new log (%d, seen %v)", at, r.v.rel(), st.Ino, r.oldIno, r.newIno, r.haveNew)
	}
}

// byPath is the service user's attempts on the canonical log by path:
// open(O_WRONLY), open(O_WRONLY|O_TRUNC), and link() into its own
// directory. Each must fail EPERM: the log is flagged at every step.
func (r *keysSwapRun) byPath(at string) {
	ops := []struct {
		name string
		do   func() error
	}{
		{"open(O_WRONLY)", func() error { return keysOpenWrite(int(r.m.dfd.Fd()), r.v.rel(), unix.O_WRONLY) }},
		{"open(O_WRONLY|O_TRUNC)", func() error {
			return keysOpenWrite(int(r.m.dfd.Fd()), r.v.rel(), unix.O_WRONLY|unix.O_TRUNC)
		}},
		{"link()", func() error {
			r.m.links++
			return unix.Linkat(int(r.m.dfd.Fd()), r.v.rel(), int(r.m.own.Fd()), fmt.Sprintf("alias-%d", r.m.links), 0)
		}},
	}
	for _, op := range ops {
		err := r.m.asService(op.do)
		r.expect(at, op.name, "by path through the data root on "+r.v.rel(), err, unix.EPERM)
	}
}

// throughHeld is the service user's attempts through the descriptors it
// held from before the verb: on the old log, F_SETFL clearing O_APPEND,
// then pwrite at offset 0 and ftruncate to 0 (each EPERM while it is
// flagged); on the live directory and on
// keystore-logs/, openat of the log for write. The errno each wants is
// what root reads of the file now: EPERM while it is flagged, success
// once the retired log is unflagged (it is no longer reachable by path
// then), ENOENT once its name is gone.
func (r *keysSwapRun) throughHeld(at string) {
	var fst unix.Stat_t
	if err := unix.Fstat(r.held.log, &fst); err != nil {
		r.failf("%s: fstat the held log descriptor: %v", at, err)
		return
	}
	flagged := fst.Flags&keysSFAppend != 0
	route := fmt.Sprintf("through the O_APPEND descriptor held on the old log (inode %d, flags %#x, nlink %d)", fst.Ino, fst.Flags, fst.Nlink)
	// While the file is flagged every write route is EPERM, the F_SETFL
	// clearing O_APPEND among them (TestAppendOnlyFlagHoldsAsRoot); once
	// the retired log is unflagged each succeeds (TestSappndDirectorySwap).
	want := unix.Errno(0)
	if flagged {
		want = unix.EPERM
	}
	err := r.m.asService(func() error {
		fl, err := unix.FcntlInt(uintptr(r.held.log), unix.F_GETFL, 0)
		if err != nil {
			return err
		}
		_, err = unix.FcntlInt(uintptr(r.held.log), unix.F_SETFL, fl&^unix.O_APPEND)
		return err
	})
	r.expect(at, "fcntl(F_SETFL) clearing O_APPEND", route, err, want)
	err = r.m.asService(func() error {
		_, err := unix.Pwrite(r.held.log, []byte(keysAttack), 0)
		return err
	})
	r.expect(at, "pwrite at offset 0", route, err, want)
	err = r.m.asService(func() error { return unix.Ftruncate(r.held.log, 0) })
	r.expect(at, "ftruncate to 0", route, err, want)

	for _, d := range []struct {
		name  string
		fd    int
		path  string
		route string
	}{
		{"live directory", r.held.dir, r.v.log, "openat through the descriptor held on the log's live directory " + r.v.dir() + "/"},
		{keysLogsDir, r.held.logs, filepath.Join(r.v.dir(), r.v.log), "openat through the descriptor held on " + keysLogsDir + "/"},
	} {
		want, state := keysWantOpenWrite(d.fd, d.path)
		err := r.m.asService(func() error {
			fd, err := unix.Openat(d.fd, d.path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(fd) }()
			_, err = unix.Pwrite(fd, []byte(keysAttack), 0)
			return err
		})
		r.expect(at, "openat(O_WRONLY) and pwrite of "+d.path, d.route+" ("+state+")", err, want)
	}
}

// expect records a failure unless err is the errno want (0: success).
func (r *keysSwapRun) expect(at, op, route string, err error, want unix.Errno) {
	var got unix.Errno
	switch {
	case err == nil && want == 0:
		return
	case err == nil:
		r.failf("%s: the service user's %s %s SUCCEEDED; want errno %d (%v)", at, op, route, int(want), want)
	case !errors.As(err, &got):
		r.failf("%s: the service user's %s %s: %v, not an errno; want errno %d (%v)", at, op, route, err, int(want), want)
	case got != want:
		r.failf("%s: the service user's %s %s: errno %d (%v), want %d (%v)", at, op, route, int(got), got, int(want), want)
	}
}

// keysOpenWrite opens path under dirfd with flag and closes it.
func keysOpenWrite(dirfd int, path string, flag int) error {
	fd, err := unix.Openat(dirfd, path, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

// keysWantOpenWrite is the errno the service user's openat(O_WRONLY) of
// path under dirfd wants, as root reads it through the same descriptor:
// ENOENT when the name is gone, EPERM when the file is flagged, success
// when it is the service user's and unflagged (the retired log after its
// flag is cleared), EACCES otherwise.
func keysWantOpenWrite(dirfd int, path string) (unix.Errno, string) {
	var st unix.Stat_t
	err := unix.Fstatat(dirfd, path, &st, unix.AT_SYMLINK_NOFOLLOW)
	var e unix.Errno
	if errors.As(err, &e) {
		return e, fmt.Sprintf("root's fstatat: %v", e)
	}
	state := fmt.Sprintf("inode %d uid %d mode %04o flags %#x nlink %d", st.Ino, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	switch {
	case st.Flags&keysSFAppend != 0:
		return unix.EPERM, state
	case st.Uid != 0:
		return 0, state
	}
	return unix.EACCES, state
}

// keysDirEmpty reports whether the directory open at fd lists nothing (a
// removed directory lists nothing too), reading a duplicate from its
// start.
func keysDirEmpty(fd int) (bool, []string) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return false, []string{err.Error()}
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer func() { _ = f.Close() }()
	if _, err := unix.Seek(dup, 0, io.SeekStart); err != nil {
		return false, []string{err.Error()}
	}
	names, err := f.Readdirnames(-1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, []string{err.Error()}
	}
	return len(names) == 0, names
}

// checkDone checks the state a finished swap of v leaves: the canonical
// log judged (the service user's 0600, SF_APPEND alone, one link, a new
// inode), no marker and no staging directory, and the retired directory,
// through the service user's held descriptor on it, empty.
func (r *keysSwapRun) checkDone(what string) {
	r.m.t.Helper()
	fail := func(format string, args ...any) {
		r.m.t.Errorf("%s: %s\nverb exit %d, stdout:\n%s\nstderr:\n%s", what, fmt.Sprintf(format, args...), r.code, r.stdout, r.stderr)
	}
	r.m.checkLive(r.v, what, r.code, r.stderr)
	if ino := r.liveIno(); ino == r.oldIno {
		fail("the canonical %s is still the old inode %d", r.v.rel(), ino)
	}
	if ok, names := keysDirEmpty(r.held.dir); !ok {
		fail("the retired %s/ (the service user's held descriptor on it) lists %v; want it empty", r.v.dir(), names)
	}
}

// checkLive checks that v's canonical log is judged and that no marker and
// no staging directory are left.
func (m *keysRootMaint) checkLive(v keysMaintVerb, what string, code int, stderr string) {
	m.t.Helper()
	fail := func(format string, args ...any) {
		m.t.Errorf("%s: %s\nverb exit %d, stderr:\n%s", what, fmt.Sprintf(format, args...), code, stderr)
	}
	var st unix.Stat_t
	if err := unix.Lstat(m.logPath(v.log), &st); err != nil {
		fail("stat the canonical %s: %v", v.rel(), err)
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != m.svcUID || st.Mode&0o7777 != 0o600 || st.Flags != keysSFAppend {
		fail("the canonical %s is uid %d mode %04o flags %#x nlink %d; want the service user's 0600, SF_APPEND alone, one link", v.rel(), st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	}
	for _, n := range []string{keysMarkerName, keysStagingDir} {
		if _, err := os.Lstat(filepath.Join(m.root, n)); !errors.Is(err, os.ErrNotExist) {
			fail("%s left: %v", n, err)
		}
	}
}

// checkArchives checks rotate's .1: root's 0600, unflagged, one link, a
// fresh inode, starting with old (the audit log's bytes before the run)
// and, when sole, no .2.
func (m *keysRootMaint) checkArchives(oldIno uint64, old string, sole bool, what, stderr string) {
	m.t.Helper()
	fail := func(format string, args ...any) {
		m.t.Errorf("%s: %s\nverb stderr:\n%s", what, fmt.Sprintf(format, args...), stderr)
	}
	p := filepath.Join(filepath.Dir(m.logPath(keystore.AuditLogName)), keystore.AuditLogName+".1")
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		fail("stat .1: %v", err)
		return
	}
	if st.Uid != 0 || st.Mode&0o7777 != 0o600 || st.Flags != 0 || st.Nlink != 1 || st.Ino == oldIno {
		fail(".1 is uid %d mode %04o flags %#x nlink %d inode %d (the old log's %d); want a fresh root 0600 unflagged copy with one link", st.Uid, st.Mode&0o7777, st.Flags, st.Nlink, st.Ino, oldIno)
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), old) || strings.Contains(string(b), keysAttack) {
		fail(".1 holds %q; want it to start with the old log's %q, and no held-descriptor write", b, old)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(p), keystore.AuditLogName+".2")); sole && !errors.Is(err, os.ErrNotExist) {
		fail("a second archive .2 exists: %v", err)
	}
}

// TestMaintenanceSwapRefusesServiceUser is U90, root-run: a process
// running as the service user holds, from before floor --rebuild or audit
// --rotate, an O_APPEND descriptor on the old log, a descriptor on the
// log's live directory and one on keystore-logs/. Before every step in
// keystore.SwapSteps and after the verb it tries, by path on the canonical
// log, open(O_WRONLY), open(O_WRONLY|O_TRUNC) and link() into its own
// directory (each EPERM), and through each held descriptor F_SETFL
// clearing O_APPEND, pwrite and ftruncate (EPERM while the file is
// flagged, success on the retired log once it is unflagged), and openat
// for write (EPERM while flagged, ENOENT once gone).
// At every hook the canonical log is a complete judged log: the old one
// with its whole content or the new one with what the verb wrote, flags
// exactly SF_APPEND, the service user's, 0600, one link. After the swap it
// appends through O_APPEND by path, which is kept. At the end the new log
// holds what the verb wrote and those appends and nothing the held
// descriptors did; staging is gone and the retired directory is empty.
func TestMaintenanceSwapRefusesServiceUser(t *testing.T) {
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U90")
			r := m.runProbed(v, "", true)
			r.report(t, v.name)
			if r.code != v.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, v.code, r.stdout, r.stderr)
			}
			if !slices.Equal(r.steps, keystore.SwapSteps) {
				t.Errorf("the steps reached are %v; want %v", r.steps, keystore.SwapSteps)
			}
			if len(r.appended) == 0 {
				t.Errorf("the service user's legitimate append to the new log never ran; steps %v", r.steps)
			}
			r.checkDone(v.name)
			if v.log == keystore.AuditLogName {
				m.checkArchives(r.oldIno, r.oldData, true, v.name, r.stderr)
			}
		})
	}
	t.Run("the wait for the store lock is bounded", func(t *testing.T) {
		m := keysMaintRoot(t, "U90")
		lock, err := os.Open(filepath.Join(m.h.keystoreDir(), ".lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
			t.Fatal(err)
		}
		before := m.snapshot()
		start := time.Now()
		// The store directly: the CLI's audit line would wait on the lock
		// too, after the verb.
		_, err = keystore.New(m.h.storeCfg).RotateAudit(context.Background(), realFileAttrWriter{}, false)
		if took := time.Since(start); err == nil || took < 30*time.Second || took > 40*time.Second {
			t.Errorf("audit --rotate under a held store lock: %v after %v, want a refusal after 30 s", err, took)
		}
		after := m.snapshot()
		for n, b := range before {
			if after[n] != b {
				t.Errorf("the timed-out rotate changed %s: %+v, was %+v", n, after[n], b)
			}
		}
		for _, n := range []string{keysMarkerName, keysStagingDir} {
			if _, err := os.Lstat(filepath.Join(m.root, n)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the timed-out rotate left %s: %v", n, err)
			}
		}
	})
}

// TestMaintenanceCrashAtEverySwapStepReruns is U90's crash half,
// root-run: floor --rebuild and audit --rotate stopped at each step in
// keystore.SwapSteps in turn, probed throughout as in
// TestMaintenanceSwapRefusesServiceUser, leave a valid live log. Rerun,
// the same verb finishes: the rebuild, whose old floor holds a line that
// does not parse, exits 4 and prints the uncrashed run's counts, whether
// the crash came before or past the commit; rotate keeps one new archive.
// Run instead, the other verb harms nothing of the first verb's log and
// finishes, and the first verb's rerun then finishes too.
func TestMaintenanceCrashAtEverySwapStepReruns(t *testing.T) {
	for _, v := range keysMaintVerbs {
		var ref string
		t.Run(v.name+"/uncrashed", func(t *testing.T) {
			m := keysMaintRoot(t, "U90")
			r := m.runProbed(v, "", false)
			r.report(t, "uncrashed")
			if r.code != v.code {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, v.code, r.stdout, r.stderr)
			}
			ref = r.stdout
		})
		for _, step := range keystore.SwapSteps {
			t.Run(v.name+"/crash before "+step+"/rerun", func(t *testing.T) {
				m := keysMaintRoot(t, "U90")
				r := m.runProbed(v, step, false)
				r.report(t, "the crashed run")
				if r.code == keysOK {
					t.Fatalf("the run crashed before %s reported success\nstderr:\n%s", step, r.stderr)
				}
				m.checkLive(v, "after the crash before "+step, r.code, r.stderr)
				rerun := m.runProbed(v, "", false)
				rerun.report(t, "the rerun after a crash before "+step)
				if rerun.code != v.code || (ref != "" && rerun.stdout != ref) {
					t.Fatalf("the rerun after a crash before %s: exit %d, want %d; stdout:\n%s\nwant (the uncrashed run's):\n%s\ncrashed run's stderr:\n%s\nrerun's stderr:\n%s", step, rerun.code, v.code, rerun.stdout, ref, r.stderr, rerun.stderr)
				}
				m.checkLive(v, "the rerun after a crash before "+step, rerun.code, rerun.stderr)
				if v.log == keystore.AuditLogName {
					m.checkArchives(r.oldIno, r.oldData, true, "the rerun after a crash before "+step, r.stderr+rerun.stderr)
				}
			})
			t.Run(v.name+"/crash before "+step+"/other verb", func(t *testing.T) {
				m := keysMaintRoot(t, "U90")
				r := m.runProbed(v, step, false)
				r.report(t, "the crashed run")
				if r.code == keysOK {
					t.Fatalf("the run crashed before %s reported success\nstderr:\n%s", step, r.stderr)
				}
				before := keysState(t, m.logPath(v.log))
				o := v.other()
				code := m.h.run(o.args...)
				stdout, stderr := m.h.stdout.String(), m.h.stderr.String()
				if code != keysOK && code != keysCommitted {
					t.Fatalf("%s after %s crashed before %s: exit %d\nstdout:\n%s\nstderr:\n%s", o.name, v.name, step, code, stdout, stderr)
				}
				m.checkLive(o, o.name+" after the crash before "+step, code, stderr)
				after := keysState(t, m.logPath(v.log))
				// The other verb's audit line may follow the audit log's
				// bytes; nothing else of the first verb's log changes.
				if after.ino != before.ino || after.flags != before.flags || after.uid != before.uid || after.mode != before.mode || !strings.HasPrefix(after.data, before.data) {
					t.Errorf("%s changed %s's log: %+v, was %+v\nstderr:\n%s", o.name, v.name, after, before, stderr)
				}
				rerun := m.runProbed(v, "", false)
				rerun.report(t, "the first verb's rerun")
				if rerun.code != keysOK && rerun.code != keysCommitted {
					t.Fatalf("%s's rerun after %s: exit %d\nstdout:\n%s\nstderr:\n%s", v.name, o.name, rerun.code, rerun.stdout, rerun.stderr)
				}
				m.checkLive(v, v.name+"'s rerun after "+o.name, rerun.code, rerun.stderr)
				if v.log == keystore.AuditLogName {
					m.checkArchives(r.oldIno, r.oldData, false, v.name+"'s rerun after "+o.name, r.stderr+rerun.stderr)
				}
			})
		}
	}
}

// TestMaintenanceOldLogRetiredNeverReowned is U118, root-run: in floor
// --rebuild and audit --rotate the new log gets, in staging, between the
// build and report steps, its fchown to the service user while root's,
// its fchmod 0600 and then its flag; the old log's one attribute call is
// its flag clear, after the swap step, so it is never chowned or
// chmodded, and is unflagged only once the swap has made it unreachable
// by path. It ends unlinked, its owner and mode as they were and its bytes
// unchanged. Rotate's .1 is a fresh root 0600 unflagged copy with one
// link; the old .1 and .2 are the new .2 and .3, the same inodes and
// bytes.
func TestMaintenanceOldLogRetiredNeverReowned(t *testing.T) {
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U118")
			var archives []keysFileState
			if v.log == keystore.AuditLogName {
				for n := 1; n <= 2; n++ {
					p := filepath.Join(filepath.Dir(m.logPath(v.log)), fmt.Sprintf("%s.%d", v.log, n))
					if err := os.WriteFile(p, fmt.Appendf(nil, "archive %d\n", n), 0o600); err != nil {
						t.Fatal(err)
					}
					archives = append(archives, keysState(t, p))
				}
			}
			old, err := os.Open(m.logPath(v.log))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = old.Close() }()
			oldSt := keysState(t, m.logPath(v.log))
			attrs := &keysStepAttrs{t: t}
			m.h.attrs = attrs
			code := m.h.run(v.args...)
			stderr := m.h.stderr.String()
			m.h.attrs = realFileAttrWriter{}
			if code != v.code {
				t.Fatalf("exit %d, want %d\nstderr:\n%s", code, v.code, stderr)
			}
			newSt := keysState(t, m.logPath(v.log))
			build, report, swap, clean := attrs.index("step build", 0), attrs.index("step report", 0), attrs.index("step swap", 0), attrs.index("step clean", 0)
			chown, chmod, chflags := attrs.index("fchown", newSt.ino), attrs.index("fchmod", newSt.ino), attrs.index("fchflags", newSt.ino)
			if build < 0 || !(build < chown && chown < chmod && chmod < chflags && chflags < report && report < swap) {
				t.Errorf("the new log's calls: build %d, fchown %d, fchmod %d, fchflags %d, report %d, swap %d; want them in that order\nevents %+v", build, chown, chmod, chflags, report, swap, attrs.events)
			} else if e := attrs.events[chown]; e.uid != 0 || e.arg != int(m.svcUID) {
				t.Errorf("the new log's fchown was to %d while uid %d; want to the service user %d while root's", e.arg, e.uid, m.svcUID)
			} else if e := attrs.events[chflags]; e.arg != keysSFAppend || e.uid != m.svcUID {
				t.Errorf("the new log's fchflags was %#x while uid %d; want SF_APPEND once it is the service user's", e.arg, e.uid)
			}
			var oldCalls []keysAttrEvent
			for i, e := range attrs.events {
				if e.ino == oldSt.ino && !strings.HasPrefix(e.call, "step ") {
					oldCalls = append(oldCalls, e)
					if i < clean {
						t.Errorf("the old log's %s at event %d comes before the clean step (%d), while it may still be reachable", e.call, i, clean)
					}
				}
			}
			if len(oldCalls) != 1 || oldCalls[0].call != "fchflags" || oldCalls[0].arg != 0 {
				t.Errorf("the old %s's attribute calls are %+v; want its flag clear alone\nstderr:\n%s", v.log, oldCalls, stderr)
			}
			var held unix.Stat_t
			if err := unix.Fstat(int(old.Fd()), &held); err != nil || held.Nlink != 0 || held.Uid != oldSt.uid || held.Mode&0o7777 != 0o600 {
				t.Errorf("the old log ends nlink %d uid %d mode %04o (%v); want unlinked, its owner and mode as they were", held.Nlink, held.Uid, held.Mode&0o7777, err)
			}
			if b, err := io.ReadAll(io.NewSectionReader(old, 0, 1<<30)); err != nil || string(b) != oldSt.data {
				t.Errorf("the old log's bytes are %q (%v); want them unchanged, %q", b, err, oldSt.data)
			}
			if v.log != keystore.AuditLogName {
				return
			}
			m.checkArchives(oldSt.ino, oldSt.data, false, v.name, stderr)
			for n, a := range archives {
				got := keysState(t, filepath.Join(filepath.Dir(m.logPath(v.log)), fmt.Sprintf("%s.%d", v.log, n+2)))
				if got.ino != a.ino || got.data != a.data || got.uid != 0 || got.flags != 0 || got.mode != 0o600 || got.nlink != 1 {
					t.Errorf(".%d ends %+v; want the old .%d %+v, carried by link, one link once the retired set is cleaned", n+2, got, n+1, a)
				}
			}
		})
	}
}

// keysPlant is a name U68 plants before a verb runs: at returns the
// planted path from the data root; clean is true when the verb cleans it
// (an entry inside keystore-staging/) and finishes, false when it refuses.
type keysPlant struct {
	name  string
	at    func(m *keysRootMaint, v keysMaintVerb, decoy string) string
	clean bool
}

// keysPlants are U68's plants: a symlink, a FIFO and a swapped directory
// at the marker, at keystore-staging/, inside keystore-staging/ and at
// the verb's log directory.
func keysPlants() []keysPlant {
	symlink := func(rel func(keysMaintVerb) string, aside bool) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, decoy string) string {
			n := rel(v)
			if aside {
				m.moveDirAside(v)
			}
			if err := os.Symlink(decoy, filepath.Join(m.root, n)); err != nil {
				m.t.Fatal(err)
			}
			return n
		}
	}
	fifo := func(rel func(keysMaintVerb) string, aside bool) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, _ string) string {
			n := rel(v)
			if aside {
				m.moveDirAside(v)
			}
			if err := unix.Mkfifo(filepath.Join(m.root, n), 0o600); err != nil {
				m.t.Fatal(err)
			}
			return n
		}
	}
	// dir plants a directory the service user owns holding a flagged log
	// of the verb's name: a swapped directory.
	dir := func(rel func(keysMaintVerb) string, aside bool) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, _ string) string {
			n := rel(v)
			if aside {
				m.moveDirAside(v)
			}
			p := filepath.Join(m.root, n)
			if err := os.Mkdir(p, 0o755); err != nil {
				m.t.Fatal(err)
			}
			lp := filepath.Join(p, v.log)
			if err := os.WriteFile(lp, []byte("planted\n"), 0o600); err != nil {
				m.t.Fatal(err)
			}
			for _, q := range []string{lp, p} {
				if err := os.Chown(q, int(m.svcUID), int(m.svcGID)); err != nil {
					m.t.Fatal(err)
				}
			}
			if err := unix.Chflags(lp, keysSFAppend); err != nil {
				m.t.Fatal(err)
			}
			return n
		}
	}
	inStaging := func(name string, place func(m *keysRootMaint, p, decoy string)) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, decoy string) string {
			s := filepath.Join(m.root, keysStagingDir)
			if err := os.Mkdir(s, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				m.t.Fatal(err)
			}
			if name == "" {
				name = v.dir() + ".new"
			}
			place(m, filepath.Join(s, name), decoy)
			return filepath.Join(keysStagingDir, name)
		}
	}
	marker := func(keysMaintVerb) string { return keysMarkerName }
	staging := func(keysMaintVerb) string { return keysStagingDir }
	logDir := func(v keysMaintVerb) string { return filepath.Join(keysLogsDir, v.dir()) }
	return []keysPlant{
		{name: "marker symlink", at: symlink(marker, false)},
		{name: "marker FIFO", at: fifo(marker, false)},
		{name: "marker directory", at: dir(marker, false)},
		{name: "staging symlink", at: symlink(staging, false)},
		{name: "staging FIFO", at: fifo(staging, false)},
		{name: "staging directory of the service user", at: dir(staging, false)},
		{name: "log directory symlink", at: symlink(logDir, true)},
		{name: "log directory FIFO", at: fifo(logDir, true)},
		{name: "log directory of the service user", at: dir(logDir, true)},
		{name: "symlink in staging at the replacement's name", clean: true, at: inStaging("", func(m *keysRootMaint, p, decoy string) {
			if err := os.Symlink(filepath.Dir(decoy), p); err != nil {
				m.t.Fatal(err)
			}
		})},
		{name: "FIFO in staging", clean: true, at: inStaging("planted-fifo", func(m *keysRootMaint, p, _ string) {
			if err := unix.Mkfifo(p, 0o600); err != nil {
				m.t.Fatal(err)
			}
		})},
		{name: "directory in staging holding a symlink", clean: true, at: inStaging("", func(m *keysRootMaint, p, decoy string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				m.t.Fatal(err)
			}
			if err := os.Symlink(decoy, filepath.Join(p, "link")); err != nil {
				m.t.Fatal(err)
			}
		})},
	}
}

// moveDirAside renames v's log directory to <dir>.saved in keystore-logs/,
// so a plant can take its name.
func (m *keysRootMaint) moveDirAside(v keysMaintVerb) {
	m.t.Helper()
	d := filepath.Join(m.root, keysLogsDir, v.dir())
	if err := os.Rename(d, d+".saved"); err != nil {
		m.t.Fatal(err)
	}
}

// allowRefusedAuditLine accepts, on the canonical audit log, the one line
// the refused verb's audit appends: after holds before's bytes and one more
// line, which names the refusal.
func (m *keysRootMaint) allowRefusedAuditLine(before, after map[string]keysFileState) {
	m.t.Helper()
	n := filepath.Join(keysLogsDir, keystore.AuditDirName, keystore.AuditLogName)
	b, okb := before[n]
	a, oka := after[n]
	if !okb || !oka || b.typ != unix.S_IFREG || !strings.HasPrefix(a.data, b.data) {
		return
	}
	extra := strings.TrimPrefix(strings.TrimPrefix(a.data, b.data), "\n")
	if strings.Count(extra, "\n") == 1 && strings.HasSuffix(extra, "\n") && strings.Contains(extra, `"refused"`) {
		a.data = b.data
		after[n] = a
	}
}

// TestMaintenanceRefusesPlantedNames is U68, root-run: floor --rebuild and
// audit --rotate each meet a symlink, a FIFO and a swapped directory (the
// service user's, holding a flagged log) at the marker, at
// keystore-staging/ and at their log's directory in keystore-logs/, and
// refuse before anything changes; a symlink, FIFO or directory inside
// keystore-staging/ is removed unread and the verb finishes. The verb
// never follows a planted name: the decoy it points at does not change. No
// log byte changes in a refusal (the audit log gains only the verb's own
// refused line), the planted name stands, and no marker or staging
// directory of the verb's is left.
func TestMaintenanceRefusesPlantedNames(t *testing.T) {
	for _, v := range keysMaintVerbs {
		for _, pl := range keysPlants() {
			t.Run(v.name+"/"+pl.name, func(t *testing.T) {
				m := keysMaintRoot(t, "U68")
				decoyDir := t.TempDir()
				decoy := filepath.Join(decoyDir, v.log)
				if err := os.WriteFile(decoy, []byte("decoy\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				decoyBefore := keysState(t, decoy)
				planted := pl.at(m, v, decoy)
				plantedBefore := keysState(t, filepath.Join(m.root, planted))
				before := m.snapshot()
				code := m.h.run(v.args...)
				stdout, stderr := m.h.stdout.String(), m.h.stderr.String()
				if got := keysState(t, decoy); got != decoyBefore {
					t.Errorf("%s: the decoy a planted name points at changed: %+v, was %+v\nstderr:\n%s", pl.name, got, decoyBefore, stderr)
				}
				if ok, names := keysDirEmptyPath(decoyDir); !ok && !slices.Equal(names, []string{v.log}) {
					t.Errorf("%s: the decoy directory now lists %v\nstderr:\n%s", pl.name, names, stderr)
				}
				if pl.clean {
					if code != v.code {
						t.Fatalf("%s: exit %d, want %d (staging cleaned, the verb finishes)\nstdout:\n%s\nstderr:\n%s", pl.name, code, v.code, stdout, stderr)
					}
					m.checkLive(v, pl.name, code, stderr)
					return
				}
				if code != keysRefused {
					t.Fatalf("%s: exit %d, want %d (refused)\nstdout:\n%s\nstderr:\n%s", pl.name, code, keysRefused, stdout, stderr)
				}
				after := m.snapshot()
				m.allowRefusedAuditLine(before, after)
				for n, b := range before {
					if a, ok := after[n]; !ok || a != b {
						t.Errorf("%s: %s changed: %+v, was %+v\nstderr:\n%s", pl.name, n, after[n], b, stderr)
					}
				}
				for n := range after {
					if _, ok := before[n]; !ok {
						t.Errorf("%s: the refused verb left %s\nstderr:\n%s", pl.name, n, stderr)
					}
				}
				if got := keysState(t, filepath.Join(m.root, planted)); got != plantedBefore {
					t.Errorf("%s: the planted %s changed: %+v, was %+v\nstderr:\n%s", pl.name, planted, got, plantedBefore, stderr)
				}
			})
		}
	}
}

// keysDirEmptyPath lists the directory p.
func keysDirEmptyPath(p string) (bool, []string) {
	names, err := os.ReadDir(p)
	if err != nil {
		return false, []string{err.Error()}
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n.Name())
	}
	return len(out) == 0, out
}
