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
// operation, the errno and the verb's stderr, so a root run's log alone
// says what went wrong.

// keysSFAppend is SF_APPEND, the system append-only file flag.
const keysSFAppend = 0x00040000

// The names the verbs use in the data root.
const (
	keysMarkerName = keystore.MaintenanceMarkerName
	keysStagingDir = keystore.StagingDirName
	keysLogsDir    = keystore.LogsDirName
)

// keysMaintVerb is one maintenance verb: its arguments, the log it swaps
// and its staging names in keystore-staging/.
type keysMaintVerb struct {
	name    string
	args    []string
	log     string
	staging []string
}

var keysMaintVerbs = []keysMaintVerb{
	{"floor-rebuild", []string{"floor", "--rebuild"}, keystore.UserFloorLogName, []string{keystore.UserFloorLogName + ".new"}},
	{"audit-rotate", []string{"audit", "--rotate"}, keystore.AuditLogName, []string{keystore.AuditLogName + ".new", keystore.AuditLogName + ".1.new"}},
}

// keysRootMaint is a root-run maintenance fixture: a harness whose store
// has an entry, its data root root's 0755 as deployed, keystore-logs/
// root's 0755 holding both logs, the service user's 0600 and flagged, and
// root's descriptors on the data root and on a directory the service user
// owns, on the same volume, into which its probes try to link.
type keysRootMaint struct {
	t      *testing.T
	h      *keysHarness
	root   string
	dfd    *os.File
	own    *os.File
	svcUID uint32
	svcGID uint32
	links  int
	// preGate is the service user's descriptor on keystore-logs/, opened
	// while the gate was open, before any verb ran.
	preGate int
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
	if err := os.Mkdir(filepath.Join(m.root, keysLogsDir), 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(m.root, keysLogsDir), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		m.placeLog(n, "", true, true)
	}
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
	m.preGate = m.preGateDir()
	h.attrs = realFileAttrWriter{}
	return m
}

// logPath is name's path in keystore-logs/.
func (m *keysRootMaint) logPath(name string) string { return filepath.Join(m.root, keysLogsDir, name) }

// placeLog creates name in keystore-logs/ holding data, mode 0600, the
// service user's when service and root's otherwise (owner first), flagged
// when flag (flag last).
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
// can be removed, and opens a closed gate.
func keysUnflagAll(root string) {
	_ = os.Chmod(filepath.Join(root, keysLogsDir), 0o755)
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

// snapshot is the state of every name in the data root and in
// keystore-logs/ (as keystore-logs/<name>) but the marker, keystore-lock
// and directories.
func (m *keysRootMaint) snapshot() map[string]keysFileState {
	m.t.Helper()
	out := map[string]keysFileState{}
	for _, dir := range []string{"", keysLogsDir} {
		names, err := os.ReadDir(filepath.Join(m.root, dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			m.t.Fatal(err)
		}
		for _, d := range names {
			n := filepath.Join(dir, d.Name())
			if d.IsDir() || n == keysMarkerName || n == "keystore-lock" {
				continue
			}
			out[n] = keysState(m.t, filepath.Join(m.root, n))
		}
	}
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

// preGateDir is the service user's descriptor on keystore-logs/, opened
// while the gate is open (before the verb runs), which it keeps across
// the gate's close.
func (m *keysRootMaint) preGateDir() int {
	m.t.Helper()
	fd := -1
	err := m.asService(func() error {
		var err error
		fd, err = unix.Openat(int(m.dfd.Fd()), keysLogsDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return err
	})
	if err != nil {
		m.t.Fatalf("the service user cannot open %s while the gate is open: %v", keysLogsDir, err)
	}
	m.t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// keysTarget is a name a probe attacks: dir is keystore-logs/ or
// keystore-staging/.
type keysTarget struct{ dir, name string }

func (k keysTarget) String() string { return k.dir + "/" + k.name }

// targets is what the service user attacks during v: the canonical log,
// which before the retire is the old log and after the rename the new one,
// and v's staging names.
func keysTargets(v keysMaintVerb) []keysTarget {
	out := []keysTarget{{keysLogsDir, v.log}}
	for _, s := range v.staging {
		out = append(out, keysTarget{keysStagingDir, s})
	}
	return out
}

// want is the errno the service user's attempt on k must fail with, as
// root sees the tree now, and the state it read: EACCES when a directory
// on the way is closed to it (keystore-staging/ always, keystore-logs/
// while the gate is closed), ENOENT when the name is absent, EPERM when
// the file is flagged. An unflagged file the service user can reach is
// itself a defect: want returns 0 and says so.
func (m *keysRootMaint) want(k keysTarget) (unix.Errno, string) {
	var dst unix.Stat_t
	if err := unix.Fstatat(int(m.dfd.Fd()), k.dir, &dst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return unix.ENOENT, k.dir + " absent"
		}
		return 0, fmt.Sprintf("stat %s: %v", k.dir, err)
	}
	if dst.Mode&0o001 == 0 {
		return unix.EACCES, fmt.Sprintf("%s mode %04o uid %d", k.dir, dst.Mode&0o7777, dst.Uid)
	}
	var st unix.Stat_t
	err := unix.Fstatat(int(m.dfd.Fd()), k.String(), &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return unix.ENOENT, fmt.Sprintf("%s mode %04o, %s absent", k.dir, dst.Mode&0o7777, k.name)
	}
	if err != nil {
		return 0, fmt.Sprintf("stat %s: %v", k, err)
	}
	state := fmt.Sprintf("%s mode %04o; %s uid %d mode %04o flags %#x nlink %d", k.dir, dst.Mode&0o7777, k.name, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	if st.Flags&keysSFAppend != 0 {
		return unix.EPERM, state
	}
	return 0, state + ": an unflagged log the service user can reach"
}

// keysOps are the service user's attempts: from a directory descriptor
// and a path under it, each returns nil when it succeeded.
var keysOps = []struct {
	name string
	do   func(m *keysRootMaint, dirfd int, path string) error
}{
	{"open(O_WRONLY)", func(_ *keysRootMaint, dirfd int, path string) error {
		return keysOpenClose(dirfd, path, unix.O_WRONLY)
	}},
	{"open(O_WRONLY|O_TRUNC)", func(_ *keysRootMaint, dirfd int, path string) error {
		return keysOpenClose(dirfd, path, unix.O_WRONLY|unix.O_TRUNC)
	}},
	{"link()", func(m *keysRootMaint, dirfd int, path string) error {
		m.links++
		return unix.Linkat(dirfd, path, int(m.own.Fd()), fmt.Sprintf("alias-%d", m.links), 0)
	}},
}

func keysOpenClose(dirfd int, path string, flag int) error {
	fd, err := unix.Openat(dirfd, path, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	return err
}

// keysProbe is one probing run: the service user's descriptors, the
// failures it found, and the bytes it holds every log to.
type keysProbe struct {
	m       *keysRootMaint
	v       keysMaintVerb
	preGate int
	// old is root's read-only descriptor on the old log, opened before the
	// verb, so its bytes are checked after it is unlinked too.
	old      *os.File
	oldBytes string
	failures []string
}

func (m *keysRootMaint) newProbe(v keysMaintVerb) *keysProbe {
	m.t.Helper()
	// After a crash past the old log's unlink there is no old log: a nil
	// old reads as empty.
	old, err := os.Open(m.logPath(v.log))
	switch {
	case errors.Is(err, os.ErrNotExist):
		old = nil
	case err != nil:
		m.t.Fatal(err)
	default:
		m.t.Cleanup(func() { _ = old.Close() })
	}
	p := &keysProbe{m: m, v: v, preGate: m.preGate, old: old}
	p.oldBytes = p.readOld()
	return p
}

func (p *keysProbe) readOld() string {
	if p.old == nil {
		return ""
	}
	b, err := io.ReadAll(io.NewSectionReader(p.old, 0, 1<<40))
	if err != nil {
		p.failf("read the old log on root's descriptor: %v", err)
	}
	return string(b)
}

func (p *keysProbe) failf(format string, args ...any) {
	p.failures = append(p.failures, fmt.Sprintf(format, args...))
}

// targetBytes is the bytes of each target present, read as root.
func (p *keysProbe) targetBytes() map[keysTarget]string {
	out := map[keysTarget]string{}
	for _, k := range keysTargets(p.v) {
		if b, err := os.ReadFile(filepath.Join(p.m.root, k.String())); err == nil {
			out[k] = string(b)
		}
	}
	return out
}

// probeAll runs every attempt on every target, through the data root and,
// for keystore-logs/, through the descriptor kept from before the gate
// closed, and records each that succeeded or failed with another errno,
// and any byte any of them changed.
func (p *keysProbe) probeAll(at string) {
	before := p.targetBytes()
	oldBefore := p.readOld()
	for _, k := range keysTargets(p.v) {
		type route struct {
			name  string
			dirfd int
			path  string
		}
		routes := []route{{"through the data root", int(p.m.dfd.Fd()), k.String()}}
		if k.dir == keysLogsDir {
			routes = append(routes, route{"through the descriptor on keystore-logs/ opened before the gate closed", p.preGate, k.name})
		}
		for _, r := range routes {
			for _, op := range keysOps {
				want, state := p.m.want(k)
				err := p.m.asService(func() error { return op.do(p.m, r.dirfd, r.path) })
				var got unix.Errno
				switch {
				case err == nil:
					p.failf("%s: the service user's %s of %s %s SUCCEEDED; want %v (state: %s)", at, op.name, k, r.name, want, state)
					continue
				case !errors.As(err, &got):
					p.failf("%s: the service user's %s of %s %s: %v, not an errno (state: %s)", at, op.name, k, r.name, err, state)
					continue
				}
				if want == 0 || got != want {
					p.failf("%s: the service user's %s of %s %s: errno %d (%v), want %d (%v) (state: %s)", at, op.name, k, r.name, int(got), got, int(want), want, state)
				}
			}
		}
	}
	after := p.targetBytes()
	for k, b := range before {
		if a, ok := after[k]; ok && a != b {
			p.failf("%s: the service user's attempts changed %s: %q, was %q", at, k, a, b)
		}
	}
	if o := p.readOld(); o != oldBefore {
		p.failf("%s: the service user's attempts changed the old log: %q, was %q", at, o, oldBefore)
	}
}

// keysProbeAttrs is the real file-attribute writer and step seam with a
// hook run before each attribute call and each step, given a label naming
// it; a hook error fails the call, as a crash at that step would leave it.
type keysProbeAttrs struct {
	t      *testing.T
	before func(label string, e keysAttrEvent) error
	events []keysAttrEvent
}

// keysAttrEvent is one hook point: the call or step and, for a call, the
// file's state just before it.
type keysAttrEvent struct {
	label string
	call  string
	arg   int
	ino   uint64
	uid   uint32
	mode  uint16
	flags uint32
	dir   bool
}

func (p *keysProbeAttrs) do(call string, fd, arg int, f func() error) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		p.t.Errorf("fstat before %s: %v", call, err)
		return err
	}
	e := keysAttrEvent{call: call, arg: arg, ino: st.Ino, uid: st.Uid, mode: st.Mode & 0o7777, flags: st.Flags, dir: st.Mode&unix.S_IFMT == unix.S_IFDIR}
	what := "a file"
	if e.dir {
		what = "a directory"
	}
	e.label = fmt.Sprintf("before %s(%#o) on %s (inode %d, uid %d, mode %04o, flags %#x)", call, arg, what, e.ino, e.uid, e.mode, e.flags)
	p.events = append(p.events, e)
	if p.before != nil {
		if err := p.before(e.label, e); err != nil {
			return err
		}
	}
	return f()
}

func (p *keysProbeAttrs) Fchown(fd, uid, gid int) error {
	return p.do("fchown", fd, uid, func() error { return unix.Fchown(fd, uid, gid) })
}

func (p *keysProbeAttrs) Fchmod(fd int, mode uint32) error {
	return p.do("fchmod", fd, int(mode), func() error { return unix.Fchmod(fd, mode) })
}

func (p *keysProbeAttrs) Fchflags(fd, flags int) error {
	return p.do("fchflags", fd, flags, func() error { return unix.Fchflags(fd, flags) })
}

func (p *keysProbeAttrs) BeforeSwapStep(step string) error {
	e := keysAttrEvent{label: "before the step " + step, call: "step " + step}
	p.events = append(p.events, e)
	if p.before != nil {
		return p.before(e.label, e)
	}
	return nil
}

// eventsOf is the attribute calls on inode ino, in order.
func (p *keysProbeAttrs) eventsOf(ino uint64) []keysAttrEvent {
	var out []keysAttrEvent
	for _, e := range p.events {
		if e.ino == ino && !strings.HasPrefix(e.call, "step ") {
			out = append(out, e)
		}
	}
	return out
}

// gateOpen reports whether keystore-logs/ is at 0755 now.
func (m *keysRootMaint) gateOpen() bool {
	var st unix.Stat_t
	return unix.Stat(filepath.Join(m.root, keysLogsDir), &st) == nil && st.Mode&0o7777 == 0o755
}

// isGateClose reports whether e is keystore-logs/'s fchmod to 0700.
func (m *keysRootMaint) isGateClose(e keysAttrEvent) bool {
	if e.call != "fchmod" || e.arg != 0o700 || !e.dir {
		return false
	}
	var st unix.Stat_t
	return unix.Stat(filepath.Join(m.root, keysLogsDir), &st) == nil && st.Ino == e.ino
}

// keysTail is what the service user appends through O_APPEND before the
// gate closes: legitimate, and kept (rotate's archive ends with it; a
// floor's tail keeps only lines that parse, so rebuild drops it).
const keysTail = "appended before the gate closed\n"

// keysSwapRun is one probed run of a verb.
type keysSwapRun struct {
	probe    *keysProbe
	attrs    *keysProbeAttrs
	code     int
	stderr   string
	appended bool
	crashed  string
	labels   []string
}

// runProbed runs v with probes before every hook point. crashAt >= 0 makes
// the crashAt-th hook point fail instead, as a crash there would. The
// service user appends keysTail through O_APPEND just before the gate
// closes, the first time.
func (m *keysRootMaint) runProbed(v keysMaintVerb, crashAt int) *keysSwapRun {
	m.t.Helper()
	r := &keysSwapRun{probe: m.newProbe(v)}
	r.probe.probeAll("before the verb")
	r.attrs = &keysProbeAttrs{t: m.t}
	r.attrs.before = func(label string, e keysAttrEvent) error {
		n := len(r.labels)
		r.labels = append(r.labels, label)
		if !r.appended && m.isGateClose(e) && m.gateOpen() {
			r.appended = true
			err := m.asService(func() error {
				fd, err := unix.Openat(r.probe.preGate, v.log, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				defer func() { _ = unix.Close(fd) }()
				_, err = unix.Write(fd, []byte(keysTail))
				return err
			})
			if err != nil {
				r.probe.failf("%s: the service user's legitimate O_APPEND write to %s: %v", label, v.log, err)
			}
			r.probe.oldBytes = r.probe.readOld()
		}
		r.probe.probeAll(fmt.Sprintf("hook %d (%s)", n, label))
		if n == crashAt {
			r.crashed = label
			return errors.New("crashed here (the test's hook)")
		}
		return nil
	}
	m.h.attrs = r.attrs
	r.code = m.h.run(v.args...)
	r.stderr = m.h.stderr.String()
	r.probe.probeAll("after the verb")
	m.h.attrs = realFileAttrWriter{}
	return r
}

// report fails the test with every failure the run's probes found, each
// with the verb's exit code and full stderr.
func (r *keysSwapRun) report(t *testing.T, what string) {
	t.Helper()
	for _, f := range r.probe.failures {
		t.Errorf("%s: %s\nverb exit %d, stderr:\n%s", what, f, r.code, r.stderr)
	}
}

// checkSwapped checks the state a finished swap of v leaves: the canonical
// log the service user's 0600, flagged, one link, passing the flag check;
// the gate open; no marker and no staging directory.
func (m *keysRootMaint) checkSwapped(v keysMaintVerb, what, stderr string) {
	m.t.Helper()
	fail := func(format string, args ...any) {
		m.t.Errorf("%s: %s\nverb stderr:\n%s", what, fmt.Sprintf(format, args...), stderr)
	}
	var st unix.Stat_t
	if err := unix.Lstat(m.logPath(v.log), &st); err != nil {
		fail("stat the canonical %s: %v", v.log, err)
		return
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != m.svcUID || st.Mode&0o7777 != 0o600 || st.Flags != keysSFAppend {
		fail("the canonical %s is uid %d mode %04o flags %#x nlink %d; want the service user's 0600, SF_APPEND alone, one link", v.log, st.Uid, st.Mode&0o7777, st.Flags, st.Nlink)
	}
	if err := keystore.New(m.h.storeCfg).CheckLogFlags(context.Background()); err != nil {
		fail("the flag check refuses: %v", err)
	}
	var dst unix.Stat_t
	if err := unix.Stat(filepath.Join(m.root, keysLogsDir), &dst); err != nil || dst.Mode&0o7777 != 0o755 {
		fail("%s mode %04o (%v); want the gate open, 0755", keysLogsDir, dst.Mode&0o7777, err)
	}
	for _, n := range []string{keysMarkerName, keysStagingDir} {
		if _, err := os.Lstat(filepath.Join(m.root, n)); !errors.Is(err, os.ErrNotExist) {
			fail("%s left: %v", n, err)
		}
	}
}

// checkArchives checks rotate's archives: .1 (and, when sole, no .2), root's 0600,
// unflagged, one link, a fresh inode (not the old log's), holding the old
// log's bytes and, when tail, keysTail once at its end.
func (m *keysRootMaint) checkArchives(oldIno uint64, oldBytes string, tail, sole bool, what, stderr string) {
	m.t.Helper()
	fail := func(format string, args ...any) {
		m.t.Errorf("%s: %s\nverb stderr:\n%s", what, fmt.Sprintf(format, args...), stderr)
	}
	var st unix.Stat_t
	p := m.logPath(keystore.AuditLogName + ".1")
	if err := unix.Lstat(p, &st); err != nil {
		fail("stat .1: %v", err)
		return
	}
	if st.Uid != 0 || st.Mode&0o7777 != 0o600 || st.Flags != 0 || st.Nlink != 1 || st.Ino == oldIno {
		fail(".1 is uid %d mode %04o flags %#x nlink %d inode %d (the old log's %d); want a fresh root 0600 unflagged copy with one link", st.Uid, st.Mode&0o7777, st.Flags, st.Nlink, st.Ino, oldIno)
	}
	b, _ := os.ReadFile(p)
	if !strings.HasPrefix(string(b), oldBytes) {
		fail(".1 holds %q; want it to start with the old log's %q", b, oldBytes)
	}
	if tail && (!strings.HasSuffix(string(b), keysTail) || strings.Count(string(b), keysTail) != 1 || len(b) != len(oldBytes)+len(keysTail)) {
		fail(".1 holds %q; want the old log's %q and then %q once", b, oldBytes, keysTail)
	}
	if _, err := os.Lstat(m.logPath(keystore.AuditLogName + ".2")); sole && !errors.Is(err, os.ErrNotExist) {
		fail("rotate made a second archive .2: %v", err)
	}
}

// TestMaintenanceRefusesPlantedSymlinkAndSwap is U68, root-run: floor
// --rebuild and audit --rotate each refuse a symlink planted at the
// marker, at keystore-staging/ or at the old log, a FIFO at the old log,
// and (rotate) a symlink at an archive, before anything changes: no log
// byte, owner or flag changes (the audit log gains only the verb's own
// refused line), the planted name and what it points at stand, and no
// marker or staging directory of the verb's is left. The old log swapped
// for another file while the verb holds it is refused under the closed
// gate, with no byte of either file changed, the marker kept and the gate
// closed, so the listener stays down until the rerun, which finishes.
func TestMaintenanceRefusesPlantedSymlinkAndSwap(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U68): run as root through hack/acceptance/keystore.sh --root")
	}
	type plant struct {
		name       string
		at         func(m *keysRootMaint, v keysMaintVerb, decoy string) string
		rotateOnly bool
	}
	symlinkAt := func(name func(v keysMaintVerb) string) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, decoy string) string {
			n := name(v)
			if n == filepath.Join(keysLogsDir, v.log) {
				m.moveAside(v.log)
			}
			if err := os.Symlink(decoy, filepath.Join(m.root, n)); err != nil {
				m.t.Fatal(err)
			}
			return n
		}
	}
	plants := []plant{
		{name: "marker symlink", at: symlinkAt(func(keysMaintVerb) string { return keysMarkerName })},
		{name: "staging directory symlink", at: symlinkAt(func(keysMaintVerb) string { return keysStagingDir })},
		{name: "old log symlink", at: symlinkAt(func(v keysMaintVerb) string { return filepath.Join(keysLogsDir, v.log) })},
		{name: "old log FIFO", at: func(m *keysRootMaint, v keysMaintVerb, _ string) string {
			m.moveAside(v.log)
			if err := unix.Mkfifo(m.logPath(v.log), 0o600); err != nil {
				m.t.Fatal(err)
			}
			return filepath.Join(keysLogsDir, v.log)
		}},
		{name: "archive symlink", rotateOnly: true, at: symlinkAt(func(keysMaintVerb) string {
			return filepath.Join(keysLogsDir, keystore.AuditLogName+".1")
		})},
	}
	for _, v := range keysMaintVerbs {
		for _, pl := range plants {
			if pl.rotateOnly && v.log != keystore.AuditLogName {
				continue
			}
			t.Run(v.name+"/"+pl.name, func(t *testing.T) {
				m := keysMaintRoot(t, "U68")
				decoy := filepath.Join(t.TempDir(), "decoy")
				if err := os.WriteFile(decoy, []byte("decoy\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				decoyBefore := keysState(t, decoy)
				planted := pl.at(m, v, decoy)
				plantedBefore := keysState(t, filepath.Join(m.root, planted))
				before := m.snapshot()
				code := m.h.run(v.args...)
				stderr := m.h.stderr.String()
				if code != keysRefused {
					t.Fatalf("%s: exit %d, want %d (refused)\nstderr:\n%s", pl.name, code, keysRefused, stderr)
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
				if got := keysState(t, decoy); got != decoyBefore {
					t.Errorf("%s: the decoy a planted name points at changed: %+v, was %+v", pl.name, got, decoyBefore)
				}
				if got := keysState(t, filepath.Join(m.root, planted)); got != plantedBefore {
					t.Errorf("%s: the planted %s changed: %+v, was %+v", pl.name, planted, got, plantedBefore)
				}
				for _, n := range []string{keysMarkerName, keysStagingDir} {
					if n == planted {
						continue
					}
					if _, err := os.Lstat(filepath.Join(m.root, n)); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("%s: the refused verb left %s: %v\nstderr:\n%s", pl.name, n, err, stderr)
					}
				}
			})
		}
		t.Run(v.name+"/old log swapped mid-run", func(t *testing.T) {
			m := keysMaintRoot(t, "U68")
			var swapped map[string]keysFileState
			m.h.attrs = &keysProbeAttrs{t: t, before: func(label string, _ keysAttrEvent) error {
				// The stage step comes after the verb opened and read the
				// old log, and before it checks the name still holds it.
				if swapped == nil && label == "before the step stage" {
					m.moveAside(v.log)
					m.placeLog(v.log, "swapped in\n", true, true)
					swapped = m.snapshot()
				}
				return nil
			}}
			code := m.h.run(v.args...)
			stderr := m.h.stderr.String()
			if swapped == nil {
				t.Fatalf("the stage step was never reached: exit %d\nstderr:\n%s", code, stderr)
			}
			if code != keysRefused || !strings.Contains(stderr, "replaced") {
				t.Fatalf("exit %d, want %d naming the replaced log\nstderr:\n%s", code, keysRefused, stderr)
			}
			after := m.snapshot()
			for _, n := range []string{filepath.Join(keysLogsDir, v.log), filepath.Join(keysLogsDir, "keystore-saved-"+v.log)} {
				if after[n].data != swapped[n].data || after[n].ino != swapped[n].ino || after[n].flags != swapped[n].flags {
					t.Errorf("%s changed: %+v, was %+v\nstderr:\n%s", n, after[n], swapped[n], stderr)
				}
			}
			if _, err := os.Lstat(filepath.Join(m.root, keysMarkerName)); err != nil {
				t.Errorf("a refusal under the closed gate removed the marker: %v\nstderr:\n%s", err, stderr)
			}
			m.h.attrs = realFileAttrWriter{}
			code = m.h.run(v.args...)
			stderr = m.h.stderr.String()
			if code != keysOK {
				t.Fatalf("the rerun: exit %d\nstderr:\n%s", code, stderr)
			}
			m.checkSwapped(v, "the rerun after the swapped log", stderr)
		})
	}
}

// moveAside renames the log name in keystore-logs/ to
// keystore-saved-<name> there, flagged as it was, so a plant can take its
// name.
func (m *keysRootMaint) moveAside(name string) {
	m.t.Helper()
	p := m.logPath(name)
	saved := m.logPath("keystore-saved-" + name)
	if err := unix.Chflags(p, 0); err != nil {
		m.t.Fatal(err)
	}
	if err := os.Rename(p, saved); err != nil {
		m.t.Fatal(err)
	}
	if err := unix.Chflags(saved, keysSFAppend); err != nil {
		m.t.Fatal(err)
	}
}

// allowRefusedAuditLine accepts, on the canonical audit log, the one line
// the refused verb's audit appends: after holds before's bytes and one more
// line, which names the refusal.
func (m *keysRootMaint) allowRefusedAuditLine(before, after map[string]keysFileState) {
	m.t.Helper()
	n := filepath.Join(keysLogsDir, keystore.AuditLogName)
	b, okb := before[n]
	a, oka := after[n]
	if !okb || !oka || b.typ != unix.S_IFREG || !strings.HasPrefix(a.data, b.data) {
		return
	}
	extra := strings.TrimPrefix(a.data, b.data)
	extra = strings.TrimPrefix(extra, "\n")
	if strings.Count(extra, "\n") == 1 && strings.HasSuffix(extra, "\n") && strings.Contains(extra, `"refused"`) {
		a.data = b.data
		after[n] = a
	}
}

// TestMaintenanceGatedSwapRefusesServiceUser is U90, root-run: before
// every step of floor --rebuild and audit --rotate (each attribute call
// and each step the step seam names) and after, the service user's
// open(O_WRONLY), open(O_WRONLY|O_TRUNC) and link() into a directory it
// owns, of the old log, the new log's canonical name and each staging
// name, through the data root and through a descriptor on keystore-logs/
// it opened before the gate closed, each fail: EACCES behind keystore-
// staging/ or the closed gate, EPERM on a flagged file, ENOENT on an
// absent name. No log byte changes. A line it appends through O_APPEND
// before the gate closes is kept (rotate's .1 ends with it). The final log
// passes the judge with one link, and the gate is open. The new log is
// staged root's 0600, written, then handed to the service user and set
// 0600 before the gate closes, and flagged after its rename; the old log
// gets one attribute call, its flag clear, and is never chowned.
func TestMaintenanceGatedSwapRefusesServiceUser(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U90): run as root through hack/acceptance/keystore.sh --root")
	}
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U90")
			oldSt := keysState(t, m.logPath(v.log))
			r := m.runProbed(v, -1)
			r.report(t, v.name)
			if r.code != keysOK {
				t.Fatalf("exit %d, want %d\nstderr:\n%s", r.code, keysOK, r.stderr)
			}
			if !r.appended {
				t.Errorf("the gate's close (fchmod 0700 of %s) was never seen; hooks: %v", keysLogsDir, r.labels)
			}
			m.checkSwapped(v, v.name, r.stderr)
			newSt := keysState(t, m.logPath(v.log))
			if newSt.ino == oldSt.ino {
				t.Errorf("the canonical %s is still the old inode", v.log)
			}
			evs := r.attrs.eventsOf(newSt.ino)
			calls := make([]string, 0, len(evs))
			for _, e := range evs {
				calls = append(calls, fmt.Sprintf("%s(%#o) uid %d flags %#x", e.call, e.arg, e.uid, e.flags))
			}
			if len(evs) != 3 || evs[0].call != "fchown" || evs[0].arg != int(m.svcUID) || evs[0].uid != 0 ||
				evs[1].call != "fchmod" || evs[1].arg != 0o600 ||
				evs[2].call != "fchflags" || evs[2].arg != keysSFAppend || evs[2].uid != m.svcUID {
				t.Errorf("the new %s's attribute calls are %v; want fchown to the service user while root's, fchmod 0600, then the flag", v.log, calls)
			}
			if v.log == keystore.AuditLogName {
				m.checkArchives(oldSt.ino, oldSt.data, true, true, v.name, r.stderr)
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
				t.Errorf("the timed-out rotate changed %s", n)
			}
		}
		if _, err := os.Lstat(filepath.Join(m.root, keysMarkerName)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the timed-out rotate left the marker: %v", err)
		}
	})
}

// TestMaintenanceCrashAtEverySwapStepReruns is U90's crash half,
// root-run: floor --rebuild and audit --rotate stopped at each hook point
// in turn (each attribute call and each step), probed as in
// TestMaintenanceGatedSwapRefusesServiceUser throughout, then rerun with
// the probes still on, end with the canonical log judged with one link,
// flagged, the gate open and no marker; rotate holds exactly one new
// archive, the old log's bytes, so a crash after the gate opened does not
// rotate twice.
func TestMaintenanceCrashAtEverySwapStepReruns(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U90): run as root through hack/acceptance/keystore.sh --root")
	}
	for _, v := range keysMaintVerbs {
		var labels []string
		t.Run(v.name+"/hook points", func(t *testing.T) {
			m := keysMaintRoot(t, "U90")
			r := m.runProbed(v, -1)
			if r.code != keysOK {
				t.Fatalf("the uncrashed run: exit %d\nstderr:\n%s", r.code, r.stderr)
			}
			labels = r.labels
		})
		for i := range labels {
			t.Run(fmt.Sprintf("%s/crash at hook %d", v.name, i), func(t *testing.T) {
				m := keysMaintRoot(t, "U90")
				oldSt := keysState(t, m.logPath(v.log))
				r := m.runProbed(v, i)
				r.report(t, fmt.Sprintf("crash at hook %d", i))
				if r.crashed == "" {
					t.Fatalf("hook %d (%s in the uncrashed run) was never reached; this run's hooks: %v\nstderr:\n%s", i, labels[i], r.labels, r.stderr)
				}
				if r.code == keysOK {
					t.Fatalf("the run crashed %s reported success\nstderr:\n%s", r.crashed, r.stderr)
				}
				if _, err := os.Lstat(filepath.Join(m.root, keysMarkerName)); errors.Is(err, os.ErrNotExist) {
					// A refusal before the gate closed: the old log stands.
					if st := keysState(t, m.logPath(v.log)); st.ino != oldSt.ino || st.flags != keysSFAppend || !strings.HasPrefix(st.data, oldSt.data) {
						t.Errorf("crashed %s, the marker gone: the canonical %s is %+v; want the old log, flagged, its bytes kept\nstderr:\n%s", r.crashed, v.log, st, r.stderr)
					}
				}
				rerun := m.runProbed(v, -1)
				rerun.report(t, fmt.Sprintf("the rerun after a crash at hook %d (%s)", i, r.crashed))
				if rerun.code != keysOK {
					t.Fatalf("the rerun after a crash %s: exit %d\ncrashed run's stderr:\n%s\nrerun's stderr:\n%s", r.crashed, rerun.code, r.stderr, rerun.stderr)
				}
				m.checkSwapped(v, "the rerun after a crash "+r.crashed, rerun.stderr)
				if v.log == keystore.AuditLogName {
					m.checkArchives(oldSt.ino, oldSt.data, false, true, "the rerun after a crash "+r.crashed, r.stderr+rerun.stderr)
				}
			})
		}
	}
}

// TestMaintenanceOldLogRetiredNeverReowned is U118, root-run: in floor
// --rebuild and audit --rotate the old log's one attribute call is its
// flag clear, under the closed gate; it is never chowned or chmodded, and
// its name is unlinked before the new log is renamed in. While it is
// unflagged the service user reaches it by no route (EACCES, the gate),
// and its bytes never change. Rotate's archives are fresh root-owned
// unflagged copies, 0600 with one link; existing archives shift up by
// rename, unchanged.
func TestMaintenanceOldLogRetiredNeverReowned(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U118): run as root through hack/acceptance/keystore.sh --root")
	}
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U118")
			oldSt := keysState(t, m.logPath(v.log))
			var archives []keysFileState
			if v.log == keystore.AuditLogName {
				for n := 1; n <= 2; n++ {
					m.placeLog(fmt.Sprintf("%s.%d", keystore.AuditLogName, n), fmt.Sprintf("archive %d\n", n), false, false)
					archives = append(archives, keysState(t, m.logPath(fmt.Sprintf("%s.%d", keystore.AuditLogName, n))))
				}
			}
			r := m.runProbed(v, -1)
			r.report(t, v.name)
			if r.code != keysOK {
				t.Fatalf("exit %d\nstderr:\n%s", r.code, r.stderr)
			}
			evs := r.attrs.eventsOf(oldSt.ino)
			if len(evs) != 1 || evs[0].call != "fchflags" || evs[0].arg != 0 {
				t.Errorf("the old %s's attribute calls are %+v; want its flag clear alone\nstderr:\n%s", v.log, evs, r.stderr)
			}
			// The hooks between the old log's flag clear and its unlink
			// saw the gate closed: the probes there wanted EACCES and any
			// other result is in r.probe.failures, reported above.
			cleared, unlinked := -1, -1
			for i, e := range r.attrs.events {
				if e.ino == oldSt.ino && e.call == "fchflags" {
					cleared = i
				}
				if e.call == "step unlink-old" {
					unlinked = i
				}
			}
			if cleared < 0 || unlinked != cleared+1 {
				t.Errorf("the old log's flag clear at hook %d and the unlink step at hook %d; want the unlink next", cleared, unlinked)
			}
			var held unix.Stat_t
			if err := unix.Fstat(int(r.probe.old.Fd()), &held); err != nil || held.Nlink != 0 || held.Uid != oldSt.uid || held.Mode&0o7777 != 0o600 {
				t.Errorf("the old log ends nlink %d uid %d mode %04o (%v); want unlinked, its owner and mode as they were", held.Nlink, held.Uid, held.Mode&0o7777, err)
			}
			if v.log != keystore.AuditLogName {
				return
			}
			m.checkArchives(oldSt.ino, oldSt.data, true, false, v.name, r.stderr)
			for n, a := range archives {
				got := keysState(t, m.logPath(fmt.Sprintf("%s.%d", keystore.AuditLogName, n+2)))
				if got.ino != a.ino || got.data != a.data || got.uid != 0 || got.flags != 0 || got.mode != 0o600 {
					t.Errorf(".%d ends %+v; want the old .%d %+v, shifted unchanged", n+2, got, n+1, a)
				}
			}
		})
	}
}
