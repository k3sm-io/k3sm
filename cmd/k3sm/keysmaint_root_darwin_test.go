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
// --rotate (docs/design/keystore.md § "Root maintenance verbs"): U68, U90
// and U118. Each runs only as root, through hack/acceptance/keystore.sh
// --root, with the real file-attribute writer and SF_APPEND set for real;
// non-root it skips, and the root-run row fails on a SKIP.

// keysSFAppend is SF_APPEND, the system append-only file flag.
const keysSFAppend = 0x00040000

// keysMaintVerb is one maintenance verb: its arguments, the log it swaps
// and its staging file, in the root-only staging directory.
type keysMaintVerb struct {
	name    string
	args    []string
	log     string
	staging string
}

var keysMaintVerbs = []keysMaintVerb{
	{"floor-rebuild", []string{"floor", "--rebuild"}, keystore.UserFloorLogName, keysStagingDir + "/" + keystore.UserFloorLogName + ".new"},
	{"audit-rotate", []string{"audit", "--rotate"}, keystore.AuditLogName, keysStagingDir + "/" + keystore.AuditLogName + ".new"},
}

// keysMarkerName is the maintenance marker in the data root, and
// keysStagingDir the verbs' root-only staging directory there.
const (
	keysMarkerName = keystore.MaintenanceMarkerName
	keysStagingDir = "keystore-staging"
)

// keysRootMaint is a root-run maintenance fixture: a harness whose store
// has an entry, its data root root's 0755 as deployed, both logs the
// service user's 0600 and flagged, and root's descriptor on the data root,
// through which the service user's probes open names.
type keysRootMaint struct {
	t      *testing.T
	h      *keysHarness
	root   string
	dfd    *os.File
	svcUID uint32
	svcGID uint32
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
	// Registered after the harness's temp dirs, so it runs before their
	// removal, which a flagged file would refuse.
	t.Cleanup(func() { keysUnflagAll(m.root) })
	if err := os.Chmod(m.root, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{keystore.UserFloorLogName, keystore.AuditLogName} {
		m.placeLog(n, "", true, true)
	}
	// An audit line, so the audit log holds bytes a refusal must keep.
	h.mustRun(keysOK, "list")
	dfd, err := os.Open(m.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dfd.Close() })
	m.dfd = dfd
	h.attrs = realFileAttrWriter{}
	return m
}

// placeLog creates name in the data root holding data, mode 0600, the
// service user's when service and root's otherwise, flagged when flag.
func (m *keysRootMaint) placeLog(name, data string, service, flag bool) {
	m.t.Helper()
	p := filepath.Join(m.root, name)
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

// snapshot is the state of every name in the data root but the marker,
// the staging names, keystore-lock and directories.
func (m *keysRootMaint) snapshot() map[string]keysFileState {
	m.t.Helper()
	names, err := os.ReadDir(m.root)
	if err != nil {
		m.t.Fatal(err)
	}
	out := map[string]keysFileState{}
	for _, d := range names {
		n := d.Name()
		if d.IsDir() || n == keysMarkerName || n == "keystore-lock" || strings.HasSuffix(n, ".new") {
			continue
		}
		out[n] = keysState(m.t, filepath.Join(m.root, n))
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

// nameOf is the name, in the data root or as keystore-staging/<name> in
// the staging directory, whose inode is ino, or "".
func (m *keysRootMaint) nameOf(ino uint64) string {
	for _, dir := range []string{"", keysStagingDir} {
		names, err := os.ReadDir(filepath.Join(m.root, dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			m.t.Fatal(err)
		}
		for _, d := range names {
			n := filepath.Join(dir, d.Name())
			var st unix.Stat_t
			if unix.Lstat(filepath.Join(m.root, n), &st) == nil && st.Ino == ino {
				return n
			}
		}
	}
	return ""
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

// serviceOpen is the service user's openat of name through the data root
// with flag, closed again if it opens: nil when it opened.
func (m *keysRootMaint) serviceOpen(name string, flag int) error {
	return m.asService(func() error {
		fd, err := unix.Openat(int(m.dfd.Fd()), name, flag|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	})
}

// keysAttrEvent is one call of the probing writer and the file as it was
// just before it.
type keysAttrEvent struct {
	call  string
	arg   int
	ino   uint64
	uid   uint32
	mode  uint16
	flags uint32
}

// keysProbeAttrs is the real file-attribute writer with a hook run before
// each call, given the call and the file's state; a hook error fails the
// call, as a crash at that step would leave it.
type keysProbeAttrs struct {
	t      *testing.T
	before func(e keysAttrEvent) error
	events []keysAttrEvent
}

func (p *keysProbeAttrs) do(call string, fd, arg int, f func() error) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		p.t.Errorf("fstat before %s: %v", call, err)
		return err
	}
	e := keysAttrEvent{call: call, arg: arg, ino: st.Ino, uid: st.Uid, mode: st.Mode & 0o7777, flags: st.Flags}
	p.events = append(p.events, e)
	if p.before != nil {
		if err := p.before(e); err != nil {
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

// eventsOf is the events on inode ino, in order.
func (p *keysProbeAttrs) eventsOf(ino uint64) []keysAttrEvent {
	var out []keysAttrEvent
	for _, e := range p.events {
		if e.ino == ino {
			out = append(out, e)
		}
	}
	return out
}

// TestMaintenanceRefusesPlantedSymlinkAndSwap is U68, root-run: floor
// --rebuild and audit --rotate each refuse a symlink planted at the marker,
// at the staging directory or at the old log, a FIFO at the old log, and
// the old log swapped for another file while the verb holds it; audit
// --rotate also refuses a symlink at an archive. A second hard link at the
// old log is no refusal: the verb repairs it (pkg/keystore's
// TestMaintenanceRepairsHardLinkedLog). A refusal
// follows no planted name and changes no byte, owner or flag of either log
// (the audit log gains only the verb's own refused line), and leaves no
// marker or staging file of its own.
func TestMaintenanceRefusesPlantedSymlinkAndSwap(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U68): run as root through hack/acceptance/keystore.sh --root")
	}
	type plant struct {
		name string
		// at plants before the run and returns the planted name, if any,
		// which must still stand after it.
		at func(m *keysRootMaint, v keysMaintVerb, decoy string) string
		// midRun, when set, swaps the old log once the verb holds it.
		midRun bool
		// rotateOnly plants a name only audit --rotate has.
		rotateOnly bool
	}
	symlinkAt := func(name func(v keysMaintVerb) string) func(*keysRootMaint, keysMaintVerb, string) string {
		return func(m *keysRootMaint, v keysMaintVerb, decoy string) string {
			n := name(v)
			if n == v.log {
				m.moveAside(n)
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
		{name: "old log symlink", at: symlinkAt(func(v keysMaintVerb) string { return v.log })},
		{name: "old log FIFO", at: func(m *keysRootMaint, v keysMaintVerb, _ string) string {
			m.moveAside(v.log)
			if err := unix.Mkfifo(filepath.Join(m.root, v.log), 0o600); err != nil {
				m.t.Fatal(err)
			}
			return v.log
		}},
		{name: "old log swapped mid-run", midRun: true},
		{name: "archive symlink", rotateOnly: true, at: func(m *keysRootMaint, _ keysMaintVerb, decoy string) string {
			n := keystore.AuditLogName + ".1"
			if err := os.Symlink(decoy, filepath.Join(m.root, n)); err != nil {
				m.t.Fatal(err)
			}
			return n
		}},
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
				planted := ""
				if pl.at != nil {
					planted = pl.at(m, v, decoy)
				}
				var plantedBefore keysFileState
				if planted != "" {
					plantedBefore = keysState(t, filepath.Join(m.root, planted))
				}
				before := m.snapshot()
				if pl.midRun {
					// The verb's first attribute call is on its staging
					// file, after it opened the old log and before it
					// checks the name still holds it.
					swapped := false
					m.h.attrs = &keysProbeAttrs{t: t, before: func(keysAttrEvent) error {
						if !swapped {
							swapped = true
							m.moveAside(v.log)
							m.placeLog(v.log, "swapped in\n", true, true)
							before = m.snapshot()
						}
						return nil
					}}
				}
				m.h.mustRun(keysRefused, v.args...)
				after := m.snapshot()
				m.allowRefusedAuditLine(before, after)
				for n, b := range before {
					if a, ok := after[n]; !ok || a != b {
						t.Errorf("%s: %s changed: %+v, was %+v", pl.name, n, after[n], b)
					}
				}
				for n := range after {
					if _, ok := before[n]; !ok {
						t.Errorf("%s: the refused verb left %s", pl.name, n)
					}
				}
				if got := keysState(t, decoy); got != decoyBefore {
					t.Errorf("%s: the decoy a planted name points at changed: %+v, was %+v", pl.name, got, decoyBefore)
				}
				for _, n := range []string{keysMarkerName, keysStagingDir} {
					p := filepath.Join(m.root, n)
					if n == planted {
						if got := keysState(t, p); got != plantedBefore {
							t.Errorf("%s: the planted %s changed: %+v, was %+v", pl.name, n, got, plantedBefore)
						}
						continue
					}
					if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("%s: the refused verb left %s: %v", pl.name, n, err)
					}
				}
			})
		}
	}
}

// moveAside renames the log name to keystore-saved-<name>, flagged as it
// was, so a plant can take its name.
func (m *keysRootMaint) moveAside(name string) {
	m.t.Helper()
	p := filepath.Join(m.root, name)
	saved := filepath.Join(m.root, "keystore-saved-"+name)
	m.withFlagCleared(p, func() {
		if err := os.Rename(p, saved); err != nil {
			m.t.Fatal(err)
		}
	})
}

// withFlagCleared clears p's flags, runs f, and sets SF_APPEND again on p,
// or on keystore-saved-<p's name> when f moved p aside.
func (m *keysRootMaint) withFlagCleared(p string, f func()) {
	m.t.Helper()
	if err := unix.Chflags(p, 0); err != nil {
		m.t.Fatal(err)
	}
	f()
	saved := filepath.Join(m.root, "keystore-saved-"+filepath.Base(p))
	if _, err := os.Lstat(p); errors.Is(err, os.ErrNotExist) {
		p = saved
	}
	if err := unix.Chflags(p, keysSFAppend); err != nil {
		m.t.Fatal(err)
	}
}

// allowRefusedAuditLine accepts, on the canonical audit log, the one line
// the refused verb's audit appends: after holds before's bytes and one more
// line, which names the refusal.
func (m *keysRootMaint) allowRefusedAuditLine(before, after map[string]keysFileState) {
	m.t.Helper()
	b, okb := before[keystore.AuditLogName]
	a, oka := after[keystore.AuditLogName]
	if !okb || !oka || b.typ != unix.S_IFREG || !strings.HasPrefix(a.data, b.data) {
		return
	}
	extra := strings.TrimPrefix(a.data, b.data)
	extra = strings.TrimPrefix(extra, "\n")
	if strings.Count(extra, "\n") == 1 && strings.HasSuffix(extra, "\n") && strings.Contains(extra, `"refused"`) {
		a.data = b.data
		after[keystore.AuditLogName] = a
	}
}

// TestMaintenanceHandsOverOnlyAfterFlag is U90, root-run: for floor
// --rebuild and audit --rotate the new file is root's 0600 from its create
// until it is flagged, the service user cannot open it at any step before
// that, the old file's flag is cleared before the rename, and the hand-over
// to the service user is the last call on the new file, made once its flag
// is set. A crash at the flag or at the hand-over leaves the marker and a
// canonical log the flag check refuses, until a rerun finishes. The wait
// for the store lock is bounded at 30 s, after which the verb refuses,
// leaving no marker and no change.
func TestMaintenanceHandsOverOnlyAfterFlag(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U90): run as root through hack/acceptance/keystore.sh --root")
	}
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U90")
			oldIno := keysState(t, filepath.Join(m.root, v.log)).ino
			p := &keysProbeAttrs{t: t}
			p.before = func(e keysAttrEvent) error {
				n := m.nameOf(e.ino)
				if e.ino == oldIno {
					if e.call == "fchflags" && e.arg == 0 {
						// The old file's clear: the new file is written
						// and nothing is renamed yet.
						if _, err := os.Lstat(filepath.Join(m.root, v.staging)); err != nil {
							t.Errorf("the old %s's flag was cleared before the new file was written: %v", v.log, err)
						}
						if n != v.log {
							t.Errorf("the old %s's flag was cleared after it was renamed to %q", v.log, n)
						}
					}
					return nil
				}
				if n == "" || e.uid != 0 {
					return nil
				}
				// A root-owned file the verb is handling: the service user
				// opens it neither to read nor to write. The mode refuses
				// with EACCES; once the file is flagged a write-open is
				// refused by the flag first, with EPERM (K0 leg 1).
				for _, flag := range []int{unix.O_RDONLY, unix.O_WRONLY} {
					err := m.serviceOpen(n, flag)
					ok := errors.Is(err, unix.EACCES) || (flag != unix.O_RDONLY && e.flags&keysSFAppend != 0 && errors.Is(err, unix.EPERM))
					if !ok {
						t.Errorf("before %s(%#x) the service user's open of %s (flags %#x, file flags %#x): %v, want EACCES, or EPERM for a write-open of a flagged file", e.call, e.arg, n, flag, e.flags, err)
					}
				}
				return nil
			}
			m.h.attrs = p
			m.h.mustRun(keysOK, v.args...)
			newSt := keysState(t, filepath.Join(m.root, v.log))
			evs := p.eventsOf(newSt.ino)
			if len(evs) < 2 {
				t.Fatalf("the new %s saw %d attribute calls: %+v", v.log, len(evs), evs)
			}
			last, flag := evs[len(evs)-1], evs[len(evs)-2]
			if last.call != "fchown" || last.arg != int(m.svcUID) || last.flags&keysSFAppend == 0 {
				t.Errorf("the new %s's last call is %+v, want the hand-over to the service user with the flag already set", v.log, last)
			}
			if flag.call != "fchflags" || flag.arg != keysSFAppend {
				t.Errorf("the call before the hand-over is %+v, want the flag", flag)
			}
			for _, e := range evs[:len(evs)-1] {
				if e.uid != 0 || e.mode != 0o600 {
					t.Errorf("the new %s was not root's 0600 at %s(%#x): uid %d mode %04o", v.log, e.call, e.arg, e.uid, e.mode)
				}
			}
			if newSt.uid != m.svcUID || newSt.flags&keysSFAppend == 0 || newSt.mode != 0o600 {
				t.Errorf("the new %s ends %+v, want the service user's 0600 and flagged", v.log, newSt)
			}
			oldEvs := p.eventsOf(oldIno)
			if len(oldEvs) == 0 || oldEvs[0].call != "fchflags" || oldEvs[0].arg != 0 {
				t.Errorf("the old %s's first call is not its flag clear: %+v", v.log, oldEvs)
			}
		})
		for _, crash := range []struct {
			name string
			at   func(m *keysRootMaint, e keysAttrEvent) bool
		}{
			{"flag", func(_ *keysRootMaint, e keysAttrEvent) bool {
				return e.call == "fchflags" && e.arg == keysSFAppend && e.uid == 0 && e.flags == 0
			}},
			{"hand-over", func(m *keysRootMaint, e keysAttrEvent) bool {
				return e.call == "fchown" && e.arg == int(m.svcUID)
			}},
		} {
			t.Run(v.name+"/crash at the "+crash.name, func(t *testing.T) {
				m := keysMaintRoot(t, "U90")
				crashed := false
				m.h.attrs = &keysProbeAttrs{t: t, before: func(e keysAttrEvent) error {
					// The first matching call on the new file: for rotate,
					// .1 is flagged after the new log, so the first flag
					// set on a root file with no flag is the new log's.
					if !crashed && crash.at(m, e) && m.nameOf(e.ino) == v.log {
						crashed = true
						return errors.New("crashed here")
					}
					return nil
				}}
				m.h.mustRun(keysRefused, v.args...)
				if !crashed {
					t.Fatal("the crash point was never reached")
				}
				if _, err := os.Lstat(filepath.Join(m.root, keysMarkerName)); err != nil {
					t.Errorf("a crash past the old log's flag clear removed the marker: %v", err)
				}
				store := keystore.New(m.h.storeCfg)
				if err := store.CheckLogFlags(context.Background()); err == nil {
					t.Errorf("after a crash at the %s the flag check passes; want the canonical %s refused", crash.name, v.log)
				}
				m.h.attrs = realFileAttrWriter{}
				m.h.mustRun(keysOK, v.args...)
				if _, err := os.Lstat(filepath.Join(m.root, keysMarkerName)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the rerun left the marker: %v", err)
				}
				if err := store.CheckLogFlags(context.Background()); err != nil {
					t.Errorf("after the rerun the flag check refuses: %v", err)
				}
			})
		}
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

// TestMaintenanceOldFileRootOwnedWhileUnflagged is U118, root-run: in
// floor --rebuild and audit --rotate the step that clears the old log's
// flag, and each archive's that rotate shifts, also makes it root's 0600 on
// the verb's descriptor, with no other call between. Before each attribute
// call, on any file, and after the verb returns, the service user's
// open(O_WRONLY|O_TRUNC) of each changes no byte: EACCES while it is
// unflagged and root's 0600, EACCES or EPERM while the flag stands (the
// flag refuses a truncating open with EPERM, K0 leg 1). The point between
// the clear and the chown is residual 12's and is not probed: the flag
// refuses root's chown, so the clear comes first. Every archive is root's
// 0600 before rotate and ends root's 0600 and flagged.
func TestMaintenanceOldFileRootOwnedWhileUnflagged(t *testing.T) {
	if !keysAsRoot() {
		t.Skip("root-run (U118): run as root through hack/acceptance/keystore.sh --root")
	}
	for _, v := range keysMaintVerbs {
		t.Run(v.name, func(t *testing.T) {
			m := keysMaintRoot(t, "U118")
			// The control: a file of the service user's in the data root,
			// which it opens for writing, so an EACCES below is the file's.
			m.placeLog("keystore-control", "c\n", true, false)
			if err := m.serviceOpen("keystore-control", unix.O_WRONLY); err != nil {
				t.Fatalf("the service user cannot open its own file in the data root: %v", err)
			}
			watched := map[uint64]string{keysState(t, filepath.Join(m.root, v.log)).ino: "the old " + v.log}
			if v.log == keystore.AuditLogName {
				// Archives are root's 0600 and flagged, as rotate leaves them.
				for n := 1; n <= 3; n++ {
					name := fmt.Sprintf("%s.%d", keystore.AuditLogName, n)
					m.placeLog(name, fmt.Sprintf("archive %d\n", n), false, true)
					watched[keysState(t, filepath.Join(m.root, name)).ino] = name
				}
			}
			unflaggedProbed := map[uint64]bool{}
			probeAll := func(at string) {
				for ino, what := range watched {
					n := m.nameOf(ino)
					if n == "" {
						continue
					}
					p := filepath.Join(m.root, n)
					before := keysState(t, p)
					if before.flags&keysSFAppend == 0 && before.uid != 0 {
						continue // residual 12: between the clear and the chown
					}
					err := m.serviceOpen(n, unix.O_WRONLY|unix.O_TRUNC)
					switch {
					case before.flags&keysSFAppend == 0 && !errors.Is(err, unix.EACCES):
						t.Errorf("%s: the service user's O_WRONLY|O_TRUNC open of %s while unflagged (uid %d mode %04o): %v, want EACCES", at, what, before.uid, before.mode, err)
					case before.flags&keysSFAppend != 0 && !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM):
						t.Errorf("%s: the service user's O_WRONLY|O_TRUNC open of %s while flagged: %v, want EACCES or EPERM", at, what, err)
					}
					if before.flags&keysSFAppend == 0 {
						unflaggedProbed[ino] = true
					}
					if after := keysState(t, p); after.data != before.data {
						t.Errorf("%s: the service user's open changed %s: %q, was %q", at, what, after.data, before.data)
					}
				}
			}
			p := &keysProbeAttrs{t: t}
			p.before = func(e keysAttrEvent) error {
				probeAll(fmt.Sprintf("before %s(%#x)", e.call, e.arg))
				return nil
			}
			m.h.attrs = p
			m.h.mustRun(keysOK, v.args...)
			probeAll("after the verb")
			for ino, what := range watched {
				evs := p.eventsOf(ino)
				if len(evs) < 3 {
					t.Errorf("%s saw %+v, want its chown, chmod and flag clear", what, evs)
					continue
				}
				if evs[0].call != "fchflags" || evs[0].arg != 0 || evs[1].call != "fchown" || evs[1].arg != 0 || evs[2].call != "fchmod" || evs[2].arg != 0o600 {
					t.Errorf("%s's first calls are %+v, want the flag clear, then root's ownership and 0600", what, evs[:3])
				}
				if !unflaggedProbed[ino] {
					t.Errorf("%s was never probed while unflagged", what)
				}
			}
			// No other call between a clear and its chown and chmod.
			for i, e := range p.events {
				if e.call == "fchflags" && e.arg == 0 && watched[e.ino] != "" {
					if i+2 >= len(p.events) || p.events[i+1].ino != e.ino || p.events[i+2].ino != e.ino {
						t.Errorf("another call came between %s's chown, chmod and flag clear", watched[e.ino])
					}
				}
			}
			if v.log == keystore.AuditLogName {
				for n := 1; n <= 4; n++ {
					name := fmt.Sprintf("%s.%d", keystore.AuditLogName, n)
					st := keysState(t, filepath.Join(m.root, name))
					if st.uid != 0 || st.mode != 0o600 || st.flags&keysSFAppend == 0 {
						t.Errorf("%s ends %+v, want root's 0600 and flagged", name, st)
					}
				}
				if got := keysState(t, filepath.Join(m.root, keystore.AuditLogName+".4")).data; got != "archive 3\n" {
					t.Errorf(".4 holds %q, want the old .3", got)
				}
			}
		})
	}
}
