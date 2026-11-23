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
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// The gated swap floor --rebuild and audit --rotate share
// (docs/design/keystore.md § "The swap"). SF_APPEND refuses root's fchown,
// fchmod, rename, link, unlink and O_TRUNC open of a flagged file (the
// 2026-11-23 probe), so a log is handed to its owner first and flagged
// last, and the old one is never chowned or reused: it is unflagged and
// unlinked. What closes the windows between those steps is the gate:
// fchmod of keystore-logs/ to 0700, so no other user can look a name up in
// it while the swap runs.
//
// The steps, each a function below:
//  1. marker, then the locks (beginMaintenance);
//  2. read the old log under its flag (the verb: readOldFloor, rotate's
//     archive copy);
//  3. write the new log in keystore-staging/, fsync, fchown to the service
//     user, fchmod 0600 (stageNewLog);
//  4. close the gate (closeGate);
//  5. re-read the old log's tail from where step 2 stopped (readTail);
//  6. retire the old log: fchflags 0, unlinkat (retireOld), then the verb's
//     retire hook (rotate shifts the archives);
//  7. renameatx_np(RENAME_EXCL) of the new log to its canonical name
//     (placeNewLog);
//  8. fchflags SF_APPEND on the held descriptor, then judge it (flagNewLog);
//  9. fsync the directories and open the gate (openGate); the marker goes
//     in end, and the caller writes the audit line (AuditRoot).

// logSwap is one swap's inputs.
type logSwap struct {
	// canonical is the log's name in keystore-logs/, staging the new log's
	// name in keystore-staging/.
	canonical, staging string
	// old is the canonical log as step 2 opened and read it, through off.
	old *os.File
	off int64
	// content is the new log's first content (rebuild's merged lines).
	content []byte
	// tail takes the bytes old gained past off (step 5) and returns what
	// to append to the new log; nil appends nothing and reads nothing.
	tail func([]byte) ([]byte, error)
	// retire runs once the old name is unlinked (step 6); may be nil.
	retire func() error
}

// swapLog runs steps 3 to 9 for sw. A failure before the gate closes
// removes the staging file and refuses, the old log untouched; from the
// gate's close on a failure keeps the marker, so the listener stays down
// until a rerun, which resumeSwap finishes.
func (s *FileStore) swapLog(m *maintenance, sw logSwap, attrs FileAttrWriter) error {
	if err := m.step(swapStepStage); err != nil {
		m.refused()
		return fmt.Errorf("%w: %w", m.refusal, err)
	}
	nf, err := s.stageNewLog(m, sw.staging, sw.content, attrs)
	if err != nil {
		m.refused()
		return fmt.Errorf("%w: %w", m.refusal, err)
	}
	defer func() { _ = nf.Close() }() // fsynced before the rename
	// From here a failure leaves the marker: the listener stays down.
	m.keep = true
	if err := m.closeGate(attrs); err != nil {
		return err
	}
	if sw.old != nil {
		if err := m.step(swapStepReadTail); err != nil {
			return err
		}
		if err := readTail(sw, nf); err != nil {
			return err
		}
		if err := m.retireOld(sw.old, sw.canonical, attrs); err != nil {
			return err
		}
	}
	if sw.retire != nil {
		if err := sw.retire(); err != nil {
			return err
		}
	}
	return s.placeNewLog(m, nf, sw.staging, sw.canonical, attrs)
}

// stageNewLog is step 3: a stale staging file is removed, the new log is
// created O_CREAT|O_EXCL|O_NOFOLLOW in keystore-staging/, where no other
// user can reach it, written, fsynced, handed to the service user and set
// to 0600, each on the held descriptor. The returned file is open for
// writing, so step 5 can append to it.
func (s *FileStore) stageNewLog(m *maintenance, staging string, content []byte, attrs FileAttrWriter) (*os.File, error) {
	if err := removeStale(m.sfd, staging, s.floorUID, int(s.uid), attrs); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(m.sfd, staging, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", staging, err)
	}
	nf := os.NewFile(uintptr(fd), staging)
	fail := func(err error) (*os.File, error) {
		_ = nf.Close()                       // nothing else holds it
		_ = unix.Unlinkat(m.sfd, staging, 0) // the old log is untouched
		return nil, err
	}
	if _, err := nf.Write(content); err != nil {
		return fail(fmt.Errorf("write %s: %w", staging, err))
	}
	if err := nf.Sync(); err != nil {
		return fail(fmt.Errorf("fsync %s: %w", staging, err))
	}
	if err := attrs.Fchown(fd, int(s.uid), int(s.gid)); err != nil {
		return fail(fmt.Errorf("hand %s to the service user: %w", staging, err))
	}
	if err := attrs.Fchmod(fd, logMode); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", staging, err))
	}
	return nf, nil
}

// closeGate is step 4: keystore-logs/ to 0700, which closes it to every
// lookup but root's.
func (m *maintenance) closeGate(attrs FileAttrWriter) error {
	if err := attrs.Fchmod(m.lfd, logsGateMode); err != nil {
		return fmt.Errorf("close %s (mode 0700): %w; rerun the verb", logsDirName, err)
	}
	return nil
}

// openGate is step 9: the directories are fsynced and keystore-logs/ goes
// back to 0755. The swap is done: the marker may go (a step seam that fails
// at swapStepEnd keeps it, as a crash before its removal would).
func (m *maintenance) openGate(attrs FileAttrWriter) error {
	for _, d := range []struct {
		fd   int
		name string
	}{{m.sfd, stagingDirName}, {m.lfd, logsDirName}, {m.dfd, "the data root"}} {
		if err := unix.Fsync(d.fd); err != nil {
			return fmt.Errorf("fsync %s: %w; rerun the verb", d.name, err)
		}
	}
	if err := attrs.Fchmod(m.lfd, logsDirMode); err != nil {
		return fmt.Errorf("open %s (mode 0755): %w; rerun the verb", logsDirName, err)
	}
	if err := m.step(swapStepEnd); err != nil {
		return err
	}
	m.keep = false
	return nil
}

// readTail is step 5: the bytes the old log gained from sw.off to its end,
// read through the descriptor step 2 held, go to sw.tail, and what it
// returns is appended to the new log, which is fsynced.
func readTail(sw logSwap, nf *os.File) error {
	if sw.tail == nil {
		return nil
	}
	b, err := io.ReadAll(io.NewSectionReader(sw.old, sw.off, 1<<62))
	if err != nil {
		return fmt.Errorf("re-read the tail of %s: %w; rerun the verb", sw.canonical, err)
	}
	add, err := sw.tail(b)
	if err != nil {
		return err
	}
	if len(add) > 0 {
		if _, err := nf.Write(add); err != nil {
			return fmt.Errorf("append the tail of %s: %w; rerun the verb", sw.canonical, err)
		}
	}
	if err := nf.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w; rerun the verb", sw.staging, err)
	}
	return nil
}

// retireOld is step 6: the canonical name must still hold the file old
// holds; its flag is cleared on old's descriptor and its name unlinked. It
// is never chowned and its inode never reused: a process holding it now
// writes to an orphan.
func (m *maintenance) retireOld(old *os.File, canonical string, attrs FileAttrWriter) error {
	var named, held unix.Stat_t
	if err := unix.Fstatat(m.lfd, canonical, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat %s: %w; rerun the verb", canonical, err)
	}
	if err := unix.Fstat(int(old.Fd()), &held); err != nil {
		return fmt.Errorf("stat %s: %w; rerun the verb", canonical, err)
	}
	if named.Dev != held.Dev || named.Ino != held.Ino {
		return fmt.Errorf("%w: %s was replaced while the verb held it; rerun the verb", errLogUntrusted, canonical)
	}
	if err := attrs.Fchflags(int(old.Fd()), 0); err != nil {
		return fmt.Errorf("clear the flag of the old %s: %w; rerun the verb", canonical, err)
	}
	if err := m.step(swapStepUnlinkOld); err != nil {
		return err
	}
	if err := unix.Unlinkat(m.lfd, canonical, 0); err != nil {
		return fmt.Errorf("unlink the old %s: %w; rerun the verb", canonical, err)
	}
	return nil
}

// placeNewLog is steps 7 to 9: the staged new log is renamed to canonical
// only while nothing stands there, flagged and judged (flagNewLog), and the
// gate opened.
func (s *FileStore) placeNewLog(m *maintenance, nf *os.File, staging, canonical string, attrs FileAttrWriter) error {
	if err := m.step(swapStepRename); err != nil {
		return err
	}
	if err := renameExcl(m.sfd, staging, m.lfd, canonical); err != nil {
		return fmt.Errorf("rename %s to %s: %w; rerun the verb", staging, canonical, err)
	}
	if err := s.flagNewLog(nf, canonical, attrs); err != nil {
		return err
	}
	return m.openGate(attrs)
}

// flagNewLog is step 8: SF_APPEND on the held descriptor, then the
// steady-state judge on it: the service user's, 0600, flags exactly
// SF_APPEND, one link, no ACL.
func (s *FileStore) flagNewLog(nf *os.File, canonical string, attrs FileAttrWriter) error {
	if err := attrs.Fchflags(int(nf.Fd()), sfAppend); err != nil {
		return fmt.Errorf("flag the new %s append-only: %w; rerun the verb", canonical, err)
	}
	var st unix.Stat_t
	if err := s.judgeLog(nf, &st); err != nil {
		return fmt.Errorf("the new %s: %w; rerun the verb", canonical, err)
	}
	return nil
}

// resumeSwap finishes a swap a crash left past step 6, before the verb
// reads anything, and reports whether it did:
//   - the canonical log missing, with the marker from that run: the old log
//     was unlinked, so the staged new log is whole; retire (rotate's archive
//     shift, which skips what is done) runs, then steps 7 to 9;
//   - the gate closed, the canonical log present and nothing staged: the
//     new log was renamed in; it is flagged when its flag is clear, judged,
//     and the gate opened;
//   - with the marker from that run, the gate open, nothing staged and the
//     canonical log judged and born no earlier than the marker: the swap
//     finished and the crash came before the marker went (swapFinished).
//     Nothing is redone (a rotate would archive the new, empty log): the
//     marker goes and the caller writes the audit line.
//
// Any other state is a swap to run from step 2: the canonical log is the
// old one (unflagged, when the crash came between the flag clear and the
// unlink), and a staged file is stale.
func (s *FileStore) resumeSwap(m *maintenance, canonical, staging string, retire func() error, attrs FileAttrWriter) (bool, error) {
	var dst, cst unix.Stat_t
	if err := unix.Fstat(m.lfd, &dst); err != nil {
		m.refused()
		return false, fmt.Errorf("%w: stat %s: %w", m.refusal, logsDirName, err)
	}
	gateClosed := dst.Mode&0o7777 == logsGateMode
	cerr := unix.Fstatat(m.lfd, canonical, &cst, unix.AT_SYMLINK_NOFOLLOW)
	var sst unix.Stat_t
	serr := unix.Fstatat(m.sfd, staging, &sst, unix.AT_SYMLINK_NOFOLLOW)
	staged := serr == nil
	switch {
	case errors.Is(cerr, unix.ENOENT) && m.crashed:
		if !staged {
			return false, nil // the verb refuses a missing log
		}
		nf, err := s.openStaged(m.sfd, staging)
		if err != nil {
			return true, fmt.Errorf("%w; rerun the verb", err)
		}
		defer func() { _ = nf.Close() }() // read-only
		m.keep = true
		if err := m.closeGate(attrs); err != nil {
			return true, err
		}
		if retire != nil {
			if err := retire(); err != nil {
				return true, err
			}
		}
		return true, s.placeNewLog(m, nf, staging, canonical, attrs)
	case cerr == nil && gateClosed && !staged:
		fd, err := unix.Openat(m.lfd, canonical, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return true, fmt.Errorf("open %s: %w; rerun the verb", canonical, err)
		}
		nf := os.NewFile(uintptr(fd), canonical)
		defer func() { _ = nf.Close() }() // read-only
		if err := s.judgeUnflagged(nf, canonical, true); err != nil {
			return true, fmt.Errorf("%w; rerun the verb", err)
		}
		m.keep = true
		if fl, err := fdFlags(fd); err != nil || fl != sfAppend {
			if err := s.flagNewLog(nf, canonical, attrs); err != nil {
				return true, err
			}
		} else if err := s.judgeLog(nf, &cst); err != nil {
			return true, fmt.Errorf("the new %s: %w; rerun the verb", canonical, err)
		}
		return true, m.openGate(attrs)
	case cerr == nil && !gateClosed && !staged && m.crashed:
		return s.swapFinished(m, canonical, &cst), nil
	}
	return false, nil
}

// swapFinished reports whether the canonical log, which cst describes, is
// the new log of the crashed run whose marker still stands: it passes the
// steady-state judge and was born no earlier than the marker, which that
// run wrote before it created the log. A log from before the run (a crash
// before step 3) was born earlier, and the verb runs again. Without birth
// times on either it reports false, and the verb runs again.
func (s *FileStore) swapFinished(m *maintenance, canonical string, cst *unix.Stat_t) bool {
	var mst unix.Stat_t
	if unix.Fstatat(m.dfd, maintenanceMarkerName, &mst, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	lb, mb := logBirth(cst), logBirth(&mst)
	if (lb == unix.Timespec{}) || (mb == unix.Timespec{}) || lb.Nano() < mb.Nano() {
		return false
	}
	fd, err := unix.Openat(m.lfd, canonical, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), canonical)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if s.judgeLog(f, &st) != nil || st.Ino != cst.Ino || st.Dev != cst.Dev {
		return false
	}
	return true
}

// openStaged opens the staged new log name in the staging directory sfd
// and judges it as step 3 leaves it (judgeUnflagged).
func (s *FileStore) openStaged(sfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(sfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	if err := s.judgeUnflagged(f, name, false); err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	return f, nil
}

// judgeUnflagged refuses f unless it is a regular file with one link, the
// service user's at 0600, with no flag (or SF_APPEND alone, when flagOK)
// and no ACL, read on its descriptor: a new log as step 3 or step 8 leaves
// it.
func (s *FileStore) judgeUnflagged(f *os.File, name string, flagOK bool) error {
	var st unix.Stat_t
	fd := int(f.Fd())
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != s.uid || st.Mode&0o7777 != logMode {
		return fmt.Errorf("%w: %s is not a regular file with one link, the service user's at 0600", errLogUntrusted, name)
	}
	fl, err := fdFlags(fd)
	if err != nil {
		return fmt.Errorf("%w: read the flags of %s: %w", errLogUntrusted, name, err)
	}
	if fl != 0 && (!flagOK || fl != sfAppend) {
		return fmt.Errorf("%w: %s carries a file flag", errLogUntrusted, name)
	}
	return judgeFlagsACL(fd, func(int) (uint32, error) { return fl, nil })
}

// removeStale removes a staging file a crashed run left at name in the
// staging directory dfd: opened O_NOFOLLOW through dfd, refused unless a
// regular file with one link owned by rootUID (the data root's owner) or
// by the service user svcUID (a staged new log), its flag cleared on its
// descriptor, then unlinked with unlinkat. No other user can reach the
// staging directory, so the file holds nothing anyone else wrote. A missing
// name is fine.
func removeStale(dfd int, name string, rootUID, svcUID int, attrs FileAttrWriter) error {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errLogUntrusted, name, err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (int64(st.Uid) != int64(rootUID) && int64(st.Uid) != int64(svcUID)) {
		return fmt.Errorf("%w: %s is not a regular file with one link, of the data root's owner or the service user", errLogUntrusted, name)
	}
	if fl, err := fdFlags(fd); err != nil || fl != 0 {
		if err := attrs.Fchflags(fd, 0); err != nil {
			return fmt.Errorf("clear the flag of %s: %w", name, err)
		}
	}
	return unix.Unlinkat(dfd, name, 0)
}
