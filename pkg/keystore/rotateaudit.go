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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// The root maintenance verb audit --rotate (docs/design/keystore.md § "Root
// maintenance verbs", "audit --rotate keeps four archives"): it swaps in a
// replacement audit/ directory holding an empty, flagged log and an
// archives/ directory (root's 0700) with the old log's bytes as
// keystore-audit.log.1 and the older archives one number up, by the same
// directory swap as floor --rebuild.

// auditArchives is how many archives rotate keeps: .1, the newest, to .4.
const auditArchives = 4

// auditArchiveName is the n-th archive's name in audit/archives/.
func auditArchiveName(n int) string { return auditLogName + "." + strconv.Itoa(n) }

// errRotateRefused marks a rotate that refused before its swap: nothing
// changed.
var errRotateRefused = errors.New("audit --rotate refused and changed nothing")

// RotateReport is what audit --rotate did: the archives kept after it,
// and whether it discarded the oldest.
type RotateReport struct {
	Archives  int
	Discarded bool
	// Earlier is set when the report is an earlier run's, which committed
	// and was not reported: this run printed it and did not rotate.
	Earlier bool
}

// RotateAudit rotates the audit log (audit --rotate). Run as root: it
// takes the floor lock, then the exclusive store lock, waiting at most 30
// s, writes the maintenance marker, opens and judges audit/archives/
// (openArchivesDir: root's 0700, unflagged, no ACL; absent, no archives)
// and every archive present in it (judgeArchives: root's 0600, unflagged,
// regular). It refuses,
// changing nothing, when keystore-audit.log.4 exists unless discardOldest.
// It opens and judges the old log (openOldLog) and builds the replacement
// directory (buildLogDir): an empty, flagged new log; and archives/, root's
// 0700, holding .1, a fresh root 0600 copy of the old log's bytes, read
// once and bounded by its size at open, and .2 to .4, hard links of the old
// .1 to .3 (link leaves the live directory untouched). The old .4 is not linked, so the swap drops it. The
// directory is swapped in (swapLogDir). A rerun after a crash past the swap
// reports the crashed run and does not rotate again.
func (s *FileStore) RotateAudit(ctx context.Context, attrs FileAttrWriter, discardOldest bool) (RotateReport, error) {
	var rep RotateReport
	if err := s.checkConfig(); err != nil {
		return rep, err
	}
	m, err := s.beginMaintenance(ctx, verbRotate, auditLogName, errRotateRefused, attrs)
	if err != nil {
		return rep, err
	}
	defer m.end()
	if m.saved != nil {
		return RotateReport{Archives: int(m.saved["archives"]), Discarded: m.saved["discarded"] != 0, Earlier: true}, nil
	}
	if err := m.step(swapStepReadOld); err != nil {
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	old, err := s.openOldLog(m.lfd, auditLogName)
	if err != nil {
		return rep, fmt.Errorf("%w: the audit log %s cannot be opened: %w", errRotateRefused, auditLogName, err)
	}
	defer old.close()
	adir, err := s.openArchivesDir(old.dir)
	if err != nil {
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if adir >= 0 {
		defer func() { _ = unix.Close(adir) }() // read-only directory descriptor
	}
	present, err := s.judgeArchives(adir)
	if err != nil {
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if present[auditArchives] && !discardOldest {
		return rep, fmt.Errorf("%w: %s exists, and rotate keeps %d archives: export the archives first (as root, copy them from %s/%s/%s/ in the data root off the Mac), then rerun with --discard-oldest, which deletes it", errRotateRefused, auditArchiveName(auditArchives), auditArchives, logsDirName, auditDirName, archivesDirName)
	}
	rep.Archives, rep.Discarded = 1, present[auditArchives]
	for n := 1; n < auditArchives; n++ {
		if present[n] {
			rep.Archives++
		}
	}
	extra := func(dir int) error { return s.placeArchives(old, adir, dir, present) }
	report := map[string]int64{"archives": int64(rep.Archives), "discarded": 0}
	if rep.Discarded {
		report["discarded"] = 1
	}
	empty := func(io.Writer) error { return nil }
	if err := s.swapLogDir(m, auditLogName, empty, extra, report, attrs); err != nil {
		return rep, err
	}
	return rep, nil
}

// placeArchives is rotate's part of step 3, in the replacement directory
// open at dir: archives/ created root's 0700, opened O_DIRECTORY|O_NOFOLLOW
// and judged; in it .1, the old log's first old.size bytes, root's 0600
// and unflagged: a clone of the old log (cloneArchive), so rotate needs no
// free space the size of a log the service user can grow, or, when the
// volume refuses the clone, a copy after a free-space check
// (copyArchive); then each
// present archive .n of .1 to .3 hard-linked from the live archives/
// (adir) as .n+1; archives/ is fsynced.
func (s *FileStore) placeArchives(old *oldLog, adir, dir int, present [auditArchives + 1]bool) error {
	if err := unix.Mkdirat(dir, archivesDirName, archivesDirMode); err != nil {
		return fmt.Errorf("create the new %s: %w", archivesDirName, err)
	}
	nad, err := unix.Openat(dir, archivesDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the new %s: %w", archivesDirName, err)
	}
	defer func() { _ = unix.Close(nad) }() // fsynced below
	// The umask may have narrowed the mode; it is set on the descriptor.
	if err := unix.Fchmod(nad, archivesDirMode); err != nil {
		return fmt.Errorf("chmod the new %s: %w", archivesDirName, err)
	}
	if err := s.judgeArchivesDir(nad); err != nil {
		return fmt.Errorf("the new %s: %w", archivesDirName, err)
	}
	if err := cloneArchive(old, nad, auditArchiveName(1)); errors.Is(err, errCloneRefused) {
		if err := copyArchive(old, nad, auditArchiveName(1), err); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for n := auditArchives - 1; n >= 1; n-- {
		if !present[n] {
			continue
		}
		if err := unix.Linkat(adir, auditArchiveName(n), nad, auditArchiveName(n+1), 0); err != nil {
			return fmt.Errorf("link %s as the new %s: %w", auditArchiveName(n), auditArchiveName(n+1), err)
		}
	}
	if err := unix.Fsync(nad); err != nil {
		return fmt.Errorf("fsync the new %s: %w", archivesDirName, err)
	}
	return nil
}

// openArchivesDir opens archives/ in the live audit/ directory dir
// O_DIRECTORY|O_NOFOLLOW and judges it (judgeArchivesDir). An absent
// archives/ holds no archive: it returns -1 and no error.
func (s *FileStore) openArchivesDir(dir int) (int, error) {
	fd, err := unix.Openat(dir, archivesDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, nil
	}
	if err != nil {
		return -1, fmt.Errorf("%w: open %s/%s: %w; as root, move it aside, recreate it root's 0700 and put the archives back in it, then rerun", errLogUntrusted, auditDirName, archivesDirName, err)
	}
	if err := s.judgeArchivesDir(fd); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, err
	}
	return fd, nil
}

// judgeArchivesDir refuses the archives directory open at fd unless it is
// a directory of the data root's owner (root) at mode 0700, with no file
// flag and no extended ACL.
func (s *FileStore) judgeArchivesDir(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", archivesDirName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o7777 != archivesDirMode {
		return fmt.Errorf("%w: %s/%s is not a directory of the data root's owner at mode 0700; as root, set it so (sudo chown root:wheel and sudo chmod 0700), then rerun", errLogUntrusted, auditDirName, archivesDirName)
	}
	fl, err := fdFlags(fd)
	if err != nil {
		return fmt.Errorf("%w: read the flags of %s: %w", errLogUntrusted, archivesDirName, err)
	}
	if fl != 0 {
		return fmt.Errorf("%w: %s/%s carries a file flag; as root, clear it (sudo chflags 0), then rerun", errLogUntrusted, auditDirName, archivesDirName)
	}
	if err := judgeFlagsACL(fd, func(int) (uint32, error) { return fl, nil }); err != nil {
		return fmt.Errorf("%s/%s: %w; as root, remove the ACL (sudo chmod -N), then rerun", auditDirName, archivesDirName, err)
	}
	return nil
}

// judgeArchives reports, by number, which archives are present in the
// archives directory dir (none when dir is -1), refusing
// any name that is not a regular file of the data root's owner (root) at
// mode 0600, unflagged: a planted symlink or FIFO, or a file the service user owns, at
// an archive's name refuses the rotate before anything changes. An archive
// with more than one link is a Warn: rotate renames it, and an alias of a
// root 0600 file gives the service user nothing.
func (s *FileStore) judgeArchives(dir int) ([auditArchives + 1]bool, error) {
	var present [auditArchives + 1]bool
	if dir < 0 {
		return present, nil
	}
	for n := 1; n <= auditArchives; n++ {
		name := auditArchiveName(n)
		var st unix.Stat_t
		err := unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return present, fmt.Errorf("stat %s: %w", name, err)
		}
		if err := s.judgeArchive(name, &st); err != nil {
			return present, err
		}
		present[n] = true
	}
	return present, nil
}

// judgeArchive refuses the archive name, which st describes, unless it is
// an unflagged regular file of the data root's owner at mode 0600, and logs a Warn
// when it has more than one link.
func (s *FileStore) judgeArchive(name string, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o7777 != logMode || statFlags(st) != 0 {
		return fmt.Errorf("%w: %s is not an unflagged regular file, root's 0600; as root, move it out of %s/%s/ or set it so, then rerun", errLogUntrusted, name, auditDirName, archivesDirName)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore audit archive has more than one link; it is root's 0600, so the other link gives no other user anything", "archive", name, "links", st.Nlink)
	}
	return nil
}

// errCloneRefused is a clone of the old log the volume refused: nothing
// was created, and rotate copies instead.
var errCloneRefused = errors.New("the audit log could not be cloned")

// cloneArchive makes name in the root-only archives directory nad a clone
// of the old log (cloneFileAt), then makes it the archive: the clone holds
// the whole file and its flag, so on its own descriptor its flag is
// cleared, it is made the caller's (root's) at mode 0600, and, reopened
// for writing and checked as the same inode, it is truncated to the size
// the old log had at open (the snapshot rule), fsynced and verified. It is
// a fresh inode in a directory only root reaches, so no other process can
// act on it meanwhile. A clone the volume refuses is errCloneRefused with
// nothing created.
func cloneArchive(old *oldLog, nad int, name string) error {
	if err := cloneFileAt(int(old.f.Fd()), nad, name); err != nil {
		return fmt.Errorf("%w: %w", errCloneRefused, err)
	}
	rfd, err := unix.Openat(nad, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the cloned %s: %w", name, err)
	}
	defer func() { _ = unix.Close(rfd) }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(rfd, &st); err != nil {
		return fmt.Errorf("stat the cloned %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return fmt.Errorf("the cloned %s is not a regular file with one link", name)
	}
	if statFlags(&st) != 0 {
		if err := unix.Fchflags(rfd, 0); err != nil {
			return fmt.Errorf("clear the flags of the cloned %s: %w", name, err)
		}
	}
	euid := os.Geteuid()
	if err := unix.Fchown(rfd, euid, -1); err != nil {
		return fmt.Errorf("chown the cloned %s: %w", name, err)
	}
	if err := unix.Fchmod(rfd, logMode); err != nil {
		return fmt.Errorf("chmod the cloned %s: %w", name, err)
	}
	if st.Size < old.size {
		return fmt.Errorf("the cloned %s holds %d bytes, fewer than the %d the audit log held at open", name, st.Size, old.size)
	}
	wfd, err := unix.Openat(nad, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the cloned %s for writing: %w", name, err)
	}
	defer func() { _ = unix.Close(wfd) }() // fsynced below
	var w unix.Stat_t
	if err := unix.Fstat(wfd, &w); err != nil {
		return fmt.Errorf("stat the cloned %s: %w", name, err)
	}
	if w.Dev != st.Dev || w.Ino != st.Ino {
		return fmt.Errorf("the cloned %s was replaced while it was made the archive", name)
	}
	if err := unix.Ftruncate(wfd, old.size); err != nil {
		return fmt.Errorf("truncate the cloned %s to the log's size at open: %w", name, err)
	}
	if err := unix.Fsync(wfd); err != nil {
		return fmt.Errorf("fsync the cloned %s: %w", name, err)
	}
	if err := unix.Fstat(wfd, &w); err != nil {
		return fmt.Errorf("stat the cloned %s: %w", name, err)
	}
	if int(w.Uid) != euid || w.Mode&0o7777 != logMode || statFlags(&w) != 0 || w.Nlink != 1 || w.Size != old.size {
		return fmt.Errorf("the cloned %s is not the caller's, mode %04o, unflagged, one link and %d bytes after it was set so", name, logMode, old.size)
	}
	return nil
}

// copyRoomSlack is the free space a copy leaves on the volume beyond the
// copied bytes.
const copyRoomSlack = 1 << 20

// volumeFree is the free space, in bytes, of the volume holding the open
// directory fd. It is a variable so a test can make a volume full.
var volumeFree = defaultVolumeFree

// defaultVolumeFree is volumeFree's fstatfs.
func defaultVolumeFree(fd int) (int64, error) {
	var sf unix.Statfs_t
	if err := unix.Fstatfs(fd, &sf); err != nil {
		return 0, err
	}
	return int64(sf.Bavail) * int64(sf.Bsize), nil
}

// copyArchive makes name in nad a copy of the old log's first old.size
// bytes, root's 0600, when the clone was refused (why). It first checks
// that the volume has room for the copy and refuses up front, before any
// byte is written, when it does not: the service user can grow the log,
// and a copy that fills the volume would stall every writer.
func copyArchive(old *oldLog, nad int, name string, why error) error {
	free, err := volumeFree(nad)
	if err != nil {
		return fmt.Errorf("read the free space of the data root's volume: %w", err)
	}
	if free < old.size+copyRoomSlack {
		return fmt.Errorf("%w: %v, and copying it into %s needs %d bytes free on the data root's volume, which has %d; free space on that volume, then rerun; nothing was changed", errRotateRefused, why, name, old.size+copyRoomSlack, free)
	}
	fd, err := unix.Openat(nad, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
	if err != nil {
		return fmt.Errorf("create the new %s: %w", name, err)
	}
	af := os.NewFile(uintptr(fd), name)
	defer func() { _ = af.Close() }() // fsynced below
	if err := unix.Fchmod(fd, logMode); err != nil {
		return fmt.Errorf("chmod the new %s: %w", name, err)
	}
	if _, err := io.Copy(af, io.NewSectionReader(old.f, 0, old.size)); err != nil {
		return fmt.Errorf("copy %s to the new %s: %w", auditLogName, name, err)
	}
	if err := af.Sync(); err != nil {
		return fmt.Errorf("fsync the new %s: %w", name, err)
	}
	return nil
}
