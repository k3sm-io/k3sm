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
	"bytes"
	"context"
	"encoding/json"
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
// replacement audit/ directory holding a flagged log, empty but for the
// server's persisted counts (rotateDroppedLines), and an
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
// directory (buildLogDir): a flagged new log holding only one line per class
// of the persisted pre-frame refusal counts (rotateDroppedLines), which are
// taken out of the file once the swap committed (clearRotatedDropped); and archives/, root's
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
		return RotateReport{Archives: int(m.saved["archives"]), Discarded: m.saved["discarded"] != 0, Earlier: true}, m.savedErr
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
	dropped, lines := s.rotateDroppedLines(m.root)
	content := func(w io.Writer) error {
		_, err := w.Write(lines)
		return err
	}
	if err := s.swapLogDir(m, auditLogName, content, extra, report, attrs); err != nil {
		return rep, err
	}
	s.clearRotatedDropped(m.root, dropped)
	return rep, nil
}

// rotateDroppedLines reads the server's persisted counts
// (PreFrameDroppedName) through root, the store directory the run judged
// and holds, and returns them with the lines rotate writes at the start of
// the new audit log for them: one per class with a count, in class order
// (countClasses), the summary-line form the server writes (preFrameRecord)
// with via root and caller uid 0, so it reads as no pre-frame line and is
// charged to no uid's share nor to the pre-frame part
// (docs/design/keystore.md § "Per-uid fairness": root's next audit
// --rotate writes any count still unwritten as one line charged to no
// uid). The post-frame and unaudited lines name their count in their
// source too. A file that does not read writes no line and is left for
// doctor to report: it never blocks the rotation.
func (s *FileStore) rotateDroppedLines(root *os.Root) (preFrameDropped, []byte) {
	d, err := s.readPreFrameDropped(root)
	if err != nil {
		slog.Warn("keystore audit --rotate: the persisted server counts do not read, so the new audit log carries no line for them; doctor reports it", "file", PreFrameDroppedName, "err", err)
		return newPreFrameDropped(), nil
	}
	totals := d.totals()
	var out []byte
	for _, c := range countClasses {
		if totals[c] == 0 {
			continue
		}
		rec := preFrameRecord(0, auditResultDropped, c, totals[c], s.now())
		rec.Via = auditViaRoot
		if !preFrameCount(c) {
			rec.Source = string(c) // the count it carries: post-frame or unaudited
		}
		line, err := json.Marshal(rec)
		if err != nil {
			continue // a fixed shape of strings and integers always encodes
		}
		out = append(append(out, line...), '\n')
	}
	return d, out
}

// clearRotatedDropped takes the counts rotate wrote (written) out of the
// persisted file once the swap committed, through root: what the server
// added since rotate read it stays. A failure is logged, not returned: the
// rotate stands, and the counts left are written again by the next one.
func (s *FileStore) clearRotatedDropped(root *os.Root, written preFrameDropped) {
	if written.empty() {
		return
	}
	cur, err := s.readPreFrameDropped(root)
	if err == nil {
		mergeDelta(cur.uids, nil, written.uids)
		mergeDelta(cur.others, nil, written.others)
		err = s.writePreFrameDropped(root, cur)
	}
	if err != nil {
		slog.Warn("keystore audit --rotate: the new audit log carries the server counts, but they were not taken out of the persisted file; the next rotate writes them again", "file", PreFrameDroppedName, "err", err)
	}
}

// placeArchives is rotate's part of step 3, in the replacement directory
// open at dir: archives/ created root's 0700, opened O_DIRECTORY|O_NOFOLLOW
// and judged; in it .1, the old log's first old.size bytes, root's 0600
// and unflagged: a clone of the old log (cloneArchive), so rotate needs no
// free space the size of a log the service user can grow, or, when the
// volume refuses the clone or an extended attribute on it cannot be
// removed, a copy after a free-space check
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
	if err := archiveLog(old, nad, auditArchiveName(1)); err != nil {
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

// archiveLog makes name in the root-only archives directory nad the
// archive of the old log: a clone (cloneArchive) or, when the clone is
// refused or discarded (errCloneRefused), a copy (copyArchive).
func archiveLog(old *oldLog, nad int, name string) error {
	err := cloneArchive(old, nad, name)
	if errors.Is(err, errCloneRefused) {
		return copyArchive(old, nad, name, err)
	}
	return err
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
		if err := s.judgeArchive(dir, name, &st); err != nil {
			return present, err
		}
		present[n] = true
	}
	return present, nil
}

// judgeArchive refuses the archive name in the archives directory dir,
// which st describes, unless it is an unflagged regular file of the data
// root's owner at mode 0600 with no extended ACL, read on a descriptor
// opened O_NOFOLLOW and checked as the inode st describes; it logs a Warn
// when it has more than one link.
func (s *FileStore) judgeArchive(dir int, name string, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o7777 != logMode || statFlags(st) != 0 {
		return fmt.Errorf("%w: %s is not an unflagged regular file, root's 0600; as root, move it out of %s/%s/ or set it so, then rerun", errLogUntrusted, name, auditDirName, archivesDirName)
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = unix.Close(fd) }() // read-only
	var ost unix.Stat_t
	if err := unix.Fstat(fd, &ost); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if ost.Dev != st.Dev || ost.Ino != st.Ino {
		return fmt.Errorf("%w: %s was replaced while it was judged; rerun", errLogUntrusted, name)
	}
	if err := judgeFlagsACL(fd, func(int) (uint32, error) { return statFlags(&ost), nil }); err != nil {
		return fmt.Errorf("%s/%s/%s: %w; as root, remove the ACL (sudo chmod -N), then rerun", auditDirName, archivesDirName, name, err)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore audit archive has more than one link; it is root's 0600, so the other link gives no other user anything", "archive", name, "links", st.Nlink)
	}
	return nil
}

// errCloneRefused is a clone of the old log the volume refused, or one
// discarded because an extended attribute on it could not be removed:
// nothing is left, and rotate copies instead.
var errCloneRefused = errors.New("the audit log could not be cloned")

// cloneArchive makes name in the root-only archives directory nad a clone
// of the old log (cloneFileAt), then makes it the archive: the clone holds
// the whole file, its flag and its extended attributes (measured as root,
// U195), so on its own descriptor its flag is cleared, every extended
// attribute is removed (stripXattrs; when one cannot be, as a protected
// system attribute cannot, the clone is unlinked and the error is
// errCloneRefused, so rotate copies), any extended ACL is removed
// (removeACL), it is made the caller's (root's) at mode 0600, and,
// reopened for writing and checked as the same inode, it is truncated to
// the size the old log had at open (the snapshot rule), fsynced and
// verified: the caller's, 0600, unflagged, one link, the size at open, no
// extended attribute, and passing the logs' flags-and-ACL judge
// (judgeFlagsACL). It is a fresh inode in a directory only root reaches,
// so no other process can act on it meanwhile. A clone the volume refuses
// is errCloneRefused with nothing created.
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
		if err := clearFdFlags(rfd); err != nil {
			return fmt.Errorf("clear the flags of the cloned %s: %w", name, err)
		}
	}
	if err := stripXattrs(rfd); err != nil {
		// A protected attribute would refuse every rotate: the clone is
		// discarded and rotate copies, and a copy carries no attribute.
		if uerr := unix.Unlinkat(nad, name, 0); uerr != nil {
			return fmt.Errorf("remove the cloned %s after its extended attributes could not be removed (%v): %w", name, err, uerr)
		}
		return fmt.Errorf("%w: the cloned %s, discarded: %w", errCloneRefused, name, err)
	}
	if err := removeACL(rfd); err != nil {
		return fmt.Errorf("the cloned %s: %w", name, err)
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
	if err := judgeFlagsACL(wfd, fdFlags); err != nil {
		return fmt.Errorf("the cloned %s after its ACL was removed: %w", name, err)
	}
	if left, err := listXattrs(wfd); err != nil || len(left) != 0 {
		return fmt.Errorf("the cloned %s still carries %d extended attributes after they were removed (%v)", name, len(left), err)
	}
	return nil
}

// fremovexattr and removeACL remove one extended attribute, and the
// extended ACL, of the file a descriptor holds. They are variables so a
// test can make a removal fail.
var (
	fremovexattr = unix.Fremovexattr
	removeACL    = removeExtendedACL
)

// maxXattrList bounds the extended-attribute name list stripXattrs reads.
const maxXattrList = 1 << 20

// listXattrs is the names of the extended attributes of the file fd
// holds (flistxattr), the list bounded by maxXattrList.
func listXattrs(fd int) ([]string, error) {
	for range 4 {
		n, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return nil, fmt.Errorf("list the extended attributes: %w", err)
		}
		if n == 0 {
			return nil, nil
		}
		if n > maxXattrList {
			return nil, fmt.Errorf("list the extended attributes: %d bytes of names, past %d", n, maxXattrList)
		}
		buf := make([]byte, n)
		n, err = unix.Flistxattr(fd, buf)
		if errors.Is(err, unix.ERANGE) {
			continue // the list grew between the calls
		}
		if err != nil {
			return nil, fmt.Errorf("list the extended attributes: %w", err)
		}
		var names []string
		for _, b := range bytes.Split(buf[:n], []byte{0}) {
			if len(b) != 0 {
				names = append(names, string(b))
			}
		}
		return names, nil
	}
	return nil, fmt.Errorf("list the extended attributes: the list kept changing")
}

// stripXattrs removes every extended attribute of the file fd holds,
// skipping none, and refuses when one cannot be removed or any remains.
func stripXattrs(fd int) error {
	names, err := listXattrs(fd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := fremovexattr(fd, n); err != nil {
			return fmt.Errorf("remove the extended attribute %q: %w", n, err)
		}
	}
	if left, err := listXattrs(fd); err != nil || len(left) != 0 {
		return fmt.Errorf("%d extended attributes remain after removal (%v)", len(left), err)
	}
	return nil
}

// copyRoomFloor and copyRoomPercent set the free space a copy leaves on the
// volume beyond the copied bytes: the larger of 1 GiB and 2% of the
// volume's size (copyRoom), so the margin scales with the volume.
const (
	copyRoomFloor   = 1 << 30
	copyRoomPercent = 2
)

// copyRoom is the free space copying size bytes needs on a volume of
// volSize bytes: size plus the larger of copyRoomFloor and copyRoomPercent
// percent of volSize.
func copyRoom(size, volSize int64) int64 {
	return size + max(int64(copyRoomFloor), volSize/100*copyRoomPercent)
}

// volumeSpace is the free space and the size, in bytes, of the volume
// holding the open directory fd, from one fstatfs. It is a variable so a
// test can make a volume full.
var volumeSpace = defaultVolumeSpace

// defaultVolumeSpace is volumeSpace's fstatfs.
func defaultVolumeSpace(fd int) (free, size int64, err error) {
	var sf unix.Statfs_t
	if err := unix.Fstatfs(fd, &sf); err != nil {
		return 0, 0, err
	}
	return int64(sf.Bavail) * int64(sf.Bsize), int64(sf.Blocks) * int64(sf.Bsize), nil
}

// copyArchive makes name in nad a copy of the old log's first old.size
// bytes, root's 0600, when the clone was refused or discarded (why). It first checks
// that the volume has room for the copy (copyRoom: the log's size plus the
// larger of 1 GiB and 2% of the volume's size, from one fstatfs) and
// refuses up front, before any byte is written, when it does not: the service user can grow the log,
// and a copy that fills the volume would stall every writer.
func copyArchive(old *oldLog, nad int, name string, why error) error {
	free, volSize, err := volumeSpace(nad)
	if err != nil {
		return fmt.Errorf("read the free space of the data root's volume: %w", err)
	}
	if need := copyRoom(old.size, volSize); free < need {
		return fmt.Errorf("%w: %v, and copying it into %s needs %d bytes free on the data root's volume (the log's size plus the larger of 1 GiB and 2%% of the volume), which has %d; free space on that volume, then rerun; nothing was changed", errRotateRefused, why, name, need, free)
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
