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
// replacement audit/ directory holding an empty, flagged log, the old log's
// bytes as keystore-audit.log.1 and the older archives one number up, by the
// same directory swap as floor --rebuild.

// auditArchives is how many archives rotate keeps: .1, the newest, to .4.
const auditArchives = 4

// auditArchiveName is the n-th archive's name in audit/.
func auditArchiveName(n int) string { return auditLogName + "." + strconv.Itoa(n) }

// errRotateRefused marks a rotate that refused before its swap: nothing
// changed.
var errRotateRefused = errors.New("audit --rotate refused and changed nothing")

// RotateReport is what audit --rotate did: the archives kept after it,
// and whether it discarded the oldest.
type RotateReport struct {
	Archives  int
	Discarded bool
}

// RotateAudit rotates the audit log (audit --rotate). Run as root: it
// takes the floor lock, then the exclusive store lock, waiting at most 30
// s, writes the maintenance marker, and judges every archive present in
// audit/ (judgeArchives: root's 0600, unflagged, regular). It refuses,
// changing nothing, when keystore-audit.log.4 exists unless discardOldest.
// It opens and judges the old log (openOldLog) and builds the replacement
// directory (buildLogDir): an empty, flagged new log; .1, a fresh root 0600
// copy of the old log's bytes, read once and bounded by its size at open;
// and .2 to .4, hard links of the old .1 to .3 (link leaves the live
// directory untouched). The old .4 is not linked, so the swap drops it. The
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
		return RotateReport{Archives: int(m.saved["archives"]), Discarded: m.saved["discarded"] != 0}, nil
	}
	if err := m.step(swapStepReadOld); err != nil {
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	old, err := s.openOldLog(m.lfd, auditLogName)
	if err != nil {
		return rep, fmt.Errorf("%w: the audit log %s cannot be opened: %w", errRotateRefused, auditLogName, err)
	}
	defer old.close()
	present, err := s.judgeArchives(old.dir)
	if err != nil {
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if present[auditArchives] && !discardOldest {
		return rep, fmt.Errorf("%w: %s exists, and rotate keeps %d archives: export the archives first (copy them off the Mac), then rerun with --discard-oldest, which deletes it", errRotateRefused, auditArchiveName(auditArchives), auditArchives)
	}
	rep.Archives, rep.Discarded = 1, present[auditArchives]
	for n := 1; n < auditArchives; n++ {
		if present[n] {
			rep.Archives++
		}
	}
	extra := func(dir int) error { return s.placeArchives(old, dir, present) }
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
// open at dir: .1 created root's 0600, O_CREAT|O_EXCL|O_NOFOLLOW, filled
// with the old log's first old.size bytes and fsynced; then each present
// archive .n of .1 to .3 hard-linked from the live audit/ as .n+1.
func (s *FileStore) placeArchives(old *oldLog, dir int, present [auditArchives + 1]bool) error {
	name := auditArchiveName(1)
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
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
	for n := auditArchives - 1; n >= 1; n-- {
		if !present[n] {
			continue
		}
		if err := unix.Linkat(old.dir, auditArchiveName(n), dir, auditArchiveName(n+1), 0); err != nil {
			return fmt.Errorf("link %s as the new %s: %w", auditArchiveName(n), auditArchiveName(n+1), err)
		}
	}
	return nil
}

// judgeArchives reports, by number, which archives are present, refusing
// any name that is not a regular file of the data root's owner (root) at
// mode 0600, unflagged: a planted symlink or FIFO, or a file the service user owns, at
// an archive's name refuses the rotate before anything changes. An archive
// with more than one link is a Warn: rotate renames it, and an alias of a
// root 0600 file gives the service user nothing.
func (s *FileStore) judgeArchives(dir int) ([auditArchives + 1]bool, error) {
	var present [auditArchives + 1]bool
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
		return fmt.Errorf("%w: %s is not an unflagged regular file, root's 0600", errLogUntrusted, name)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore audit archive has more than one link; it is root's 0600, so the other link gives no other user anything", "archive", name, "links", st.Nlink)
	}
	return nil
}
