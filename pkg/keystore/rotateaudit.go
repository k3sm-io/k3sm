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
	"log/slog"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// The root maintenance verb audit --rotate (docs/design/keystore.md § "Root
// maintenance verbs", "audit --rotate keeps four archives"): it moves the
// audit log aside to keystore-audit.log.1, shifting the older archives up
// to .4, and swaps in an empty, flagged log under the same maintenance
// procedure as floor --rebuild.

const (
	// auditStagingName is audit --rotate's staging file.
	auditStagingName = auditLogName + ".new"
	// auditArchives is how many archives rotate keeps: .1, the newest, to
	// .4.
	auditArchives = 4
)

// auditArchiveName is the n-th archive's name in the data root.
func auditArchiveName(n int) string { return auditLogName + "." + strconv.Itoa(n) }

// errRotateRefused marks a rotate that refused before it touched the old
// log or any archive: nothing changed.
var errRotateRefused = errors.New("audit --rotate refused and changed nothing")

// RotateReport is what audit --rotate did: the archives kept after it,
// and whether it discarded the oldest.
type RotateReport struct {
	Archives  int
	Discarded bool
}

// RotateAudit rotates the audit log (audit --rotate). Run as root: it
// writes the maintenance marker, takes the floor lock, then the exclusive
// store lock, waiting at most 30 s, and opens the audit log and judges every
// archive present, each through the data-root descriptor with O_NOFOLLOW.
// The audit log must be a regular file; one with more than one link is
// taken as input, with a Warn, since rotate replaces its inode. Each archive
// must be a regular file, root's 0600; an archive with more than one link
// is a Warn, since an alias of a root 0600 file gives the service user
// nothing. It refuses, changing nothing, when keystore-audit.log.4 exists
// unless discardOldest.
//
// It then writes and fsyncs an empty staging log, root's 0600, in the
// root-only staging directory; clears the old log's flag and makes it
// root's 0600, on its descriptor; with discardOldest unlinks .4 after
// clearing its flag on its descriptor; opens each archive from .3 down to
// .1, clears its flag and makes it root's 0600 (already so), renames it one number up and sets the flag again on the same
// descriptor; renames the old log to .1 and the staging log over the
// canonical name; flags the new log and .1, each on its held descriptor;
// and only then hands the new log to the service user. The new log is a
// fresh inode, and the old one, now .1, stays root's 0600: every archive is
// root's evidence, and the service user never appends to one. The marker is
// removed last; a failure past the old log's first attribute change keeps
// it, so the listener stays down until a rerun.
//
// A rerun after a crash between the old log's rename to .1 and the new
// log's rename in (the marker standing from that run, the canonical name
// empty, .1 present) finishes: it writes a fresh log by the same procedure,
// flags it and .1, hands it over and removes the marker. Without that
// marker a missing audit log refuses.
func (s *FileStore) RotateAudit(ctx context.Context, attrs FileAttrWriter, discardOldest bool) (RotateReport, error) {
	var rep RotateReport
	if err := s.checkConfig(); err != nil {
		return rep, err
	}
	m, err := s.beginMaintenance(ctx, errRotateRefused)
	if err != nil {
		return rep, err
	}
	defer m.end()
	old, err := openOldLog(m.dfd, auditLogName)
	if errors.Is(err, unix.ENOENT) && m.crashed {
		return s.finishRotate(m, attrs)
	}
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: the audit log %s cannot be opened: %w", errRotateRefused, auditLogName, err)
	}
	defer func() { _ = old.Close() }() // read-only until its attributes change
	present, err := s.judgeArchives(m.dfd)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if present[auditArchives] && !discardOldest {
		m.refused()
		return rep, fmt.Errorf("%w: %s exists, and rotate keeps %d archives: export the archives first (copy them off the Mac), then rerun with --discard-oldest, which deletes it", errRotateRefused, auditArchiveName(auditArchives), auditArchives)
	}
	kept := 1
	for n := 1; n < auditArchives; n++ {
		if present[n] {
			kept++
		}
	}
	hooks := swapHooks{
		afterClear: func() error {
			if present[auditArchives] {
				if err := s.discardArchive(m.dfd, auditArchiveName(auditArchives), attrs); err != nil {
					return fmt.Errorf("discard %s: %w; rerun the verb", auditArchiveName(auditArchives), err)
				}
				rep.Discarded = true
			}
			for n := auditArchives - 1; n >= 1; n-- {
				if present[n] {
					if err := s.shiftArchive(m.dfd, n, attrs); err != nil {
						return err
					}
				}
			}
			return renameFreshAt(m.dfd, auditLogName, m.dfd, auditArchiveName(1))
		},
		afterFlag: func() error {
			if err := attrs.Fchflags(int(old.Fd()), sfAppend); err != nil {
				return fmt.Errorf("flag %s append-only: %w; rerun the verb", auditArchiveName(1), err)
			}
			return nil
		},
	}
	if err := s.swapLog(m, old, auditStagingName, auditLogName, nil, attrs, hooks); err != nil {
		return rep, err
	}
	rep.Archives = kept
	return rep, nil
}

// finishRotate is RotateAudit's rerun after a crash that left the
// canonical audit log missing and .1 the old log: it requires .1 and the
// other archives to judge as rotate leaves them, writes a fresh log by the
// normal procedure, flags it and .1, and hands the new log over.
func (s *FileStore) finishRotate(m *maintenance, attrs FileAttrWriter) (RotateReport, error) {
	var rep RotateReport
	present, err := s.judgeArchives(m.dfd)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if !present[1] {
		m.refused()
		return rep, fmt.Errorf("%w: the audit log %s and %s are both missing", errRotateRefused, auditLogName, auditArchiveName(1))
	}
	one, err := s.openArchive(m.dfd, auditArchiveName(1))
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	defer func() { _ = one.Close() }() // read-only
	hooks := swapHooks{afterFlag: func() error {
		if err := attrs.Fchflags(int(one.Fd()), sfAppend); err != nil {
			return fmt.Errorf("flag %s append-only: %w; rerun the verb", auditArchiveName(1), err)
		}
		return nil
	}}
	if err := s.swapLog(m, nil, auditStagingName, auditLogName, nil, attrs, hooks); err != nil {
		return rep, err
	}
	for n := 1; n <= auditArchives; n++ {
		if present[n] {
			rep.Archives++
		}
	}
	return rep, nil
}

// judgeArchives reports, by number, which archives are present, refusing
// any name that is not a regular file of the data root's owner (root) at
// mode 0600: a planted symlink or FIFO, or a file the service user owns, at
// an archive's name refuses the rotate before anything changes. An archive
// with more than one link is a Warn: rotate renames it, and an alias of a
// root 0600 file gives the service user nothing.
func (s *FileStore) judgeArchives(dfd int) ([auditArchives + 1]bool, error) {
	var present [auditArchives + 1]bool
	for n := 1; n <= auditArchives; n++ {
		name := auditArchiveName(n)
		var st unix.Stat_t
		err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
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
// a regular file of the data root's owner at mode 0600, and logs a Warn
// when it has more than one link.
func (s *FileStore) judgeArchive(name string, st *unix.Stat_t) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o7777 != logMode {
		return fmt.Errorf("%w: %s is not a regular file, root's 0600", errLogUntrusted, name)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore audit archive has more than one link; it is root's 0600, so the other link gives no other user anything", "archive", name, "links", st.Nlink)
	}
	return nil
}

// openArchive opens the archive name read-only through dfd with O_NOFOLLOW
// and judges it on its descriptor (judgeArchive).
func (s *FileStore) openArchive(dfd int, name string) (*os.File, error) {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close() // read-only
		return nil, fmt.Errorf("stat %s: %w", name, err)
	}
	if err := s.judgeArchive(name, &st); err != nil {
		_ = f.Close() // read-only
		return nil, err
	}
	return f, nil
}

// discardArchive unlinks the archive name (--discard-oldest): opened and
// judged (openArchive), its flag cleared on its descriptor, then unlinked
// with unlinkat. Another link to it keeps only a root 0600 file.
func (s *FileStore) discardArchive(dfd int, name string, attrs FileAttrWriter) error {
	f, err := s.openArchive(dfd, name)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only
	if err := attrs.Fchflags(int(f.Fd()), 0); err != nil {
		return fmt.Errorf("clear the flag of %s: %w", name, err)
	}
	return unix.Unlinkat(dfd, name, 0)
}

// shiftArchive moves archive n to n+1: opened O_NOFOLLOW through dfd and
// judged (openArchive), its flag cleared and made root's 0600 (already so)
// on its descriptor, renamed, and flagged again on the
// same descriptor.
func (s *FileStore) shiftArchive(dfd, n int, attrs FileAttrWriter) error {
	from, to := auditArchiveName(n), auditArchiveName(n+1)
	f, err := s.openArchive(dfd, from)
	if err != nil {
		return fmt.Errorf("%w; rerun the verb", err)
	}
	defer func() { _ = f.Close() }() // read-only
	fd := int(f.Fd())
	if err := s.unflagToRoot(fd, from, attrs); err != nil {
		return err
	}
	if err := renameFreshAt(dfd, from, dfd, to); err != nil {
		return err
	}
	if err := attrs.Fchflags(fd, sfAppend); err != nil {
		return fmt.Errorf("flag %s append-only: %w; rerun the verb", to, err)
	}
	return nil
}

// renameFreshAt renames from in fromDir to to in toDir, refusing when
// anything stands at to: nothing is renamed over a file, flagged or not.
func renameFreshAt(fromDir int, from string, toDir int, to string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(toDir, to, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: %s exists, so %s is not renamed over it; rerun the verb", errLogUntrusted, to, from)
	}
	if err := unix.Renameat(fromDir, from, toDir, to); err != nil {
		return fmt.Errorf("rename %s to %s: %w; rerun the verb", from, to, err)
	}
	return nil
}
