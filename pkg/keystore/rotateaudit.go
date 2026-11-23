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
// maintenance verbs", "audit --rotate keeps four archives"): it copies the
// audit log to a new archive, keystore-audit.log.1, shifting the older
// archives up to .4, and swaps in an empty, flagged log by the same gated
// swap as floor --rebuild.

const (
	// auditStagingName is audit --rotate's staged new log, and
	// auditArchiveStagingName its staged archive, both in keystore-staging/.
	auditStagingName        = auditLogName + ".new"
	auditArchiveStagingName = auditLogName + ".1.new"
	// auditArchives is how many archives rotate keeps: .1, the newest, to
	// .4.
	auditArchives = 4
)

// auditArchiveName is the n-th archive's name in keystore-logs/.
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
// archive present, each through keystore-logs/ with O_NOFOLLOW. The audit
// log must be a regular file; one with more than one link is taken as
// input, with a Warn, since rotate replaces its inode. Each archive must be
// a regular file, root's 0600, unflagged; an archive with more than one
// link is a Warn, since an alias of a root 0600 file gives the service user
// nothing. It refuses, changing nothing, when keystore-audit.log.4 exists
// unless discardOldest.
//
// It copies the old log, read through its descriptor while still flagged,
// into a staging archive (root's 0600, in keystore-staging/), then runs the
// gated swap (swapLog) with an empty new log: under the closed gate it
// appends the old log's tail to the staging archive, retires the old log,
// discards .4 with discardOldest, shifts .3 to .4 down to .1 to .2 with
// plain renames, renames the staging archive to .1 and swaps the new log
// in. A rerun after a crash finishes from whatever state the crash left
// (resumeSwap); without the marker a missing audit log refuses.
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
	present, err := s.judgeArchives(m.lfd)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	if present[auditArchives] && !discardOldest {
		m.refused()
		return rep, fmt.Errorf("%w: %s exists, and rotate keeps %d archives: export the archives first (copy them off the Mac), then rerun with --discard-oldest, which deletes it", errRotateRefused, auditArchiveName(auditArchives), auditArchives)
	}
	retire := func() error { return s.retireArchives(m, discardOldest, &rep) }
	done, err := s.resumeSwap(m, auditLogName, auditStagingName, retire, attrs)
	if done || err != nil {
		if err == nil {
			rep.Archives, err = s.countArchives(m.lfd)
		}
		return rep, err
	}
	old, err := openOldLog(m.lfd, auditLogName)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: the audit log %s cannot be opened: %w", errRotateRefused, auditLogName, err)
	}
	defer func() { _ = old.Close() }() // read-only
	af, off, err := s.stageArchive(m, old, attrs)
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: %w", errRotateRefused, err)
	}
	defer func() { _ = af.Close() }() // fsynced before its rename
	sw := logSwap{
		canonical: auditLogName,
		staging:   auditStagingName,
		old:       old,
		off:       off,
		tail: func(b []byte) ([]byte, error) {
			if _, err := af.Write(b); err != nil {
				return nil, fmt.Errorf("append the tail to %s: %w; rerun the verb", auditArchiveStagingName, err)
			}
			if err := af.Sync(); err != nil {
				return nil, fmt.Errorf("fsync %s: %w; rerun the verb", auditArchiveStagingName, err)
			}
			return nil, nil
		},
		retire: retire,
	}
	if err := s.swapLog(m, sw, attrs); err != nil {
		_ = unix.Unlinkat(m.sfd, auditArchiveStagingName, 0) // only when the swap refused before the gate: the old log stands
		return rep, err
	}
	rep.Archives, err = s.countArchives(m.lfd)
	return rep, err
}

// stageArchive is rotate's step 2: a stale staging archive is removed, and
// a new one created root's 0600, O_CREAT|O_EXCL|O_NOFOLLOW, in
// keystore-staging/, and filled with the old log's bytes, read through its
// descriptor while it is still flagged. It returns the archive and how many
// bytes it copied.
func (s *FileStore) stageArchive(m *maintenance, old *os.File, attrs FileAttrWriter) (*os.File, int64, error) {
	name := auditArchiveStagingName
	if err := removeStale(m.sfd, name, s.floorUID, s.floorUID, attrs); err != nil {
		return nil, 0, err
	}
	fd, err := unix.Openat(m.sfd, name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
	if err != nil {
		return nil, 0, fmt.Errorf("create %s: %w", name, err)
	}
	af := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, int64, error) {
		_ = af.Close()                    // nothing else holds it
		_ = unix.Unlinkat(m.sfd, name, 0) // the old log is untouched
		return nil, 0, err
	}
	if err := attrs.Fchmod(fd, logMode); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", name, err))
	}
	n, err := io.Copy(af, io.NewSectionReader(old, 0, 1<<62))
	if err != nil {
		return fail(fmt.Errorf("copy %s to %s: %w", auditLogName, name, err))
	}
	if err := af.Sync(); err != nil {
		return fail(fmt.Errorf("fsync %s: %w", name, err))
	}
	return af, n, nil
}

// retireArchives is rotate's retire hook (step 6), run under the closed
// gate once the old log is unlinked, and on a rerun that finds it so: with
// the staging archive present it discards .4 (discardOldest), shifts each
// archive one number up with a plain rename, from .3 down, skipping a
// number whose shift a crashed run made, then renames the staging archive
// to .1. With no staging archive there is nothing left to do.
func (s *FileStore) retireArchives(m *maintenance, discardOldest bool, rep *RotateReport) error {
	var st unix.Stat_t
	if err := unix.Fstatat(m.sfd, auditArchiveStagingName, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w; rerun the verb", auditArchiveStagingName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int64(st.Uid) != int64(s.floorUID) {
		return fmt.Errorf("%w: %s is not a regular file with one link, root's; rerun the verb", errLogUntrusted, auditArchiveStagingName)
	}
	present, err := s.judgeArchives(m.lfd)
	if err != nil {
		return fmt.Errorf("%w; rerun the verb", err)
	}
	if present[auditArchives] {
		if !discardOldest {
			return fmt.Errorf("%s exists: rerun sudo k3sm keys audit --rotate with --discard-oldest once the archives are exported", auditArchiveName(auditArchives))
		}
		if err := unix.Unlinkat(m.lfd, auditArchiveName(auditArchives), 0); err != nil {
			return fmt.Errorf("discard %s: %w; rerun the verb", auditArchiveName(auditArchives), err)
		}
		rep.Discarded = true
	}
	for n := auditArchives - 1; n >= 1; n-- {
		if !present[n] {
			continue
		}
		if err := renameExcl(m.lfd, auditArchiveName(n), m.lfd, auditArchiveName(n+1)); err != nil {
			return fmt.Errorf("rename %s to %s: %w; rerun the verb", auditArchiveName(n), auditArchiveName(n+1), err)
		}
	}
	if err := renameExcl(m.sfd, auditArchiveStagingName, m.lfd, auditArchiveName(1)); err != nil {
		return fmt.Errorf("rename %s to %s: %w; rerun the verb", auditArchiveStagingName, auditArchiveName(1), err)
	}
	return nil
}

// countArchives is how many archives keystore-logs/ holds.
func (s *FileStore) countArchives(lfd int) (int, error) {
	present, err := s.judgeArchives(lfd)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range present[1:] {
		if p {
			n++
		}
	}
	return n, nil
}

// judgeArchives reports, by number, which archives are present, refusing
// any name that is not a regular file of the data root's owner (root) at
// mode 0600, unflagged: a planted symlink or FIFO, or a file the service user owns, at
// an archive's name refuses the rotate before anything changes. An archive
// with more than one link is a Warn: rotate renames it, and an alias of a
// root 0600 file gives the service user nothing.
func (s *FileStore) judgeArchives(lfd int) ([auditArchives + 1]bool, error) {
	var present [auditArchives + 1]bool
	for n := 1; n <= auditArchives; n++ {
		name := auditArchiveName(n)
		var st unix.Stat_t
		err := unix.Fstatat(lfd, name, &st, unix.AT_SYMLINK_NOFOLLOW)
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
