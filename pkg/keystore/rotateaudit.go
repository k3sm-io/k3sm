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

// RotateAudit rotates the audit log (audit --rotate). Run as root: it takes
// the exclusive store lock, waiting at most 30 s, then the floor lock,
// writes the maintenance marker, and opens the audit log and judges every
// archive present, each through the data-root descriptor with O_NOFOLLOW
// and refused unless a regular file with one link. It refuses, changing
// nothing, when keystore-audit.log.4 exists unless discardOldest.
//
// It then writes and fsyncs an empty staging log, root's 0600; clears the
// old log's flag and makes it root's 0600 in one step on its descriptor;
// with discardOldest unlinks .4 after clearing its flag on its descriptor;
// opens each archive from .3 down to .1, clears its flag and makes it
// root's 0600 in the same step, renames it one number up and sets the flag
// again on the same descriptor; renames the old log to .1 and the staging
// log over the canonical name; flags the new log and .1, each on its held
// descriptor; and only then hands the new log to the service user. Every
// archive stays root 0600 and flagged. The marker is removed last; a
// failure past the old log's flag clear keeps it, so the listener stays
// down until a rerun.
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
	if err != nil {
		m.refused()
		return rep, fmt.Errorf("%w: the audit log %s cannot be opened: %w", errRotateRefused, auditLogName, err)
	}
	defer func() { _ = old.Close() }() // read-only until its attributes change
	present, err := judgeArchives(m.dfd)
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
				if err := removeStale(m.dfd, auditArchiveName(auditArchives), attrs); err != nil {
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
			return renameFresh(m.dfd, auditLogName, auditArchiveName(1))
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

// judgeArchives reports, by number, which archives are present, refusing
// any name that is not a regular file with one link: a planted symlink or
// FIFO at an archive's name refuses the rotate before anything changes.
func judgeArchives(dfd int) ([auditArchives + 1]bool, error) {
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
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
			return present, fmt.Errorf("%w: %s is not a regular file with one link", errLogUntrusted, name)
		}
		present[n] = true
	}
	return present, nil
}

// shiftArchive moves archive n to n+1: opened O_NOFOLLOW through dfd and
// judged, its flag cleared and made root's 0600 in one step on its
// descriptor, renamed, and flagged again on the same descriptor.
func (s *FileStore) shiftArchive(dfd, n int, attrs FileAttrWriter) error {
	from, to := auditArchiveName(n), auditArchiveName(n+1)
	f, err := openOldLog(dfd, from)
	if err != nil {
		return fmt.Errorf("open %s: %w; rerun the verb", from, err)
	}
	defer func() { _ = f.Close() }() // read-only
	fd := int(f.Fd())
	if err := s.unflagToRoot(fd, from, attrs); err != nil {
		return err
	}
	if err := renameFresh(dfd, from, to); err != nil {
		return err
	}
	if err := attrs.Fchflags(fd, sfAppend); err != nil {
		return fmt.Errorf("flag %s append-only: %w; rerun the verb", to, err)
	}
	return nil
}

// renameFresh renames from to to through dfd, refusing when anything
// stands at to: nothing is renamed over a file, flagged or not.
func renameFresh(dfd int, from, to string) error {
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, to, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w: %s exists, so %s is not renamed over it; rerun the verb", errLogUntrusted, to, from)
	}
	if err := unix.Renameat(dfd, from, dfd, to); err != nil {
		return fmt.Errorf("rename %s to %s: %w; rerun the verb", from, to, err)
	}
	return nil
}
