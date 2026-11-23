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
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// A maintenance verb's run can commit its swap and then fail before its
// report is printed (errSwapCommitted), or die. Its marker then holds the
// report. A rerun of the same verb prints it; a later run of the other verb,
// or install, would replace or remove the marker, so each first reports
// it: on stderr, as "an earlier <verb> committed and was not reported", and
// as an audit line (op the earlier verb, result committed), before the
// marker goes.

// EarlierRun is a committed maintenance run found in the marker by a run
// of another verb, or by install.
type EarlierRun struct {
	// Verb is the earlier run's audit op: floor-rebuild or audit-rotate.
	Verb string
	// Report is its saved report, by field.
	Report map[string]int64
	// AuditErr is why its audit line was not written; nil when it was.
	AuditErr error
	// RecordErr is why its drop counts were not recorded in the lossy-run
	// record (keystore-maintenance-runs); nil when they were, or when it
	// dropped nothing.
	RecordErr error
}

// String is the stderr line for r.
func (r EarlierRun) String() string {
	var f []string
	for _, k := range slices.Sorted(maps.Keys(r.Report)) {
		f = append(f, fmt.Sprintf("%s=%d", k, r.Report[k]))
	}
	rep := strings.Join(f, ", ")
	if rep == "" {
		rep = "no counts recorded"
	}
	s := fmt.Sprintf("an earlier %s committed and was not reported: %s", verbDisplay(r.Verb), rep)
	if n := r.Dropped(); n > 0 {
		s = fmt.Sprintf("an earlier %s committed and dropped %d lines, and was not reported: %s", verbDisplay(r.Verb), n, rep)
	}
	if r.AuditErr != nil {
		s += fmt.Sprintf("; its audit line was not written: %v", r.AuditErr)
	}
	if r.RecordErr != nil {
		s += fmt.Sprintf("; its drop counts were not recorded: %v", r.RecordErr)
	}
	return s
}

// dropFields are the saved report's fields that count dropped lines or
// keys (RebuildReport.fields).
var dropFields = []string{"dropped", "overlong", "past-share", "absent", "removed"}

// Dropped is how many lines or keys r's saved report shows dropped: more
// than 0 makes the verb that reports it exit at least 4.
func (r EarlierRun) Dropped() int64 {
	var n int64
	for _, k := range dropFields {
		n += max(r.Report[k], 0)
	}
	return n
}

// StandingMaintenance reads the maintenance marker in the data root, for
// doctor: present reports whether one stands, and verb is the command of
// the run that wrote it ("" when it names none this build knows). The
// marker is root's 0644, so any account reads it.
func (s *FileStore) StandingMaintenance(ctx context.Context) (verb string, present bool, err error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	fd, err := unix.Open(filepath.Join(s.dataRoot, maintenanceMarkerName), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return "", false, nil
	}
	if err != nil {
		return "", true, err
	}
	f := os.NewFile(uintptr(fd), maintenanceMarkerName)
	defer func() { _ = f.Close() }() // read-only
	b, err := io.ReadAll(io.LimitReader(f, maxMarkerSize))
	if err != nil {
		return "", true, err
	}
	switch v := parseMarker(b).verb; v {
	case verbRebuild, verbRotate:
		return verbDisplay(v), true, nil
	}
	return "", true, nil
}

// verbDisplay is the command a marker's verb names.
func verbDisplay(verb string) string {
	switch verb {
	case verbRebuild:
		return "floor --rebuild"
	case verbRotate:
		return "audit --rotate"
	}
	return "maintenance verb"
}

// verbLog is the log a marker's verb swaps, or "" for an unknown verb.
func verbLog(verb string) string {
	switch verb {
	case verbRebuild:
		return userFloorLogName
	case verbRotate:
		return auditLogName
	}
	return ""
}

type earlierRunKey struct{}

// WithEarlierRun returns ctx carrying report, which a maintenance verb
// calls with a committed run of the other verb it finds in the marker,
// after writing its audit line and before it replaces the marker. With
// none, the run is logged at Warn.
func WithEarlierRun(ctx context.Context, report func(EarlierRun)) context.Context {
	return context.WithValue(ctx, earlierRunKey{}, report)
}

// reportEarlierRun reports prior, a committed run of a verb other than the
// running one: its audit line, written under the store lock the
// maintenance holds, and its drop counts recorded in the lossy-run record
// through the data root dfd (recordLossyRun), then the report through ctx.
// beginMaintenance calls it only for a known verb whose recorded log is
// live.
func (s *FileStore) reportEarlierRun(ctx context.Context, dfd int, prior *marker) {
	op := prior.verb
	r := EarlierRun{Verb: op, Report: map[string]int64{}}
	for k, v := range prior.report {
		if auditWord(k) {
			r.Report[k] = v
		}
	}
	r.AuditErr = s.auditSink.append(auditLine{op: op, via: auditViaRoot, scope: scopeSystem, name: auditPlaceholder, result: auditResultCommitted})
	r.RecordErr = s.recordLossyRun(dfd, prior.run, prior.verb, prior.ino, prior.report)
	if f, ok := ctx.Value(earlierRunKey{}).(func(EarlierRun)); ok && f != nil {
		f(r)
		return
	}
	slog.Warn(r.String())
}

// EarlierRunAtInstall is install's report of the marker it is about to
// remove: when the marker, judged on its descriptor in the data root dfd
// as root's file (rootUID), records a run whose swap committed (its log's
// live inode under the logs directory lfd is the one it recorded), it
// appends that run's audit line (op the verb, via root, result committed)
// to the audit log, appends its record to the lossy-run record in the data
// root when its report drops anything (RecordErr says why it could not),
// and returns the run; install prints it. A record already holding the run
// id is left as it is, so an install that dies after recording and before
// removing the marker records the run once when it runs again. dataRoot is
// the data root's path, for the record's repair text. Anything else, no
// marker, one not judged, one that never committed, returns nil: install
// removes it, and it held no committed report.
func EarlierRunAtInstall(dfd, lfd, rootUID int, dataRoot string, now time.Time) *EarlierRun {
	fd, err := unix.Openat(dfd, maintenanceMarkerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	f := os.NewFile(uintptr(fd), maintenanceMarkerName)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || judgeRootFile(fd, &st, maintenanceMarkerName, int64(rootUID)) != nil {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMarkerSize))
	if err != nil {
		return nil
	}
	prior := parseMarker(b)
	pl := verbLog(prior.verb)
	if !prior.swapped || pl == "" {
		return nil
	}
	dir, err := unix.Openat(lfd, logDirOf(pl), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer func() { _ = unix.Close(dir) }() // read-only directory descriptor
	if unix.Fstatat(dir, pl, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || uint64(st.Dev) != prior.dev || st.Ino != prior.ino {
		return nil
	}
	r := &EarlierRun{Verb: prior.verb, Report: map[string]int64{}}
	for k, v := range prior.report {
		if auditWord(k) {
			r.Report[k] = v
		}
	}
	r.AuditErr = appendInstallAudit(lfd, auditLine{op: prior.verb, via: auditViaRoot, scope: scopeSystem, name: auditPlaceholder, result: auditResultCommitted}, now)
	r.RecordErr = recordLossyRunAt(dfd, int64(rootUID), dataRoot, prior.run, prior.verb, prior.ino, prior.report, now)
	return r
}

// appendInstallAudit appends l to the audit log under the logs directory
// lfd, as root, with O_APPEND and a newline first, after judging it on its
// descriptor: a regular file with one link.
func appendInstallAudit(lfd int, l auditLine, now time.Time) error {
	line, err := marshalAuditLine(l, now)
	if err != nil {
		return err
	}
	dir, err := unix.Openat(lfd, auditDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", auditDirName, err)
	}
	defer func() { _ = unix.Close(dir) }() // read-only directory descriptor
	fd, err := unix.Openat(dir, auditLogName, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", auditLogName, err)
	}
	f := os.NewFile(uintptr(fd), auditLogName)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		_ = f.Close() // nothing written
		return errors.New("the audit log is not a regular file with one link")
	}
	_, err = f.Write(append([]byte{'\n'}, line...))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
