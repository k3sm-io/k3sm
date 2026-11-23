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
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// The lossy-run record (docs/design/keystore.md § "The maintenance
// report"). A maintenance verb's report lives in the marker only until the
// next run replaces or removes it. A committed run whose report drops any
// line or key also appends one record to keystore-maintenance-runs in the
// data root, before the marker goes: the run id, the verb, the UTC time,
// the drop counts by reason and the new log's inode as the marker records
// it. It names no value, no entry and no path. The keystore- prefix puts it
// under every Pod's data-root deny.

const (
	// maintenanceRunsName is the record, in the data root.
	maintenanceRunsName = "keystore-maintenance-runs"
	// maintenanceRunsTemp is the name it is written at before its rename.
	maintenanceRunsTemp = maintenanceRunsName + ".new"
	// maintenanceRunsMode is its mode: root's, readable by doctor run by
	// any account.
	maintenanceRunsMode = 0o644
	// maintenanceRunsHeader is the record's first line: its format.
	maintenanceRunsHeader = "k3sm keystore lossy maintenance runs v1"
	// maxMaintenanceRuns is how many records it keeps: the newest.
	maxMaintenanceRuns = 64
	// maxMaintenanceRunLine bounds a record's line, its newline excluded.
	maxMaintenanceRunLine = 256
	// maxMaintenanceRunsSize bounds the whole file.
	maxMaintenanceRunsSize = len(maintenanceRunsHeader) + 1 + maxMaintenanceRuns*(maxMaintenanceRunLine+1)
	// maintenanceRunTime is a record's time layout: UTC, to the second.
	maintenanceRunTime = "2006-01-02T15:04:05Z"
)

// MaintenanceRunsName is the lossy-run record's name in the data root.
const MaintenanceRunsName = maintenanceRunsName

// errMaintenanceRunsBad is a lossy-run record that does not judge or
// parse. It is reported, never reset: a run that would append to it says
// so instead.
var errMaintenanceRunsBad = errors.New("the lossy maintenance run record " + maintenanceRunsName + " in the data root is damaged or untrusted, and is left as found: as root, move it aside (keep it, it is the only copy of earlier runs' drop counts), and the next lossy run starts a new one")

// MaintenanceRun is one committed lossy maintenance run, as the record
// keeps it.
type MaintenanceRun struct {
	// Run is the run id the marker recorded: 16 lowercase hex digits.
	Run string
	// Verb is its audit op: floor-rebuild or audit-rotate.
	Verb string
	// Time is when the record was written, UTC, to the second.
	Time time.Time
	// Ino is the new log's inode, as the marker recorded it.
	Ino uint64
	// Drops is its drop counts by reason (the dropFields), each present.
	Drops map[string]int64
}

// Dropped is the sum of r's drop counts.
func (r MaintenanceRun) Dropped() int64 {
	var n int64
	for _, k := range dropFields {
		n += r.Drops[k]
	}
	return n
}

// encode renders r as its record line, without the newline.
func (r MaintenanceRun) encode() string {
	var b strings.Builder
	fmt.Fprintf(&b, "run=%s verb=%s time=%s ino=%d", r.Run, r.Verb, r.Time.UTC().Format(maintenanceRunTime), r.Ino)
	for _, k := range dropFields {
		fmt.Fprintf(&b, " %s=%d", k, r.Drops[k])
	}
	return b.String()
}

// lossyRunOf is the record of a committed run of verb, its run id run and
// new log's inode ino, with report: ok is false when report drops nothing.
func lossyRunOf(run, verb string, ino uint64, report map[string]int64, now time.Time) (MaintenanceRun, bool) {
	r := MaintenanceRun{Run: run, Verb: verb, Time: now.UTC().Truncate(time.Second), Ino: ino, Drops: map[string]int64{}}
	for _, k := range dropFields {
		r.Drops[k] = max(report[k], 0)
	}
	return r, r.Dropped() > 0
}

// parseMaintenanceRun parses one record line strictly: the fields in
// encode's order, each canonical, a known verb, a non-zero inode and at
// least one non-zero count.
func parseMaintenanceRun(line string) (MaintenanceRun, error) {
	f := strings.Split(line, " ")
	keys := append([]string{"run", "verb", "time", "ino"}, dropFields...)
	if len(f) != len(keys) {
		return MaintenanceRun{}, fmt.Errorf("%d fields, want %d", len(f), len(keys))
	}
	vals := make([]string, len(f))
	for i, kv := range f {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k != keys[i] || v == "" {
			return MaintenanceRun{}, fmt.Errorf("field %d is not %s=", i+1, keys[i])
		}
		vals[i] = v
	}
	r := MaintenanceRun{Run: vals[0], Verb: vals[1], Drops: map[string]int64{}}
	if len(r.Run) != 16 || !isLowerHex(r.Run) {
		return MaintenanceRun{}, errors.New("the run id is not 16 lowercase hex digits")
	}
	if verbLog(r.Verb) == "" {
		return MaintenanceRun{}, errors.New("an unknown verb")
	}
	t, err := time.Parse(maintenanceRunTime, vals[2])
	if err != nil || t.Format(maintenanceRunTime) != vals[2] {
		return MaintenanceRun{}, errors.New("the time is not UTC to the second")
	}
	r.Time = t
	if r.Ino, err = strconv.ParseUint(vals[3], 10, 64); err != nil || r.Ino == 0 || strconv.FormatUint(r.Ino, 10) != vals[3] {
		return MaintenanceRun{}, errors.New("the inode is not a canonical non-zero decimal")
	}
	for i, k := range dropFields {
		n, err := strconv.ParseInt(vals[4+i], 10, 64)
		if err != nil || n < 0 || strconv.FormatInt(n, 10) != vals[4+i] {
			return MaintenanceRun{}, fmt.Errorf("the count %s is not a canonical decimal", k)
		}
		r.Drops[k] = n
	}
	if r.Dropped() <= 0 {
		return MaintenanceRun{}, errors.New("a record that dropped nothing")
	}
	return r, nil
}

// parseMaintenanceRuns parses the record strictly: the header line, then at
// most maxMaintenanceRuns record lines, oldest first, each within
// maxMaintenanceRunLine and newline-terminated, no run id twice.
func parseMaintenanceRuns(b []byte) ([]MaintenanceRun, error) {
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return nil, errors.New("it does not end in a newline")
	}
	lines := strings.Split(string(b[:len(b)-1]), "\n")
	if lines[0] != maintenanceRunsHeader {
		return nil, errors.New("its first line is not the format header")
	}
	lines = lines[1:]
	if len(lines) > maxMaintenanceRuns {
		return nil, fmt.Errorf("it holds %d records, past %d", len(lines), maxMaintenanceRuns)
	}
	runs := make([]MaintenanceRun, 0, len(lines))
	seen := map[string]bool{}
	for i, l := range lines {
		if len(l) > maxMaintenanceRunLine {
			return nil, fmt.Errorf("record %d is longer than %d bytes", i+1, maxMaintenanceRunLine)
		}
		r, err := parseMaintenanceRun(l)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i+1, err)
		}
		if seen[r.Run] {
			return nil, fmt.Errorf("record %d repeats a run id", i+1)
		}
		seen[r.Run] = true
		runs = append(runs, r)
	}
	return runs, nil
}

// encodeMaintenanceRuns renders runs as the record.
func encodeMaintenanceRuns(runs []MaintenanceRun) []byte {
	var b bytes.Buffer
	b.WriteString(maintenanceRunsHeader + "\n")
	for _, r := range runs {
		b.WriteString(r.encode() + "\n")
	}
	return b.Bytes()
}

// readMaintenanceRuns reads the record through the judged data root dfd
// with O_NOFOLLOW and judges it on its descriptor as a root-written file of
// owner (judgeRootFile), within maxMaintenanceRunsSize, then parses it
// strictly. A missing record holds no run; anything else that does not
// read is errMaintenanceRunsBad.
func readMaintenanceRuns(dfd int, owner int64, dataRoot string) ([]MaintenanceRun, error) {
	fd, err := unix.Openat(dfd, maintenanceRunsName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", errMaintenanceRunsBad, err)
	}
	f := os.NewFile(uintptr(fd), maintenanceRunsName)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: stat: %w", errMaintenanceRunsBad, err)
	}
	if err := judgeRootFile(fd, &st, maintenanceRunsName, owner); err != nil {
		if fix := rootFileFlagRepair(err, dataRoot, maintenanceRunsName); fix != "" {
			return nil, fmt.Errorf("%s: %w; the first repair is %s, which clears the flag on this root-owned file; only if that does not work: %w", maintenanceRunsName, err, fix, errMaintenanceRunsBad)
		}
		return nil, fmt.Errorf("%w: %w", errMaintenanceRunsBad, err)
	}
	if st.Size > int64(maxMaintenanceRunsSize) {
		return nil, fmt.Errorf("%w: past %d bytes", errMaintenanceRunsBad, maxMaintenanceRunsSize)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(maxMaintenanceRunsSize)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", errMaintenanceRunsBad, err)
	}
	if len(b) > maxMaintenanceRunsSize {
		return nil, fmt.Errorf("%w: past %d bytes", errMaintenanceRunsBad, maxMaintenanceRunsSize)
	}
	runs, err := parseMaintenanceRuns(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMaintenanceRunsBad, err)
	}
	return runs, nil
}

// writeMaintenanceRuns writes runs as the record through the data root
// dfd, by the removed-scopes record's discipline (writeRemovedScopes): a
// temporary file, created O_EXCL|O_NOFOLLOW after any leftover is
// unlinked, set to maintenanceRunsMode, written, fsynced, renamed over the
// record, and the data root fsynced. Root runs it, so the file is root's.
func writeMaintenanceRuns(dfd int, runs []MaintenanceRun) error {
	b := encodeMaintenanceRuns(runs)
	if err := unix.Unlinkat(dfd, maintenanceRunsTemp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove a leftover %s: %w", maintenanceRunsTemp, err)
	}
	fd, err := unix.Openat(dfd, maintenanceRunsTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, maintenanceRunsMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", maintenanceRunsTemp, err)
	}
	f := os.NewFile(uintptr(fd), maintenanceRunsTemp)
	err = unix.Fchmod(fd, maintenanceRunsMode)
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, maintenanceRunsTemp, 0) // a partial temporary file is never read
		return fmt.Errorf("write %s: %w", maintenanceRunsTemp, err)
	}
	if err := unix.Renameat(dfd, maintenanceRunsTemp, dfd, maintenanceRunsName); err != nil {
		return fmt.Errorf("rename %s: %w", maintenanceRunsTemp, err)
	}
	return unix.Fsync(dfd)
}

// appendMaintenanceRun appends r to the record in the data root dfd,
// keeping the newest maxMaintenanceRuns. A record that already holds r's
// run id is left as it is, so a rerun that reports a saved run appends it
// once. A record that does not read is not replaced: its error is
// returned.
func appendMaintenanceRun(dfd int, owner int64, dataRoot string, r MaintenanceRun) error {
	runs, err := readMaintenanceRuns(dfd, owner, dataRoot)
	if err != nil {
		return err
	}
	for _, have := range runs {
		if have.Run == r.Run {
			return nil
		}
	}
	runs = append(runs, r)
	if n := len(runs) - maxMaintenanceRuns; n > 0 {
		runs = runs[n:]
	}
	return writeMaintenanceRuns(dfd, runs)
}

// recordLossyRun appends the record of a committed run of verb, its run
// id run and new log's inode ino, when report drops anything; a report
// that drops nothing appends nothing. The maintenance verb calls it
// holding its locks and before the marker goes.
func (s *FileStore) recordLossyRun(dfd int, run, verb string, ino uint64, report map[string]int64) error {
	r, lossy := lossyRunOf(run, verb, ino, report, s.now())
	if !lossy {
		return nil
	}
	if err := appendMaintenanceRun(dfd, int64(s.floorUID), s.dataRoot, r); err != nil {
		return fmt.Errorf("record the run's drop counts (%s) in %s: %w", r.dropText(), maintenanceRunsName, err)
	}
	return nil
}

// dropText is r's drop counts as key=value pairs, for an error that says
// what was not recorded.
func (r MaintenanceRun) dropText() string {
	f := make([]string, 0, len(dropFields))
	for _, k := range dropFields {
		f = append(f, fmt.Sprintf("%s=%d", k, r.Drops[k]))
	}
	return strings.Join(f, ", ")
}

// LossyMaintenanceRuns reads the lossy-run record in the data root, for
// doctor: the committed maintenance runs that dropped lines or keys, oldest
// first, at most the newest 64. No record is no run. A record that does not
// judge or parse is an error, never an empty list. The record is root's
// 0644, so any account reads it.
func (s *FileStore) LossyMaintenanceRuns(ctx context.Context) ([]MaintenanceRun, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	return readMaintenanceRuns(dfd, int64(s.floorUID), s.dataRoot)
}
