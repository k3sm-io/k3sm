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
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The directory swap floor --rebuild and audit --rotate share
// (docs/design/keystore.md § "The swap"). Each log lives alone (the audit
// log with its archives) in a root-owned directory in keystore-logs/. A
// verb builds the complete replacement directory in the root-only
// keystore-staging/, its new log handed to the service user and flagged
// SF_APPEND before it is reachable, and exchanges it with the live one in
// one renameatx_np(RENAME_SWAP). The canonical directory is always a
// complete, flagged, judged set: the old one or the new one. The old log
// is unflagged only once it is unreachable by path and no longer an input,
// and is never read again.
//
// The steps:
//  1. the locks, keystore-lock before .lock, then the marker, recording
//     the verb and a random run id (beginMaintenance);
//  2. the old log opened and judged by descriptor and read once, bounded
//     by its size at open (openOldLog; the verb reads it);
//  3. the replacement directory built in keystore-staging/
//     (buildLogDir);
//  4. the verb's report written into the marker (writeMarker);
//  5. renameatx_np(RENAME_SWAP), the commit point, and both parents
//     fsynced (swapLogDir);
//  6. the retired directory, now in staging, cleaned (cleanStaging);
//  7. the marker removed (end); the caller prints the report and writes
//     the audit line.

// The verbs a marker records.
const (
	verbRebuild = "floor-rebuild"
	verbRotate  = "audit-rotate"
)

// maxMarkerSize bounds the marker's read: its fields are a few short
// lines.
const maxMarkerSize = 4096

// marker is the maintenance marker's content: the verb and run id of the
// run that wrote it, and, once the run reached step 4, the new log's
// device and inode and the verb's report.
type marker struct {
	verb, run string
	swapped   bool
	dev, ino  uint64
	report    map[string]int64
}

// encode renders m as key=value lines.
func (mk *marker) encode() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "verb=%s\nrun=%s\n", mk.verb, mk.run)
	if mk.swapped {
		fmt.Fprintf(&b, "swapped=1\ndev=%d\nino=%d\n", mk.dev, mk.ino)
		for _, k := range slices.Sorted(maps.Keys(mk.report)) {
			fmt.Fprintf(&b, "report.%s=%d\n", k, mk.report[k])
		}
	}
	return b.Bytes()
}

// parseMarker reads b as encode writes it; anything it does not know is
// a marker of no verb, which no run finishes from.
func parseMarker(b []byte) *marker {
	mk := &marker{report: map[string]int64{}}
	for line := range strings.SplitSeq(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch {
		case k == "verb":
			mk.verb = v
		case k == "run":
			mk.run = v
		case k == "swapped":
			mk.swapped = v == "1"
		case k == "dev":
			mk.dev, _ = strconv.ParseUint(v, 10, 64)
		case k == "ino":
			mk.ino, _ = strconv.ParseUint(v, 10, 64)
		case strings.HasPrefix(k, "report."):
			n, err := strconv.ParseInt(v, 10, 64)
			if err == nil {
				mk.report[strings.TrimPrefix(k, "report.")] = n
			}
		}
	}
	if mk.swapped && (mk.ino == 0 || mk.verb == "") {
		mk.swapped = false
	}
	return mk
}

// maintenance is a maintenance verb's hold: the floor lock, the store lock,
// the keystore root, and the judged descriptors on the data root, the
// staging directory and the logs directory.
type maintenance struct {
	s    *FileStore
	root *os.Root
	done func()
	fl   *floorLock
	dfd  int
	sfd  int
	lfd  int
	// mk is this run's marker, and marker records that it stands.
	mk     marker
	marker bool
	// saved is the report of a crashed run of this verb whose swap
	// committed: the verb prints it and does not run again.
	saved map[string]int64
	// refusal is the verb's refused-and-changed-nothing error.
	refusal error
	// keep leaves the marker in place: the run failed past step 4, so a
	// rerun reads it.
	keep bool
	// hook is the attribute writer's step seam, or nil.
	hook SwapStepper
}

// step calls the step seam, when there is one, before the step name.
func (m *maintenance) step(name string) error {
	if m.hook == nil {
		return nil
	}
	if err := m.hook.BeforeSwapStep(name); err != nil {
		return fmt.Errorf("before the step %s: %w; rerun the verb", name, err)
	}
	return nil
}

// errStoreLockHeld is the maintenance verbs' refusal when the store lock
// is not had within maintenanceLockWait. The verb already holds
// keystore-lock, which every root verb takes first, so the holder is a
// process running as the service user: the server or one of its processes.
var errStoreLockHeld = errors.New("a process running as the service user held the store lock (keystore/.lock) for 30 s: stop the server (sudo k3sm stop) or that process, then rerun; nothing was changed")

// lockMaintenance takes a maintenance verb's two locks in the order every
// verb that takes both keeps (docs/design/keystore.md § "Concurrency"):
// keystore-lock first, then the exclusive store lock, waiting at most
// maintenanceLockWait for it (errStoreLockHeld past it). A failure
// releases what it took.
func (s *FileStore) lockMaintenance(ctx context.Context, root *os.Root) (*floorLock, func(), error) {
	fl, _, err := s.lockFloor(ctx)
	if err != nil {
		return nil, nil, err
	}
	saved := s.lockWait
	s.lockWait = maintenanceLockWait
	unlock, err := s.lock(ctx, root, true)
	s.lockWait = saved
	if err != nil {
		fl.unlock()
		if errors.Is(err, errLockTimeout) {
			return nil, nil, errStoreLockHeld
		}
		return nil, nil, err
	}
	return fl, unlock, nil
}

// beginMaintenance is step 1 for verb, whose log is logName: it opens and
// judges the data root, takes keystore-lock and the exclusive store lock
// (lockMaintenance), opens and judges keystore-staging/ and cleans it
// (cleanStaging: whatever a crashed run left there is removed, never
// read), and opens and judges keystore-logs/. A marker found then is a run
// that died: when it is this verb's, its report says the swap was reached,
// and the live log is the inode it recorded for the new log, the swap
// committed, and m.saved is its report (the verb prints it and does not
// run again). Otherwise, the other verb's marker among them, the live set
// is valid and this run writes its own marker and runs from the start; a
// committed run of the other verb is first reported (reportEarlierRun).
func (s *FileStore) beginMaintenance(ctx context.Context, verb, logName string, refusal error, attrs FileAttrWriter) (*maintenance, error) {
	root, err := s.openDir(s.dir, false)
	if err != nil {
		return nil, err
	}
	m := &maintenance{s: s, root: root, done: func() { _ = root.Close() }, dfd: -1, sfd: -1, lfd: -1, refusal: refusal}
	m.hook, _ = attrs.(SwapStepper)
	if m.dfd, err = s.openLogDataRoot(); err != nil {
		m.end()
		return nil, err
	}
	fl, unlock, err := s.lockMaintenance(ctx, root)
	if err != nil {
		m.end()
		return nil, err
	}
	m.fl = fl
	m.done = func() { unlock(); _ = root.Close() }
	if m.sfd, err = m.openStagingDir(); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	if err := cleanStaging(m.sfd, attrs); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: clean %s: %w", refusal, stagingDirName, err)
	}
	if m.lfd, err = s.openLogsDir(m.dfd); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	for _, name := range []string{userFloorLogName, auditLogName} {
		if oldLogLocation(m.dfd, m.lfd, name) {
			m.end()
			return nil, fmt.Errorf("%w: %w", refusal, errLogOldLocation(name))
		}
	}
	prior, err := m.readMarker()
	if err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	if prior != nil && prior.verb == verb && prior.swapped {
		var st unix.Stat_t
		if s.statLog(m.lfd, logName, &st) == nil && uint64(st.Dev) == prior.dev && st.Ino == prior.ino {
			m.marker = true // it goes in end
			m.saved = prior.report
			return m, nil
		}
	}
	if prior != nil && prior.swapped && prior.verb != verb {
		// The other verb's report counts only when its swap committed: its
		// log's live inode is the one it recorded.
		var st unix.Stat_t
		if pl := verbLog(prior.verb); pl != "" && s.statLog(m.lfd, pl, &st) == nil && uint64(st.Dev) == prior.dev && st.Ino == prior.ino {
			s.reportEarlierRun(ctx, prior)
		}
	}
	var run [8]byte
	if err := s.readRandom(run[:]); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: name the run: %w", refusal, err)
	}
	m.mk = marker{verb: verb, run: hex.EncodeToString(run[:])}
	if err := m.writeMarker(); err != nil {
		m.end()
		return nil, fmt.Errorf("%w: %w", refusal, err)
	}
	return m, nil
}

// readMarker reads the marker a crashed run left, or returns nil when
// there is none. A marker judgeRootFile refuses refuses the verb; a second
// link is a Warn.
func (m *maintenance) readMarker() (*marker, error) {
	fd, err := unix.Openat(m.dfd, maintenanceMarkerName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %w; root repairs it with sudo k3sm install, which removes a marker it cannot read", errLogUntrusted, maintenanceMarkerName, err)
	}
	f := os.NewFile(uintptr(fd), maintenanceMarkerName)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("stat %s: %w", maintenanceMarkerName, err)
	}
	if err := judgeRootFile(fd, &st, maintenanceMarkerName, int64(m.s.floorUID)); err != nil {
		return nil, fmt.Errorf("%w: %s: %w; root repairs it with sudo k3sm install, which removes a marker it cannot read", errLogUntrusted, maintenanceMarkerName, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxMarkerSize))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", maintenanceMarkerName, err)
	}
	m.marker = true
	return parseMarker(b), nil
}

// writeMarker writes m.mk as the marker: a fresh root 0644 file in
// keystore-staging/, written, fsynced and renamed over the marker's name in
// the data root, which is fsynced.
func (m *maintenance) writeMarker() error {
	tmp := maintenanceMarkerName + ".new"
	_ = unix.Unlinkat(m.sfd, tmp, 0) // cleanStaging removed any; a missing name is fine
	fd, err := unix.Openat(m.sfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, markerMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", maintenanceMarkerName, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, err = f.Write(m.mk.encode())
	if err == nil {
		err = unix.Fchmod(fd, markerMode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(m.sfd, tmp, m.dfd, maintenanceMarkerName)
	}
	if err != nil {
		_ = unix.Unlinkat(m.sfd, tmp, 0) // the marker stands as it was
		return fmt.Errorf("write %s: %w", maintenanceMarkerName, err)
	}
	m.marker = true
	if err := unix.Fsync(m.dfd); err != nil {
		return fmt.Errorf("fsync the data root: %w", err)
	}
	return nil
}

// openStagingDir creates the staging directory in the data root, root's
// 0700, or keeps the one a crashed run left, and opens it
// O_DIRECTORY|O_NOFOLLOW and judges it on its descriptor: a directory of
// the data root's owner (root), mode 0700, with no file flag and no
// extended ACL. Only root can reach a name in it.
func (m *maintenance) openStagingDir() (int, error) {
	if err := unix.Mkdirat(m.dfd, stagingDirName, stagingDirMode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, fmt.Errorf("create %s: %w", stagingDirName, err)
	}
	fd, err := unix.Openat(m.dfd, stagingDirName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: %s: %w; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", errLogUntrusted, stagingDirName, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("stat %s: %w", stagingDirName, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(m.s.floorUID) || st.Mode&0o7777 != stagingDirMode {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%w: %s is not a directory of the data root's owner at mode 0700; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", errLogUntrusted, stagingDirName)
	}
	if err := judgeFlagsACL(fd, fdFlags); err != nil {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%s: %w; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", stagingDirName, err)
	}
	if fl, _ := fdFlags(fd); fl != 0 {
		_ = unix.Close(fd) // read-only
		return -1, fmt.Errorf("%w: %s carries a file flag; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", errLogUntrusted, stagingDirName)
	}
	return fd, nil
}

// end removes the staging directory, when empty, and the marker unless
// keep, then releases the locks.
func (m *maintenance) end() {
	if m.lfd >= 0 {
		_ = unix.Close(m.lfd) // read-only directory descriptor
	}
	if m.sfd >= 0 {
		_ = unix.Close(m.sfd)                                       // read-only directory descriptor
		_ = unix.Unlinkat(m.dfd, stagingDirName, unix.AT_REMOVEDIR) // a staging directory left is cleaned and reused by the next run
	}
	if m.marker && !m.keep {
		_ = unix.Unlinkat(m.dfd, maintenanceMarkerName, 0) // a marker left only keeps the listener down
		_ = unix.Fsync(m.dfd)
	}
	if m.dfd >= 0 {
		_ = unix.Close(m.dfd) // read-only directory descriptor
	}
	if m.fl != nil {
		m.fl.unlock()
	}
	m.done()
}

// oldLog is a verb's old log, step 2: the open file, its size at open
// (the one read is bounded by it), and its directory's descriptor.
type oldLog struct {
	f    *os.File
	size int64
	ino  uint64
	dir  int
}

// close releases the old log and its directory.
func (o *oldLog) close() {
	_ = o.f.Close()       // read-only
	_ = unix.Close(o.dir) // read-only directory descriptor
}

// errOldLogUnflagged is an old log with its SF_APPEND flag clear that the
// service user owns: while it was clear any descriptor the service user
// held could have rewritten it, so no verb takes it as input.
var errOldLogUnflagged = fmt.Errorf("%w: its SF_APPEND flag is clear and the service user owns it, so it could have been rewritten; an unflagged log is taken as input only when root owns it (a restore): as root, restore the log from a backup (root-owned, mode 0600), then rerun the verb", errLogUntrusted)

// openOldLog is step 2's open: the log name, in its judged directory
// under lfd, opened read-only with O_NOFOLLOW and judged on its
// descriptor. It must be a regular file; flagged SF_APPEND (its owner is
// then the service user, or root), or, unflagged, root's (a restore). A log
// with more than one link is taken as input, with a Warn naming it: the
// verb swaps in a fresh inode, so the other link keeps only the old file.
func (s *FileStore) openOldLog(lfd int, name string) (*oldLog, error) {
	dir, err := s.openLogDir(lfd, name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(dir) // read-only directory descriptor
		return nil, err
	}
	o := &oldLog{f: os.NewFile(uintptr(fd), name), dir: dir}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		o.close()
		return nil, err
	}
	fl, err := s.logFlags(o.f)
	if err != nil {
		o.close()
		return nil, fmt.Errorf("%w: read the flags of %s: %w; rerun the verb", errLogUntrusted, name, err)
	}
	if err := s.judgeOldLog(name, &st, fl); err != nil {
		o.close()
		return nil, err
	}
	o.size, o.ino = st.Size, st.Ino
	return o, nil
}

// judgeOldLog refuses the old log name, which st and its flags fl
// describe, unless it is a regular file, flagged SF_APPEND or, unflagged,
// root's (errOldLogUnflagged). More than one link is a Warn.
func (s *FileStore) judgeOldLog(name string, st *unix.Stat_t, fl uint32) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file: as root, move it aside and restore the log from a backup, then rerun the verb", errLogUntrusted, name)
	}
	if fl&sfAppend == 0 && int64(st.Uid) != int64(s.floorUID) {
		return fmt.Errorf("%s: %w", name, errOldLogUnflagged)
	}
	if st.Nlink > 1 {
		slog.Warn("a keystore append-only log has more than one link; the maintenance verb replaces it with a fresh file, and the other link keeps only the old one", "log", name, "links", st.Nlink)
	}
	return nil
}

// newDirName is the replacement directory's name in keystore-staging/
// for the log name.
func newDirName(name string) string { return logDirOf(name) + ".new" }

// buildLogDir is step 3: the complete replacement directory for the log
// name, built in keystore-staging/ and judged by descriptor at every step.
// The directory is created and opened O_DIRECTORY|O_NOFOLLOW; the new log
// is created in it O_EXCL|O_NOFOLLOW, filled by content, fsynced, handed
// to the service user, set to 0600, flagged SF_APPEND and judged on its
// descriptor (judgeLog: the service user's, 0600, flags exactly SF_APPEND,
// one link, no ACL); extra, when set, places more files in the directory
// (rotate's archives); the directory is set to root's 0755 and fsynced. It
// returns the new log's device and inode.
func (s *FileStore) buildLogDir(m *maintenance, name string, content func(io.Writer) error, extra func(dir int) error, attrs FileAttrWriter) (uint64, uint64, error) {
	nd := newDirName(name)
	if err := unix.Mkdirat(m.sfd, nd, stagingDirMode); err != nil {
		return 0, 0, fmt.Errorf("create %s: %w", nd, err)
	}
	dir, err := unix.Openat(m.sfd, nd, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", nd, err)
	}
	defer func() { _ = unix.Close(dir) }() // fsynced below
	var dst unix.Stat_t
	if err := unix.Fstat(dir, &dst); err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", nd, err)
	}
	if dst.Mode&unix.S_IFMT != unix.S_IFDIR || int64(dst.Uid) != int64(s.floorUID) {
		return 0, 0, fmt.Errorf("%w: %s is not a directory of the data root's owner; rerun the verb, which cleans keystore-staging/ first", errLogUntrusted, nd)
	}
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, logMode)
	if err != nil {
		return 0, 0, fmt.Errorf("create %s/%s: %w", nd, name, err)
	}
	nf := os.NewFile(uintptr(fd), name)
	defer func() { _ = nf.Close() }() // fsynced below
	bw := bufio.NewWriterSize(nf, 64<<10)
	if err := content(bw); err != nil {
		return 0, 0, fmt.Errorf("write %s/%s: %w", nd, name, err)
	}
	if err := bw.Flush(); err != nil {
		return 0, 0, fmt.Errorf("write %s/%s: %w", nd, name, err)
	}
	if err := nf.Sync(); err != nil {
		return 0, 0, fmt.Errorf("fsync %s/%s: %w", nd, name, err)
	}
	if err := attrs.Fchown(fd, int(s.uid), int(s.gid)); err != nil {
		return 0, 0, fmt.Errorf("hand %s/%s to the service user: %w", nd, name, err)
	}
	if err := attrs.Fchmod(fd, logMode); err != nil {
		return 0, 0, fmt.Errorf("chmod %s/%s: %w", nd, name, err)
	}
	if err := attrs.Fchflags(fd, sfAppend); err != nil {
		return 0, 0, fmt.Errorf("flag %s/%s append-only: %w", nd, name, err)
	}
	var st unix.Stat_t
	if err := s.judgeLog(nf, &st); err != nil {
		return 0, 0, fmt.Errorf("the new %s: %w", name, err)
	}
	if extra != nil {
		if err := extra(dir); err != nil {
			return 0, 0, err
		}
	}
	if err := unix.Fchmod(dir, logsDirMode); err != nil {
		return 0, 0, fmt.Errorf("chmod %s: %w", nd, err)
	}
	if err := s.judgeLogDir(dir, nd); err != nil {
		return 0, 0, err
	}
	if err := unix.Fsync(dir); err != nil {
		return 0, 0, fmt.Errorf("fsync %s: %w", nd, err)
	}
	return uint64(st.Dev), st.Ino, nil
}

// The steps a SwapStepper is called before, in the order the swap runs
// them (docs/design/keystore.md § "The swap"). The attribute calls of step
// 3 (the new log's fchown, fchmod and fchflags) reach the writer itself.
const (
	swapStepReadOld = "read-old"
	swapStepBuild   = "build"
	swapStepReport  = "report"
	swapStepSwap    = "swap"
	swapStepClean   = "clean"
	swapStepEnd     = "end"
)

// SwapSteps is the step seam's step names, in order.
var SwapSteps = []string{swapStepReadOld, swapStepBuild, swapStepReport, swapStepSwap, swapStepClean, swapStepEnd}

// swapLogDir runs steps 3 to 7 for the log name: it builds the
// replacement directory (buildLogDir), writes report into the marker, swaps
// the directory in, cleans the retired one, and leaves the marker for end
// to remove. A failure before step 4 cleans staging and refuses, the live
// set untouched; from step 4 on it keeps the marker, which a rerun reads.
func (s *FileStore) swapLogDir(m *maintenance, name string, content func(io.Writer) error, extra func(int) error, report map[string]int64, attrs FileAttrWriter) error {
	refuse := func(err error) error {
		_ = cleanStaging(m.sfd, attrs) // the next run cleans what this leaves
		return fmt.Errorf("%w: %w", m.refusal, err)
	}
	if err := m.step(swapStepBuild); err != nil {
		return refuse(err)
	}
	dev, ino, err := s.buildLogDir(m, name, content, extra, attrs)
	if err != nil {
		return refuse(err)
	}
	if err := m.step(swapStepReport); err != nil {
		return refuse(err)
	}
	m.mk.swapped, m.mk.dev, m.mk.ino, m.mk.report = true, dev, ino, report
	m.keep = true
	if err := m.writeMarker(); err != nil {
		return fmt.Errorf("%w; rerun the verb", err)
	}
	if err := m.step(swapStepSwap); err != nil {
		return err
	}
	nd, dir := newDirName(name), logDirOf(name)
	if err := renameSwap(m.sfd, nd, m.lfd, dir); err != nil {
		return fmt.Errorf("swap %s/%s with %s/%s: %w; rerun the verb", stagingDirName, nd, logsDirName, dir, err)
	}
	// The swap committed: the new log is live, so every error from here on
	// is committed, never a refusal (errSwapCommitted).
	for _, d := range []struct {
		fd   int
		name string
	}{{m.sfd, stagingDirName}, {m.lfd, logsDirName}} {
		if err := unix.Fsync(d.fd); err != nil {
			return swapCommitted(fmt.Errorf("fsync %s: %w; rerun the verb, which reports the committed swap", d.name, err))
		}
	}
	if err := m.step(swapStepClean); err != nil {
		return swapCommitted(err)
	}
	if err := cleanStaging(m.sfd, attrs); err != nil {
		slog.Warn("the retired keystore log directory was not removed; the next maintenance verb or install removes it", "dir", stagingDirName+"/"+nd, "err", err)
	}
	if err := m.step(swapStepEnd); err != nil {
		return swapCommitted(err)
	}
	m.keep = false
	return nil
}

// errSwapCommitted marks an error a maintenance verb met after its
// RENAME_SWAP: the new log is live and the change stands (Committed), so the
// CLI exits 4 and audits committed, never refused, and prints the verb's
// report.
var errSwapCommitted = fmt.Errorf("the swap committed and the new log is in place: %w", errCommitted)

// swapCommitted marks err as met after the swap committed.
func swapCommitted(err error) error { return fmt.Errorf("%w; %w", errSwapCommitted, err) }

// maxStagingDepth bounds cleanStaging's descent: a replacement directory
// holds files and, audit/'s, the archives/ directory of files.
const maxStagingDepth = 2

// cleanStaging removes everything in the staging directory sfd, which no
// other user can reach: what a crashed run left, and a swap's retired
// directory. Nothing in it is trusted or read. A regular file carrying a
// flag has it cleared on its descriptor first, but only with one link (a
// file with another link could be reachable elsewhere, and is refused);
// every other entry is unlinked with unlinkat, which never follows, and a
// directory is emptied by descriptor, re-checked to be the entry named,
// then removed.
func cleanStaging(sfd int, attrs FileAttrWriter) error {
	return cleanDir(sfd, attrs, 0)
}

// CleanStagingDir is cleanStaging for install, on its descriptor of
// keystore-staging/.
func CleanStagingDir(sfd int, attrs FileAttrWriter) error { return cleanStaging(sfd, attrs) }

// cleanDir removes every entry of the directory open at dfd.
func cleanDir(dfd int, attrs FileAttrWriter, depth int) error {
	names, err := dirNames(dfd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := removeEntry(dfd, n, attrs, depth); err != nil {
			return err
		}
	}
	return nil
}

// dirNames lists the directory open at dfd, through a duplicate of the
// descriptor read from its start.
func dirNames(dfd int) ([]string, error) {
	dup, err := unix.Dup(dfd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer func() { _ = f.Close() }() // read-only
	if _, err := unix.Seek(dup, 0, io.SeekStart); err != nil {
		return nil, err
	}
	return f.Readdirnames(-1)
}

// removeEntry removes name in the directory pfd (cleanStaging).
func removeEntry(pfd int, name string, attrs FileAttrWriter, depth int) error {
	var st unix.Stat_t
	if err := unix.Fstatat(pfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		if depth >= maxStagingDepth {
			return fmt.Errorf("%w: %s is nested deeper than a maintenance verb builds; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", errLogUntrusted, name)
		}
		fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", name, err)
		}
		err = sameFile(fd, &st, name)
		if err == nil {
			err = cleanDir(fd, attrs, depth+1)
		}
		_ = unix.Close(fd) // read-only directory descriptor
		if err != nil {
			return err
		}
		return unix.Unlinkat(pfd, name, unix.AT_REMOVEDIR)
	case unix.S_IFREG:
		if statFlags(&st) != 0 {
			if st.Nlink != 1 {
				return fmt.Errorf("%w: %s carries a file flag and has more than one link; remove keystore-staging/ in the data root as root (sudo chflags -R 0 and sudo rm -rf), then rerun the verb, which makes it afresh", errLogUntrusted, name)
			}
			fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", name, err)
			}
			err = sameFile(fd, &st, name)
			if err == nil {
				err = attrs.Fchflags(fd, 0)
			}
			_ = unix.Close(fd) // read-only; never read
			if err != nil {
				return fmt.Errorf("clear the flag of %s: %w", name, err)
			}
		}
	}
	return unix.Unlinkat(pfd, name, 0)
}

// sameFile refuses the descriptor fd unless it is the file st described.
func sameFile(fd int, st *unix.Stat_t, name string) error {
	var got unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		return fmt.Errorf("stat %s: %w", name, err)
	}
	if got.Dev != st.Dev || got.Ino != st.Ino {
		return fmt.Errorf("%w: %s was replaced while it was removed; rerun the verb", errLogUntrusted, name)
	}
	return nil
}
