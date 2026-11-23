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
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// PreFrameBudget is the pre-frame part of the reconciler budget in the
// audit log, in bytes: the refused lines of connections the socket listener
// refuses before their first frame, and their dropped-count summaries
// (docs/design/keystore.md § "Per-uid fairness", the reconciler budget, and
// Open requirement 9). Each such line is charged its own length, newline
// included, and the leading newline its append writes; the part is counted
// from the audit log, never from memory.
const PreFrameBudget = 256 << 10

// The pre-frame part's split (docs/design/keystore.md § "Per-uid fairness",
// the reconciler budget). Every pre-frame line is charged to exactly one
// class, and no class draws on another's bytes:
//
//   - login: a refusal of a peer whose uid is in the login range (501 to
//     2147483647) and whose reason is not a uid-range reason (sandboxed,
//     sandbox-unknown, token-mismatch, cred-unreadable with its uid read);
//     each uid has its own sub-share within the class.
//   - root: a refusal whose reason is root.
//   - service-uid: a refusal whose reason is service-uid.
//   - no-uid: a refusal under uid 4294967295, no uid read.
//   - system-high: a refusal whose reason is system-uid or high-uid, and
//     any other refusal outside the login range; each uid has its own
//     sub-share within the class.
//
// A refusal line's class is read off its uid and result; a dropped-count
// summary line names its class in its own "class" field (preFrameClass),
// which the recount reads, so a summary is charged to the class of the
// refusals it summarises whatever uid it names. Each class is recounted
// from the log, never from memory.
const (
	// PreFrameLoginUIDShare is the most one login uid's pre-frame lines may
	// take of an audit log, for the life of that log.
	PreFrameLoginUIDShare = 8 << 10
	// PreFrameLoginBudget is the most all login uids' pre-frame lines may
	// take of an audit log together.
	PreFrameLoginBudget = 128 << 10
	// PreFrameReserved is the part kept for the pre-frame lines of
	// ineligible peers, split by class below.
	PreFrameReserved = PreFrameBudget - PreFrameLoginBudget
	// PreFrameRootBudget is the most root's refusal lines and their
	// summaries may take.
	PreFrameRootBudget = 32 << 10
	// PreFrameServiceUIDBudget is the most the service uid's refusal lines
	// and their summaries may take.
	PreFrameServiceUIDBudget = 32 << 10
	// PreFrameNoUIDBudget is the most the refusals with no uid read
	// (cred-unreadable under uid 4294967295) and their summaries may take.
	PreFrameNoUIDBudget = 16 << 10
	// PreFrameSystemHighBudget is the most all system-uid and high-uid
	// lines may take together.
	PreFrameSystemHighBudget = 48 << 10
	// PreFrameSystemHighUIDShare is the most one system or high uid's
	// lines may take within PreFrameSystemHighBudget.
	PreFrameSystemHighUIDShare = 8 << 10
)

// The reserved classes add up to the reserved part, exactly: a constant
// changed alone fails to compile (a negative array length).
var _ [0]struct{} = [PreFrameRootBudget + PreFrameServiceUIDBudget + PreFrameNoUIDBudget + PreFrameSystemHighBudget - PreFrameReserved]struct{}{}

// preFrameClass is a pre-frame line's class: a closed set, named on the
// wire in a summary line's "class" field.
type preFrameClass string

// The pre-frame classes.
const (
	preFrameClassLogin      preFrameClass = "login"
	preFrameClassRoot       preFrameClass = "root"
	preFrameClassServiceUID preFrameClass = "service-uid"
	preFrameClassNoUID      preFrameClass = "no-uid"
	preFrameClassSystemHigh preFrameClass = "system-high"
)

// preFrameClasses is every class, in the order the budgets list them.
var preFrameClasses = []preFrameClass{preFrameClassLogin, preFrameClassRoot, preFrameClassServiceUID, preFrameClassNoUID, preFrameClassSystemHigh}

// budget is the most c's lines may take of an audit log together.
func (c preFrameClass) budget() int64 {
	switch c {
	case preFrameClassLogin:
		return PreFrameLoginBudget
	case preFrameClassRoot:
		return PreFrameRootBudget
	case preFrameClassServiceUID:
		return PreFrameServiceUIDBudget
	case preFrameClassNoUID:
		return PreFrameNoUIDBudget
	case preFrameClassSystemHigh:
		return PreFrameSystemHighBudget
	}
	return 0
}

// uidShare is the most one uid's lines may take within c, or 0 when c has
// no per-uid limit.
func (c preFrameClass) uidShare() int64 {
	switch c {
	case preFrameClassLogin:
		return PreFrameLoginUIDShare
	case preFrameClassSystemHigh:
		return PreFrameSystemHighUIDShare
	}
	return 0
}

// PreFrameNoUID is the uid a pre-frame refusal names when none was read:
// (uid_t)-1, which no process runs as. The socket package's NoUID is
// this constant, so the two cannot drift apart.
const PreFrameNoUID = ^uint32(0)

// PendingSummariesPerAppend is how many uids' pending dropped counts a
// refused line that lands carries after it as summary lines, in uid order;
// the rest wait for the next line or the minute's summary pass
// (docs/design/keystore.md Open requirement 9: a dropped count reaches the
// log with the next line written).
const PendingSummariesPerAppend = 8

// ServerAppendLockWait is the longest a server append waits for the store
// lock (docs/design/keystore.md § "The audit log": every append takes the
// store lock); past it the line is not written and is counted as dropped.
const ServerAppendLockWait = 2 * time.Second

// The fields that mark a pre-frame line, and its words.
const (
	auditViaSocket      = "socket"
	auditOpRefused      = "refused"
	auditResultDropped  = "dropped"
	auditChargeReconcil = "reconciler"
	auditSourcePreFrame = "pre-frame"
)

// errPreFrameBudgetSpent is a pre-frame line the budget has no room for.
var errPreFrameBudgetSpent = errors.New("the audit log's pre-frame refusal budget is spent; the line is counted as dropped until root rotates the audit log")

// LogFileID names one file: its device and inode.
type LogFileID struct{ Dev, Ino uint64 }

// ServerLogs is the server's hold on the two append-only logs: an append
// descriptor for each, opened through the data root and judged, and the
// pre-frame part of the reconciler budget counted from the audit log the
// descriptor names. The server constructs one over its store
// (FileStore.ServerLogs) and appends the socket listener's pre-frame
// refusals through it (docs/design/keystore.md § "The audit log",
// "The server reopens after maintenance", "Every append checks that its
// descriptor is still the canonical file").
//
// Every append takes the exclusive store lock, waiting at most
// ServerAppendLockWait, and under it compares each descriptor's (dev, ino)
// with the canonical name's, read on the judged data root without following
// a symlink, reopening and recounting on a mismatch, so a line never lands
// in a renamed archive or an unlinked file even when the server never saw
// the maintenance marker. Reopen does the same unconditionally: the start
// step, and the step after maintenance. A line that is not written (the
// lock not had, the budget spent, a log refused) is counted as dropped for
// its uid, and the count is carried into that uid's next summary line.
//
// It is safe for concurrent use.
type ServerLogs struct {
	s *FileStore

	mu    sync.Mutex // guards what follows; taken inside the store lock
	audit heldLog
	floor heldLog
	// used is the pre-frame bytes counted in the held audit file up to
	// audit.off; usedByClass each class's part of it, and usedByUID each
	// uid's within a class that has per-uid limits.
	used        int64
	usedByClass map[preFrameClass]int64
	usedByUID   map[preFrameKey]int64
	// pending is each uid's dropped count, by class, not yet in a summary
	// line.
	pending map[preFrameKey]uint64
	// sync fsyncs the held audit file after an append; a test replaces it.
	sync func(*os.File) error
}

// preFrameKey is one uid within one class.
type preFrameKey struct {
	class preFrameClass
	uid   uint32
}

// heldLog is one held append descriptor and its file's identity. For the
// audit log, off is how far the pre-frame count has read.
type heldLog struct {
	log *appendLog
	f   *os.File
	id  LogFileID
	off int64
}

// ServerLogs returns the store's server append surface. It opens nothing:
// the first Reopen or append opens both logs and counts the budget.
func (s *FileStore) ServerLogs() *ServerLogs {
	return &ServerLogs{
		s:           s,
		audit:       heldLog{log: &appendLog{s: s, name: auditLogName}},
		floor:       heldLog{log: &appendLog{s: s, name: userFloorLogName}},
		pending:     map[preFrameKey]uint64{},
		usedByClass: map[preFrameClass]int64{},
		usedByUID:   map[preFrameKey]int64{},
		sync:        (*os.File).Sync,
	}
}

// Reopen takes the store lock exclusively, reopens both append descriptors
// through the data root, judges them, recounts the pre-frame budget from the
// new audit file and only then releases the lock. The server calls it at
// start and after maintenance, before the listener starts again.
func (l *ServerLogs) Reopen(ctx context.Context) error {
	return l.locked(ctx, func() error {
		l.closeLocked()
		return l.ensureLocked()
	})
}

// CheckServerLogs is Reopen's judgement, read-only, for doctor: it opens
// both logs O_RDONLY through the data root (the floor's first, as Reopen
// does), applies the same flag, owner, mode and link checks on each
// descriptor, and counts the audit log's pre-frame lines with Reopen's
// recount, so a log past the reader's bound, or one that does not read, is
// refused here exactly as the server's reopen refuses it. It takes no store
// lock, holds nothing after it returns and writes nothing. It returns the
// identity of the two files it judged, for the caller's device check.
func (s *FileStore) CheckServerLogs(ctx context.Context) (audit, floor LogFileID, err error) {
	if err := s.checkConfig(); err != nil {
		return LogFileID{}, LogFileID{}, err
	}
	if err := ctx.Err(); err != nil {
		return LogFileID{}, LogFileID{}, err
	}
	l := &ServerLogs{
		s:           s,
		audit:       heldLog{log: &appendLog{s: s, name: auditLogName}},
		floor:       heldLog{log: &appendLog{s: s, name: userFloorLogName}},
		usedByClass: map[preFrameClass]int64{},
		usedByUID:   map[preFrameKey]int64{},
	}
	defer l.closeLocked() // read-only descriptors; l is never shared
	for _, h := range []*heldLog{&l.floor, &l.audit} {
		f, st, err := h.log.open(unix.O_RDONLY)
		if err != nil {
			return LogFileID{}, LogFileID{}, err
		}
		h.f, h.id = f, LogFileID{Dev: uint64(st.Dev), Ino: st.Ino}
	}
	var st unix.Stat_t
	if err := s.judgeLog(l.audit.f, &st); err != nil {
		return LogFileID{}, LogFileID{}, fmt.Errorf("%s: %w", auditLogName, err)
	}
	if err := l.countLocked(st.Size); err != nil {
		return LogFileID{}, LogFileID{}, err
	}
	return l.audit.id, l.floor.id, nil
}

// Refused appends one refused line, via socket, for a connection from uid
// refused before its first frame for reason (a word of lowercase letters
// and '-', otherwise written as the placeholder): no scope, no name, no
// value. It draws on PreFrameBudget. A line not written is counted as
// dropped for uid and the error says why. A line that lands is followed,
// under the same lock, by the summary lines of up to
// PendingSummariesPerAppend uids' pending dropped counts; a summary that
// does not land keeps its count pending and does not fail the call.
func (l *ServerLogs) Refused(ctx context.Context, uid uint32, reason string) error {
	if !auditWord(reason) {
		reason = auditPlaceholder
	}
	err := l.locked(ctx, func() error {
		if err := l.appendLocked(preFrameRecord(uid, reason, "", 0, l.s.now())); err != nil {
			return err
		}
		l.writePendingLocked(PendingSummariesPerAppend)
		return nil
	})
	if err != nil {
		l.mu.Lock()
		l.pending[preFrameKey{refusalClass(uid, reason), uid}]++
		l.mu.Unlock()
	}
	return err
}

// writePendingLocked writes the summary lines of up to max uids' pending
// dropped counts, in uid order, forgetting each count written; a count not
// written stays pending. It returns the first error.
func (l *ServerLogs) writePendingLocked(max int) error {
	keys := make([]preFrameKey, 0, len(l.pending))
	for k, c := range l.pending {
		if c > 0 {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b preFrameKey) int {
		if c := cmp.Compare(a.uid, b.uid); c != 0 {
			return c
		}
		return cmp.Compare(a.class, b.class)
	})
	var first error
	for i, k := range keys {
		if i == max {
			break
		}
		if err := l.appendLocked(preFrameRecord(k.uid, auditResultDropped, k.class, l.pending[k], l.s.now())); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		delete(l.pending, k)
	}
	return first
}

// Dropped adds n to uid's dropped count and writes one summary line for
// each uid whose count is not 0, in uid order, each carrying its count
// since its last summary line, and forgets each count written. A summary
// line draws on PreFrameBudget too; a count not written is kept for the
// next call, and one uid's count not written does not hold back another's.
// With n 0 it only writes what is pending, which the listener's minute
// pass does whether or not its rate limit dropped anything.
func (l *ServerLogs) Dropped(ctx context.Context, uid uint32, n uint64) error {
	l.mu.Lock()
	if n > 0 {
		l.pending[preFrameKey{l.uidClass(uid), uid}] += n
	}
	l.mu.Unlock()
	return l.locked(ctx, func() error {
		return l.writePendingLocked(len(l.pending))
	})
}

// MaintenanceMarked is the store's FileStore.MaintenanceMarked, so the
// one value serves the socket's reopen after maintenance.
func (l *ServerLogs) MaintenanceMarked() (bool, error) { return l.s.maintenanceMarked() }

// PendingDropped is uid's dropped count not yet written in a summary
// line, every class's together.
func (l *ServerLogs) PendingDropped(uid uint32) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var n uint64
	for k, c := range l.pending {
		if k.uid == uid {
			n += c
		}
	}
	return n
}

// PreFrameUsed is the pre-frame bytes counted in the held audit file when
// it was last read: at the last Reopen or append, the append's own lines
// included.
func (l *ServerLogs) PreFrameUsed() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used
}

// Files returns the identity of the audit and floor files the descriptors
// hold, zero for one not open.
func (l *ServerLogs) Files() (audit, floor LogFileID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.audit.id, l.floor.id
}

// Close closes both descriptors. A later Reopen or append opens them again.
func (l *ServerLogs) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeLocked()
	return nil
}

// locked runs fn under the exclusive store lock, waited for at most
// ServerAppendLockWait, and l.mu.
func (l *ServerLogs) locked(ctx context.Context, fn func() error) error {
	if err := l.s.checkConfig(); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, ServerAppendLockWait)
	defer cancel()
	_, done, err := l.s.openLocked(waitCtx, false, true)
	if err != nil {
		return fmt.Errorf("take the store lock for a server append: %w", err)
	}
	defer done()
	l.mu.Lock()
	defer l.mu.Unlock()
	return fn()
}

// closeLocked closes both descriptors and forgets the count.
func (l *ServerLogs) closeLocked() {
	for _, h := range []*heldLog{&l.audit, &l.floor} {
		if h.f != nil {
			_ = h.f.Close() // an append descriptor; each append was fsynced
		}
		h.f, h.id, h.off = nil, LogFileID{}, 0
	}
	l.resetCountLocked()
}

// resetCountLocked forgets the pre-frame count.
func (l *ServerLogs) resetCountLocked() {
	l.used = 0
	clear(l.usedByClass)
	clear(l.usedByUID)
}

// ensureLocked makes each held descriptor the canonical file's, judged:
// a descriptor not open, or whose (dev, ino) is not the canonical name's,
// is reopened, and a reopened audit log's budget is recounted from its
// start. The held audit descriptor is judged again on every call, as every
// other append's is, and its count read on to its end.
func (l *ServerLogs) ensureLocked() error {
	for _, h := range []*heldLog{&l.floor, &l.audit} {
		same, err := l.canonical(h)
		if err != nil {
			return err
		}
		if same {
			continue
		}
		if h.f != nil {
			_ = h.f.Close() // renamed away or replaced: never appended to again
			h.f = nil
		}
		f, st, err := h.log.open(unix.O_RDWR | unix.O_APPEND)
		if err != nil {
			h.id, h.off = LogFileID{}, 0
			if h == &l.audit {
				l.resetCountLocked()
			}
			return err
		}
		h.f, h.id, h.off = f, LogFileID{Dev: uint64(st.Dev), Ino: st.Ino}, 0
		if h == &l.audit {
			l.resetCountLocked()
		}
	}
	var st unix.Stat_t
	if err := l.s.judgeLog(l.audit.f, &st); err != nil {
		return fmt.Errorf("%s: %w", auditLogName, err)
	}
	return l.countLocked(st.Size)
}

// canonical reports whether h holds the file at its log's canonical name,
// read with fstatat on the judged log directory, AT_SYMLINK_NOFOLLOW. A
// descriptor not open is not.
func (l *ServerLogs) canonical(h *heldLog) (bool, error) {
	if h.f == nil {
		return false, nil
	}
	var held unix.Stat_t
	if err := unix.Fstat(int(h.f.Fd()), &held); err != nil {
		return false, fmt.Errorf("stat the held %s: %w", h.log.name, err)
	}
	dfd, lfd, err := l.s.openLogDirs()
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(dfd); _ = unix.Close(lfd) }() // read-only directory descriptors
	var name unix.Stat_t
	if err := l.s.statLog(lfd, h.log.name, &name); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil // reopening reports the missing log
		}
		return false, fmt.Errorf("stat %s: %w", h.log.name, err)
	}
	return uint64(held.Dev) == uint64(name.Dev) && held.Ino == name.Ino, nil
}

// countLocked reads the held audit file from where the count stopped to
// size and adds each pre-frame line's charge. A file shorter than where the
// count stopped is counted again from its start. A last line with no
// newline is left for the next read; a line that does not read as a
// pre-frame line is charged nothing here. On an error the count is
// forgotten, so the next read counts the file again from its start rather
// than charging twice what this one read.
func (l *ServerLogs) countLocked(size int64) (err error) {
	h := &l.audit
	defer func() {
		if err != nil {
			h.off = 0
			l.resetCountLocked()
		}
	}()
	if size < h.off {
		h.off = 0
		l.resetCountLocked()
	}
	if size == h.off {
		return nil
	}
	if size > l.s.logReadBound() {
		return fmt.Errorf("%w: %s", errLogTooLarge, auditLogName)
	}
	r := bufio.NewReaderSize(io.NewSectionReader(h.f, h.off, size-h.off), 64<<10)
	off := h.off
	for off < size {
		line, err := readLogLine(r)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if errors.Is(err, errLogTorn) {
			break // read again once an append closes it
		}
		if errors.Is(err, errLogLineTooLong) {
			n, serr := skipRestOfLine(r, line)
			if errors.Is(serr, io.EOF) {
				break
			}
			if serr != nil {
				return h.log.unreadable(off, serr)
			}
			off += n
			continue
		}
		if err != nil {
			return h.log.unreadable(off, err)
		}
		if k, cost, ok := preFrameCharge(line); ok {
			l.chargeLocked(k, cost)
		}
		off += int64(len(line))
	}
	h.off = off
	return nil
}

// appendLocked appends rec to the held audit descriptor, after
// ensureLocked: one write(2) of a leading newline and the line, held to
// PreFrameBudget, the reader's size bound, the free-space margin and a
// block reservation, then fsynced. The hard cap does not refuse it: the
// reconciler budget is excluded from the hard-cap test.
func (l *ServerLogs) appendLocked(rec preFrameRec) error {
	if err := l.ensureLocked(); err != nil {
		return err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("encode an audit line: %w", err)
	}
	if len(line)+1 > maxLogLine {
		return fmt.Errorf("%w: refused a %d-byte audit line for %s", errLogLineTooLong, len(line)+1, rec.Op)
	}
	out := make([]byte, 0, len(line)+2)
	out = append(append(append(out, '\n'), line...), '\n')
	charged, cost, ok := preFrameCharge(out[1:])
	if !ok {
		return fmt.Errorf("encode an audit line: the %s line does not read as a pre-frame line", rec.Op)
	}
	if !l.roomLocked(charged, cost) {
		return errPreFrameBudgetSpent
	}
	h := &l.audit
	var st unix.Stat_t
	if err := unix.Fstat(int(h.f.Fd()), &st); err != nil {
		return fmt.Errorf("stat the held %s: %w", auditLogName, err)
	}
	if st.Size+int64(len(out)) > l.s.logReadBound() {
		return h.log.pastCap()
	}
	if err := h.log.preflight(h.f, len(out), false); err != nil {
		return err
	}
	if err := h.log.reserveBlocks(h.f, int64(len(out))); err != nil {
		return err
	}
	n, err := h.f.Write(out)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = h.f.Sync() // what part of the line reached the file is the recount's
		return fmt.Errorf("append to %s: %w", auditLogName, err)
	}
	// The whole line is in the file, so it is written, not dropped: a
	// failed fsync leaves only its durability unknown. It is logged here,
	// once, and the call succeeds, so the line is never also counted as
	// dropped.
	if serr := l.sync(h.f); serr != nil {
		l.s.logger().Warn("keystore: a pre-frame audit line was written but its fsync failed; its durability is unknown", "result", rec.Result, "uid", rec.Caller.UID, "err", serr)
	}
	// The running count reads on through what this append wrote, with the
	// recount's one rule, so it charges the line now and charges it as a
	// reopen's recount of the file would: the leading newline written, a
	// torn tail it closed, the line.
	// The line landed, so a count that fails here does not fail the call
	// nor count the line as dropped: the count is forgotten and the next
	// append recounts the file from its start before it tests the budget.
	_ = l.countLocked(st.Size + int64(len(out)))
	return nil
}

// preFrameCharge is the pre-frame part's one charging rule, which the
// running count after each append and the recount of the file both use:
// line, a whole audit line with its newline, is charged only if it reads
// strictly as a pre-frame line (preFrameLineOf), to the class its record
// names (preFrameLineClass), and costs its length, newline included, plus
// the leading newline its append writes.
func preFrameCharge(line []byte) (preFrameKey, int64, bool) {
	if len(line) < 2 || line[len(line)-1] != '\n' {
		return preFrameKey{}, 0, false
	}
	rec, ok := preFrameLineOf(line[:len(line)-1])
	if !ok {
		return preFrameKey{}, 0, false
	}
	return preFrameKey{preFrameLineClass(rec), rec.Caller.UID}, int64(len(line)) + 1, true
}

// chargeLocked adds n bytes to k's class, and to k's uid within it when
// the class has per-uid limits.
func (l *ServerLogs) chargeLocked(k preFrameKey, n int64) {
	l.used += n
	l.usedByClass[k.class] += n
	if k.class.uidShare() > 0 {
		l.usedByUID[k] += n
	}
}

// roomLocked reports whether n more bytes fit k: its uid's share within
// its class when the class has one, its class's budget, and the whole
// pre-frame part.
func (l *ServerLogs) roomLocked(k preFrameKey, n int64) bool {
	if l.used+n > PreFrameBudget || l.usedByClass[k.class]+n > k.class.budget() {
		return false
	}
	if share := k.class.uidShare(); share > 0 && l.usedByUID[k]+n > share {
		return false
	}
	return true
}

// The pre-frame reasons that name the uid's own class whatever uid the
// line carries.
const (
	preFrameReasonRoot       = "root"
	preFrameReasonServiceUID = "service-uid"
	preFrameReasonSystemUID  = "system-uid"
	preFrameReasonHighUID    = "high-uid"
)

// refusalClass is the class of a refusal of uid for reason: a uid-range
// reason names its class, uid 4294967295 is no-uid, any other uid in the
// login range is login, and the rest system-high.
func refusalClass(uid uint32, reason string) preFrameClass {
	switch {
	case reason == preFrameReasonRoot:
		return preFrameClassRoot
	case reason == preFrameReasonServiceUID:
		return preFrameClassServiceUID
	case reason == preFrameReasonSystemUID || reason == preFrameReasonHighUID:
		return preFrameClassSystemHigh
	case uid == PreFrameNoUID:
		return preFrameClassNoUID
	case uid >= minScopeUID && uid <= maxScopeUID:
		return preFrameClassLogin
	}
	return preFrameClassSystemHigh
}

// uidClass is the class of the refusals the socket listener counted as
// dropped for uid, read as the listener reads a peer's uid: 0 is root, the
// store's service uid is service-uid, 4294967295 is no-uid, a login uid is
// login, and any other system-high. It is used only when the count is
// written; the summary line then carries the class.
func (l *ServerLogs) uidClass(uid uint32) preFrameClass {
	switch {
	case uid == 0:
		return preFrameClassRoot
	case uid == l.s.uid:
		return preFrameClassServiceUID
	case uid == PreFrameNoUID:
		return preFrameClassNoUID
	case uid >= minScopeUID && uid <= maxScopeUID:
		return preFrameClassLogin
	}
	return preFrameClassSystemHigh
}

// preFrameLineClass is the class rec is charged to: a summary line's own
// class field, a refusal's refusalClass.
func preFrameLineClass(rec preFrameRec) preFrameClass {
	if rec.Result == auditResultDropped {
		return rec.Class
	}
	return refusalClass(rec.Caller.UID, rec.Result)
}

// preFrameRec is a pre-frame refused line, or its summary: the audit
// line's fields (auditRecord) with the peer uid as the caller, the charge
// and source that put it on the reconciler budget's pre-frame part, and,
// in a summary, the dropped count.
type preFrameRec struct {
	V         int            `json:"v"`
	TS        string         `json:"ts"`
	Op        string         `json:"op"`
	Via       string         `json:"via"`
	Caller    preFrameCaller `json:"caller"`
	Scope     string         `json:"scope"`
	Name      string         `json:"name"`
	Namespace string         `json:"namespace"`
	Result    string         `json:"result"`
	Charge    string         `json:"charge"`
	Source    string         `json:"source"`
	Dropped   uint64         `json:"dropped,omitempty"`
	Class     preFrameClass  `json:"class,omitempty"`
}

// preFrameCaller is the refused peer: its uid only.
type preFrameCaller struct {
	UID uint32 `json:"uid"`
}

// preFrameKeys are preFrameRec's JSON keys, exact.
var preFrameKeys = append(slices.Clone(auditKeys), "caller", "charge", "source", "dropped", "class")

// preFrameRecord is a pre-frame line: a refusal when result is a reason
// (class ""), a summary of dropped refusals of class when result is
// "dropped".
func preFrameRecord(uid uint32, result string, class preFrameClass, dropped uint64, now time.Time) preFrameRec {
	return preFrameRec{
		V:       auditFormat,
		TS:      now.UTC().Format(time.RFC3339Nano),
		Op:      auditOpRefused,
		Via:     auditViaSocket,
		Caller:  preFrameCaller{UID: uid},
		Result:  result,
		Charge:  auditChargeReconcil,
		Source:  auditSourcePreFrame,
		Dropped: dropped,
		Class:   class,
	}
}

// preFrameLineOf decodes line, without its newline, and reports whether it
// reads strictly as a pre-frame line: format 1, op refused, via socket, no
// scope, charged to the reconciler's pre-frame part, and a class field
// exactly on a summary line, naming a class of the closed set. Only such
// lines are counted against PreFrameBudget.
func preFrameLineOf(line []byte) (preFrameRec, bool) {
	if err := auditKeysStrictOf(line, preFrameKeys); err != nil {
		return preFrameRec{}, false
	}
	var r preFrameRec
	if err := json.Unmarshal(line, &r); err != nil {
		return preFrameRec{}, false
	}
	if r.Result == auditResultDropped {
		if !slices.Contains(preFrameClasses, r.Class) {
			return preFrameRec{}, false
		}
	} else if r.Class != "" {
		return preFrameRec{}, false
	}
	return r, r.V == auditFormat && r.Op == auditOpRefused && r.Via == auditViaSocket && r.Scope == "" &&
		r.Charge == auditChargeReconcil && r.Source == auditSourcePreFrame
}
