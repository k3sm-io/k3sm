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
// the reconciler budget). A refusal of a peer whose uid is in the login
// range (501 to 2147483647) and whose reason is not a uid-range reason (it
// was refused as sandboxed, as sandbox-unknown, as token-mismatch, or as
// cred-unreadable with its uid read), and a summary line of such a uid, is a
// login line: it is charged to its uid's sub-share and to the login part.
// Every other pre-frame line (root, the service uid, a system or high uid,
// no uid read) is charged to the reserved part, which no login line draws
// on. Each part is recounted from the log, the class read off the line's
// uid and result, never from memory.
const (
	// PreFrameLoginUIDShare is the most one login uid's pre-frame lines may
	// take of an audit log, for the life of that log.
	PreFrameLoginUIDShare = 8 << 10
	// PreFrameLoginBudget is the most all login uids' pre-frame lines may
	// take of an audit log together.
	PreFrameLoginBudget = 128 << 10
	// PreFrameReserved is the part kept for the pre-frame lines of
	// ineligible peers.
	PreFrameReserved = PreFrameBudget - PreFrameLoginBudget
)

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
	// audit.off; usedLogin the login lines' part of it, and usedByUID each
	// login uid's.
	used      int64
	usedLogin int64
	usedByUID map[uint32]int64
	// pending is each uid's dropped count not yet in a summary line.
	pending map[uint32]uint64
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
		s:         s,
		audit:     heldLog{log: &appendLog{s: s, name: auditLogName}},
		floor:     heldLog{log: &appendLog{s: s, name: userFloorLogName}},
		pending:   map[uint32]uint64{},
		usedByUID: map[uint32]int64{},
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

// Refused appends one refused line, via socket, for a connection from uid
// refused before its first frame for reason (a word of lowercase letters
// and '-', otherwise written as the placeholder): no scope, no name, no
// value. It draws on PreFrameBudget. A line not written is counted as
// dropped for uid and the error says why.
func (l *ServerLogs) Refused(ctx context.Context, uid uint32, reason string) error {
	if !auditWord(reason) {
		reason = auditPlaceholder
	}
	err := l.locked(ctx, func() error {
		return l.appendLocked(preFrameRecord(uid, reason, 0, l.s.now()))
	})
	if err != nil {
		l.mu.Lock()
		l.pending[uid]++
		l.mu.Unlock()
	}
	return err
}

// Dropped adds n to uid's dropped count and writes one summary line for
// each uid whose count is not 0, in uid order, each carrying its count
// since its last summary line, and forgets each count written. A summary
// line draws on PreFrameBudget too; a count not written is kept for the
// next call.
func (l *ServerLogs) Dropped(ctx context.Context, uid uint32, n uint64) error {
	l.mu.Lock()
	if n > 0 {
		l.pending[uid] += n
	}
	l.mu.Unlock()
	return l.locked(ctx, func() error {
		uids := make([]uint32, 0, len(l.pending))
		for u, c := range l.pending {
			if c > 0 {
				uids = append(uids, u)
			}
		}
		slices.Sort(uids)
		for _, u := range uids {
			if err := l.appendLocked(preFrameRecord(u, auditResultDropped, l.pending[u], l.s.now())); err != nil {
				return err
			}
			delete(l.pending, u)
		}
		return nil
	})
}

// MaintenanceMarked is the store's FileStore.MaintenanceMarked, so the
// one value serves the socket's reopen after maintenance.
func (l *ServerLogs) MaintenanceMarked() (bool, error) { return l.s.maintenanceMarked() }

// PendingDropped is uid's dropped count not yet written in a summary line.
func (l *ServerLogs) PendingDropped(uid uint32) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pending[uid]
}

// PreFrameUsed is the pre-frame bytes counted in the held audit file when
// it was last read: at the last Reopen or append.
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
	l.used, l.usedLogin = 0, 0
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
// pre-frame line is charged nothing here.
func (l *ServerLogs) countLocked(size int64) error {
	h := &l.audit
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
		if len(line) > 1 {
			if rec, ok := preFrameLineOf(line[:len(line)-1]); ok {
				l.chargeLocked(rec, int64(len(line))+1)
			}
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
	if !l.roomLocked(rec, int64(len(out))) {
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
	if serr := h.f.Sync(); err == nil {
		err = serr
	}
	if err != nil {
		return fmt.Errorf("append to %s: %w", auditLogName, err)
	}
	return nil
}

// chargeLocked adds n bytes of rec's to the count of its part.
func (l *ServerLogs) chargeLocked(rec preFrameRec, n int64) {
	l.used += n
	if preFrameLoginLine(rec) {
		l.usedLogin += n
		l.usedByUID[rec.Caller.UID] += n
	}
}

// roomLocked reports whether n more bytes of rec's fit its part: a login
// line its uid's sub-share and the login part, any other line the reserved
// part, and every line the whole pre-frame part.
func (l *ServerLogs) roomLocked(rec preFrameRec, n int64) bool {
	if l.used+n > PreFrameBudget {
		return false
	}
	if preFrameLoginLine(rec) {
		return l.usedByUID[rec.Caller.UID]+n <= PreFrameLoginUIDShare && l.usedLogin+n <= PreFrameLoginBudget
	}
	return l.used-l.usedLogin+n <= PreFrameReserved
}

// The pre-frame reasons that say the peer's uid is not a login uid: these
// lines are charged to the reserved part whatever uid they name.
var preFrameUIDRangeReasons = []string{"root", "service-uid", "system-uid", "high-uid"}

// preFrameLoginLine reports whether rec is a login line: its uid in the
// login range and its result not a uid-range reason. A summary line is
// classed by its uid; the service uid is a system uid, below the range.
func preFrameLoginLine(rec preFrameRec) bool {
	uid := rec.Caller.UID
	return uid >= minScopeUID && uid <= maxScopeUID && !slices.Contains(preFrameUIDRangeReasons, rec.Result)
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
}

// preFrameCaller is the refused peer: its uid only.
type preFrameCaller struct {
	UID uint32 `json:"uid"`
}

// preFrameKeys are preFrameRec's JSON keys, exact.
var preFrameKeys = append(slices.Clone(auditKeys), "caller", "charge", "source", "dropped")

func preFrameRecord(uid uint32, result string, dropped uint64, now time.Time) preFrameRec {
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
	}
}

// preFrameLineOf decodes line, without its newline, and reports whether it
// reads strictly as a pre-frame line: format 1, op refused, via socket, no
// scope, charged to the reconciler's pre-frame part. Only such lines are
// counted against PreFrameBudget.
func preFrameLineOf(line []byte) (preFrameRec, bool) {
	if err := auditKeysStrictOf(line, preFrameKeys); err != nil {
		return preFrameRec{}, false
	}
	var r preFrameRec
	if err := json.Unmarshal(line, &r); err != nil {
		return preFrameRec{}, false
	}
	return r, r.V == auditFormat && r.Op == auditOpRefused && r.Via == auditViaSocket && r.Scope == "" &&
		r.Charge == auditChargeReconcil && r.Source == auditSourcePreFrame
}
