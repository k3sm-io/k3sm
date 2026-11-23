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
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The user-scope floor and the audit log are append-only files in the logs
// directory, keystore-logs/ in the data root (docs/design/keystore.md § "The
// user-scope floor", "The audit log"): keystore-user-floor.log and
// keystore-audit.log, each owned by the service
// user at mode 0600 with the BSD system append-only flag (SF_APPEND, which
// chflags spells sappnd) set by root at install. The K0 spike measured that
// flag on the rig's APFS data volume at kern.securelevel 0: the service user
// can append and cannot truncate, overwrite, rename, unlink or clear it. The
// store reaches each through an interface on FileStore, and New installs
// the file-backed ones below; tests may install in-memory fakes.
//
// Each file is opened per use through descriptors on the data root and the
// logs directory, each judged, by openat with O_NOFOLLOW, and judged on its own descriptor: a regular file
// with one link, owned by the service user, mode 0600, and SF_APPEND set,
// read through the flag-source seam. A clear flag is errLogNotAppendOnly
// and a wrong owner, mode or type errLogUntrusted; nothing is read from or
// appended to such a file. Opening per use means an append always lands in
// the file the canonical name holds now, never in one a maintenance verb
// renamed away.
//
// Every append runs while the caller holds the store lock (auditSink).
// Every append is one write(2) of one whole line of at most maxLogLine
// bytes, so a reader under the same lock never sees half a line, and a line
// that is not whole is damage.

const (
	// userFloorLogName and auditLogName are the two logs' names in the logs
	// directory.
	userFloorLogName = "keystore-user-floor.log"
	auditLogName     = "keystore-audit.log"
	// logsDirName is the logs directory in the data root: root's 0755, with
	// no flag and no ACL. It holds one root-owned directory per log
	// (floorDirName, auditDirName), each root's 0755 with no flag and no
	// ACL, so a maintenance verb replaces a log and its archives as one
	// directory, swapped in whole (docs/design/keystore.md § "The swap").
	logsDirName  = "keystore-logs"
	floorDirName = "floor"
	auditDirName = "audit"
	// logsDirMode is the mode of keystore-logs/ and of each log's
	// directory.
	logsDirMode = 0o755
	// maxLogLine bounds one line of either log, its newline included.
	maxLogLine = 1024
	// maxAppendLine is the most one append of one line writes: the newline
	// every append leads with (appendLines), then the line.
	maxAppendLine = maxLogLine + 1
	// sfAppend is SF_APPEND, the system append-only file flag
	// (<sys/stat.h>): only root can clear it, and while it is set the file
	// can only be appended to.
	sfAppend = 0x00040000
	// logMode is both logs' mode.
	logMode = 0o600

	// The cap defaults (docs/design/keystore.md § "Size caps"), and the
	// per-uid revocation budget the revocation class draws on past the hard
	// cap (the socket margin of "Per-uid fairness").
	defaultLogSoftCap = 64 << 20
	defaultLogHardCap = 256 << 20
	// maxBurialTombstones is the most tombstones one rm's burial writes for
	// an entry with one live floor generation, as the server writes it: the
	// floor's live generation, the one the pointer authenticates, and
	// maxTreeGenerations named by the tree alone.
	maxBurialTombstones = 2 + maxTreeGenerations
	// maxTombLineBytes and maxRmAuditLineBytes are the longest tombstone and
	// rm audit line: the longest scope (user/2147483647), a 253-byte name,
	// the longest result and a full RFC3339Nano timestamp
	// (TestCheckConfigRevocationBudgetFloor). The tombstone is
	// 15 + 1 + 253 + 1 + 32 + 1 + 2 ("rm") + 1 + 8 (its checksum) + 1 (its
	// newline) = 315 bytes.
	maxTombLineBytes    = 315
	maxRmAuditLineBytes = 384
	// minLogRevokeBudget is the least revocation budget checkConfig accepts:
	// one worst-case burial plus its audit line, each one append led by its
	// newline, 6 × 315 + 1 + 384 + 1 = 2,276 bytes, which is over two whole
	// appends (2,050).
	minLogRevokeBudget = maxBurialTombstones*maxTombLineBytes + 1 + maxRmAuditLineBytes + 1
	// defaultLogRevocationBytes holds one scope's full revocation, under the
	// longest scope and a 253-byte name, each append charged its leading
	// newline: each of maxScopeEntries entries rm'd, a burial of
	// maxBurialTombstones 315-byte tombstones and a 384-byte audit line,
	// 256 × (6 × 315 + 1 + 384 + 1) = 582,656 bytes; and maxDeliveries
	// withdraws, each a 91-byte floor line (15 + 1 + 11 + 1 + 32 + 1 + 20 +
	// 1 + 8 + 1, the checksum included) and a withdraw audit line of at
	// most 250 bytes, 320 × (91 + 1 + 250 + 1) = 109,760 bytes; 692,416
	// bytes in all, rounded up to 704 KiB (720,896). With it
	// logReadBound at the default caps is 256 MiB + 1024 × 704 KiB + 1 MiB
	// = 961 MiB, and at the configuration's upper bounds 2^40 + 1024 × 2^30
	// + 2^20, which cannot overflow
	// (TestDefaultRevocationBudgetHoldsFullRevocation).
	defaultLogRevocationBytes = 704 << 10

	// The reader's bounds (docs/design/keystore.md § "Size caps"). A log
	// is read whole, and the service user can append to it without limit,
	// so a log larger than logReadBound is damage, and so is a floor with
	// more than keyBound distinct keys. The bound is the hard cap,
	// plus maxRevokeUIDs uids' revocation budgets past it, plus
	// logBoundMargin; the server never appends past either itself.
	maxRevokeUIDs  = 1024
	logBoundMargin = 1 << 20
	// maxChargedUIDs bounds the reader's per-uid map of bytes charged past
	// the hard cap (logState.pastCap): maxRevokeUIDs, whose budgets the size
	// bound holds, plus a fixed margin. A log charging more distinct uids is
	// sticky damage (errLogTooManyUIDs), so forged lines of many uids cannot
	// grow the map past it.
	maxChargedUIDs = maxRevokeUIDs + 64
	// maxFloorKeysCeiling is the absolute ceiling on the floor's key bound,
	// whatever the caps are configured to: what bounds the reader's memory.
	// At the default caps the size alone would allow about 10.2M keys. The
	// reader's worst case at this ceiling plus the revocation headroom
	// (278,528 keys), read from scratch on an M1 Ultra: 253-byte names and
	// the longest scope, about 128 MiB of heap and 0.41 s
	// (BenchmarkFloorReadLongNames); the most lines the size bound held
	// under the former 64 KiB revocation budget, about 7.3M, about 69 MiB
	// and 3.9 s (BenchmarkFloorReadLineCount), about 9.8 s scaled to the
	// 18.3M lines of 55 bytes today's 961 MiB bound holds (not
	// re-measured). At
	// 1<<20 the long-name case held about 494 MiB, so the ceiling was
	// lowered to stay under 200 MiB (docs/design/keystore.md § "Size caps").
	maxFloorKeysCeiling = 1 << 18
	// uidKeyShare is one uid's lifetime share of floor keys: a grant line
	// that adds a key is refused once its scope's uid has added uidKeyShare
	// keys, buried or live, since a buried key stays in the floor for good
	// (docs/design/keystore.md § "Per-uid fairness"). A scope holds at most
	// maxScopeEntries live entries plus its delivery record, 257 live keys,
	// and the share is 16 times that, 4,112 keys: 63 uids at their shares
	// hold 259,056 keys, under the 2^18 ceiling, so filling the global key
	// bound takes at least 64 uids.
	uidKeyShare = 16 * (maxScopeEntries + 1)
	// revokeHeadroomDivisor sizes the revocation headroom, keyBound /
	// revokeHeadroomDivisor keys past the key bound that only a revocation's
	// line (a tombstone or a catch-up line) may add; the reader's key bound
	// includes it.
	revokeHeadroomDivisor = 16
	// logFreeMargin is the free space an append leaves on the log's file
	// system beyond its own line.
	logFreeMargin = 1 << 20
	// maxLogHardCap and maxLogRevokeBudget bound the configured hard cap
	// (and so the soft cap) and the per-uid revocation budget from above, so
	// logReadBound, at most 2^40 + 1024 × 2^30 + 2^20, cannot overflow.
	maxLogHardCap      = 1 << 40
	maxLogRevokeBudget = 1 << 30
	// revokeFreeSlack replaces logFreeMargin for a revocation's line: the
	// minimal check, so a nearly full volume still records a revocation. It
	// is two 4 KiB blocks, as many as one append can newly touch when it
	// straddles a block boundary, plus the longest line.
	revokeFreeSlack = 2*(4<<10) + maxLogLine
)

// minFloorLine is the shortest line that adds a key to the floor: the
// lowest user scope, a one-byte name, sequence 1 and its checksum,
// 8 + 1 + 1 + 1 + 32 + 1 + 1 + 1 + 8 + 1 = 55 bytes. logReadBound itself
// is the caps' and the margin's alone, so the checksum leaves it as it
// was; it lowers the key bound the size alone allows, from about 21.9M
// keys to about 18.3M at the default caps, both far over the 2^18 ceiling
// that binds.
var minFloorLine = func() int {
	b, err := floorLine(userScopeOf(minScopeUID), "a", [generationSize]byte{}, 1)
	if err != nil {
		panic(err)
	}
	return len(b)
}()

// keyBound is the most distinct keys the floor may hold: as many as lines of
// minFloorLine bytes fit in logReadBound, held to maxFloorKeysCeiling, which
// is met first at the default caps. The writer refuses a grant's line that
// would add a key past it, and a revocation's past it plus the revocation
// headroom (keyHeadroom), so the reader, whose bound includes the headroom,
// never meets damage in a floor the server wrote.
func (l *appendLog) keyBound() int {
	if l.maxKeys != 0 {
		return l.maxKeys
	}
	return int(min(l.s.logReadBound()/int64(minFloorLine)+1, maxFloorKeysCeiling))
}

// keyShare is the most keys one uid's lines may add to the floor in its
// lifetime: uidKeyShare, held to keyBound. Every key a uid adds is charged
// to it, buried or live, since no server write frees a key. Only a grant's
// line is held to it: a tombstone for a key the floor holds adds no key, and
// a revocation's line that adds one is charged but never refused here.
func (l *appendLog) keyShare() int {
	if l.maxKeys != 0 {
		if l.maxShare != 0 {
			return l.maxShare
		}
		return l.maxKeys
	}
	return min(uidKeyShare, l.keyBound())
}

// keyHeadroom is the revocation headroom: the keys past keyBound that only
// a revocation's line may add, so grants at the key bound cannot refuse a
// tombstone or a catch-up line for a key the floor lacks.
func (l *appendLog) keyHeadroom() int {
	if l.maxKeys != 0 {
		return l.maxHeadroom
	}
	return l.keyBound() / revokeHeadroomDivisor
}

// readKeyBound is the reader's key bound: keyBound plus the revocation
// headroom. A floor holding more keys is damage.
func (l *appendLog) readKeyBound() int { return l.keyBound() + l.keyHeadroom() }

// logReadBound is the size past which a log is damage: the hard cap, the
// revocation budgets of maxRevokeUIDs uids, and a margin.
func (s *FileStore) logReadBound() int64 {
	return s.logHardCap + maxRevokeUIDs*s.logRevokeBudget + logBoundMargin
}

// logMissingScopesError is errLogMissingScopes: it matches errLogMissing,
// and its text names the matched-set restore, never install.
type logMissingScopesError struct{}

func (logMissingScopesError) Error() string {
	return "the keystore append-only log is missing while user scopes exist, so a new one would lower their floor: restore the matched set (keystore/, keystore/.user/ and both logs) from one backup, then run sudo k3sm keys floor --rebuild and sudo k3sm keys audit --rotate, which flag the restored logs append-only, and sudo k3sm doctor"
}

func (logMissingScopesError) Is(target error) bool { return target == errLogMissing }

// restoreRemedy is the remedy a user-scope floor error names for damage a
// skipped line cannot absorb, a floor past the reader's bounds that the
// rebuild cannot read: the matched-set restore and what it costs, then
// floor --rebuild, which flags the restored floor append-only, and doctor.
// A torn or garbage line is never such damage: the reader skips it.
const restoreRemedy = "restore the matched set (keystore/, keystore/.user/ and both logs) from one backup, which brings back every entry deleted since the backup, then run sudo k3sm keys floor --rebuild and sudo k3sm doctor"

// ErrLogFull refuses an operation because an append-only log is past its
// hard cap, or, for a revocation past the hard cap, because the uid's
// revocation budget in that log is spent. Nothing was changed.
var ErrLogFull = errors.New("the keystore log is full: the user-scope floor or audit log is past its hard cap or the floor's key bound, so no user-scope change can be recorded; root must run sudo k3sm doctor, then sudo k3sm keys audit --rotate for the audit log or sudo k3sm keys floor --rebuild for the floor; nothing was changed")

var (
	// errLogMissing is a log that does not exist: the data root has not been
	// through sudo k3sm install.
	errLogMissing = errors.New("the keystore append-only log is missing: sudo k3sm install creates it")
	// errLogMissingScopes is errLogMissing while user scopes exist: a log
	// created now would lower every scope's floor, so install refuses to
	// create one and the remedy is the matched-set restore.
	errLogMissingScopes error = logMissingScopesError{}
	// errLogNotAppendOnly is a log whose SF_APPEND flag is clear.
	errLogNotAppendOnly = errors.New("the keystore append-only log is not flagged append-only (SF_APPEND is clear), so it could be truncated or rewritten: root must " + restoreRemedy)
	// errLogUntrusted is a log, or the data root holding it, that is not
	// what install makes.
	errLogUntrusted = errors.New("the keystore append-only log is not trusted: it must be a regular file with one link, owned by the service user, mode 0600, with no file flag but SF_APPEND and no extended ACL, in a data root owned by root, not group- or other-writable, with no such flag or ACL either")
	// errLogNoSpace refuses an append because the log's file system has
	// less than logFreeMargin free beyond the line: retryable once space
	// is freed, never damage, and nothing was written.
	errLogNoSpace = errors.New("the keystore log's volume is nearly full, so the line was not appended; free some space and retry; nothing was changed")
	// errLogTooLarge is a log larger than logReadBound: damage.
	errLogTooLarge = errors.New("the keystore append-only log is larger than the reader's bound")
	// errFloorTooManyKeys is a floor with more distinct keys than its key
	// bound: damage.
	errFloorTooManyKeys = errors.New("the user-scope floor holds more distinct keys than its key bound")
	// errLogTooManyUIDs is a log whose lines past the hard cap are charged
	// to more distinct uids than maxChargedUIDs: damage, as a log past its
	// size bound is, which it matches.
	errLogTooManyUIDs = fmt.Errorf("%w: its lines past the hard cap are charged to more distinct uids than the reader's bound", errLogTooLarge)
	// errLogTorn is a last line with no newline: damage.
	errLogTorn = errors.New("the last line has no newline")
	// errLogLineTooLong is a line over maxLogLine, which is never written.
	errLogLineTooLong = fmt.Errorf("a keystore log line is at most %d bytes", maxLogLine)
	// errFloorLogMalformed is a user-scope floor past the reader's bounds
	// (larger than logReadBound, or holding more keys than its key bound),
	// which the server never writes: damage, which refuses every user-scope
	// operation that reads the floor, revocations included, until root
	// repairs it. A line that does not parse is not this: the reader skips
	// it and counts it (FloorDamage).
	errFloorLogMalformed = fmt.Errorf("%w: the user-scope floor %s is past the reader's bound; root must "+restoreRemedy, ErrCorrupt, userFloorLogName)
	// errLogUnreadable is a log whose bytes could not be read: an I/O
	// error, transient and never damage. It is never kept, matches no
	// ErrCorrupt, and so refuses a grant or read and lets a revocation go
	// ahead.
	errLogUnreadable = errors.New("the keystore append-only log could not be read")
	// errFloorBuried is a generation the user-scope floor holds a tombstone
	// for: rm deleted it. A reader turns it into userDeletedError.
	errFloorBuried = errors.New("the user-scope floor buries this generation: the entry was deleted")
)

// errFloorDegraded refuses a key a damaged floor line could name, and, while
// the floor holds damage no key can be read from, a put or deliver line and
// a generation the floor has no line for: a skipped line could be a
// tombstone, so a live line written now could bring a deleted entry back.
// No verb clears it yet: root reads the damage and acknowledges damage no
// key can be read from as root maintenance, which never lifts a key's taint.
var errFloorDegraded = fmt.Errorf("the user-scope floor %s holds damaged lines, one of which could be a tombstone or a later sequence for this key (or, when no key can be read from it, for any key), so this put, deliver or read is refused; rm and withdraw still run; root must read the damage count (CheckLogBounds, at the server's start), and can acknowledge damage no key can be read from as root maintenance, which never lifts a key's taint", userFloorLogName)

// floorTombstone is a tombstone line's last field, where a live line has
// its sequence.
const floorTombstone = "rm"

// userFloorLog is the user-scope floor: (scope, name, generation, seq)
// lines, of which a reader takes, per (scope, name), the highest seq among
// the lines of a generation, so the floor only rises; and (scope, name,
// generation) tombstones, which rm appends and which bury that generation
// for good.
type userFloorLog interface {
	// floor returns the highest seq recorded for scope, name and gen, or 0
	// when none is; errFloorBuried when a tombstone buries gen.
	floor(scope, name string, gen [generationSize]byte) (uint64, error)
	// append records one line; revoke marks the line of an operation that
	// revokes (a withdraw), which the free-space margin does not hold.
	append(scope, name string, gen [generationSize]byte, seq uint64, revoke bool) error
	// bury records the tombstone of scope, name and gen.
	bury(scope, name string, gen [generationSize]byte) error
	// liveGens returns, in byte order, every generation of scope and name
	// the floor holds a live line for and no tombstone buries: what rm
	// buries beside the generations the entry's tree names.
	liveGens(scope, name string) ([][generationSize]byte, error)
	// check judges the floor as a grant needs it: present, trusted,
	// flagged, readable and parsing. A grant calls it before its first
	// write.
	check() error
}

// auditLine is one audit line's fields that this package fills: never a
// value and never a value's length.
type auditLine struct {
	op, scope, name, namespace, result string
	// via is the path the operation came by, "root" for a root verb;
	// empty writes no via field.
	via string
	// delivery is the KeyDelivery UID a withdraw names, or
	// auditPlaceholder for one outside the grammar; empty for other ops.
	delivery string
	// revoke marks the line of an operation in the revocation class that
	// revoked something: past the hard cap it draws on its uid's revocation
	// budget, where every other line is refused.
	revoke bool
}

// auditSink appends audit lines.
//
// The contract (docs/design/keystore.md § "The audit log": every append
// takes the store .lock): every append runs while the caller holds the
// exclusive store lock. A grant appends its line before its first write and
// a revocation after its commit, each under the lock it does its work in; a
// refusal after the lock was taken is appended before the lock is released;
// a refusal before it takes the lock briefly to append (auditBriefly), and
// one for which the lock cannot be had is not audited.
type auditSink interface {
	append(auditLine) error
}

// LogSizes is the size of each append-only log and the caps they are held
// to, for the doctor row (docs/design/keystore.md § "Size caps").
type LogSizes struct {
	// UserFloor and Audit are the logs' sizes in bytes.
	UserFloor, Audit int64
	// SoftCap and HardCap are the configured caps, the same for both logs.
	SoftCap, HardCap int64
}

// LogSizes returns the sizes of the two append-only logs, read by
// descriptor through the data root without following a symlink. It takes
// no lock and judges nothing but the name: a missing log is an error
// matching fs.ErrNotExist.
func (s *FileStore) LogSizes(ctx context.Context) (LogSizes, error) {
	if err := ctx.Err(); err != nil {
		return LogSizes{}, err
	}
	dfd, lfd, err := s.openLogDirs()
	if err != nil {
		return LogSizes{}, err
	}
	defer func() { _ = unix.Close(dfd); _ = unix.Close(lfd) }() // read-only
	out := LogSizes{SoftCap: s.logSoftCap, HardCap: s.logHardCap}
	for _, l := range []struct {
		name string
		size *int64
	}{{userFloorLogName, &out.UserFloor}, {auditLogName, &out.Audit}} {
		var st unix.Stat_t
		if err := s.statLog(lfd, l.name, &st); err != nil {
			return LogSizes{}, fmt.Errorf("%s: %w", l.name, err)
		}
		*l.size = st.Size
	}
	return out, nil
}

// FloorDamage is the count of the user-scope floor's damaged lines, which
// the reader skips: lines that do not parse, and a last line with no
// newline. It is root's, for doctor: a damaged line lost only what it
// would have recorded. The floor is opened and judged as for any read; a
// store with no file-backed floor has none. A floor past the reader's
// bounds (its size or key bound) returns that damage as the error, beside
// the count read before it: floor --rebuild, which streams the floor with
// no size bound, is its repair.
func (s *FileStore) FloorDamage(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ff, ok := s.userFloor.(*fileFloorLog)
	if !ok {
		return 0, nil
	}
	f, st, err := ff.log.open(unix.O_RDONLY)
	if err != nil {
		ff.log.forgetUnflagged(err, false)
		return 0, err
	}
	defer func() { _ = f.Close() }() // read-only
	ff.log.mu.Lock()
	defer ff.log.mu.Unlock()
	state, err := ff.log.sync(f, st)
	if err != nil {
		return 0, err
	}
	return state.damaged(), state.bad
}

// appendLog is one append-only log and what has been read of it: the
// sizes of the lines that start past the hard cap, per uid, which is how
// much of each uid's revocation budget is spent, and for the floor the
// highest seq per key. What was read is kept for one file (dev, ino and
// birth time) and is read on from where it stopped, once the last whole line
// parsed still reads back the same; a different file, a shorter one, one
// whose last parsed line changed, or one whose flag was seen clear, is read
// again from the start.
type appendLog struct {
	s    *FileStore
	name string
	// lineUID parses one line, without its newline, and returns the uid it
	// is charged to (0 for none). For the floor it also records the line.
	lineUID func(st *logState, line []byte) (uint32, error)
	// whole reports whether every line must be read (the floor), or only
	// those past the hard cap (the audit log).
	whole bool
	// freeSpace, when set, replaces logFreeSpace: the test seam for the
	// free-space preflight.
	freeSpace func(fd int) (uint64, error)
	// reserve, when set, replaces reserveLogBlocks: the test seam for the
	// block reservation an append makes before its write.
	reserve func(f *os.File, n int64) error
	// write, when set, replaces f.Write: the test seam for a short or
	// failed append.
	write func(f *os.File, b []byte) (int, error)
	// fsync, when set, replaces f.Sync: the test seam for an append whose
	// write landed and whose fsync failed.
	fsync func(f *os.File) error
	// maxKeys, when not 0, replaces maxFloorKeys: the test seam for the
	// key bound.
	maxKeys int
	// maxShare and maxHeadroom, when maxKeys is set, replace the per-uid key
	// share and the revocation headroom; left 0, the share is maxKeys and
	// the headroom 0.
	maxShare, maxHeadroom int
	// readAt, when set, is the source sync reads f through: the test seam
	// for a read I/O error.
	readAt func(f *os.File) io.ReaderAt
	// addsKey, set for the floor, reports whether line, its newline
	// included, would add a key to what state holds.
	addsKey func(state *logState, line []byte) (bool, error)

	// mu guards state: reads under the shared store lock run together.
	mu    sync.Mutex
	state logState
	// servedWarned is the floor files a known generation was served over
	// damage in, each logged at Warn once (warnServedOverDamage); under mu.
	servedWarned map[fileID]bool
}

// logState is what has been read of one file.
type logState struct {
	dev, ino uint64
	birth    unix.Timespec
	// hardCap and bound are the hard cap and logReadBound it was read
	// under.
	hardCap, bound int64
	// keys is the floor's count of distinct keys, buried ones included,
	// which bounds the reader's memory; uidKeys is, per uid, the count of
	// keys its scope's lines added, buried or live, which the lifetime key
	// share holds.
	keys    int
	uidKeys map[uint32]int
	// off is where reading stopped: just past the last whole line read.
	off int64
	// lastAt and last are the start and bytes, its newline included, of the
	// last whole line parsed: sync reads them again before it uses the
	// state, and reads the file from the start when they changed. A line is
	// at most maxLogLine bytes, so last is too.
	lastAt int64
	last   []byte
	// pastCap is each uid's bytes in lines that start at or past hardCap.
	pastCap map[uint32]int64
	// maxSeq is the floor's highest seq per key, and buried its tombstones.
	maxSeq map[floorKey]uint64
	buried map[floorKey]bool
	// scopes interns the floor's scope strings, so each key shares its
	// scope's one copy. firstGen and moreGens index every key's generation
	// by (scope, name), in the order the keys were first read, for
	// liveGens: the first inline, since nearly every name has one, and the
	// rest in moreGens.
	scopes   map[string]string
	firstGen map[nameKey][generationSize]byte
	moreGens map[nameKey][][generationSize]byte
	// bad is the error of damage that refuses the whole log, which sticks
	// for this file: a log past the reader's size bound, or a floor past its
	// key bound. A line that does not parse is not bad: it is skipped and
	// counted in damage.
	bad error
	// badAt is the byte offset bad, or the first damaged line, was met at:
	// root's, never in an error a socket caller can see.
	badAt int64
	// damage counts the lines skipped because they do not parse (outside
	// the grammar, or over maxLogLine): never applied to the state, so a
	// skipped line can only lose what it would have said, never undo a
	// tombstone already read. warned is the count last logged at Warn.
	damage, warned int
	// leadEnd is the offset just past the last empty line read, which
	// starts at leadAt: an append's leading newline. A line that parses at
	// leadEnd is charged that byte too when leadAt is at or past hardCap,
	// as the writer charges it. An empty line is otherwise benign: no
	// damage, charged to no uid.
	leadAt, leadEnd int64
	// tornSize, when not 0, is the size of the file whose last line had no
	// newline: a pending damaged line, counted by damaged while the file
	// keeps that size, and reading resumes at off, the torn line's start,
	// once an append closes it.
	tornSize int64
	// The floor's taint (userfloor_taint.go): taintNames and taintGens are
	// the keys skipped lines could have named, and taintOverflow, sticky
	// for the file, a taint past the set's cap, which taints every key;
	// unattrib and unattribAt mark unattributable damage and the start of
	// the latest, and unattribN counts its lines; tornKind, tornKey and
	// tornAt are the torn last line's, in force while tornSize is.
	taintNames map[nameKey]bool
	taintGens  map[floorKey]bool
	// taintPrefixes are the scope and name prefixes lines torn inside
	// their scope or name could have named.
	taintPrefixes map[prefixTaint]bool
	taintOverflow bool
	unattrib      bool
	unattribAt    int64
	unattribN     int
	tornKind      taintKind
	tornKey       floorKey
	tornAt        int64
	// unrecovered marks a whole line with a bad checksum that no unique
	// single-bit correction recovers, and unrecoveredAt the start of the
	// latest (userfloor_taint.go): every generation of every key is
	// refused while it counts. unrecoveredN counts those lines and
	// unrecoveredOffs holds the start of the first maxUnrecoveredOffsets
	// of them, in file order, for root's review (floorAckView).
	unrecovered     bool
	unrecoveredAt   int64
	unrecoveredN    int
	unrecoveredOffs []int64
	// frozen holds the torn last line's bytes as first read, by its
	// offset: its classification is fixed there. The line that later
	// starts at that offset is damage unless it is exactly those bytes and
	// a newline (the server's next append leads with one), so bytes a
	// foreign writer appends with no leading newline can never complete
	// the fragment into a line that parses or that names another key. It
	// holds one entry at most, dropped once the line is read whole; it is
	// kept for this reading of the file only, never across a fresh read.
	frozen map[int64][]byte
}

// damaged is the count of damaged lines: those skipped, and a last line
// with no newline.
func (s *logState) damaged() int {
	if s.tornSize != 0 {
		return s.damage + 1
	}
	return s.damage
}

// skip counts the line at off as damage, keeping the first offset.
func (s *logState) skip(off int64) {
	if s.damaged() == 0 {
		s.badAt = off
	}
	s.damage++
}

// at records off as where the sticky error err was met, kept apart from
// err's text, which a socket caller can see, and returns err.
func (s *logState) at(off int64, err error) error {
	s.badAt = off
	return err
}

// floorKey is one floor line's key.
type floorKey struct {
	scope, name string
	gen         [generationSize]byte
}

// nameKey is the (scope, name) a floor key's generations are indexed by.
type nameKey struct{ scope, name string }

// openLogDataRoot opens the data root as a directory without following a
// symlink and judges it on the descriptor, as the system floor's is.
func (s *FileStore) openLogDataRoot() (int, error) {
	if s.dataRoot == "" {
		return -1, fmt.Errorf("%w: no data root is configured", errLogUntrusted)
	}
	dfd, err := unix.Open(s.dataRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open the data root: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		_ = unix.Close(dfd) // abandoned
		return -1, fmt.Errorf("stat the data root: %w", err)
	}
	if int64(st.Uid) != int64(s.floorUID) || st.Mode&0o022 != 0 {
		_ = unix.Close(dfd) // abandoned
		slog.Debug("the keystore data root is not trusted", "path", s.dataRoot, "uid", st.Uid, "mode", fmt.Sprintf("%04o", st.Mode&0o7777))
		return -1, fmt.Errorf("%w: the data root is not owned by root, or is group- or other-writable", errLogUntrusted)
	}
	if err := judgeFlagsACL(dfd, fdFlags); err != nil {
		_ = unix.Close(dfd) // abandoned
		slog.Debug("the keystore data root is not trusted", "path", s.dataRoot, "err", err)
		return -1, fmt.Errorf("the data root: %w", err)
	}
	return dfd, nil
}

// logDirOf is the directory in keystore-logs/ that holds the log name.
func logDirOf(name string) string {
	if name == userFloorLogName {
		return floorDirName
	}
	return auditDirName
}

// openLogsDir opens the logs directory through the judged data root dfd,
// O_DIRECTORY|O_NOFOLLOW, and judges it on its descriptor (judgeLogDir).
func (s *FileStore) openLogsDir(dfd int) (int, error) {
	return s.openJudgedDir(dfd, logsDirName)
}

// openLogDir opens the directory of the log name through the judged logs
// directory lfd, O_DIRECTORY|O_NOFOLLOW, and judges it on its descriptor
// (judgeLogDir). A missing directory is an error matching unix.ENOENT.
func (s *FileStore) openLogDir(lfd int, name string) (int, error) {
	return s.openJudgedDir(lfd, logDirOf(name))
}

// openJudgedDir opens dir under pfd and judges it (judgeLogDir).
func (s *FileStore) openJudgedDir(pfd int, dir string) (int, error) {
	fd, err := unix.Openat(pfd, dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("%w: open %s: %w; sudo k3sm install creates it", errLogUntrusted, dir, err)
	}
	if err := s.judgeLogDir(fd, dir); err != nil {
		_ = unix.Close(fd) // read-only directory descriptor
		return -1, err
	}
	return fd, nil
}

// judgeLogDir refuses the directory dir open at fd unless it is a
// directory of the data root's owner (root) at mode 0755, with no file flag
// and no extended ACL: keystore-logs/ and each log's directory.
func (s *FileStore) judgeLogDir(fd int, dir string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int64(st.Uid) != int64(s.floorUID) {
		return fmt.Errorf("%w: %s is not a directory of the data root's owner", errLogUntrusted, dir)
	}
	if mode := st.Mode & 0o7777; mode != logsDirMode {
		slog.Debug("a keystore logs directory is not at its mode", "dir", dir, "mode", fmt.Sprintf("%04o", mode))
		return fmt.Errorf("%w: %s is not at mode 0755", errLogUntrusted, dir)
	}
	fl, err := fdFlags(fd)
	if err != nil {
		return fmt.Errorf("%w: read the flags of %s: %w", errLogUntrusted, dir, err)
	}
	if fl != 0 {
		return fmt.Errorf("%w: %s carries a file flag", errLogUntrusted, dir)
	}
	return judgeFlagsACL(fd, func(int) (uint32, error) { return fl, nil })
}

// errLogOldLocation is a log found where no release keeps one: at the top
// of the data root, or directly in keystore-logs/. The logs live in their
// own directories in keystore-logs/.
func errLogOldLocation(name string) error {
	return fmt.Errorf("%w: %s is at a location this build keeps no log at (the log lives in %s/%s/); clear its flag and remove it (sudo chflags nosappnd and sudo rm), then run sudo k3sm install", errLogUntrusted, name, logsDirName, logDirOf(name))
}

// oldLogLocation reports whether the log name stands at an earlier
// location: the top of the data root dfd, or directly in the logs
// directory lfd (when lfd >= 0).
func oldLogLocation(dfd, lfd int, name string) bool {
	var st unix.Stat_t
	if unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil {
		return true
	}
	return lfd >= 0 && unix.Fstatat(lfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil
}

// statLog stats the log name in its directory under lfd, without
// following a symlink, the directory judged.
func (s *FileStore) statLog(lfd int, name string, st *unix.Stat_t) error {
	ld, err := s.openLogDir(lfd, name)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(ld) }() // read-only directory descriptor
	return unix.Fstatat(ld, name, st, unix.AT_SYMLINK_NOFOLLOW)
}

// openLogDirs opens and judges the data root and, through it, the logs
// directory (gate open), and returns both descriptors.
func (s *FileStore) openLogDirs() (dfd, lfd int, err error) {
	dfd, err = s.openLogDataRoot()
	if err != nil {
		return -1, -1, err
	}
	lfd, err = s.openLogsDir(dfd)
	if err != nil {
		_ = unix.Close(dfd) // read-only directory descriptor
		return -1, -1, err
	}
	return dfd, lfd, nil
}

// open opens the log with flag (O_RDONLY, or O_WRONLY|O_APPEND) through
// the data root and the logs directory, never following a symlink, and
// judges it on the descriptor. It returns the file and its stat.
func (l *appendLog) open(flag int) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	dfd, err := l.s.openLogDataRoot()
	if err != nil {
		return nil, st, err
	}
	defer func() { _ = unix.Close(dfd) }() // the file is opened; the directory is done with
	// A missing logs directory, or log directory, is a missing log, as
	// before install.
	lfd, err := l.s.openLogsDir(dfd)
	fd := -1
	if err == nil {
		defer func() { _ = unix.Close(lfd) }() // as dfd
		var ld int
		ld, err = l.s.openLogDir(lfd, l.name)
		if err == nil {
			// O_NONBLOCK, so a FIFO planted at the name is opened, and refused
			// on its descriptor, rather than blocking the open.
			fd, err = unix.Openat(ld, l.name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			_ = unix.Close(ld) // read-only directory descriptor
		}
	} else {
		lfd = -1
	}
	if err != nil && fd < 0 && !errors.Is(err, unix.ENOENT) && errors.Is(err, errLogUntrusted) {
		return nil, st, err // a judged directory refused
	}
	if errors.Is(err, unix.ENOENT) {
		if oldLogLocation(dfd, lfd, l.name) {
			return nil, st, errLogOldLocation(l.name)
		}
		missing := errLogMissing
		if _, err := os.Lstat(filepath.Join(l.s.dir, userScopesName)); err == nil {
			missing = errLogMissingScopes
		}
		return nil, st, fmt.Errorf("%w: %s: %w", missing, l.name, fs.ErrNotExist)
	}
	if errors.Is(err, unix.ELOOP) {
		return nil, st, fmt.Errorf("%w: %s is a symlink", errLogUntrusted, l.name)
	}
	if err != nil {
		return nil, st, fmt.Errorf("open %s: %w", l.name, err)
	}
	f := os.NewFile(uintptr(fd), l.name)
	if err := l.s.judgeLog(f, &st); err != nil {
		_ = f.Close() // refused; nothing written
		return nil, st, fmt.Errorf("%s: %w", l.name, err)
	}
	return f, st, nil
}

// judgeLog fills st from f's descriptor and refuses f unless it is a
// regular file with one link, owned by the service user, mode 0600, with
// SF_APPEND set as the flag source reads it.
func (s *FileStore) judgeLog(f *os.File, st *unix.Stat_t) error {
	if err := unix.Fstat(int(f.Fd()), st); err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	// The figures (links, owner, mode) are root's, logged at Debug: the
	// error reaches the socket.
	bad := ""
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		bad = "not a regular file"
	case st.Nlink != 1:
		bad = "more than one link"
	case st.Uid != s.uid:
		bad = "not owned by the service user"
	case st.Mode&0o7777 != logMode:
		bad = "not at the log's mode"
	}
	if bad != "" {
		slog.Debug("a keystore append-only log is not trusted", "log", f.Name(), "links", st.Nlink, "uid", st.Uid, "mode", fmt.Sprintf("%04o", st.Mode&0o7777))
		if st.Nlink != 1 && st.Mode&unix.S_IFMT == unix.S_IFREG {
			return logLinkedError{log: f.Name()}
		}
		return fmt.Errorf("%w: %s", errLogUntrusted, bad)
	}
	flags, err := s.logFlags(f)
	if err != nil {
		return fmt.Errorf("%w: read its flags: %w", errLogNotAppendOnly, err)
	}
	if flags&sfAppend == 0 {
		return errLogNotAppendOnly
	}
	return judgeFlagsACL(int(f.Fd()), func(int) (uint32, error) { return flags, nil })
}

// logLinkedError is judgeLog's refusal of a log with more than one link.
// It matches errLogUntrusted, and its text names the maintenance verb that
// repairs it by replacing the log with a fresh file (repairVerb).
type logLinkedError struct{ log string }

func (e logLinkedError) Error() string {
	return fmt.Sprintf("%v: more than one link: %s replaces it with a fresh file", errLogUntrusted, repairVerb(e.log))
}

func (e logLinkedError) Is(target error) bool { return target == errLogUntrusted }

// repairVerb is the root verb that replaces the log name with a fresh
// file: floor --rebuild for the floor, audit --rotate for the audit log.
func repairVerb(name string) string {
	if name == userFloorLogName {
		return "sudo k3sm keys floor --rebuild"
	}
	return "sudo k3sm keys audit --rotate"
}

// judgeFlagsACL refuses, as errLogUntrusted, the descriptor fd when its
// st_flags, read through flags, carry any bit beside SF_APPEND (an
// immutable or user append-only flag install never sets, and which an owner
// who set it could clear), or when it carries a non-empty extended ACL,
// which can grant what the mode does not show. An ACL that cannot be read is
// refused too.
func judgeFlagsACL(fd int, flags func(int) (uint32, error)) error {
	fl, err := flags(fd)
	if err != nil {
		return fmt.Errorf("%w: read its flags: %w", errLogUntrusted, err)
	}
	if extra := fl &^ sfAppend; extra != 0 {
		slog.Debug("a keystore log or data root carries a flag beside SF_APPEND", "flags", fmt.Sprintf("%#x", extra))
		return fmt.Errorf("%w: a file flag beside SF_APPEND", errLogUntrusted)
	}
	acl, err := fdHasACL(fd)
	if err != nil {
		return fmt.Errorf("%w: read its ACL: %w", errLogUntrusted, err)
	}
	if acl {
		return fmt.Errorf("%w: it carries an extended ACL", errLogUntrusted)
	}
	return nil
}

// forgetUnflagged drops what was read when err is a log seen with its
// SF_APPEND flag clear: while it was clear the file could have been
// rewritten anywhere, so it is read again from the start once the flag is
// back. held reports whether the caller holds l.mu.
func (l *appendLog) forgetUnflagged(err error, held bool) {
	if !errors.Is(err, errLogNotAppendOnly) {
		return
	}
	if !held {
		l.mu.Lock()
		defer l.mu.Unlock()
	}
	l.state = logState{}
}

// sync reads f (which st describes) on from where reading stopped, under
// l.mu, and returns the state. A line that does not parse, over-long lines
// included, is skipped and counted (state.damage); a last line with no
// newline is pending damage while the file keeps its size (state.tornSize);
// a log past the reader's size bound or a floor past its key bound is
// state.bad, which sticks; a read I/O error is errLogUnreadable, returned
// and not kept, and reading resumes past the last whole line read.
func (l *appendLog) sync(f *os.File, st unix.Stat_t) (*logState, error) {
	s, err := l.syncRead(f, st)
	if err == nil && s.damaged() > s.warned {
		// Root's figures, in the server's log: never in an error a socket
		// caller can see.
		slog.Warn("a keystore append-only log holds lines that do not parse; they are skipped", "log", l.name, "damaged", s.damaged(), "first", s.badAt)
		s.warned = s.damaged()
	}
	return s, err
}

// syncRead is sync's reading.
func (l *appendLog) syncRead(f *os.File, st unix.Stat_t) (*logState, error) {
	s := &l.state
	bound := l.s.logReadBound()
	var src io.ReaderAt = f
	if l.readAt != nil {
		src = l.readAt(f)
	}
	fresh := func() {
		*s = logState{dev: uint64(st.Dev), ino: st.Ino, birth: logBirth(&st), hardCap: l.s.logHardCap, bound: bound, pastCap: map[uint32]int64{}, uidKeys: map[uint32]int{}, maxSeq: map[floorKey]uint64{}, buried: map[floorKey]bool{}, scopes: map[string]string{}, firstGen: map[nameKey][generationSize]byte{}, moreGens: map[nameKey][][generationSize]byte{}}
	}
	if s.pastCap == nil || s.dev != uint64(st.Dev) || s.ino != st.Ino || s.birth != logBirth(&st) || s.hardCap != l.s.logHardCap || s.bound != bound || st.Size < s.off {
		fresh()
	} else if len(s.last) > 0 {
		// The same file at the same or a larger size can still have been
		// rewritten in place: the last line parsed must read back.
		got := make([]byte, len(s.last))
		n, err := src.ReadAt(got, s.lastAt)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, l.unreadable(s.lastAt, err)
		}
		// A short read is a file that no longer holds the line.
		if !bytes.Equal(got[:n], s.last) {
			fresh()
		}
	}
	if s.tornSize != 0 {
		if st.Size == s.tornSize {
			return s, nil
		}
		// The torn line has been appended to: read it again.
		s.tornSize = 0
	}
	if s.bad != nil || st.Size == s.off {
		return s, nil
	}
	if st.Size > bound {
		s.bad = fmt.Errorf("%w: %s", errLogTooLarge, l.name)
		return s, nil
	}
	start := s.off
	if !l.whole && start < s.hardCap {
		if st.Size <= s.hardCap {
			// Nothing past the cap to charge; the audit log's lines before
			// it are not read.
			return s, nil
		}
		// The first line past the cap starts after the newline at or after
		// hardCap-1.
		start = s.hardCap - 1
	}
	r := bufio.NewReaderSize(io.NewSectionReader(src, start, st.Size-start), 64<<10)
	off := start
	if !l.whole && s.off < s.hardCap {
		// Skip the line that straddles the cap, however long: it is read
		// through, a chunk the size of the buffer at a time. A last line
		// with no newline is damage, as it is anywhere.
		for {
			skipped, err := r.ReadSlice('\n')
			off += int64(len(skipped))
			if err == nil {
				break
			}
			switch {
			case errors.Is(err, bufio.ErrBufferFull):
				continue
			case errors.Is(err, io.EOF):
				// s.off stays before the cap, so the skip runs again.
				s.tornSize = st.Size
				return s, nil
			}
			return nil, l.unreadable(off, err)
		}
	}
	for off < st.Size {
		line, err := readLogLine(r)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil && !errors.Is(err, errLogLineTooLong) && !errors.Is(err, errLogTorn) {
			s.off = off
			return nil, l.unreadable(off, err)
		}
		if errors.Is(err, errLogTorn) {
			if s.damaged() == 0 {
				s.badAt = off
			}
			s.off, s.tornSize = off, st.Size
			if _, ok := s.frozen[off]; !ok {
				s.frozen = map[int64][]byte{off: line}
			}
			if l.whole {
				s.tornTaint(off, s.frozen[off])
			}
			return s, nil
		}
		if frag, ok := s.frozen[off]; ok {
			delete(s.frozen, off)
			if !bytes.Equal(line[:len(line)-1], frag) {
				// Bytes appended to a torn line with no leading newline
				// are a foreign writer's: the merged line is damage,
				// classified by the fragment as first read.
				s.skip(off)
				if l.whole {
					s.taintLine(off, frag)
				}
				s.lastAt, s.last = off, line
				off += int64(len(line))
				continue
			}
		}
		if errors.Is(err, errLogLineTooLong) {
			// An over-long line is damage, skipped and charged to no uid. It
			// is read through to its newline.
			n, serr := skipRestOfLine(r, line)
			switch {
			case errors.Is(serr, io.EOF):
				if s.damaged() == 0 {
					s.badAt = off
				}
				s.off, s.tornSize = off, st.Size
				s.tornKind, s.tornAt = taintUnattributable, off
				return s, nil
			case serr != nil:
				s.off = off
				return nil, l.unreadable(off, serr)
			}
			s.skip(off)
			s.unattributable(off)
			off += n
			continue
		}
		if len(line) == 1 {
			// An empty line: an append's leading newline (appendLines).
			s.leadAt, s.leadEnd = off, off+1
			off++
			continue
		}
		uid, perr := l.lineUID(s, line[:len(line)-1])
		if errors.Is(perr, errFloorTooManyKeys) {
			s.bad = s.at(off, perr)
			return s, nil
		}
		if perr != nil {
			// A line that does not parse is skipped and changes nothing:
			// lineUID refuses before it records anything. On the floor
			// it taints what it could have named.
			s.skip(off)
			if l.whole {
				s.taintLine(off, line[:len(line)-1])
			}
			uid = 0
		}
		if off >= s.hardCap && uid != 0 {
			if _, ok := s.pastCap[uid]; !ok && len(s.pastCap) >= maxChargedUIDs {
				// Sticky damage, as a log past its size bound: the map
				// of charged uids grows no further.
				s.bad = s.at(off, fmt.Errorf("%w: %s", errLogTooManyUIDs, l.name))
				return s, nil
			}
			s.pastCap[uid] += int64(len(line))
			if s.leadEnd == off && s.leadAt >= s.hardCap {
				s.pastCap[uid]++
			}
		}
		s.lastAt, s.last = off, line
		off += int64(len(line))
	}
	s.off = off
	return s, nil
}

// unreadable is errLogUnreadable for a read of this log that failed at off:
// the offset is root's, logged at Debug, never in the error a socket caller
// can see.
func (l *appendLog) unreadable(off int64, err error) error {
	slog.Debug("a keystore append-only log could not be read", "log", l.name, "offset", off, "err", err)
	return fmt.Errorf("%w: %s: %w", errLogUnreadable, l.name, err)
}

// readLogLine reads one whole line, its newline included, of at most
// maxLogLine bytes. A last line with no newline is an error, as is a
// longer one, for which it returns the bytes it read of it.
func readLogLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLogLine {
			return line, errLogLineTooLong
		}
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return line, errLogTorn
		default:
			return line, err
		}
	}
}

// skipRestOfLine reads through the rest of a line of which read is the
// start, to and including its newline, a buffer at a time, and returns the
// whole line's length. A line with no newline before the end is io.EOF.
func skipRestOfLine(r *bufio.Reader, read []byte) (int64, error) {
	n := int64(len(read))
	if len(read) > 0 && read[len(read)-1] == '\n' {
		return n, nil
	}
	for {
		chunk, err := r.ReadSlice('\n')
		n += int64(len(chunk))
		switch {
		case err == nil:
			return n, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		}
		return n, err
	}
}

// room refuses, as ErrLogFull, an operation of uid's that would append to
// this log past its hard cap: every operation but one that revokes, and one
// that revokes when uid's revocation budget has no room for a whole line. A
// log that cannot be opened or read is no answer here: the operation's own
// read or append of it refuses or, for a revocation, goes ahead.
func (l *appendLog) room(uid uint32, revoke bool) error {
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		l.forgetUnflagged(err, false)
		return nil
	}
	defer func() { _ = f.Close() }() // read-only
	if !revoke && l.addsKey != nil {
		if err := l.keyRoom(f, st); err != nil {
			return err
		}
	}
	if st.Size < l.s.logHardCap {
		return nil
	}
	if !revoke {
		return l.pastCap()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		return nil
	}
	// The line is not written yet: room charges the longest one append of
	// a line can be, its leading newline included, through the predicate
	// appendLine charges the real line through.
	return l.revokeRoom(state, st.Size, uid, maxAppendLine)
}

// revokeRoomFor refuses, as ErrLogFull, n more bytes of uid's revocation
// lines, appended now, several appends at once: when they would take the
// log past logReadBound, or their bytes that could start at or past the
// hard cap (at most all of n, and at most what lands past the cap) past
// uid's revocation budget. A log that cannot be opened or read is no
// answer here, as for room.
func (l *appendLog) revokeRoomFor(uid uint32, n int64) error {
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		l.forgetUnflagged(err, false)
		return nil
	}
	defer func() { _ = f.Close() }() // read-only
	if st.Size+n <= l.s.logHardCap {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		return nil
	}
	if st.Size+n > l.s.logReadBound() {
		return l.pastCap()
	}
	return l.revokeRoom(state, st.Size, uid, min(n, st.Size+n-l.s.logHardCap))
}

// auditRevokeRoom refuses, as ErrLogFull, n more bytes of uid's revocation
// audit lines on the file-backed audit log (revokeRoomFor).
func (s *FileStore) auditRevokeRoom(uid uint32, n int64) error {
	if a, ok := s.auditSink.(*fileAuditLog); ok {
		return a.log.revokeRoomFor(uid, n)
	}
	return nil
}

// grantKeys is the most keys one grant adds to the floor: a put that mints
// its scope adds the delivery record's key and the entry's.
const grantKeys = 2

// keyRoom refuses, as ErrLogFull, a grant when the floor (f, which st
// describes) has no room for grantKeys more keys under its key bound. Only a
// revocation's line for a key the floor already holds is written past it.
// A floor that cannot be read is no answer here, as in room.
func (l *appendLog) keyRoom(f *os.File, st unix.Stat_t) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		return nil
	}
	if bound := l.keyBound(); state.keys+grantKeys > bound {
		return fmt.Errorf("%w (%s has no room for the caller's keys under its key bound)", ErrLogFull, l.name)
	}
	return nil
}

// addKeyRoom refuses, as ErrLogFull, n more keys charged to uid: for a
// revocation's line (revoke) past keyBound plus the revocation headroom; for
// any other line past keyBound, or past uid's key share. appendLine and
// floorGrantRoom both judge through it. The texts name no figure.
func (l *appendLog) addKeyRoom(state *logState, uid uint32, n int, revoke bool) error {
	if revoke {
		if state.keys+n > l.readKeyBound() {
			return fmt.Errorf("%w (%s is at its key bound and revocation headroom)", ErrLogFull, l.name)
		}
		return nil
	}
	// One text for the floor at its key bound and the caller's share spent,
	// so a caller cannot tell whether other uids filled the floor.
	if state.keys+n > l.keyBound() || state.uidKeys[uid]+n > l.keyShare() {
		return fmt.Errorf("%w (%s has no room for the caller's keys under its key bound)", ErrLogFull, l.name)
	}
	return nil
}

// pastCap is the one ErrLogFull text for a log past its hard cap and for
// one at the reader's bound, so a caller cannot tell which it met, nor so
// how far other uids' lines took the log.
func (l *appendLog) pastCap() error {
	return fmt.Errorf("%w (%s is past its hard cap)", ErrLogFull, l.name)
}

// revokeRoom refuses, as ErrLogFull, n more bytes for uid past the hard
// cap: when they would take the log past logReadBound, or uid's lines that
// start past the hard cap past its revocation budget. room and appendLine
// both judge through it.
func (l *appendLog) revokeRoom(state *logState, size int64, uid uint32, n int64) error {
	if size+n > l.s.logReadBound() {
		return l.pastCap()
	}
	if state.pastCap[uid]+n > l.s.logRevokeBudget {
		return fmt.Errorf("%w (the caller's revocation budget in %s is spent)", ErrLogFull, l.name)
	}
	return nil
}

// appendLine appends line, which ends in a newline, charged to uid. Past
// the hard cap only a line that may draw on uid's revocation budget
// (budget) is written, and only while the budget has room for it. A
// revocation's line (revoke) is held to revokeFreeSlack rather than the
// free-space margin. It never writes what the reader would refuse: a line
// past logReadBound, or a floor line that adds a key past the key bound.
// Every append writes a newline first, in the same write(2), so bytes a
// foreign writer left with no newline read as a line of their own, which
// the reader skips as damage, and line reads back whole; with no such bytes
// the newline is an empty line, which the reader passes over.
func (l *appendLog) appendLine(uid uint32, line []byte, budget, revoke bool) error {
	return l.appendLineSlack(uid, line, budget, revoke, revoke)
}

// appendLineSlack is appendLine with the free-space check apart from the
// class: slack holds the line to revokeFreeSlack, as a committed change's
// floor line is, whatever its class.
func (l *appendLog) appendLineSlack(uid uint32, line []byte, budget, revoke, slack bool) error {
	return l.appendLines(uid, [][]byte{line}, budget, revoke, slack, 0)
}

// appendLines appends lines, each ending in a newline, charged to uid, as
// one buffer: one block reservation for the whole of it and one write(2) on
// one descriptor, so the lines land whole or not at all, short of a crash or
// an EIO, which leave a torn tail the reader skips. Its admission and key
// checks are appendLine's, over every line: a line that starts at or past
// the hard cap needs budget and room in uid's revocation budget, the keys
// the lines add are judged together, and the free space must hold the
// buffer, and, with extra bytes the caller appends after it (an rm's audit
// line), the buffer's block-rounded reservation plus those bytes, beyond
// the margin, so the caller's append passes its own preflight.
// An error means nothing was committed, except a *linesLanded one: a
// write that failed or landed short after whole lines of the buffer
// reached the file, which the reader reads and holds in force.
func (l *appendLog) appendLines(uid uint32, lines [][]byte, budget, revoke, slack bool, extra int) error {
	for _, line := range lines {
		if len(line) > maxLogLine {
			return fmt.Errorf("%w: refused a line for %s", errLogLineTooLong, l.name)
		}
	}
	// Read-write, so the tail and, for the floor, the keys are read on the
	// descriptor the lines are appended through.
	f, st, err := l.open(unix.O_RDWR | unix.O_APPEND)
	if err != nil {
		l.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = f.Close() }() // each append is fsynced below
	l.mu.Lock()
	defer l.mu.Unlock()
	// Every buffer leads with a newline, never judged from the tail: a
	// foreign writer racing a check of the last byte could still leave an
	// unterminated fragment before the write, which would glue to the first
	// line. With the newline the fragment is a damaged line of its own and
	// every line here parses; with no fragment it is an empty line, which
	// the reader passes over.
	out := []byte{'\n'}
	lead := int64(len(out))
	// charge is uid's bytes in lines that start at or past the hard cap,
	// which the reader charges to its revocation budget, and the leading
	// newline when it, too, is at or past the cap.
	var charge int64
	if st.Size >= l.s.logHardCap {
		charge = lead
	}
	for _, line := range lines {
		if st.Size+int64(len(out)) >= l.s.logHardCap {
			charge += int64(len(line))
		}
		out = append(out, line...)
	}
	if bound := l.s.logReadBound(); st.Size+int64(len(out)) > bound {
		// Never make the damage the reader refuses.
		return l.pastCap()
	}
	var state *logState
	read := func() error {
		if state != nil {
			return nil
		}
		var err error
		state, err = l.sync(f, st)
		if err != nil {
			return err
		}
		if state.bad != nil {
			return fmt.Errorf("%s: %w", l.name, state.bad)
		}
		return nil
	}
	if charge > 0 {
		if !budget || uid == 0 {
			return l.pastCap()
		}
		if err := read(); err != nil {
			return err
		}
		// The leading newline is charged with the lines past the cap, and
		// otherwise only counted in the size.
		size := st.Size
		if st.Size < l.s.logHardCap {
			size += lead
		}
		if err := l.revokeRoom(state, size, uid, charge); err != nil {
			return err
		}
	}
	if l.addsKey != nil {
		if err := read(); err != nil {
			return err
		}
		keys := 0
		for _, line := range lines {
			adds, err := l.addsKey(state, line)
			if err != nil {
				return fmt.Errorf("%s: %w", l.name, err)
			}
			if adds {
				keys++
			}
		}
		if keys > 0 {
			if err := l.addKeyRoom(state, uid, keys, revoke); err != nil {
				return err
			}
		}
	}
	need := len(out)
	if extra > 0 {
		// The caller appends extra bytes after the buffer (an rm's audit
		// line), whose own preflight asks revokeFreeSlack plus its line
		// of what this append leaves: the free space less the buffer's
		// block-rounded reservation. Held to that here, before anything
		// is written, the second append's preflight passes too.
		need = int(reserveSize(int64(len(out)))) + extra
	}
	if err := l.preflight(f, need, slack); err != nil {
		return err
	}
	// Reserve the buffer's blocks on this descriptor before the write, so a
	// disk filler racing the preflight cannot make the write short: a
	// refused reservation writes nothing.
	if err := l.reserveBlocks(f, int64(len(out))); err != nil {
		return err
	}
	// One write(2) of the whole buffer, into reserved blocks. An EIO, or a
	// crash mid-write, can still leave a torn tail the flag keeps: in
	// either log a skipped, counted line once the next append closes it,
	// which loses only what the torn bytes would have recorded
	// (docs/design/keystore.md § "The user-scope floor").
	write := l.write
	if write == nil {
		write = (*os.File).Write
	}
	fsync := l.fsync
	if fsync == nil {
		fsync = (*os.File).Sync
	}
	n, err := write(f, out)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
	// An fsync that fails leaves nothing known durable, but the lines the
	// write left visible are what every reader reads and holds in force:
	// when whole lines of ours are visible in the file, re-read from its
	// real end, they are counted as landed with their durability uncertain
	// (an rm: committed, run it again); when none is, nothing landed and
	// the caller refuses (an rm: nothing removed, run it again). The bytes
	// the write reported are not trusted here: only the file's tail.
	if serr := fsync(f); serr != nil {
		serr = fmt.Errorf("append to %s: fsync: %w", l.name, errors.Join(err, serr))
		if k := l.landedLines(f, st.Size, out, int(lead), -1); k > 0 {
			return &linesLanded{lines: k, unsynced: true, err: serr}
		}
		return serr
	}
	if err != nil {
		err = fmt.Errorf("append to %s: %w", l.name, err)
		if k := l.landedLines(f, st.Size, out, int(lead), n); k > 0 {
			return &linesLanded{lines: k, err: err}
		}
		return err
	}
	return nil
}

// maxLandedSearch bounds how far before the real end of the file
// landedLines looks for the caller's bytes, beyond their own length: room
// for foreign appends racing the write.
const maxLandedSearch = 64 << 10

// linesLanded is an append that failed after lines of its buffer reached
// the file whole: the reader reads them, so what they record is in force.
// unsynced is set when the fsync after the write failed: the lines are
// visible, but not known durable.
type linesLanded struct {
	lines    int // whole lines of the caller's that landed, in order
	unsynced bool
	err      error
}

func (e *linesLanded) Error() string {
	return fmt.Sprintf("%v (%d whole line(s) landed before it)", e.err, e.lines)
}

func (e *linesLanded) Unwrap() error { return e.err }

// landedLines counts the caller's lines of out (lead bytes, the leading
// newline, then the lines) that reached f whole and newline-terminated,
// in order, after a write that failed or landed short or an fsync that
// failed. It re-reads the tail on f's descriptor from the file's real end,
// a fresh fstat, never from size, where the open saw it end: a foreign
// append between the open and the write moves the caller's bytes on, and
// one after it puts bytes past them. It searches the tail, from its end
// back to size, for the latest place the leading newline and the first
// whole line stand, and counts the whole lines that match from there. A
// tail that cannot be read falls back to n, the bytes the write reported,
// at size; n < 0 trusts no report and counts nothing. A fragment after the
// last whole line is a torn tail the reader skips as damage.
func (l *appendLog) landedLines(f *os.File, size int64, out []byte, lead, n int) int {
	first := bytes.IndexByte(out[lead:], '\n')
	if first < 0 {
		return 0
	}
	anchor := out[:lead+first+1]
	got := out[:max(0, min(n, len(out)))]
	var fst unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &fst); err == nil && fst.Size > size {
		var src io.ReaderAt = f
		if l.readAt != nil {
			src = l.readAt(f)
		}
		from := max(size, fst.Size-int64(len(out))-maxLandedSearch)
		buf := make([]byte, fst.Size-from)
		if k, err := src.ReadAt(buf, from); err == nil || k == len(buf) {
			got = nil
			if at := bytes.LastIndex(buf, anchor); at >= 0 {
				// The bytes on disk that match the buffer, from its start.
				m := 0
				for at+m < len(buf) && m < len(out) && buf[at+m] == out[m] {
					m++
				}
				got = out[:m]
			}
		}
	}
	if len(got) <= lead {
		return 0
	}
	return bytes.Count(got[lead:], []byte{'\n'})
}

// preflight refuses, as errLogNoSpace, an append of n bytes while the
// file system holding f, read with fstatfs on its descriptor, has less than
// logFreeMargin free beyond them, or, for a revocation's line (revoke),
// less than revokeFreeSlack. A file system that cannot be asked is refused
// the same way.
func (l *appendLog) preflight(f *os.File, n int, revoke bool) error {
	free := l.freeSpace
	if free == nil {
		free = logFreeSpace
	}
	avail, err := free(int(f.Fd()))
	if err != nil {
		return fmt.Errorf("%w: fstatfs %s: %w", errLogNoSpace, l.name, err)
	}
	margin := uint64(logFreeMargin)
	if revoke {
		margin = revokeFreeSlack
	}
	if avail < margin+uint64(n) {
		return fmt.Errorf("%w (%s)", errLogNoSpace, l.name)
	}
	return nil
}

// reserveBlocks reserves n bytes, rounded up to whole blocks, on f's
// descriptor before an append writes them, and refuses as errLogNoSpace
// when the file system will not give them.
func (l *appendLog) reserveBlocks(f *os.File, n int64) error {
	reserve := l.reserve
	if reserve == nil {
		reserve = reserveLogBlocks
	}
	if err := reserve(f, reserveSize(n)); err != nil {
		return fmt.Errorf("%w (%s): reserve: %w", errLogNoSpace, l.name, err)
	}
	return nil
}

// sealTail appends one newline when the log's last byte is not one: the
// start step's seal (sealUserLogTails), under the exclusive store lock, so
// a torn last line becomes a closed damaged line (on the floor, read
// through taintLine), never one that parses, and bytes a foreign writer later appends start a line of their own,
// even across a restart, where the reader's frozen fragment is not kept.
// The newline is held to the reader's bound, the revocation slack and a
// block reservation, as a revocation's line is, and is charged to no uid
// (an empty line, or the close of a damaged one, is charged to none).
// A tail torn only at its newline, whose bytes would parse once closed, is
// left as it is (wholeLine): the seal never makes a torn line parse.
func (l *appendLog) sealTail() error {
	f, st, err := l.open(unix.O_RDWR | unix.O_APPEND)
	if err != nil {
		l.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = f.Close() }() // the newline is fsynced below
	l.mu.Lock()
	defer l.mu.Unlock()
	if st.Size == 0 {
		return nil
	}
	var last [1]byte
	if _, err := f.ReadAt(last[:], st.Size-1); err != nil {
		return fmt.Errorf("read the last byte of %s: %w", l.name, err)
	}
	if last[0] == '\n' {
		return nil
	}
	if frag, ok := l.tailFragment(f, st.Size); !ok {
		return fmt.Errorf("read the torn tail of %s", l.name)
	} else if l.wholeLine(frag) {
		// A line torn only at its newline is whole: closing it would make
		// it parse, and no foreign byte can complete it into another line.
		return nil
	}
	if st.Size+1 > l.s.logReadBound() {
		return l.pastCap()
	}
	if err := l.preflight(f, 1, true); err != nil {
		return err
	}
	if err := l.reserveBlocks(f, 1); err != nil {
		return err
	}
	write := l.write
	if write == nil {
		write = (*os.File).Write
	}
	if _, err := write(f, []byte{'\n'}); err != nil {
		return fmt.Errorf("seal the torn tail of %s: %w", l.name, err)
	}
	fsync := l.fsync
	if fsync == nil {
		fsync = (*os.File).Sync
	}
	if err := fsync(f); err != nil {
		return fmt.Errorf("sync %s: %w", l.name, err)
	}
	return nil
}

// tailFragment returns the bytes after the last newline of f, which is
// size bytes long, read from at most maxLogLine+1 bytes before its end: a
// fragment longer than maxLogLine is returned cut to its last maxLogLine+1
// bytes, which no reader parses. ok is false when the tail cannot be read.
func (l *appendLog) tailFragment(f *os.File, size int64) (frag []byte, ok bool) {
	from := max(0, size-maxLogLine-1)
	buf := make([]byte, size-from)
	if _, err := f.ReadAt(buf, from); err != nil {
		return nil, false
	}
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		return buf[i+1:], true
	}
	return buf, true
}

// wholeLine reports whether frag, a torn tail without its newline, would
// parse as a line of this log once closed: a floor line whose checksum
// matches, or an audit line.
func (l *appendLog) wholeLine(frag []byte) bool {
	if len(frag) == 0 || len(frag)+1 > maxLogLine {
		return false
	}
	if l.whole {
		_, err := parseFloorLine(frag)
		return err == nil
	}
	_, err := parseAuditLine(frag)
	return err == nil
}

// logBlock is the block an append's reservation is rounded up to, the
// APFS allocation block.
const logBlock = 4 << 10

// reserveSize is n rounded up to whole logBlock blocks: the most new blocks
// an append of n bytes can take past the file's physical end, which
// F_PEOFPOSMODE allocates from.
func reserveSize(n int64) int64 {
	return (n + logBlock - 1) / logBlock * logBlock
}

// logFreeSpace is the bytes free to an unprivileged writer on the file
// system holding fd.
func logFreeSpace(fd int) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// scopeUID returns the uid of a user scope, user/<uid>, or 0 for any other
// scope string.
func scopeUID(scope string) uint32 {
	rest, ok := strings.CutPrefix(scope, "user/")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(rest, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != rest || n < minScopeUID || n > maxScopeUID {
		return 0
	}
	return uint32(n)
}

// fileFloorLog is the file-backed user-scope floor.
type fileFloorLog struct{ log *appendLog }

func newFileFloorLog(s *FileStore) *fileFloorLog {
	l := &appendLog{s: s, name: userFloorLogName, whole: true}
	l.lineUID = func(st *logState, line []byte) (uint32, error) {
		r, err := parseFloorLine(line)
		if err != nil {
			return 0, err
		}
		// A key is recorded on its first line, even at sequence 0: floor
		// --rebuild writes 0 for an entry with no authenticated pointer, and
		// that line is what keeps the entry damage, so it is present.
		if sc, ok := st.scopes[r.key.scope]; ok {
			r.key.scope = sc
		} else {
			st.scopes[r.key.scope] = r.key.scope
		}
		seq, inSeq := st.maxSeq[r.key]
		uid := scopeUID(r.key.scope)
		if !inSeq && !st.buried[r.key] {
			if st.keys >= l.readKeyBound() {
				return 0, errFloorTooManyKeys
			}
			st.keys++
			st.uidKeys[uid]++
			nk := nameKey{r.key.scope, r.key.name}
			if _, ok := st.firstGen[nk]; ok {
				st.moreGens[nk] = append(st.moreGens[nk], r.key.gen)
			} else {
				st.firstGen[nk] = r.key.gen
			}
		}
		switch {
		case r.tomb:
			st.buried[r.key] = true
		case !inSeq || r.seq > seq:
			st.maxSeq[r.key] = r.seq
		}
		return uid, nil
	}
	l.addsKey = func(st *logState, line []byte) (bool, error) {
		r, err := parseFloorLine(bytes.TrimSuffix(line, []byte{'\n'}))
		if err != nil {
			return false, err
		}
		_, inSeq := st.maxSeq[r.key]
		return !inSeq && !st.buried[r.key], nil
	}
	return &fileFloorLog{log: l}
}

// read opens, judges and reads the floor and runs fn on what was read,
// under the log's lock. A floor past the reader's size or key bound is
// errFloorLogMalformed; a line that does not parse is skipped (sync).
func (f *fileFloorLog) read(fn func(*logState)) error {
	file, st, err := f.log.open(unix.O_RDONLY)
	if err != nil {
		f.log.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = file.Close() }() // read-only
	f.log.mu.Lock()
	defer f.log.mu.Unlock()
	state, err := f.log.sync(file, st)
	if err != nil {
		return err
	}
	if state.bad != nil {
		// The offset is root's: the server's debug log, never the error.
		slog.Debug("the user-scope floor is past the reader's bound", "log", f.log.name, "offset", state.badAt, "err", state.bad)
		return fmt.Errorf("%w (%v)", errFloorLogMalformed, state.bad)
	}
	fn(state)
	return nil
}

func (f *fileFloorLog) check() error { return f.read(func(*logState) {}) }

// floor is the floor's word on scope, name and gen. A tainted key
// (userfloor_taint.go), the delivery record's included, is errFloorDegraded
// for every generation, known or not: the skipped line could have been its
// tombstone or a higher live line. So is every key while the floor holds an
// unrecovered flip that counts. While the floor holds unattributable
// damage that counts, an entry generation it has no line for is
// errFloorDegraded too; the delivery record has no tombstone, so its
// unknown generations are not. A known, untainted generation is served over
// damage, logged at Warn once per damaged file.
func (f *fileFloorLog) floor(scope, name string, gen [generationSize]byte) (uint64, error) {
	var (
		seq                     uint64
		known, buried, refusing bool
	)
	k := floorKey{scope, name, gen}
	if err := f.read(func(state *logState) {
		seq, known = state.maxSeq[k]
		buried = state.buried[k]
		switch {
		case buried:
		case state.tainted(k), f.unrecovered(state):
			refusing = true
		case !known && name != deliveriesFloorName && f.unattributable(state):
			refusing = true
		case state.damaged() > 0:
			f.log.warnServedOverDamage(state)
		}
	}); err != nil {
		return 0, err
	}
	if buried {
		return 0, errFloorBuried
	}
	if refusing {
		// The highest sequence the floor's whole lines hold for k still
		// comes back: a revocation checks a record against it.
		return seq, errFloorDegraded
	}
	return seq, nil
}

// liveRefused reports whether a live line for k is refused: k is tainted,
// the floor holds an unrecovered flip that counts, or it holds
// unattributable damage that counts and no line for k.
func (f *fileFloorLog) liveRefused(k floorKey) (bool, error) {
	var refused bool
	err := f.read(func(state *logState) {
		_, known := state.maxSeq[k]
		refused = state.tainted(k) || f.unrecovered(state) || (!known && f.unattributable(state))
	})
	return refused, err
}

// grantRefused reports whether a put's or a deliver's line for k is
// refused: k is tainted, or the floor holds unattributable damage that
// counts.
func (f *fileFloorLog) grantRefused(k floorKey) (bool, error) {
	var refused bool
	err := f.read(func(state *logState) {
		refused = state.tainted(k) || f.unattributable(state)
	})
	return refused, err
}

func (f *fileFloorLog) liveGens(scope, name string) ([][generationSize]byte, error) {
	var out [][generationSize]byte
	err := f.read(func(state *logState) {
		nk := nameKey{scope, name}
		first, ok := state.firstGen[nk]
		if !ok {
			return
		}
		for _, g := range append([][generationSize]byte{first}, state.moreGens[nk]...) {
			k := floorKey{scope, name, g}
			if _, live := state.maxSeq[k]; live && !state.buried[k] {
				out = append(out, g)
			}
		}
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b [generationSize]byte) int { return bytes.Compare(a[:], b[:]) })
	return out, nil
}

func (f *fileFloorLog) append(scope, name string, gen [generationSize]byte, seq uint64, revoke bool) error {
	line, err := floorLine(scope, name, gen, seq)
	if err != nil {
		return err
	}
	// A withdraw's line, the delivery record's in the revocation class, is
	// always written. Any other is refused for a tainted key, or while
	// unattributable damage counts: an entry's live line or a grant's
	// could stand where a skipped tombstone was.
	if name != deliveriesFloorName || !revoke {
		if refused, err := f.grantRefused(floorKey{scope, name, gen}); err != nil {
			return err
		} else if refused {
			return errFloorDegraded
		}
	}
	// Past the hard cap only a revocation's floor line draws on the uid's
	// revocation budget: any other line is refused there, and a grant checks
	// before its first write that its lines start below the cap
	// (floorGrantRoom). Every floor line follows its change's commit, as
	// its integrity record, so each is held only to the revocation slack:
	// the grant's free-space margin was judged before its first write.
	return f.log.appendLineSlack(scopeUID(scope), line, revoke, revoke, true)
}

func (f *fileFloorLog) bury(scope, name string, gen [generationSize]byte) error {
	return f.buryAll(scope, name, [][generationSize]byte{gen})
}

// buryAll appends the tombstones of scope, name and every one of gens, in
// that order, as one write (appendLines): they land whole or not at all,
// short of a crash. rm is in the revocation class: past the hard cap its
// tombstones draw on the uid's revocation budget, the free-space margin does
// not hold them, and the free space must also hold the rm's audit line,
// which follows them as one more append (maxAppendLine) held to
// revokeFreeSlack after the burial's block-rounded reservation.
func (f *fileFloorLog) buryAll(scope, name string, gens [][generationSize]byte) error {
	lines := make([][]byte, 0, len(gens))
	for _, g := range gens {
		line, err := tombLine(scope, name, g)
		if err != nil {
			return err
		}
		lines = append(lines, line)
	}
	return f.log.appendLines(scopeUID(scope), lines, true, true, true, maxAppendLine)
}

// floorLine encodes one floor line: "<scope> <name> <generation> <seq>
// <crc>\n", the generation in lowercase hex, seq in decimal and crc the
// line's checksum (floorCRC). It refuses a field the parser would refuse,
// so every line written reads back.
func floorLine(scope, name string, gen [generationSize]byte, seq uint64) ([]byte, error) {
	return encodeFloorLine(appendFloorCRC(fmt.Appendf(nil, "%s %s %x %d", scope, name, gen[:], seq)))
}

// tombLine encodes one tombstone line: "<scope> <name> <generation> rm
// <crc>\n". Only an entry name has one; the delivery record is never
// deleted.
func tombLine(scope, name string, gen [generationSize]byte) ([]byte, error) {
	return encodeFloorLine(appendFloorCRC(fmt.Appendf(nil, "%s %s %x %s", scope, name, gen[:], floorTombstone)))
}

// floorCRCTable is CRC-32C (Castagnoli), the floor line's checksum.
var floorCRCTable = crc32.MakeTable(crc32.Castagnoli)

// floorCRCLen is the checksum field's length: 8 lowercase hex digits.
const floorCRCLen = 8

// floorCRC is the checksum of body, a floor line's bytes before " <crc>".
func floorCRC(body []byte) uint32 { return crc32.Checksum(body, floorCRCTable) }

// appendFloorCRC is body with " <crc>" appended: the checksum field that
// makes every floor line self-delimiting, so a line torn or flipped in
// place never parses, and a closed tear never reads as a lower sequence.
func appendFloorCRC(body []byte) []byte {
	return fmt.Appendf(body, " %08x", floorCRC(body))
}

// splitFloorCRC splits line at its last space into the body and the
// checksum field, and reports whether that field is canonical (8 lowercase
// hex digits) and matches the body.
func splitFloorCRC(line []byte) (body []byte, canonical, match bool) {
	sp := bytes.LastIndexByte(line, ' ')
	if sp < 0 {
		return nil, false, false
	}
	body, sum := line[:sp], line[sp+1:]
	if len(sum) != floorCRCLen {
		return body, false, false
	}
	var v uint32
	for _, c := range sum {
		d := unhex(c)
		if d < 0 {
			return body, false, false
		}
		v = v<<4 | uint32(d)
	}
	return body, true, v == floorCRC(body)
}

// encodeFloorLine refuses b, a floor line without its newline, unless it
// parses, so every line written reads back, and returns it with its newline.
func encodeFloorLine(b []byte) ([]byte, error) {
	if _, err := parseFloorLine(b); err != nil {
		return nil, fmt.Errorf("encode a user-scope floor line: %w", err)
	}
	if len(b)+1 > maxLogLine {
		return nil, errLogLineTooLong
	}
	return append(b, '\n'), nil
}

// floorRec is one parsed floor line: a live line's key and seq, or a
// tombstone's key.
type floorRec struct {
	key  floorKey
	seq  uint64
	tomb bool
}

// parseFloorLine decodes one floor line without its newline, strictly: a
// user scope, an entry name or the delivery record's floor name, a
// generation of 32 lowercase hex digits, either a decimal seq with no sign
// or leading zero or, for an entry name only, the tombstone marker "rm",
// and the checksum of the bytes before it, 8 lowercase hex digits of
// CRC-32C; separated by single spaces. Anything else is an error: a line
// torn or flipped in place fails its checksum.
func parseFloorLine(line []byte) (floorRec, error) {
	if len(line)+1 > maxLogLine {
		return floorRec{}, errLogLineTooLong
	}
	body, canonical, match := splitFloorCRC(line)
	if !canonical {
		return floorRec{}, errors.New("a floor line has no checksum of 8 lowercase hex digits")
	}
	if !match {
		return floorRec{}, errors.New("a floor line's checksum does not match")
	}
	return parseFloorBody(body)
}

// parseFloorBody decodes a floor line's body, the bytes before " <crc>".
func parseFloorBody(line []byte) (floorRec, error) {
	var r floorRec
	f := bytes.Split(line, []byte{' '})
	if len(f) != 4 {
		return r, errors.New("a floor line has the wrong number of fields")
	}
	k := &r.key
	k.scope, k.name = string(f[0]), string(f[1])
	if scopeUID(k.scope) == 0 || userScopeOf(scopeUID(k.scope)) != k.scope {
		return floorRec{}, errors.New("a floor line's scope is not a user scope")
	}
	if k.name != deliveriesFloorName && checkName(k.name) != nil {
		return floorRec{}, errors.New("a floor line's name is not an entry name")
	}
	g := f[2]
	if len(g) != 2*generationSize {
		return floorRec{}, errors.New("a floor line's generation is not 32 hex digits")
	}
	for i := range generationSize {
		hi, lo := unhex(g[2*i]), unhex(g[2*i+1])
		if hi < 0 || lo < 0 {
			return floorRec{}, errors.New("a floor line's generation is not lowercase hex")
		}
		k.gen[i] = byte(hi<<4 | lo)
	}
	if string(f[3]) == floorTombstone {
		if k.name == deliveriesFloorName {
			return floorRec{}, errors.New("a floor tombstone names the delivery record, which is never deleted")
		}
		r.tomb = true
		return r, nil
	}
	seq, err := strconv.ParseUint(string(f[3]), 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != string(f[3]) {
		return floorRec{}, errors.New("a floor line's sequence is neither a canonical decimal number nor the tombstone marker")
	}
	r.seq = seq
	return r, nil
}

// unhex is the value of one lowercase hex digit, or -1.
func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return -1
}

// admit refuses, as ErrLogFull, a user-scope operation of uid's that
// would append past a log's hard cap (appendLog.room): any operation
// unless revoke, which marks one that revokes. Only the file-backed logs
// have caps.
func (s *FileStore) admit(uid uint32, revoke bool) error {
	for _, l := range []any{s.userFloor, s.auditSink} {
		var log *appendLog
		switch v := l.(type) {
		case *fileFloorLog:
			log = v.log
		case *fileAuditLog:
			log = v.log
		default:
			continue
		}
		if err := log.room(uid, revoke); err != nil {
			return err
		}
	}
	return nil
}

// floorGrantRoom refuses, before a grant's first write, a grant whose floor
// lines, one per name in names in the order it appends them, the floor
// would refuse after its commit: a line that would start at or past the
// hard cap (a grant's line draws on no revocation budget), lines that would
// take the floor past logReadBound, past its key bound or past the scope
// uid's key share (each counted as a new key), or lines that, with write
// more bytes the grant writes before them (its records), the free-space
// margin would not hold. The post-commit append is then held only to the
// revocation slack (fileFloorLog.append), so a grant committed without its
// floor line is left by a crash, an I/O error, or a volume filled past the
// margin and the slack both between this check and the append. Only the
// file-backed floor is held.
func (s *FileStore) floorGrantRoom(scope string, names []string, write int64) error {
	return s.floorGrantRoomKeys(scope, names, write, nil, func(st *logState) bool {
		for _, n := range names {
			if st.nameTainted(scope, n) {
				return true
			}
		}
		return false
	})
}

// floorDeliverRoom is floorGrantRoom for a deliver's one floor line, the
// delivery record's at gen: a new key only when the floor lacks it.
func (s *FileStore) floorDeliverRoom(scope string, gen [generationSize]byte) error {
	k := floorKey{scope, deliveriesFloorName, gen}
	return s.floorGrantRoomKeys(scope, []string{deliveriesFloorName}, 0, func(st *logState) int {
		if _, ok := st.maxSeq[k]; ok || st.buried[k] {
			return 0
		}
		return 1
	}, func(st *logState) bool { return st.tainted(k) })
}

// floorGrantRoomKeys is floorGrantRoom with newKeys, when set, counting the
// keys the lines add from what the floor holds; nil counts each line as a
// new key. tainted reports whether a line's key is tainted, which refuses
// the grant as errFloorDegraded, as unattributable damage that counts does.
func (s *FileStore) floorGrantRoomKeys(scope string, names []string, write int64, newKeys func(*logState) int, tainted func(*logState) bool) error {
	ff, ok := s.userFloor.(*fileFloorLog)
	if !ok {
		return nil
	}
	l := ff.log
	var lines [][]byte
	total := 0
	for _, n := range names {
		// Every generation is 16 bytes, so the line's length is the real one.
		line, err := floorLine(scope, n, [generationSize]byte{}, 1)
		if err != nil {
			return err
		}
		lines = append(lines, line)
		total += len(line)
	}
	f, st, err := l.open(unix.O_RDONLY)
	if err != nil {
		l.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = f.Close() }() // read-only
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil {
		return err
	}
	if state.bad != nil {
		return fmt.Errorf("%w (%v)", errFloorLogMalformed, state.bad)
	}
	if tainted(state) || ff.unattributable(state) {
		// The grant's floor line would be refused after its commit.
		return errFloorDegraded
	}
	// Each line is its own append, led by its newline (appendLines): the
	// line starts after it, and the free space must hold it.
	size := st.Size
	for _, line := range lines {
		size++
		total++
		if size >= s.logHardCap {
			return l.pastCap()
		}
		size += int64(len(line))
	}
	if size > s.logReadBound() {
		return l.pastCap()
	}
	n := len(lines)
	if newKeys != nil {
		n = newKeys(state)
	}
	if n > 0 {
		if err := l.addKeyRoom(state, scopeUID(scope), n, false); err != nil {
			return err
		}
	}
	return l.preflight(f, total+int(write), false)
}

// errLogBoundsBelowLog refuses, at store open, a configuration whose
// reader's bounds sit below what an existing log already holds: under it the
// log would read as damage and refuse every user-scope operation.
// errLogRevokeBudgetSpent is a configuration under which a uid's lines past
// the hard cap already exceed its revocation budget, which the writer never
// produces, so the caps were lowered: root-only, refused at store open.
var errLogRevokeBudgetSpent = errors.New("the configured log caps leave a uid's revocation budget already spent past the hard cap, so its revocations would be refused; configure the caps the log was written under, or restore the caps and rotate the audit log with sudo k3sm keys audit --rotate, then run sudo k3sm doctor")

var errLogBoundsBelowLog = errors.New("the configured log caps put the reader's bounds below what an existing append-only log already holds, so it would read as damage; configure the caps the log was written under, or " + restoreRemedy)

// CheckLogBounds refuses, as errInvalidConfig and errLogBoundsBelowLog, a
// configuration whose reader's bounds sit below what an existing log
// already holds: a log larger than logReadBound, or a floor with more keys
// than the reader's key bound; and, as errLogRevokeBudgetSpent, one under
// which a uid's lines past the hard cap in either log exceed its revocation
// budget, which the writer never produces, so only lowered caps make it. A
// uid with under one whole append (maxAppendLine) of its budget left is no
// refusal: the writer reaches it honestly, and only that uid's revocations
// are refused, at run time, as ever. Each such uid is logged at Warn and
// counted in spent (distinct uids across both logs). It fails closed: a
// file-backed log that is missing, untrusted or unflagged, one that cannot
// be read, or one whose state is damage that refuses it whole, is an error,
// so the start step (startUserScopes) does not start the user scope.
// Bounded damage, lines the reader skips, is no error: damage is their
// count across both logs. It is the server's store-open check, and its
// error, which names the current figures, is root's alone: it never
// reaches the socket.
func (s *FileStore) CheckLogBounds(ctx context.Context) (damage, spent int, err error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if err := s.checkConfig(); err != nil {
		return 0, 0, err
	}
	bound := s.logReadBound()
	spentUIDs := map[uint32]bool{}
	for _, l := range []any{s.userFloor, s.auditSink} {
		var log *appendLog
		switch v := l.(type) {
		case *fileFloorLog:
			log = v.log
		case *fileAuditLog:
			log = v.log
		default:
			continue
		}
		f, st, err := log.open(unix.O_RDONLY)
		if err != nil {
			log.forgetUnflagged(err, false)
			return 0, 0, err
		}
		n, err := func() (int, error) {
			defer func() { _ = f.Close() }() // read-only
			if st.Size > bound {
				return 0, fmt.Errorf("%w: %w (%s is %d bytes, over the reader's bound of %d)", errInvalidConfig, errLogBoundsBelowLog, log.name, st.Size, bound)
			}
			log.mu.Lock()
			defer log.mu.Unlock()
			state, err := log.sync(f, st)
			if err != nil {
				return 0, err
			}
			for uid, n := range state.pastCap {
				if uid == 0 {
					continue
				}
				if n > s.logRevokeBudget {
					return 0, fmt.Errorf("%w: %w (uid %d has %d bytes past the hard cap in %s, over its budget of %d)", errInvalidConfig, errLogRevokeBudgetSpent, uid, n, log.name, s.logRevokeBudget)
				}
				if n+maxAppendLine > s.logRevokeBudget {
					// Root's figures, in the server's log only.
					slog.Warn("a uid's revocation budget past the hard cap has under one line left; its revocations are refused until the audit log is rotated", "log", log.name, "uid", uid, "bytes", n, "budget", s.logRevokeBudget)
					spentUIDs[uid] = true
				}
			}
			if log.addsKey != nil {
				// A state read under a larger key bound is judged by its count.
				if errors.Is(state.bad, errFloorTooManyKeys) || state.keys > log.readKeyBound() {
					return 0, fmt.Errorf("%w: %w (%s holds more than the reader's key bound of %d keys)", errInvalidConfig, errLogBoundsBelowLog, log.name, log.readKeyBound())
				}
			}
			if state.bad != nil {
				return 0, fmt.Errorf("%s: %w", log.name, state.bad)
			}
			return state.damaged(), nil
		}()
		if err != nil {
			return 0, 0, err
		}
		damage += n
	}
	return damage, len(spentUIDs), nil
}
