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
	"io"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The user-scope floor and the audit log are append-only files in the data
// root (docs/design/keystore.md § "The user-scope floor", "The audit log"):
// keystore-user-floor.log and keystore-audit.log, each owned by the service
// user at mode 0600 with the BSD system append-only flag (SF_APPEND, which
// chflags spells sappnd) set by root at install. The K0 spike measured that
// flag on the rig's APFS data volume at kern.securelevel 0: the service user
// can append and cannot truncate, overwrite, rename, unlink or clear it. The
// store reaches each through an interface on FileStore, and New installs
// the file-backed ones below; tests may install in-memory fakes.
//
// Each file is opened per use through a descriptor on the data root, by
// openat with O_NOFOLLOW, and judged on its own descriptor: a regular file
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
	// userFloorLogName and auditLogName are the two logs' names in the data
	// root.
	userFloorLogName = "keystore-user-floor.log"
	auditLogName     = "keystore-audit.log"
	// maxLogLine bounds one line of either log, its newline included.
	maxLogLine = 1024
	// sfAppend is SF_APPEND, the system append-only file flag
	// (<sys/stat.h>): only root can clear it, and while it is set the file
	// can only be appended to.
	sfAppend = 0x00040000
	// logMode is both logs' mode.
	logMode = 0o600

	// The cap defaults (docs/design/keystore.md § "Size caps"), and the
	// per-uid revocation budget the revocation class draws on past the hard
	// cap (the socket margin of "Per-uid fairness").
	defaultLogSoftCap         = 64 << 20
	defaultLogHardCap         = 256 << 20
	defaultLogRevocationBytes = 64 << 10

	// The reader's bounds (docs/design/keystore.md § "Size caps"). A log
	// is read whole, and the service user can append to it without limit,
	// so a log larger than logReadBound is damage, and so is a floor with
	// more than keyBound distinct keys. The bound is the hard cap,
	// plus maxRevokeUIDs uids' revocation budgets past it, plus
	// logBoundMargin; the server never appends past either itself.
	maxRevokeUIDs  = 1024
	logBoundMargin = 1 << 20
	// maxFloorKeysCeiling is the absolute ceiling on the floor's key bound,
	// whatever the caps are configured to: what bounds the reader's memory.
	// At the default caps the size alone would allow about 7.3M keys. The
	// reader's worst case at this ceiling plus the revocation headroom
	// (278,528 keys), read from scratch on an M1 Ultra: 253-byte names and
	// the longest scope, about 128 MiB of heap and 0.41 s
	// (BenchmarkFloorReadLongNames); the most lines the size bound holds,
	// about 7.3M, about 69 MiB and 3.9 s (BenchmarkFloorReadLineCount). At
	// 1<<20 the long-name case held about 494 MiB, so the ceiling was
	// lowered to stay under 200 MiB (docs/design/keystore.md § "Size caps").
	maxFloorKeysCeiling = 1 << 18
	// maxKeyShareDivisor bounds one uid's floor keys: a grant line that adds
	// a key is refused once its scope's uid holds keyBound/maxKeyShareDivisor
	// keys (docs/design/keystore.md § "Per-uid fairness").
	maxKeyShareDivisor = 16
	// revokeHeadroomDivisor sizes the revocation headroom, keyBound /
	// revokeHeadroomDivisor keys past the key bound that only a revocation's
	// line (a tombstone or a catch-up line) may add; the reader's key bound
	// includes it.
	revokeHeadroomDivisor = 16
	// logFreeMargin is the free space an append leaves on the log's file
	// system beyond its own line.
	logFreeMargin = 1 << 20
	// revokeFreeSlack replaces logFreeMargin for a revocation's line: the
	// minimal check, so a nearly full volume still records a revocation.
	revokeFreeSlack = 4 << 10
)

// minFloorLine is the shortest line that adds a key to the floor: the
// lowest user scope, a one-byte name and sequence 1, 46 bytes.
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

// keyShare is the most keys one uid's grant lines may hold in the floor:
// keyBound/maxKeyShareDivisor. A revocation's line is never held to it.
func (l *appendLog) keyShare() int {
	if l.maxKeys != 0 {
		if l.maxShare != 0 {
			return l.maxShare
		}
		return l.maxKeys
	}
	return l.keyBound() / maxKeyShareDivisor
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

// ErrLogFull refuses an operation because an append-only log is past its
// hard cap, or, for a revocation past the hard cap, because the uid's
// revocation budget in that log is spent. Nothing was changed.
var ErrLogFull = errors.New("the keystore log is full: the user-scope floor or audit log is past its hard cap or the floor's key bound, so no user-scope change can be recorded; root must run sudo k3sm keys audit --rotate or sudo k3sm keys floor --rebuild; nothing was changed")

var (
	// errLogMissing is a log that does not exist: the data root has not been
	// through sudo k3sm install.
	errLogMissing = errors.New("the keystore append-only log is missing: sudo k3sm install creates it")
	// errLogNotAppendOnly is a log whose SF_APPEND flag is clear.
	errLogNotAppendOnly = errors.New("the keystore append-only log is not flagged append-only (SF_APPEND is clear), so it could be truncated or rewritten: a restore must end with sudo k3sm keys floor --rebuild and sudo k3sm keys audit --rotate")
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
	// errLogTorn is a last line with no newline: damage.
	errLogTorn = errors.New("the last line has no newline")
	// errLogTornTail refuses an append to the floor whose last byte is not a
	// newline: the line would complete the torn one into a line that does
	// not parse. Nothing was written; root must run sudo k3sm keys floor
	// --rebuild.
	errLogTornTail = errors.New("the keystore log's last line has no newline (a torn tail), so the line was not appended; root must run sudo k3sm keys floor --rebuild")
	// errLogLineTooLong is a line over maxLogLine, which is never written.
	errLogLineTooLong = fmt.Errorf("a keystore log line is at most %d bytes", maxLogLine)
	// errFloorLogMalformed is a user-scope floor whose bytes do not parse:
	// damage, which refuses every user-scope operation that reads the floor,
	// revocations included, until root rebuilds it.
	errFloorLogMalformed = fmt.Errorf("%w: the user-scope floor %s does not parse; root must run sudo k3sm keys floor --rebuild", ErrCorrupt, userFloorLogName)
	// errLogUnreadable is a log whose bytes could not be read: an I/O
	// error, transient and never damage. It is never kept, matches no
	// ErrCorrupt, and so refuses a grant or read and lets a revocation go
	// ahead.
	errLogUnreadable = errors.New("the keystore append-only log could not be read")
	// errFloorBuried is a generation the user-scope floor holds a tombstone
	// for: rm deleted it. A reader turns it into userDeletedError.
	errFloorBuried = errors.New("the user-scope floor buries this generation: the entry was deleted")
)

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
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return LogSizes{}, err
	}
	defer func() { _ = unix.Close(dfd) }() // read-only
	out := LogSizes{SoftCap: s.logSoftCap, HardCap: s.logHardCap}
	for _, l := range []struct {
		name string
		size *int64
	}{{userFloorLogName, &out.UserFloor}, {auditLogName, &out.Audit}} {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, l.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return LogSizes{}, fmt.Errorf("%s: %w", l.name, err)
		}
		*l.size = st.Size
	}
	return out, nil
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
}

// logState is what has been read of one file.
type logState struct {
	dev, ino uint64
	birth    unix.Timespec
	// hardCap and bound are the hard cap and logReadBound it was read
	// under.
	hardCap, bound int64
	// keys is the floor's count of distinct keys, and uidKeys that count
	// per uid, each key charged to its scope's uid.
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
	// bad is the error of a line that did not parse, which sticks for this
	// file.
	bad error
	// badAt is the byte offset bad was met at: root's, never in an error a
	// socket caller can see.
	badAt int64
	// tornSize, when not 0, is the size of the file whose last line had no
	// newline: bad then holds only for that size, since an append completes
	// the line, and reading resumes at off, the torn line's start.
	tornSize int64
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
		return -1, fmt.Errorf("open the data root %s: %w", s.dataRoot, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(dfd, &st); err != nil {
		_ = unix.Close(dfd) // abandoned
		return -1, fmt.Errorf("stat the data root %s: %w", s.dataRoot, err)
	}
	if int64(st.Uid) != int64(s.floorUID) || st.Mode&0o022 != 0 {
		_ = unix.Close(dfd) // abandoned
		return -1, fmt.Errorf("%w: the data root %s is owned by uid %d at mode %04o", errLogUntrusted, s.dataRoot, st.Uid, st.Mode&0o7777)
	}
	if err := judgeFlagsACL(dfd, fdFlags); err != nil {
		_ = unix.Close(dfd) // abandoned
		return -1, fmt.Errorf("the data root %s: %w", s.dataRoot, err)
	}
	return dfd, nil
}

// open opens the log with flag (O_RDONLY, or O_WRONLY|O_APPEND) through
// the data root, never following a symlink, and judges it on the
// descriptor. It returns the file and its stat.
func (l *appendLog) open(flag int) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	dfd, err := l.s.openLogDataRoot()
	if err != nil {
		return nil, st, err
	}
	defer func() { _ = unix.Close(dfd) }() // the file is opened; the directory is done with
	// O_NONBLOCK, so a FIFO planted at the name is opened, and refused on
	// its descriptor, rather than blocking the open.
	fd, err := unix.Openat(dfd, l.name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, st, fmt.Errorf("%w: %s: %w", errLogMissing, l.name, fs.ErrNotExist)
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
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: not a regular file", errLogUntrusted)
	case st.Nlink != 1:
		return fmt.Errorf("%w: %d links", errLogUntrusted, st.Nlink)
	case st.Uid != s.uid:
		return fmt.Errorf("%w: owned by uid %d, want the service user's %d", errLogUntrusted, st.Uid, s.uid)
	case st.Mode&0o7777 != logMode:
		return fmt.Errorf("%w: mode %04o, want %04o", errLogUntrusted, st.Mode&0o7777, logMode)
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
		return fmt.Errorf("%w: flags %#x beside SF_APPEND", errLogUntrusted, extra)
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
// l.mu, and returns the state. A line that does not parse is state.bad,
// which sticks; a last line with no newline is state.bad only while the
// file keeps its size; a read I/O error is errLogUnreadable, returned and
// not kept, and reading resumes past the last whole line read.
func (l *appendLog) sync(f *os.File, st unix.Stat_t) (*logState, error) {
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
			return nil, fmt.Errorf("%w: %s at byte %d: %w", errLogUnreadable, l.name, s.lastAt, err)
		}
		// A short read is a file that no longer holds the line.
		if !bytes.Equal(got[:n], s.last) {
			fresh()
		}
	}
	if s.tornSize != 0 && st.Size != s.tornSize {
		// The torn line has been appended to: read it again.
		s.bad, s.tornSize = nil, 0
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
				s.bad, s.tornSize = s.at(off, errLogTorn), st.Size
				return s, nil
			}
			return nil, fmt.Errorf("%w: %s at byte %d: %w", errLogUnreadable, l.name, off, err)
		}
	}
	for off < st.Size {
		line, err := readLogLine(r)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil && !errors.Is(err, errLogLineTooLong) && !errors.Is(err, errLogTorn) {
			s.off = off
			return nil, fmt.Errorf("%w: %s at byte %d: %w", errLogUnreadable, l.name, off, err)
		}
		if errors.Is(err, errLogTorn) {
			s.off, s.bad, s.tornSize = off, s.at(off, err), st.Size
			return s, nil
		}
		if errors.Is(err, errLogLineTooLong) && !l.whole {
			// The tolerant audit reader drops an over-long line, charged to
			// no uid, as it drops any line it cannot read; only the floor
			// is strict. It is read through to its newline.
			n, serr := skipRestOfLine(r, line)
			switch {
			case errors.Is(serr, io.EOF):
				s.off, s.bad, s.tornSize = off, s.at(off, errLogTorn), st.Size
				return s, nil
			case serr != nil:
				s.off = off
				return nil, fmt.Errorf("%w: %s at byte %d: %w", errLogUnreadable, l.name, off, serr)
			}
			off += n
			continue
		}
		if err != nil {
			s.bad = s.at(off, err)
			return s, nil
		}
		uid, perr := l.lineUID(s, line[:len(line)-1])
		if perr != nil {
			s.bad = s.at(off, perr)
			return s, nil
		}
		if off >= s.hardCap && uid != 0 {
			s.pastCap[uid] += int64(len(line))
		}
		s.lastAt, s.last = off, line
		off += int64(len(line))
	}
	s.off = off
	return s, nil
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
			return nil, errLogTorn
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
		return fmt.Errorf("%w (%s is past its hard cap)", ErrLogFull, l.name)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		return nil
	}
	// The line is not written yet: room charges the longest a line can
	// be, through the predicate appendLine charges the real line through.
	return l.revokeRoom(state, st.Size, uid, maxLogLine)
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
		return fmt.Errorf("%w (%s is at its key bound)", ErrLogFull, l.name)
	}
	return nil
}

// addKeyRoom refuses, as ErrLogFull, n more keys charged to uid: for a
// revocation's line (revoke) past keyBound plus the revocation headroom; for
// any other line past keyBound, or past uid's key share. appendLine and
// floorGrantRoom both judge through it. The texts name the bound met, never
// a figure.
func (l *appendLog) addKeyRoom(state *logState, uid uint32, n int, revoke bool) error {
	if revoke {
		if state.keys+n > l.readKeyBound() {
			return fmt.Errorf("%w (%s is at its key bound and revocation headroom)", ErrLogFull, l.name)
		}
		return nil
	}
	if state.keys+n > l.keyBound() {
		return fmt.Errorf("%w (%s is at its key bound)", ErrLogFull, l.name)
	}
	if state.uidKeys[uid]+n > l.keyShare() {
		return fmt.Errorf("%w (the caller's share of the key bound in %s is spent)", ErrLogFull, l.name)
	}
	return nil
}

// revokeRoom refuses, as ErrLogFull, n more bytes for uid past the hard
// cap: when they would take the log past logReadBound, or uid's lines that
// start past the hard cap past its revocation budget. room and appendLine
// both judge through it.
func (l *appendLog) revokeRoom(state *logState, size int64, uid uint32, n int64) error {
	if size+n > l.s.logReadBound() {
		return fmt.Errorf("%w (%s is at the reader's bound)", ErrLogFull, l.name)
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
// free-space margin. It never
// writes what the reader would refuse: a line past logReadBound, a floor
// line that adds a key past the key bound, or a floor line after a torn
// tail, which it would merge with. After a torn tail in the audit log it
// writes a newline first, so the torn bytes read as a line of their own,
// which the tolerant audit reader drops, and line reads back whole.
func (l *appendLog) appendLine(uid uint32, line []byte, budget, revoke bool) error {
	return l.appendLineSlack(uid, line, budget, revoke, revoke)
}

// appendLineSlack is appendLine with the free-space check apart from the
// class: slack holds the line to revokeFreeSlack, as a committed change's
// floor line is, whatever its class.
func (l *appendLog) appendLineSlack(uid uint32, line []byte, budget, revoke, slack bool) error {
	if len(line) > maxLogLine {
		return fmt.Errorf("%w: refused a %d-byte line for %s", errLogLineTooLong, len(line), l.name)
	}
	// Read-write, so the tail and, for the floor, the keys are read on the
	// descriptor the line is appended through.
	f, st, err := l.open(unix.O_RDWR | unix.O_APPEND)
	if err != nil {
		l.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = f.Close() }() // each append is fsynced below
	l.mu.Lock()
	defer l.mu.Unlock()
	torn, err := l.tornTail(f, st.Size)
	if err != nil {
		return err
	}
	out := line
	if torn {
		if l.addsKey != nil {
			return fmt.Errorf("%w (%s)", errLogTornTail, l.name)
		}
		out = append([]byte{'\n'}, line...)
	}
	if bound := l.s.logReadBound(); st.Size+int64(len(out)) > bound {
		// Never make the damage the reader refuses.
		return fmt.Errorf("%w (%s is at the reader's bound)", ErrLogFull, l.name)
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
		// The torn verdict is the tail the newline above closes.
		if state.bad != nil && !(torn && state.tornSize == st.Size) {
			return fmt.Errorf("%s: %w", l.name, state.bad)
		}
		return nil
	}
	if st.Size >= l.s.logHardCap {
		if !budget || uid == 0 {
			return fmt.Errorf("%w (%s is past its hard cap)", ErrLogFull, l.name)
		}
		if err := read(); err != nil {
			return err
		}
		// The newline closing a torn tail ends the torn line, which is
		// charged to no uid; line is uid's.
		if err := l.revokeRoom(state, st.Size+int64(len(out)-len(line)), uid, int64(len(line))); err != nil {
			return err
		}
	}
	if l.addsKey != nil {
		if err := read(); err != nil {
			return err
		}
		adds, err := l.addsKey(state, line)
		if err != nil {
			return fmt.Errorf("%s: %w", l.name, err)
		}
		if adds {
			if err := l.addKeyRoom(state, uid, 1, revoke); err != nil {
				return err
			}
		}
	}
	if err := l.preflight(f, len(out), slack); err != nil {
		return err
	}
	// One write(2) of the whole line. An ENOSPC or EIO between the
	// preflight and the write, or a crash mid-write, can still leave a
	// torn tail the flag keeps: damage in the floor, which floor --rebuild
	// repairs (docs/design/keystore.md § "The user-scope floor"), and a
	// dropped line in the audit log once the next append closes it.
	_, err = f.Write(out)
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return fmt.Errorf("append to %s: %w", l.name, err)
	}
	return nil
}

// tornTail reports whether f, size bytes long, is non-empty and its last
// byte is not a newline, read by pread on f's descriptor.
func (l *appendLog) tornTail(f *os.File, size int64) (bool, error) {
	if size == 0 {
		return false, nil
	}
	var b [1]byte
	var src io.ReaderAt = f
	if l.readAt != nil {
		src = l.readAt(f)
	}
	if _, err := src.ReadAt(b[:], size-1); err != nil {
		return false, fmt.Errorf("%w: %s at byte %d: %w", errLogUnreadable, l.name, size-1, err)
	}
	return b[0] != '\n', nil
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
// under the log's lock. A floor that does not parse is
// errFloorLogMalformed.
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
		slog.Debug("the user-scope floor does not parse", "log", f.log.name, "offset", state.badAt, "err", state.bad)
		return fmt.Errorf("%w (%v)", errFloorLogMalformed, state.bad)
	}
	fn(state)
	return nil
}

func (f *fileFloorLog) check() error { return f.read(func(*logState) {}) }

func (f *fileFloorLog) floor(scope, name string, gen [generationSize]byte) (uint64, error) {
	var (
		seq    uint64
		buried bool
	)
	k := floorKey{scope, name, gen}
	if err := f.read(func(state *logState) { seq, buried = state.maxSeq[k], state.buried[k] }); err != nil {
		return 0, err
	}
	if buried {
		return 0, errFloorBuried
	}
	return seq, nil
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
	// Past the hard cap only a revocation's floor line draws on the uid's
	// revocation budget: any other line is refused there, and a grant checks
	// before its first write that its lines start below the cap
	// (floorGrantRoom). Every floor line follows its change's commit, as
	// its integrity record, so each is held only to the revocation slack:
	// the grant's free-space margin was judged before its first write.
	return f.log.appendLineSlack(scopeUID(scope), line, revoke, revoke, true)
}

func (f *fileFloorLog) bury(scope, name string, gen [generationSize]byte) error {
	line, err := tombLine(scope, name, gen)
	if err != nil {
		return err
	}
	// rm is in the revocation class: past the hard cap its tombstone draws
	// on the uid's revocation budget, and the free-space margin does not
	// hold it.
	return f.log.appendLine(scopeUID(scope), line, true, true)
}

// floorLine encodes one floor line: "<scope> <name> <generation> <seq>\n",
// the generation in lowercase hex and seq in decimal. It refuses a field
// the parser would refuse, so every line written reads back.
func floorLine(scope, name string, gen [generationSize]byte, seq uint64) ([]byte, error) {
	return encodeFloorLine(fmt.Appendf(nil, "%s %s %x %d", scope, name, gen[:], seq))
}

// tombLine encodes one tombstone line: "<scope> <name> <generation> rm\n".
// Only an entry name has one; the delivery record is never deleted.
func tombLine(scope, name string, gen [generationSize]byte) ([]byte, error) {
	return encodeFloorLine(fmt.Appendf(nil, "%s %s %x %s", scope, name, gen[:], floorTombstone))
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
// generation of 32 lowercase hex digits, and either a decimal seq with no
// sign or leading zero or, for an entry name only, the tombstone marker
// "rm"; separated by single spaces. Anything else is an error.
func parseFloorLine(line []byte) (floorRec, error) {
	var r floorRec
	if len(line)+1 > maxLogLine {
		return r, errLogLineTooLong
	}
	f := bytes.Split(line, []byte{' '})
	if len(f) != 4 {
		return r, fmt.Errorf("a floor line has %d fields, want 4", len(f))
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
	return s.floorGrantRoomKeys(scope, names, write, nil)
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
	})
}

// floorGrantRoomKeys is floorGrantRoom with newKeys, when set, counting the
// keys the lines add from what the floor holds; nil counts each line as a
// new key.
func (s *FileStore) floorGrantRoomKeys(scope string, names []string, write int64, newKeys func(*logState) int) error {
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
	size := st.Size
	for _, line := range lines {
		if size >= s.logHardCap {
			return fmt.Errorf("%w (%s would be past its hard cap before the put's last floor line)", ErrLogFull, l.name)
		}
		size += int64(len(line))
	}
	if size > s.logReadBound() {
		return fmt.Errorf("%w (%s would pass the reader's bound)", ErrLogFull, l.name)
	}
	n := len(lines)
	if newKeys != nil {
		n = newKeys(state)
	}
	if err := l.addKeyRoom(state, scopeUID(scope), n, false); err != nil {
		return err
	}
	return l.preflight(f, total+int(write), false)
}

// errLogBoundsBelowLog refuses, at store open, a configuration whose
// reader's bounds sit below what an existing log already holds: under it the
// log would read as damage and refuse every user-scope operation.
var errLogBoundsBelowLog = errors.New("the configured log caps put the reader's bounds below what an existing append-only log already holds, so it would read as damage; raise the caps back, or run sudo k3sm keys floor --rebuild or sudo k3sm keys audit --rotate")

// CheckLogBounds refuses, as errInvalidConfig and errLogBoundsBelowLog, a
// configuration whose reader's bounds sit below what an existing log
// already holds: a log larger than logReadBound, or a floor with more keys
// than the reader's key bound. It is the server's store-open check, and its
// error, which names the current figures, is root's alone: it never reaches
// the socket. A log that does not open is left to each operation's own
// judgement.
func (s *FileStore) CheckLogBounds(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.checkConfig(); err != nil {
		return err
	}
	bound := s.logReadBound()
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
			continue
		}
		err = func() error {
			defer func() { _ = f.Close() }() // read-only
			if st.Size > bound {
				return fmt.Errorf("%w: %w (%s is %d bytes, over the reader's bound of %d)", errInvalidConfig, errLogBoundsBelowLog, log.name, st.Size, bound)
			}
			if log.addsKey == nil {
				return nil
			}
			log.mu.Lock()
			defer log.mu.Unlock()
			state, err := log.sync(f, st)
			if err != nil {
				return nil
			}
			// A state read under a larger key bound is judged by its count.
			if errors.Is(state.bad, errFloorTooManyKeys) || state.keys > log.readKeyBound() {
				return fmt.Errorf("%w: %w (%s holds more than the reader's key bound of %d keys)", errInvalidConfig, errLogBoundsBelowLog, log.name, log.readKeyBound())
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
