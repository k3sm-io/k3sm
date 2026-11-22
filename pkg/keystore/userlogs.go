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
	"os"
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
)

// ErrLogFull refuses an operation because an append-only log is past its
// hard cap, or, for a revocation past the hard cap, because the uid's
// revocation budget in that log is spent. Nothing was changed.
var ErrLogFull = errors.New("the keystore log is full: the user-scope floor or audit log is past its hard cap, so no user-scope change can be recorded; root must run sudo k3sm keys audit --rotate or sudo k3sm keys floor --rebuild; nothing was changed")

var (
	// errLogMissing is a log that does not exist: the data root has not been
	// through sudo k3sm install.
	errLogMissing = errors.New("the keystore append-only log is missing: sudo k3sm install creates it")
	// errLogNotAppendOnly is a log whose SF_APPEND flag is clear.
	errLogNotAppendOnly = errors.New("the keystore append-only log is not flagged append-only (SF_APPEND is clear), so it could be truncated or rewritten: a restore must end with sudo k3sm keys floor --rebuild and sudo k3sm keys audit --rotate")
	// errLogUntrusted is a log, or the data root holding it, that is not
	// what install makes.
	errLogUntrusted = errors.New("the keystore append-only log is not trusted: it must be a regular file with one link, owned by the service user, mode 0600, in a data root owned by root and not group- or other-writable")
	// errLogLineTooLong is a line over maxLogLine, which is never written.
	errLogLineTooLong = fmt.Errorf("a keystore log line is at most %d bytes", maxLogLine)
	// errFloorLogMalformed is a user-scope floor whose bytes do not parse:
	// damage, which refuses every user-scope operation that reads the floor,
	// revocations included, until root rebuilds it.
	errFloorLogMalformed = fmt.Errorf("%w: the user-scope floor %s does not parse; root must run sudo k3sm keys floor --rebuild", ErrCorrupt, userFloorLogName)
)

// userFloorLog is the user-scope floor: (scope, name, generation, seq)
// lines, of which a reader takes, per (scope, name), the highest seq among
// the lines of a generation, so the floor only rises.
type userFloorLog interface {
	// floor returns the highest seq recorded for scope, name and gen, or 0
	// when none is.
	floor(scope, name string, gen [generationSize]byte) (uint64, error)
	// append records one line.
	append(scope, name string, gen [generationSize]byte, seq uint64) error
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
// highest seq per key. What was read is kept for one file (dev, ino) and is
// read on from where it stopped; a different file, or a shorter one, is
// read again from the start.
type appendLog struct {
	s    *FileStore
	name string
	// lineUID parses one line, without its newline, and returns the uid it
	// is charged to (0 for none). For the floor it also records the line.
	lineUID func(st *logState, line []byte) (uint32, error)
	// whole reports whether every line must be read (the floor), or only
	// those past the hard cap (the audit log).
	whole bool

	// mu guards state: reads under the shared store lock run together.
	mu    sync.Mutex
	state logState
}

// logState is what has been read of one file.
type logState struct {
	dev, ino uint64
	hardCap  int64
	// off is where reading stopped: just past the last whole line read.
	off int64
	// pastCap is each uid's bytes in lines that start at or past hardCap.
	pastCap map[uint32]int64
	// maxSeq is the floor's highest seq per key.
	maxSeq map[floorKey]uint64
	// bad is the error of a line that did not parse, which sticks for this
	// file.
	bad error
}

// floorKey is one floor line's key.
type floorKey struct {
	scope, name string
	gen         [generationSize]byte
}

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
	fd, err := unix.Openat(dfd, l.name, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
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
	return nil
}

// sync reads f (which st describes) on from where reading stopped, under
// l.mu, and returns the state. A line that does not parse is state.bad.
func (l *appendLog) sync(f *os.File, st unix.Stat_t) (*logState, error) {
	s := &l.state
	if s.dev != uint64(st.Dev) || s.ino != st.Ino || s.hardCap != l.s.logHardCap || st.Size < s.off {
		*s = logState{dev: uint64(st.Dev), ino: st.Ino, hardCap: l.s.logHardCap, pastCap: map[uint32]int64{}, maxSeq: map[floorKey]uint64{}}
	}
	if s.bad != nil || st.Size == s.off {
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
	r := bufio.NewReaderSize(io.NewSectionReader(f, start, st.Size-start), 64<<10)
	off := start
	if !l.whole && s.off < s.hardCap {
		skipped, err := r.ReadSlice('\n')
		if err != nil {
			// No newline yet past the cap: a line straddles it, and nothing
			// starts past it.
			return s, nil
		}
		off += int64(len(skipped))
	}
	for off < st.Size {
		line, err := readLogLine(r)
		if errors.Is(err, io.EOF) && len(line) == 0 {
			break
		}
		if err != nil {
			s.bad = fmt.Errorf("at byte %d: %w", off, err)
			return s, nil
		}
		uid, perr := l.lineUID(s, line[:len(line)-1])
		if perr != nil {
			s.bad = fmt.Errorf("at byte %d: %w", off, perr)
			return s, nil
		}
		if off >= s.hardCap && uid != 0 {
			s.pastCap[uid] += int64(len(line))
		}
		off += int64(len(line))
	}
	s.off = off
	return s, nil
}

// readLogLine reads one whole line, its newline included, of at most
// maxLogLine bytes. A last line with no newline is an error, as is a
// longer one.
func readLogLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLogLine {
			return nil, errLogLineTooLong
		}
		switch {
		case err == nil:
			return line, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return nil, errors.New("the last line has no newline")
		default:
			return line, err
		}
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
		return nil
	}
	defer func() { _ = f.Close() }() // read-only
	if st.Size < l.s.logHardCap {
		return nil
	}
	if !revoke {
		return fmt.Errorf("%w (%s is %d bytes, its hard cap %d)", ErrLogFull, l.name, st.Size, l.s.logHardCap)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil || state.bad != nil {
		return nil
	}
	if state.pastCap[uid]+maxLogLine > l.s.logRevokeBudget {
		return fmt.Errorf("%w (uid %d has spent its %d-byte revocation budget in %s)", ErrLogFull, uid, l.s.logRevokeBudget, l.name)
	}
	return nil
}

// appendLine appends line, which ends in a newline, charged to uid. Past
// the hard cap only a line that may draw on uid's revocation budget
// (budget) is written, and only while the budget has room for it.
func (l *appendLog) appendLine(uid uint32, line []byte, budget bool) error {
	if len(line) > maxLogLine {
		return fmt.Errorf("%w: refused a %d-byte line for %s", errLogLineTooLong, len(line), l.name)
	}
	f, st, err := l.open(unix.O_WRONLY | unix.O_APPEND)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // each append is fsynced below
	l.mu.Lock()
	defer l.mu.Unlock()
	if st.Size >= l.s.logHardCap {
		if !budget || uid == 0 {
			return fmt.Errorf("%w (%s is %d bytes, its hard cap %d)", ErrLogFull, l.name, st.Size, l.s.logHardCap)
		}
		r, rst, err := l.open(unix.O_RDONLY)
		if err != nil {
			return err
		}
		defer func() { _ = r.Close() }() // read-only
		if rst.Dev != st.Dev || rst.Ino != st.Ino {
			return fmt.Errorf("%s changed while it was opened", l.name)
		}
		state, err := l.sync(r, rst)
		if err != nil {
			return err
		}
		if state.bad != nil {
			return fmt.Errorf("%s: %w", l.name, state.bad)
		}
		if state.pastCap[uid]+int64(len(line)) > l.s.logRevokeBudget {
			return fmt.Errorf("%w (uid %d has spent its %d-byte revocation budget in %s)", ErrLogFull, uid, l.s.logRevokeBudget, l.name)
		}
	}
	n, err := f.Write(line)
	if err == nil && n != len(line) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if err != nil {
		return fmt.Errorf("append to %s: %w", l.name, err)
	}
	return nil
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
		k, seq, err := parseFloorLine(line)
		if err != nil {
			return 0, err
		}
		if seq > st.maxSeq[k] {
			st.maxSeq[k] = seq
		}
		return scopeUID(k.scope), nil
	}
	return &fileFloorLog{log: l}
}

func (f *fileFloorLog) floor(scope, name string, gen [generationSize]byte) (uint64, error) {
	file, st, err := f.log.open(unix.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }() // read-only
	f.log.mu.Lock()
	defer f.log.mu.Unlock()
	state, err := f.log.sync(file, st)
	if err != nil {
		return 0, err
	}
	if state.bad != nil {
		return 0, fmt.Errorf("%w (%v)", errFloorLogMalformed, state.bad)
	}
	return state.maxSeq[floorKey{scope, name, gen}], nil
}

func (f *fileFloorLog) append(scope, name string, gen [generationSize]byte, seq uint64) error {
	line, err := floorLine(scope, name, gen, seq)
	if err != nil {
		return err
	}
	// Past the hard cap only a revocation's floor line, or the last line of
	// an operation admitted below it, is reached: every other operation was
	// refused before its first write (FileStore.admit).
	return f.log.appendLine(scopeUID(scope), line, true)
}

// floorLine encodes one floor line: "<scope> <name> <generation> <seq>\n",
// the generation in lowercase hex and seq in decimal. It refuses a field
// the parser would refuse, so every line written reads back.
func floorLine(scope, name string, gen [generationSize]byte, seq uint64) ([]byte, error) {
	b := fmt.Appendf(nil, "%s %s %x %d", scope, name, gen[:], seq)
	if _, _, err := parseFloorLine(b); err != nil {
		return nil, fmt.Errorf("encode a user-scope floor line: %w", err)
	}
	if len(b)+1 > maxLogLine {
		return nil, errLogLineTooLong
	}
	return append(b, '\n'), nil
}

// parseFloorLine decodes one floor line without its newline, strictly: a
// user scope, an entry name or the delivery record's floor name, a
// generation of 32 lowercase hex digits and a decimal seq with no sign or
// leading zero, separated by single spaces. Anything else is an error.
func parseFloorLine(line []byte) (floorKey, uint64, error) {
	var k floorKey
	if len(line)+1 > maxLogLine {
		return k, 0, errLogLineTooLong
	}
	f := bytes.Split(line, []byte{' '})
	if len(f) != 4 {
		return k, 0, fmt.Errorf("a floor line has %d fields, want 4", len(f))
	}
	k.scope, k.name = string(f[0]), string(f[1])
	if scopeUID(k.scope) == 0 || userScopeOf(scopeUID(k.scope)) != k.scope {
		return k, 0, errors.New("a floor line's scope is not a user scope")
	}
	if k.name != deliveriesFloorName && checkName(k.name) != nil {
		return k, 0, errors.New("a floor line's name is not an entry name")
	}
	g := f[2]
	if len(g) != 2*generationSize {
		return k, 0, errors.New("a floor line's generation is not 32 hex digits")
	}
	for i := range generationSize {
		hi, lo := unhex(g[2*i]), unhex(g[2*i+1])
		if hi < 0 || lo < 0 {
			return k, 0, errors.New("a floor line's generation is not lowercase hex")
		}
		k.gen[i] = byte(hi<<4 | lo)
	}
	seq, err := strconv.ParseUint(string(f[3]), 10, 64)
	if err != nil || strconv.FormatUint(seq, 10) != string(f[3]) {
		return k, 0, errors.New("a floor line's sequence is not a canonical decimal number")
	}
	return k, seq, nil
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
