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
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// The floor's damage acknowledgement (docs/design/keystore.md § "The
// user-scope floor", "Damage and taint"): keystore-user-floor.ack in the
// data root, root's, judged as keystore-floor.json is (owned by root, not
// group- or other-writable) and also a regular file with one link, no file
// flag and no extended ACL. It is one line,
//
//	k3sm-user-floor-ack v1 <ino> <birth-sec> <birth-nsec> <watermark>\n
//
// in canonical decimal: the floor file's inode and birth time when root
// acknowledged its damage, and the floor's size then. For that file,
// unattributable damage that starts before the watermark no longer counts,
// so the floor-wide rule and the start step's quarantine it caused are
// lifted. A taint is never lifted: a key a damaged line could name stays
// refused, so a torn tombstone stays in force. Damage at or past the
// watermark counts again, and an acknowledgement for another file (a
// different inode or birth time) is ignored. The audit log's damage gates
// nothing (it is counted and logged, never refused on), so it has no
// acknowledgement.

const (
	// floorAckName is the acknowledgement's name in the data root.
	floorAckName = "keystore-user-floor.ack"
	// floorAckTag is its first field.
	floorAckTag = "k3sm-user-floor-ack v1"
	// maxFloorAckSize bounds what is read of it.
	maxFloorAckSize = 128
)

// floorAck is one parsed acknowledgement.
type floorAck struct {
	ino       uint64
	birth     unix.Timespec
	watermark int64
}

// encode is the acknowledgement's one line.
func (a floorAck) encode() []byte {
	return fmt.Appendf(nil, "%s %d %d %d %d\n", floorAckTag, a.ino, a.birth.Sec, a.birth.Nsec, a.watermark)
}

// parseFloorAck decodes b strictly: the tag, then exactly four fixed
// fields of canonical decimal, each after one space, and a newline. Every
// field is unsigned, so a sign, a negative, a leading zero or an empty
// field is refused, as is a nanosecond count of a second or more.
func parseFloorAck(b []byte) (floorAck, error) {
	rest, ok := bytes.CutPrefix(b, []byte(floorAckTag+" "))
	if !ok {
		return floorAck{}, errors.New("the floor acknowledgement does not parse: its tag is wrong")
	}
	rest, ok = bytes.CutSuffix(rest, []byte{'\n'})
	if !ok {
		return floorAck{}, errors.New("the floor acknowledgement does not parse: it does not end in a newline")
	}
	fields := bytes.Split(rest, []byte{' '})
	if len(fields) != 4 {
		return floorAck{}, errors.New("the floor acknowledgement does not parse: it does not hold four fields")
	}
	var v [4]uint64
	for i, f := range fields {
		bits := 63 // the signed fields' non-negative range
		if i == 0 {
			bits = 64 // the inode
		}
		n, err := canonicalDecimal(f, bits)
		if err != nil {
			return floorAck{}, fmt.Errorf("the floor acknowledgement does not parse: %w", err)
		}
		v[i] = n
	}
	if v[2] >= 1e9 {
		return floorAck{}, errors.New("the floor acknowledgement does not parse: its nanoseconds are a second or more")
	}
	return floorAck{ino: v[0], birth: unix.Timespec{Sec: int64(v[1]), Nsec: int64(v[2])}, watermark: int64(v[3])}, nil
}

// canonicalDecimal parses f as unsigned decimal of at most bits bits, in
// its canonical form: digits only, and no leading zero but "0" itself.
func canonicalDecimal(f []byte, bits int) (uint64, error) {
	if len(f) == 0 || (f[0] == '0' && len(f) > 1) {
		return 0, errors.New("a field is not canonical decimal")
	}
	for _, c := range f {
		if c < '0' || c > '9' {
			return 0, errors.New("a field is not canonical decimal")
		}
	}
	n, err := strconv.ParseUint(string(f), 10, bits)
	if err != nil {
		return 0, errors.New("a field is out of range")
	}
	return n, nil
}

// readFloorAck reads and judges the acknowledgement. ok is false for none,
// or for one that is not trusted or does not parse, which is ignored: an
// acknowledgement only ever lifts a refusal, so ignoring one fails closed.
func (s *FileStore) readFloorAck() (floorAck, bool) {
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return floorAck{}, false
	}
	defer func() { _ = unix.Close(dfd) }() // read-only
	fd, err := unix.Openat(dfd, floorAckName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return floorAck{}, false
	}
	f := os.NewFile(uintptr(fd), floorAckName)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return floorAck{}, false
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o022 != 0 {
		return floorAck{}, false
	}
	if fl, err := fdFlags(fd); err != nil || fl != 0 || judgeFlagsACL(fd, fdFlags) != nil {
		return floorAck{}, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFloorAckSize+1))
	if err != nil || len(b) > maxFloorAckSize {
		return floorAck{}, false
	}
	a, err := parseFloorAck(b)
	if err != nil {
		return floorAck{}, false
	}
	return a, true
}

// errAckNotRoot refuses ackFloorDamage for a caller that is not root.
var errAckNotRoot = errors.New("acknowledging the user-scope floor's damage is root maintenance")

// errAckStale refuses ackFloorDamage when the floor is not the one root
// reviewed: its size, its count of unattributable damaged lines or its
// count of unrecovered lines changed.
var errAckStale = errors.New("the user-scope floor changed since its damage was reviewed; review it again before acknowledging")

// floorReview is what root reviews before it acknowledges the floor's
// damage (floorAckView), and what ackFloorDamage compares again under the
// lock. size is the floor's size; unattributable counts its unattributable
// damaged lines, the torn last line and the unrecovered lines included;
// unrecovered counts the unrecovered lines alone (logState.unrecovered),
// each a line that could have been any key's tombstone, and unrecoveredAt
// holds the byte offsets where the first maxUnrecoveredOffsets of them
// start, in file order. Acknowledging a floor with unrecovered lines
// accepts that a tombstone one of them held may stay lost: past the
// watermark every known generation is served again, and a copy back of a
// generation whose tombstone was there is no longer refused by it.
type floorReview struct {
	size           int64
	unattributable int
	unrecovered    int
	unrecoveredAt  []int64
}

// floorAckView is what root reviews before it acknowledges the floor's
// damage: the floor's size, its damage counts and the unrecovered lines'
// offsets (floorReview), which ackFloorDamage compares again under the
// lock.
//
//lint:ignore U1000 root maintenance calls it once its verb lands; until then the tests hold it.
func (s *FileStore) floorAckView(ctx context.Context) (floorReview, error) {
	if err := ctx.Err(); err != nil {
		return floorReview{}, err
	}
	ff, ok := s.userFloor.(*fileFloorLog)
	if !ok {
		return floorReview{}, errors.New("the store has no file-backed user-scope floor to acknowledge")
	}
	f, st, err := ff.log.open(unix.O_RDONLY)
	if err != nil {
		ff.log.forgetUnflagged(err, false)
		return floorReview{}, err
	}
	defer func() { _ = f.Close() }() // read-only
	ff.log.mu.Lock()
	defer ff.log.mu.Unlock()
	state, err := ff.log.sync(f, st)
	if err != nil {
		return floorReview{}, err
	}
	return reviewOf(st.Size, state), nil
}

// reviewOf is the floor's review at size from its state. The caller holds
// the floor's mutex.
func reviewOf(size int64, state *logState) floorReview {
	return floorReview{
		size:           size,
		unattributable: state.unattributableLines(),
		unrecovered:    state.unrecoveredN,
		unrecoveredAt:  slices.Clone(state.unrecoveredOffs),
	}
}

// ackFloorDamage records, as root, the acknowledgement of the floor's damage
// as it stands, compare-and-set: under the exclusive store lock and the
// floor's mutex it refuses (errAckStale) unless the floor's size, its count
// of unattributable damaged lines and its count of unrecovered lines are
// want's, the figures root reviewed (floorAckView), then writes the floor
// file's inode and birth time and that size as the watermark through the
// data-root descriptor it judged. Acknowledging unrecovered lines accepts
// that a tombstone one of them held may stay lost (floorReview). Still
// under the store lock it then runs the start step's catch-up again, when
// the user scope is started, so a scope quarantined only by acknowledged
// damage is served; a scope a taint still refuses stays quarantined, and
// no catch-up line is written for a generation whose key a damaged line
// could name. It is root maintenance with no verb yet.
//
//lint:ignore U1000 root maintenance calls it once its verb lands; until then the tests hold it.
func (s *FileStore) ackFloorDamage(ctx context.Context, want floorReview) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if int64(s.euid()) != int64(s.floorUID) {
		return errAckNotRoot
	}
	ff, ok := s.userFloor.(*fileFloorLog)
	if !ok {
		return errors.New("the store has no file-backed user-scope floor to acknowledge")
	}
	if err := s.checkConfig(); err != nil {
		return err
	}
	root, done, err := s.openLocked(ctx, false, true)
	if err != nil {
		return err
	}
	defer done()
	if err := s.writeFloorAck(ff, want); err != nil {
		return err
	}
	if s.userScopesStarted == nil || !s.userScopesStarted.Load() {
		return nil
	}
	quarantined, scopeErrs, err := s.catchUpUserLocked(ctx, root)
	if err != nil {
		return errors.Join(err, scopeErrs)
	}
	s.quarantined.Store(&quarantined)
	return nil
}

// writeFloorAck is ackFloorDamage's compare and write, under the floor's
// mutex. The caller holds the exclusive store lock.
func (s *FileStore) writeFloorAck(ff *fileFloorLog, want floorReview) error {
	f, st, err := ff.log.open(unix.O_RDONLY)
	if err != nil {
		ff.log.forgetUnflagged(err, false)
		return err
	}
	defer func() { _ = f.Close() }() // read-only
	ff.log.mu.Lock()
	defer ff.log.mu.Unlock()
	state, err := ff.log.sync(f, st)
	if err != nil {
		return err
	}
	if got := reviewOf(st.Size, state); got.size != want.size || got.unattributable != want.unattributable || got.unrecovered != want.unrecovered {
		return errAckStale
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // the write is fsynced in writeFileAt
	// The acknowledgement names the floor file in the directory it is
	// written to: the judged descriptor's entry must be the file sized.
	var named unix.Stat_t
	if err := unix.Fstatat(dfd, userFloorLogName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat the user-scope floor in the data root: %w", err)
	}
	if named.Dev != st.Dev || named.Ino != st.Ino {
		return errAckStale
	}
	a := floorAck{ino: st.Ino, birth: logBirth(&st), watermark: st.Size}
	return s.writeFileAt(dfd, floorAckName, a.encode(), uint32(s.floorUID), uint32(s.floorGID), floorFileMode)
}

// writeFileAt is writeFileAs through the directory descriptor dfd: a fresh
// temporary file, owned and moded on its descriptor, written and fsynced,
// renamed over name, and the directory fsynced.
func (s *FileStore) writeFileAt(dfd int, name string, data []byte, uid, gid uint32, mode os.FileMode) error {
	var suffix [tempSuffixSize]byte
	if err := s.readRandom(suffix[:]); err != nil {
		return fmt.Errorf("name a temporary file: %w", err)
	}
	tmp := tempName(name, suffix)
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(fileMode))
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(fd), tmp)
	renamed := false
	defer func() {
		if !renamed {
			_ = unix.Unlinkat(dfd, tmp, 0) // best effort: a leftover temporary file is ignored by every reader
		}
	}()
	err = s.ownAs(f, uid, gid, mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = s.step("write " + name)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, name, err)
	}
	renamed = true
	if err := unix.Fsync(dfd); err != nil {
		return fmt.Errorf("sync the data root: %w", err)
	}
	return nil
}

// unattributable reports whether the floor holds unattributable damage that
// counts, which refuses every put and deliver line and every live line for
// a generation the floor has no line for: damage that starts at or past an
// acknowledgement's watermark for this file, or any, with none. The caller
// holds f.log.mu.
func (f *fileFloorLog) unattributable(state *logState) bool {
	at, ok := state.unattributedAt()
	return ok && f.counts(state, at)
}

// unrecovered reports whether the floor holds an unrecovered flip that
// counts (logState.unrecovered), which refuses every generation of every
// key, known or not: one that starts at or past an acknowledgement's
// watermark for this file, or any, with none. The root acknowledgement
// lifts it as it lifts other unattributable damage. The caller holds
// f.log.mu.
func (f *fileFloorLog) unrecovered(state *logState) bool {
	return state.unrecovered && f.counts(state, state.unrecoveredAt)
}

// counts reports whether damage that starts at at counts: at or past an
// acknowledgement's watermark for this file, or any, with none.
func (f *fileFloorLog) counts(state *logState, at int64) bool {
	a, ok := f.log.s.readFloorAck()
	if !ok || a.ino != state.ino || a.birth != state.birth {
		return true
	}
	return at >= a.watermark
}
