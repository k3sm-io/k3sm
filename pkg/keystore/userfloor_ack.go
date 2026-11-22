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
	"os"

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

// parseFloorAck decodes b strictly: it must be what encode writes.
func parseFloorAck(b []byte) (floorAck, error) {
	var a floorAck
	var sec, nsec int64
	if _, err := fmt.Sscanf(string(b), floorAckTag+" %d %d %d %d\n", &a.ino, &sec, &nsec, &a.watermark); err != nil {
		return floorAck{}, fmt.Errorf("the floor acknowledgement does not parse: %w", err)
	}
	a.birth = unix.Timespec{Sec: sec, Nsec: nsec}
	if a.watermark < 0 || string(a.encode()) != string(b) {
		return floorAck{}, errors.New("the floor acknowledgement is not canonical")
	}
	return a, nil
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

// ackFloorDamage records, as root, the acknowledgement of the floor's damage
// as it stands: the floor file's inode and birth time and its size as the
// watermark. It then runs the start step's catch-up again, when the user
// scope is started, so a scope quarantined only by acknowledged damage is
// served; a scope a taint still refuses stays quarantined. It is root
// maintenance with no verb yet.
//
//lint:ignore U1000 root maintenance calls it once its verb lands; until then the tests hold it.
func (s *FileStore) ackFloorDamage(ctx context.Context) error {
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
	f, st, err := ff.log.open(unix.O_RDONLY)
	if err != nil {
		ff.log.forgetUnflagged(err, false)
		return err
	}
	_ = f.Close() // only its identity and size are needed
	a := floorAck{ino: st.Ino, birth: logBirth(&st), watermark: st.Size}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return err
	}
	_ = unix.Close(dfd) // judged; the write goes through an os.Root
	root, err := os.OpenRoot(s.dataRoot)
	if err != nil {
		return fmt.Errorf("open the data root: %w", err)
	}
	defer func() { _ = root.Close() }() // the write is fsynced by writeFileAs
	if err := s.writeFileAs(root, floorAckName, a.encode(), uint32(s.floorUID), uint32(s.floorGID), floorFileMode); err != nil {
		return err
	}
	if s.userScopesStarted == nil || !s.userScopesStarted.Load() {
		return nil
	}
	quarantined, scopeErrs, err := s.catchUpUserScopes(ctx)
	if err != nil {
		return errors.Join(err, scopeErrs)
	}
	s.quarantined.Store(&quarantined)
	return nil
}

// unattributable reports whether the floor holds unattributable damage that
// counts, which refuses every put and deliver line and every live line for
// a generation the floor has no line for: damage that starts at or past an
// acknowledgement's watermark for this file, or any, with none. The caller
// holds f.log.mu.
func (f *fileFloorLog) unattributable(state *logState) bool {
	at, ok := state.unattributedAt()
	if !ok {
		return false
	}
	a, ok := f.log.s.readFloorAck()
	if !ok || a.ino != state.ino || a.birth != state.birth {
		return true
	}
	return at >= a.watermark
}
