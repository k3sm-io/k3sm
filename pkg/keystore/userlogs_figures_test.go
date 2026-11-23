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
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The log errors a socket caller can see name no figure: not the free
// bytes of a nearly full volume, not the size of a log past the reader's
// bound, and not the byte offset of a floor line that does not parse.
func TestLogErrorsNameNoFigures(t *testing.T) {
	ctx := context.Background()
	t.Run("no space", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return 777777, nil }
		_, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v"))
		if !errors.Is(err, errLogNoSpace) || strings.Contains(err.Error(), "777777") {
			t.Fatalf("put on a nearly full volume: %v, want errLogNoSpace naming no free bytes", err)
		}
	})
	t.Run("too large", func(t *testing.T) {
		s, server, u := fileLogScope(t)
		line, err := floorLine("user/1001", "token", entryGeneration(t, server, "token"), 1)
		if err != nil {
			t.Fatal(err)
		}
		appendLogBytes(t, s, userFloorLogName, bytes.Repeat(line, (4<<20)/len(line)))
		size := len(readLog(t, s, userFloorLogName))
		s.logSoftCap, s.logHardCap, s.logRevokeBudget = 1, 1, minLogRevokeBudget
		_, _, err = u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errFloorLogMalformed) || strings.Contains(err.Error(), strconv.Itoa(size)) || strings.Contains(err.Error(), strconv.FormatInt(s.logReadBound(), 10)) {
			t.Fatalf("current over a floor past the reader's bound: %v, want it refused naming no size", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		// A line that does not parse is skipped, so no error names it; its
		// offset is root's, kept and logged.
		s, _, u := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("not a floor line\n"))
		// It cannot be a tear and no one-bit correction parses: it is
		// unrecovered, so the read is refused, naming no offset.
		want := int64(len(readLog(t, s, userFloorLogName)) - len("not a floor line\n"))
		if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) || strings.Contains(err.Error(), strconv.FormatInt(want, 10)) {
			t.Fatalf("current over a malformed line: %v, want errFloorDegraded naming no offset", err)
		}
		l := s.userFloor.(*fileFloorLog).log
		l.mu.Lock()
		at := l.state.badAt
		l.mu.Unlock()
		if at != want {
			t.Fatalf("the kept offset is %d, want %d", at, want)
		}
	})
	t.Run("field count", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		appendLogBytes(t, s, userFloorLogName, []byte("one two three four five six seven\n"))
		// More fields than the grammar's cannot be a tear: unrecovered.
		if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("current over a floor line with the wrong field count: %v, want errFloorDegraded", err)
		}
		if n := floorDamage(t, s); n != 1 {
			t.Fatalf("%d damaged lines, want 1", n)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		s.userFloor.(*fileFloorLog).log.readAt = func(*os.File) io.ReaderAt { return failingReaderAt{} }
		_, _, err := u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errLogUnreadable) || strings.Contains(err.Error(), "at byte") {
			t.Fatalf("current over an unreadable floor: %v, want errLogUnreadable naming no offset", err)
		}
	})
	t.Run("log mode", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		if err := os.Chmod(filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName), 0o640); err != nil {
			t.Fatal(err)
		}
		_, _, err := u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errLogUntrusted) || strings.Contains(err.Error(), "0640") || strings.Contains(err.Error(), "uid") {
			t.Fatalf("current over a floor at the wrong mode: %v, want errLogUntrusted naming no mode", err)
		}
	})
	t.Run("log links", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		if err := os.Link(filepath.Join(s.dataRoot, logsDirName, floorDirName, userFloorLogName), filepath.Join(s.dataRoot, logsDirName, floorDirName, "floor-link")); err != nil {
			t.Fatal(err)
		}
		_, _, err := u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errLogUntrusted) || strings.Contains(err.Error(), "2 links") {
			t.Fatalf("current over a floor with two links: %v, want errLogUntrusted naming no count", err)
		}
	})
	t.Run("data root", func(t *testing.T) {
		s, _, u := fileLogScope(t)
		if err := os.Chmod(s.dataRoot, 0o777); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(s.dataRoot, 0o755) })
		_, _, err := u.Current(ctx, "user/1001/token")
		if !errors.Is(err, errLogUntrusted) || strings.Contains(err.Error(), "0777") || strings.Contains(err.Error(), "uid") || strings.Contains(err.Error(), s.dataRoot) {
			t.Fatalf("current under a writable data root: %v, want errLogUntrusted naming no mode, uid or path", err)
		}
	})
}

// The two grant refusals for keys, the floor at its key bound and the
// caller's share spent, read the same, so the text does not tell a caller
// whether other uids filled the floor.
func TestLogFullKeyRefusalsReadTheSame(t *testing.T) {
	s, _, _ := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	atBound := &logState{keys: l.keyBound(), uidKeys: map[uint32]int{}}
	atShare := &logState{uidKeys: map[uint32]int{1001: l.keyShare()}}
	eb, es := l.addKeyRoom(atBound, 1001, 1, false), l.addKeyRoom(atShare, 1001, 1, false)
	if !errors.Is(eb, ErrLogFull) || !errors.Is(es, ErrLogFull) {
		t.Fatalf("the key refusals: %v, %v, want ErrLogFull", eb, es)
	}
	if eb.Error() != es.Error() {
		t.Fatalf("the key refusals differ:\n%v\n%v", eb, es)
	}
}

// The data root that does not open is reported without its path.
func TestLogDataRootOpenNamesNoPath(t *testing.T) {
	s, _, _ := fileLogScope(t)
	s.dataRoot = filepath.Join(t.TempDir(), "no-such-data-root-7f3a")
	_, err := s.openLogDataRoot()
	if err == nil || strings.Contains(err.Error(), "no-such-data-root-7f3a") {
		t.Fatalf("open of a missing data root: %v, want an error naming no path", err)
	}
}

// A log past its hard cap and one at the reader's bound refuse with one
// text, so a caller cannot tell which it met.
func TestLogFullCapAndBoundReadTheSame(t *testing.T) {
	s, _, _ := fileLogScope(t)
	l := s.userFloor.(*fileFloorLog).log
	s.logSoftCap, s.logHardCap = 1, 1
	pastCap := l.room(1001, false)
	state := &logState{pastCap: map[uint32]int64{}}
	atBound := l.revokeRoom(state, s.logReadBound(), 1001, 1)
	if !errors.Is(pastCap, ErrLogFull) || !errors.Is(atBound, ErrLogFull) {
		t.Fatalf("the refusals: %v, %v, want ErrLogFull", pastCap, atBound)
	}
	if pastCap.Error() != atBound.Error() {
		t.Fatalf("the hard-cap and reader's-bound refusals differ:\n%v\n%v", pastCap, atBound)
	}
}
