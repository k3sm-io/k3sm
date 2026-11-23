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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// cachedFloor appends two floor lines past what fileLogScope wrote, reads
// the floor so the reader caches it, and returns the two lines' offsets.
func cachedFloor(t *testing.T, s *FileStore, u *UserScope) (first, last int64, lastLen int) {
	t.Helper()
	first = int64(len(readLog(t, s, userFloorLogName)))
	a, err := floorLine("user/1001", "k0", guid(1), 7)
	if err != nil {
		t.Fatal(err)
	}
	b, err := floorLine("user/1001", "k1", guid(1), 7)
	if err != nil {
		t.Fatal(err)
	}
	appendLogBytes(t, s, userFloorLogName, append(a, b...))
	if _, _, err := u.Current(context.Background(), "user/1001/token"); err != nil {
		t.Fatalf("current over the cached floor: %v", err)
	}
	return first, first + int64(len(a)), len(b)
}

// spoilLineAt flips, in place, one bit of the checksum's last digit of the
// line ending at end, so the line no longer parses, its one correction taints
// only its own key, and the file keeps its inode and size.
func spoilLineAt(t *testing.T, s *FileStore, end int64) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(s.dataRoot, userFloorLogName), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := make([]byte, 1)
	if _, err := f.ReadAt(c, end-2); err != nil {
		t.Fatal(err)
	}
	c[0] ^= 0x01
	if _, err := f.WriteAt(c, end-2); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// An in-place change to the last line already read, in the same inode at
// the same or a larger size, is noticed: the reader reads that line again
// before it reads on, and on a mismatch reads the floor from the start,
// where it meets the spoiled line and skips it as damage.
func TestLogSyncNoticesRewrittenLastLine(t *testing.T) {
	ctx := context.Background()
	for _, grow := range []bool{false, true} {
		s, _, u := fileLogScope(t)
		_, last, n := cachedFloor(t, s, u)
		spoilLineAt(t, s, last+int64(n))
		if grow {
			line, err := floorLine("user/1001", "k2", guid(1), 7)
			if err != nil {
				t.Fatal(err)
			}
			appendLogBytes(t, s, userFloorLogName, line)
		}
		if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
			t.Fatalf("grow %v: current after the last line read was rewritten: %v, want it served", grow, err)
		}
		if n := floorDamage(t, s); n != 1 {
			t.Fatalf("grow %v: %d damaged lines after the last line read was rewritten, want 1 (read again from the start)", grow, n)
		}
	}
}

// A flag observed clear on a read drops what was read: once the flag is
// back, the floor is read from the start, so a change to a line before the
// last one read, which the last-line check cannot see, is noticed.
func TestLogSyncForgetsOnClearFlag(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	_, last, _ := cachedFloor(t, s, u)
	spoilLineAt(t, s, last)
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current over a cached floor: %v (the earlier line is not read again)", err)
	}
	if n := floorDamage(t, s); n != 0 {
		t.Fatalf("%d damaged lines over a cached floor, want 0 (the earlier line is not read again)", n)
	}
	s.logFlags = func(*os.File) (uint32, error) { return 0, nil }
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errLogNotAppendOnly) {
		t.Fatalf("current over an unflagged floor: %v, want errLogNotAppendOnly", err)
	}
	if st := &s.userFloor.(*fileFloorLog).log.state; st.off != 0 || st.maxSeq != nil {
		t.Fatalf("a clear flag kept the state: read to byte %d", st.off)
	}
	s.logFlags = flagged
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current once the flag is back: %v, want it served", err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("%d damaged lines once the flag is back, want 1 (read again from the start)", n)
	}
}

// syncFloor opens the floor and syncs it under st.
func syncFloor(t *testing.T, l *appendLog, st unix.Stat_t) *logState {
	t.Helper()
	f, _, err := l.open(unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	l.mu.Lock()
	defer l.mu.Unlock()
	state, err := l.sync(f, st)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
