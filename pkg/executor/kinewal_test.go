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

package executor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// walFrame is one synthetic WAL frame: the page it writes and, for a commit
// frame, the database size in pages after it.
type walFrame struct {
	pgno, commitPages uint32
	stale             bool // carries salts from before a WAL reset
}

// writeWAL writes a WAL in SQLite's format beside db (state.db-wal), with pageSize
// pages, and sizes db to dbPages pages.
func writeWAL(t *testing.T, db string, pageSize uint32, dbPages int, frames []walFrame) {
	t.Helper()
	if err := os.WriteFile(db, make([]byte, dbPages*int(pageSize)), 0o600); err != nil {
		t.Fatal(err)
	}
	be := binary.BigEndian
	var b bytes.Buffer
	hdr := make([]byte, walHeaderSize)
	be.PutUint32(hdr[0:4], walMagicBE)
	be.PutUint32(hdr[4:8], 3007000)
	be.PutUint32(hdr[8:12], pageSize)
	be.PutUint32(hdr[16:20], 0x11111111)
	be.PutUint32(hdr[20:24], 0x22222222)
	b.Write(hdr)
	for _, f := range frames {
		fh := make([]byte, walFrameHeaderSize)
		be.PutUint32(fh[0:4], f.pgno)
		be.PutUint32(fh[4:8], f.commitPages)
		s1, s2 := uint32(0x11111111), uint32(0x22222222)
		if f.stale {
			s1, s2 = 0x33333333, 0x44444444
		}
		be.PutUint32(fh[8:12], s1)
		be.PutUint32(fh[12:16], s2)
		b.Write(fh)
		b.Write(make([]byte, pageSize))
	}
	if err := os.WriteFile(db+"-wal", b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWALCheckpointGrowth(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dbPages int
		frames  []walFrame
		want    int64
		wantErr bool
	}{
		{name: "last frame commits: growth to its size", dbPages: 10,
			frames: []walFrame{{pgno: 11}, {pgno: 12, commitPages: 12}, {pgno: 13}, {pgno: 20, commitPages: 20}},
			want:   10 * 4096},
		{name: "trailing uncommitted frames are skipped", dbPages: 10,
			frames: []walFrame{{pgno: 15, commitPages: 15}, {pgno: 16}, {pgno: 17}},
			want:   5 * 4096},
		{name: "stale frames from before a reset are skipped", dbPages: 10,
			frames: []walFrame{{pgno: 12, commitPages: 12}, {pgno: 99, commitPages: 99, stale: true}},
			want:   2 * 4096},
		{name: "a WAL that shrinks nothing grows nothing", dbPages: 30,
			frames: []walFrame{{pgno: 3, commitPages: 30}},
			want:   0},
		{name: "no commit frame is an error", dbPages: 10,
			frames:  []walFrame{{pgno: 11}, {pgno: 12}},
			wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "state.db")
			writeWAL(t, db, 4096, tc.dbPages, tc.frames)
			got, err := walCheckpointGrowth(db)
			if (err != nil) != tc.wantErr {
				t.Fatalf("walCheckpointGrowth = %d, %v; wantErr %v", got, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("walCheckpointGrowth = %d, want %d", got, tc.want)
			}
		})
	}
	t.Run("not a WAL is an error", func(t *testing.T) {
		db := filepath.Join(t.TempDir(), "state.db")
		if err := os.WriteFile(db+"-wal", bytes.Repeat([]byte{1}, 4096), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := walCheckpointGrowth(db); err == nil {
			t.Fatal("walCheckpointGrowth on garbage = nil error")
		}
	})
}

func TestKineReadyTimeout(t *testing.T) {
	for _, tc := range []struct {
		wal  int64
		want time.Duration
	}{
		{0, componentReadyTimeout},
		{largeWALBytes - 1, componentReadyTimeout},
		{largeWALBytes, componentReadyTimeout + walRecoveryPerGiB},
		{1 << 30, componentReadyTimeout + walRecoveryPerGiB},
		{7 << 30, componentReadyTimeout + 7*walRecoveryPerGiB},
		{7<<30 + 1, componentReadyTimeout + 8*walRecoveryPerGiB},
	} {
		if got := kineReadyTimeout(tc.wal); got != tc.want {
			t.Errorf("kineReadyTimeout(%d) = %v, want %v", tc.wal, got, tc.want)
		}
	}
}

// TestPrepareKineWAL covers the three outcomes of the pre-start WAL check: a small
// WAL changes nothing, a large one is logged and waited for in proportion, and a
// large one the volume cannot checkpoint is refused before kine starts.
func TestPrepareKineWAL(t *testing.T) {
	// A large WAL: 64 MiB + one frame of 4 KiB pages, committing 2000 pages over a
	// 1000-page database, so the checkpoint grows state.db by 1000 pages.
	largeFrames := func() []walFrame {
		n := largeWALBytes/(walFrameHeaderSize+4096) + 1
		fr := make([]walFrame, n)
		for i := range fr {
			fr[i] = walFrame{pgno: uint32(i%2000 + 1)}
		}
		fr[n-1].commitPages = 2000
		return fr
	}
	const growth = 1000 * 4096

	origFree := freeSpace
	t.Cleanup(func() { freeSpace = origFree })

	t.Run("a small WAL keeps the ordinary wait", func(t *testing.T) {
		work := t.TempDir()
		if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
			t.Fatal(err)
		}
		writeWAL(t, StateDBPath(work), 4096, 10, []walFrame{{pgno: 11, commitPages: 11}})
		freeSpace = func(string) (uint64, error) { return 0, nil } // must not matter
		wait, err := prepareKineWAL(slog.New(slog.DiscardHandler), work)
		if err != nil || wait != componentReadyTimeout {
			t.Fatalf("prepareKineWAL = %v, %v; want %v, nil", wait, err, componentReadyTimeout)
		}
	})
	t.Run("a large WAL is logged and waited for", func(t *testing.T) {
		work := t.TempDir()
		if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
			t.Fatal(err)
		}
		writeWAL(t, StateDBPath(work), 4096, 1000, largeFrames())
		freeSpace = func(string) (uint64, error) { return growth + walSpaceMargin, nil }
		var logs bytes.Buffer
		wait, err := prepareKineWAL(slog.New(slog.NewTextHandler(&logs, nil)), work)
		if err != nil {
			t.Fatalf("prepareKineWAL = %v", err)
		}
		if want := componentReadyTimeout + walRecoveryPerGiB; wait != want {
			t.Errorf("wait = %v, want %v", wait, want)
		}
		if !strings.Contains(logs.String(), "level=INFO") || !strings.Contains(logs.String(), "recovering a large datastore WAL") ||
			!strings.Contains(logs.String(), "state.db-growth-bytes=4096000") {
			t.Errorf("no Info line naming the recovery and its growth: %q", logs.String())
		}
	})
	t.Run("a large WAL the volume cannot take is refused", func(t *testing.T) {
		work := t.TempDir()
		if err := os.MkdirAll(dbDir(work), 0o700); err != nil {
			t.Fatal(err)
		}
		writeWAL(t, StateDBPath(work), 4096, 1000, largeFrames())
		freeSpace = func(string) (uint64, error) { return growth + walSpaceMargin - 1, nil }
		_, err := prepareKineWAL(slog.New(slog.DiscardHandler), work)
		if !errors.Is(err, ErrKineWALSpace) {
			t.Fatalf("prepareKineWAL = %v, want ErrKineWALSpace", err)
		}
		if !strings.Contains(err.Error(), "free space and start the server again") {
			t.Errorf("refusal %q names no remedy", err)
		}
	})
}
