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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// archiveOne is the path of keystore-audit.log.1.
func archiveOne(s *FileStore) string {
	return filepath.Join(s.dataRoot, logsDirName, auditDirName, archivesDirName, auditArchiveName(1))
}

// assertArchiveOne fails unless .1 holds want, is the caller's, mode
// 0600, unflagged and one link.
func assertArchiveOne(t *testing.T, s *FileStore, want []byte) {
	t.Helper()
	b, err := os.ReadFile(archiveOne(s))
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf(".1 holds %q (%v), want the log's bytes at open %q", b, err, want)
	}
	var st unix.Stat_t
	if err := unix.Lstat(archiveOne(s), &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o7777 != logMode || statFlags(&st) != 0 || st.Nlink != 1 {
		t.Fatalf(".1 is uid %d mode %04o flags %#x nlink %d, want the caller's 0600, unflagged, one link", st.Uid, st.Mode&0o7777, statFlags(&st), st.Nlink)
	}
}

// Rotate makes .1 a clone of the old log, so it needs no free space the
// size of the log: the clone is made the caller's 0600 and unflagged and
// holds exactly the log's bytes at open.
func TestRotateAuditClonesArchive(t *testing.T) {
	s, _, _ := fileLogScope(t)
	want := readLog(t, s, auditLogName)
	var cloned bool
	prev := cloneFileAt
	cloneFileAt = func(src, dir int, name string) error {
		err := prev(src, dir, name)
		cloned = err == nil
		return err
	}
	t.Cleanup(func() { cloneFileAt = prev })
	volumeSpace = func(int) (int64, int64, error) { return 0, 1 << 40, nil } // a clone needs no room
	t.Cleanup(func() { volumeSpace = defaultVolumeSpace })
	if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !cloned {
		t.Skip("this volume refuses clonefile; the copy path is tested below")
	}
	assertArchiveOne(t, s, want)
}

// A cloned archive is truncated to the log's size at open: bytes the clone
// captured past it are not archived.
func TestCloneArchiveTruncatesToSnapshot(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "log")
	if err := os.WriteFile(src, []byte("one\ntwo\nlate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	nad, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(nad) }()
	err = cloneArchive(&oldLog{f: f, size: 8}, nad, "one")
	if errors.Is(err, errCloneRefused) {
		t.Skipf("this volume refuses clonefile: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "one")); err != nil || string(b) != "one\ntwo\n" {
		t.Fatalf("the clone holds %q (%v), want the 8 bytes at open", b, err)
	}
}

// When the volume refuses the clone, rotate copies, but only after it
// checks the volume's free space: short of room it refuses up front with
// a clear message, and nothing changes; with room the copy is the archive.
func TestRotateAuditCopyChecksFreeSpace(t *testing.T) {
	prev := cloneFileAt
	cloneFileAt = func(int, int, string) error { return unix.ENOTSUP }
	t.Cleanup(func() { cloneFileAt = prev; volumeSpace = defaultVolumeSpace })
	s, _, _ := fileLogScope(t)
	want := readLog(t, s, auditLogName)
	// Room for the bytes and a 1 MiB margin is short of the 1 GiB floor.
	volumeSpace = func(int) (int64, int64, error) { return int64(len(want)) + 1<<20, 10 << 30, nil }
	_, err := s.RotateAudit(context.Background(), &inoRecorder{}, false)
	if !errors.Is(err, errRotateRefused) || Committed(err) || !strings.Contains(err.Error(), "bytes free on the data root's volume") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("rotate on a full volume: %v, want a refusal naming the free space", err)
	}
	if !bytes.Equal(readLog(t, s, auditLogName), want) {
		t.Fatal("the refused rotate changed the audit log")
	}
	if _, err := os.Lstat(archiveOne(s)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused rotate left .1: %v", err)
	}
	assertNoMaintenanceLeft(t, s)
	volumeSpace = func(int) (int64, int64, error) { return int64(len(want)) + 1<<30, 10 << 30, nil }
	if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
		t.Fatalf("rotate with room: %v", err)
	}
	assertArchiveOne(t, s, want)
}

// The copy's margin is the larger of 1 GiB and 2% of the volume: a small
// volume needs the log's size plus 1 GiB, a large one the log's size plus
// 2% of it, and a free space one byte short of either refuses.
func TestCopyArchiveMarginScalesWithVolume(t *testing.T) {
	const gib = int64(1) << 30
	for _, tt := range []struct {
		name          string
		size, volSize int64
		want          int64
	}{
		{"an empty volume size", 7, 0, 7 + gib},
		{"a 10 GiB volume: 1 GiB is larger", 100, 10 * gib, 100 + gib},
		{"a 50 GiB volume: both are 1 GiB", 100, 50 * gib, 100 + gib},
		{"a 1 TiB volume: 2% is larger", 100, 1024 * gib, 100 + 1024*gib/100*2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := copyRoom(tt.size, tt.volSize); got != tt.want {
				t.Fatalf("copyRoom(%d, %d) = %d, want %d", tt.size, tt.volSize, got, tt.want)
			}
		})
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "log")
	if err := os.WriteFile(src, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	nad, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(nad) }()
	t.Cleanup(func() { volumeSpace = defaultVolumeSpace })
	old := &oldLog{f: f, size: 4}
	vol := 1024 * gib
	need := old.size + vol/100*2
	volumeSpace = func(int) (int64, int64, error) { return need - 1, vol, nil }
	err = copyArchive(old, nad, "short", unix.ENOTSUP)
	if !errors.Is(err, errRotateRefused) || !strings.Contains(err.Error(), strconv.FormatInt(need, 10)) || !strings.Contains(err.Error(), "2% of the volume") {
		t.Fatalf("a copy one byte short of 2%% of a 1 TiB volume: %v, want a refusal naming %d bytes", err, need)
	}
	if _, err := os.Lstat(filepath.Join(dir, "short")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the refused copy created its file: %v", err)
	}
	volumeSpace = func(int) (int64, int64, error) { return need, vol, nil }
	if err := copyArchive(old, nad, "room", unix.ENOTSUP); err != nil {
		t.Fatalf("a copy with exactly the room: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "room")); err != nil || string(b) != "one\n" {
		t.Fatalf("the copy holds %q (%v)", b, err)
	}
}
