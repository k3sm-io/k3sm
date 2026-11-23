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
	volumeFree = func(int) (int64, error) { return 0, nil } // a clone needs no room
	t.Cleanup(func() { volumeFree = defaultVolumeFree })
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
	t.Cleanup(func() { cloneFileAt = prev; volumeFree = defaultVolumeFree })
	s, _, _ := fileLogScope(t)
	want := readLog(t, s, auditLogName)
	volumeFree = func(int) (int64, error) { return int64(len(want)), nil }
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
	volumeFree = defaultVolumeFree
	if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
		t.Fatalf("rotate with room: %v", err)
	}
	assertArchiveOne(t, s, want)
}
