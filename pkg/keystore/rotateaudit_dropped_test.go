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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// writeDropped persists d as the server would, in s's store directory.
func writeDropped(t *testing.T, s *FileStore, d preFrameDropped) {
	t.Helper()
	root, err := s.openDir(s.dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := s.writePreFrameDropped(root, d); err != nil {
		t.Fatal(err)
	}
}

// TestRotateAuditWritesDroppedCounts: audit --rotate writes the server's
// persisted counts (pre-frame, post-frame and unaudited) at the start of
// the new audit log, one summary line per class via root, charged to no uid and to no pre-frame
// part, and takes them out of the file once the swap committed; a server
// that held them in memory drops them at its reopen, so none is written
// twice.
func TestRotateAuditWritesDroppedCounts(t *testing.T) {
	s, _, _ := fileLogScope(t)
	d := newPreFrameDropped()
	d.uids[preFrameKey{preFrameClassLogin, 1001}] = 2
	d.uids[preFrameKey{preFrameClassLogin, 1002}] = 3
	d.uids[preFrameKey{preFrameClassRoot, 0}] = 1
	d.others[preFrameClassLogin] = 4
	d.uids[preFrameKey{countClassPostFrame, 1001}] = 3
	d.others[countClassPostFrame] = 1
	d.others[countClassUnaudited] = 2
	writeDropped(t, s, d)
	l := s.ServerLogs()
	t.Cleanup(func() { _ = l.Close() })
	if got := l.PendingDropped(1001); got != 2 {
		t.Fatalf("the server opened with %d pending for 1001, want 2", got)
	}
	if got, un := s.PostFrameDropped(1001), s.UnauditedOps(); got != 3 || un != 2 {
		t.Fatalf("the server opened with %d post-frame for 1001 and %d unaudited, want 3 and 2", got, un)
	}
	if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
		t.Fatal(err)
	}
	log := readLog(t, s, auditLogName)
	lines := strings.Split(strings.TrimSuffix(string(log), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("the new audit log holds %d lines, want one per class with a count:\n%s", len(lines), log)
	}
	for i, want := range []string{
		`"result":"dropped","charge":"reconciler","source":"pre-frame","dropped":9,"class":"login"}`,
		`"source":"pre-frame","dropped":1,"class":"root"}`,
		`"source":"post-frame","dropped":4,"class":"post-frame"}`,
	} {
		if !strings.HasSuffix(lines[i], want) || !strings.Contains(lines[i], `"op":"refused","via":"root","caller":{"uid":0}`) {
			t.Fatalf("line %d is %s, want a via-root summary ending %s", i, lines[i], want)
		}
		if _, _, ok := preFrameCharge([]byte(lines[i] + "\n")); ok {
			t.Fatalf("line %d is charged to the pre-frame part: %s", i, lines[i])
		}
	}
	// The unaudited count is its own op: committed revocations whose
	// lines are missing, neither refused nor dropped. The strict reader
	// takes it, charged to no uid and to no pre-frame part.
	un := lines[3]
	if !strings.Contains(un, `"op":"unaudited","via":"root","caller":{"uid":0}`) || !strings.HasSuffix(un, `"result":"committed","count":2}`) ||
		strings.Contains(un, "refused") || strings.Contains(un, "dropped") {
		t.Fatalf("the unaudited line is %s, want op unaudited, result committed, count 2, and no refused or dropped", un)
	}
	if uid, recon, err := auditLineCharge([]byte(un)); err != nil || uid != 0 || recon {
		t.Fatalf("the strict reader on the unaudited line: uid %d, reconciler %v, %v; want uid 0 and accepted", uid, recon, err)
	}
	if _, _, ok := preFrameCharge([]byte(un + "\n")); ok {
		t.Fatalf("the unaudited line is charged to the pre-frame part: %s", un)
	}
	if damage, _, err := s.CheckLogBounds(context.Background()); err != nil || damage != 0 {
		t.Fatalf("the audit log reader judges the new log: damage %d, %v", damage, err)
	}
	b, err := os.ReadFile(filepath.Join(s.dir, PreFrameDroppedName))
	if err != nil || string(b) != preFrameDroppedHeader {
		t.Fatalf("the persisted file after the rotate: %q %v, want the header alone", b, err)
	}
	if err := l.Reopen(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := l.PendingDropped(1001) + l.PendingDropped(1002) + l.PendingDropped(0); got != 0 || len(l.others) != 0 {
		t.Fatalf("the server kept %d pending (others %v) after the rotate wrote them", got, l.others)
	}
	if got, un := s.PostFrameDropped(1001), s.UnauditedOps(); got != 0 || un != 0 {
		t.Fatalf("the server kept %d post-frame for 1001 and %d unaudited after the rotate wrote them", got, un)
	}
	if err := l.Dropped(context.Background(), 1001, 0); err != nil {
		t.Fatal(err)
	}
	if after := readLog(t, s, auditLogName); !bytes.Equal(after, log) {
		t.Fatalf("the server wrote a count the rotate already wrote:\n%s", after[len(log):])
	}
}

// TestRotateAuditKeepsDroppedOnRefusal: a rotate refused before its swap
// leaves the persisted counts as they were.
func TestRotateAuditKeepsDroppedOnRefusal(t *testing.T) {
	s, _, _ := fileLogScope(t)
	d := newPreFrameDropped()
	d.uids[preFrameKey{preFrameClassLogin, 1001}] = 2
	writeDropped(t, s, d)
	before, err := os.ReadFile(filepath.Join(s.dir, PreFrameDroppedName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RotateAudit(context.Background(), &stepCrash{at: swapStepSwap}, false); err == nil {
		t.Fatal("the rotate did not stop before the swap")
	}
	after, err := os.ReadFile(filepath.Join(s.dir, PreFrameDroppedName))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the persisted file after a rotate stopped before its swap: %q %v, want %q", after, err, before)
	}
}

// TestRotateAuditIgnoresHostileDropped: whatever the service user leaves
// at PreFrameDroppedName in place of the server's file cannot block audit
// --rotate. A symlink to another file, a FIFO, a second hard link, mode
// 0644, a file over the size cap and a file that does not parse (the
// unaudited count on a uid line, a class it does not know and a post-frame
// line out of order included) each leave the rotate succeeding, the new
// audit log with no count line, and the name exactly as it was (a
// symlink's target untouched too), for doctor to report.
func TestRotateAuditIgnoresHostileDropped(t *testing.T) {
	valid := func() []byte {
		d := newPreFrameDropped()
		d.uids[preFrameKey{preFrameClassLogin, 1001}] = 2
		return encodePreFrameDropped(d)
	}
	write := func(t *testing.T, path string, b []byte, mode fs.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	body := func(b string, mode fs.FileMode) func(t *testing.T, name, _ string) {
		return func(t *testing.T, name, _ string) { write(t, name, []byte(b), mode) }
	}
	h := preFrameDroppedHeader
	for _, tc := range []struct {
		name  string
		place func(t *testing.T, name, other string)
	}{
		{"symlink to another file", func(t *testing.T, name, other string) {
			write(t, other, valid(), fileMode)
			if err := os.Symlink(other, name); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to an unaudited count", func(t *testing.T, name, other string) {
			write(t, other, []byte(h+"others unaudited 1\n"), fileMode)
			if err := os.Symlink(other, name); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo", func(t *testing.T, name, _ string) {
			if err := unix.Mkfifo(name, uint32(fileMode)); err != nil {
				t.Fatal(err)
			}
		}},
		{"second hard link", func(t *testing.T, name, other string) {
			write(t, name, valid(), fileMode)
			if err := os.Link(name, other); err != nil {
				t.Fatal(err)
			}
		}},
		{"mode 0644", func(t *testing.T, name, _ string) {
			write(t, name, valid(), 0o644)
		}},
		{"mode 0644 with the new classes", body(h+"1001 post-frame 2\nothers unaudited 1\n", 0o644)},
		{"over the size cap", func(t *testing.T, name, _ string) {
			b := append(valid(), bytes.Repeat([]byte("x"), maxPreFrameDroppedSize)...)
			write(t, name, b, fileMode)
		}},
		{"over the size cap in lines", body(h+strings.Repeat("1 login 1\n", maxPreFrameDroppedSize/10+1), fileMode)},
		{"does not parse", body(h+"1001 login 02\n", fileMode)},
		{"no header", body("1001 login 2\n", fileMode)},
		{"unaudited on a uid line", body(h+"1001 unaudited 2\n", fileMode)},
		{"unknown class", body(h+"1001 postframe 2\n", fileMode)},
		{"post-frame out of order", body(h+"others post-frame 1\n1001 post-frame 2\n", fileMode)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			name := filepath.Join(s.dir, PreFrameDroppedName)
			other := filepath.Join(t.TempDir(), "other")
			tc.place(t, name, other)
			before := snapshotPath(t, name)
			otherBefore := snapshotPath(t, other)
			if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
				t.Fatalf("audit --rotate with a hostile %s: %v", PreFrameDroppedName, err)
			}
			if log := readLog(t, s, auditLogName); len(log) != 0 {
				t.Fatalf("the new audit log holds a line for a hostile %s:\n%s", PreFrameDroppedName, log)
			}
			if after := snapshotPath(t, name); after != before {
				t.Fatalf("%s after the rotate: %+v, want it as it was: %+v", PreFrameDroppedName, after, before)
			}
			if after := snapshotPath(t, other); after != otherBefore {
				t.Fatalf("the other file after the rotate: %+v, want it as it was: %+v", after, otherBefore)
			}
		})
	}
}

// pathSnapshot is what TestRotateAuditIgnoresHostileDropped compares of a
// name: its lstat identity and mode, its link target, and a regular file's
// bytes.
type pathSnapshot struct {
	exists  bool
	mode    fs.FileMode
	ino     uint64
	nlink   uint64
	target  string
	content string
}

func snapshotPath(t *testing.T, path string) pathSnapshot {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if err == unix.ENOENT {
			return pathSnapshot{}
		}
		t.Fatal(err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := pathSnapshot{exists: true, mode: fi.Mode(), ino: uint64(st.Ino), nlink: uint64(st.Nlink)}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		if snap.target, err = os.Readlink(path); err != nil {
			t.Fatal(err)
		}
	case fi.Mode().IsRegular():
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		snap.content = string(b)
	}
	return snap
}
