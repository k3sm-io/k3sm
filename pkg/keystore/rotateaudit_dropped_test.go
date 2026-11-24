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
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		`"source":"unaudited","dropped":2,"class":"unaudited"}`,
	} {
		if !strings.HasSuffix(lines[i], want) || !strings.Contains(lines[i], `"op":"refused","via":"root","caller":{"uid":0}`) {
			t.Fatalf("line %d is %s, want a via-root summary ending %s", i, lines[i], want)
		}
		if _, _, ok := preFrameCharge([]byte(lines[i] + "\n")); ok {
			t.Fatalf("line %d is charged to the pre-frame part: %s", i, lines[i])
		}
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

// TestRotateAuditIgnoresHostileDropped: a server-counts file rotate cannot
// read (it does not parse, the unaudited count on a uid line or a class
// it does not know included; it is not the service user's 0600 file; it is
// a symlink) never blocks the rotation: the new audit log carries no count
// line and the file is left as it was, for doctor to report.
func TestRotateAuditIgnoresHostileDropped(t *testing.T) {
	h := preFrameDroppedHeader
	cases := []struct {
		name string
		body string
		mode os.FileMode
		link bool
	}{
		{"no-header", "1001 login 2\n", 0o600, false},
		{"unaudited-on-a-uid-line", h + "1001 unaudited 2\n", 0o600, false},
		{"unknown-class", h + "1001 postframe 2\n", 0o600, false},
		{"post-frame-out-of-order", h + "others post-frame 1\n1001 post-frame 2\n", 0o600, false},
		{"over-the-bound", h + strings.Repeat("1 login 1\n", maxPreFrameDroppedSize/10+1), 0o600, false},
		{"mode-0644", h + "1001 post-frame 2\nothers unaudited 1\n", 0o644, false},
		{"symlink", h + "others unaudited 1\n", 0o600, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := fileLogScope(t)
			p := filepath.Join(s.dir, PreFrameDroppedName)
			target := p
			if tc.link {
				target = filepath.Join(t.TempDir(), "counts")
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(target, []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
				t.Fatalf("a hostile counts file blocked the rotation: %v", err)
			}
			if log := readLog(t, s, auditLogName); len(log) != 0 {
				t.Fatalf("the new audit log carries %q, want no count line", log)
			}
			after, err := os.ReadFile(target)
			if err != nil || string(after) != tc.body {
				t.Fatalf("the counts file after the rotate: %q %v, want it as it was", after, err)
			}
			if tc.link {
				if fi, err := os.Lstat(p); err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("the symlink after the rotate: %v %v", fi, err)
				}
			}
		})
	}
}
