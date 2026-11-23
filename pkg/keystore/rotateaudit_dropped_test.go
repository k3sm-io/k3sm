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
// persisted pre-frame refusal counts at the start of the new audit log, one
// summary line per class via root, charged to no uid and to no pre-frame
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
	writeDropped(t, s, d)
	l := s.ServerLogs()
	t.Cleanup(func() { _ = l.Close() })
	if got := l.PendingDropped(1001); got != 2 {
		t.Fatalf("the server opened with %d pending for 1001, want 2", got)
	}
	if _, err := s.RotateAudit(context.Background(), &inoRecorder{}, false); err != nil {
		t.Fatal(err)
	}
	log := readLog(t, s, auditLogName)
	lines := strings.Split(strings.TrimSuffix(string(log), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("the new audit log holds %d lines, want one per class with a count:\n%s", len(lines), log)
	}
	for i, want := range []string{`"result":"dropped","charge":"reconciler","source":"pre-frame","dropped":9,"class":"login"}`, `"dropped":1,"class":"root"}`} {
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
