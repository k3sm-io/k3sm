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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// droppedClock sets s's clock to a fixed time and returns the function that
// moves it on.
func droppedClock(s *FileStore) func(time.Duration) {
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return func(d time.Duration) { now = now.Add(d) }
}

// hideAudit moves the audit log away, so every append is dropped, and
// returns the function that puts it back.
func hideAudit(t *testing.T, auditPath string) func() {
	t.Helper()
	aside := auditPath + ".aside"
	if err := os.Rename(auditPath, aside); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.Rename(aside, auditPath); err != nil {
			t.Fatal(err)
		}
	}
}

// droppedFile reads s's persisted pre-frame refusal count.
func droppedFile(t *testing.T, s *FileStore) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dir, PreFrameDroppedName))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestPreFrameDroppedSurvivesReopen: dropped pre-frame counts are written
// to the store directory, 0600, and a ServerLogs opened after Close starts
// from them.
func TestPreFrameDroppedSurvivesReopen(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	droppedClock(s)
	ctx := t.Context()
	restore := hideAudit(t, auditPath)
	l := s.ServerLogs()
	if err := l.Dropped(ctx, 1001, 5); err == nil {
		t.Fatal("Dropped wrote with no audit log")
	}
	if err := l.Refused(ctx, 0, preFrameReasonRoot); err == nil {
		t.Fatal("Refused wrote with no audit log")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	want := preFrameDroppedHeader + "0 root 1\n1001 login 5\n"
	if got := droppedFile(t, s); got != want {
		t.Fatalf("persisted %q, want %q", got, want)
	}
	fi, err := os.Lstat(filepath.Join(s.dir, PreFrameDroppedName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("persisted file: %v %v, want mode 0600", fi, err)
	}
	restore()
	l2 := s.ServerLogs()
	t.Cleanup(func() { _ = l2.Close() })
	if got := l2.PendingDropped(1001); got != 5 {
		t.Fatalf("reopened with %d pending for 1001, want 5", got)
	}
	if got := l2.PendingDropped(0); got != 1 {
		t.Fatalf("reopened with %d pending for 0, want 1", got)
	}
	c, err := s.PreFrameDropped(ctx)
	if err != nil || c != (PreFrameDroppedCounts{Refusals: 6, UIDs: 2}) {
		t.Fatalf("PreFrameDropped = %+v, %v; want 6 refusals for 2 uids", c, err)
	}
}

// TestPreFrameDroppedClearedOnceWritten: once every count reaches the
// audit log in a summary line, the persisted file is emptied to its header.
func TestPreFrameDroppedClearedOnceWritten(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	tick := droppedClock(s)
	ctx := t.Context()
	restore := hideAudit(t, auditPath)
	l := s.ServerLogs()
	t.Cleanup(func() { _ = l.Close() })
	if err := l.Dropped(ctx, 1001, 2); err == nil {
		t.Fatal("Dropped wrote with no audit log")
	}
	if got := droppedFile(t, s); got != preFrameDroppedHeader+"1001 login 2\n" {
		t.Fatalf("persisted %q", got)
	}
	restore()
	tick(time.Second)
	if err := l.Dropped(ctx, 1001, 0); err != nil {
		t.Fatal(err)
	}
	if got := droppedFile(t, s); got != preFrameDroppedHeader {
		t.Fatalf("persisted %q after the summary landed, want the header alone", got)
	}
	b, err := os.ReadFile(auditPath)
	if err != nil || !bytes.Contains(b, []byte(`"dropped":2`)) {
		t.Fatalf("the summary line is not in the log: %q %v", b, err)
	}
}

// TestPreFrameDroppedCoalesced: changes inside a second of the last write
// wait for the next call past it; Close writes what is left.
func TestPreFrameDroppedCoalesced(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	tick := droppedClock(s)
	ctx := t.Context()
	hideAudit(t, auditPath)
	l := s.ServerLogs()
	_ = l.Dropped(ctx, 1001, 1)
	_ = l.Dropped(ctx, 1001, 1)
	if got := droppedFile(t, s); got != preFrameDroppedHeader+"1001 login 1\n" {
		t.Fatalf("a second write inside the second: %q", got)
	}
	tick(time.Second)
	_ = l.Dropped(ctx, 1001, 1)
	if got := droppedFile(t, s); got != preFrameDroppedHeader+"1001 login 3\n" {
		t.Fatalf("no write past the second: %q", got)
	}
	_ = l.Dropped(ctx, 1001, 1)
	_ = l.Close()
	if got := droppedFile(t, s); got != preFrameDroppedHeader+"1001 login 4\n" {
		t.Fatalf("Close did not write the change left: %q", got)
	}
}

// TestPreFrameDroppedFoldsOthers: past 256 uids the persisted file folds
// the rest into one others line per class, and a reopen keeps their count.
func TestPreFrameDroppedFoldsOthers(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	droppedClock(s)
	ctx := t.Context()
	restore := hideAudit(t, auditPath)
	l := s.ServerLogs()
	for i := range preFrameDroppedUIDs + 1 {
		l.pending[preFrameKey{preFrameClassLogin, uint32(1000 + i)}] = 1
	}
	l.droppedDirty = true
	_ = l.Dropped(ctx, 1000+preFrameDroppedUIDs, 1) // the 257th uid, now at 2
	_ = l.Close()
	got := droppedFile(t, s)
	if n := strings.Count(got, "\n"); n != 1+preFrameDroppedUIDs+1 {
		t.Fatalf("persisted %d lines, want the header, 256 uids and one others line", n)
	}
	if !strings.HasSuffix(got, "\nothers login 2\n") || strings.Contains(got, fmt.Sprintf("\n%d ", 1000+preFrameDroppedUIDs)) {
		t.Fatalf("the 257th uid is not folded into others: %q", got[len(got)-64:])
	}
	restore()
	c, err := s.PreFrameDropped(ctx)
	if err != nil || c != (PreFrameDroppedCounts{Refusals: preFrameDroppedUIDs + 2, UIDs: preFrameDroppedUIDs, Others: 2}) {
		t.Fatalf("PreFrameDropped = %+v, %v", c, err)
	}
	l2 := s.ServerLogs()
	t.Cleanup(func() { _ = l2.Close() })
	if l2.others[preFrameClassLogin] != 2 {
		t.Fatalf("reopened with others %v, want login 2", l2.others)
	}
}

// TestPreFrameDroppedCorruptFile: a persisted file that does not parse is
// reported, never reset: the server keeps its counts in memory and leaves
// the file as it is, and the read-only read names it.
func TestPreFrameDroppedCorruptFile(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	droppedClock(s)
	ctx := t.Context()
	p := filepath.Join(s.dir, PreFrameDroppedName)
	const corrupt = "not a count\n"
	if err := os.WriteFile(p, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	hideAudit(t, auditPath)
	l := s.ServerLogs()
	if err := l.DroppedPersistError(); !errors.Is(err, errPreFrameDroppedMalformed) {
		t.Fatalf("DroppedPersistError = %v, want the malformed file", err)
	}
	_ = l.Dropped(ctx, 1001, 3)
	_ = l.Close()
	if got := droppedFile(t, s); got != corrupt {
		t.Fatalf("the unreadable file was overwritten: %q", got)
	}
	if got := l.PendingDropped(1001); got != 3 {
		t.Fatalf("pending %d in memory, want 3", got)
	}
	if _, err := s.PreFrameDropped(ctx); !errors.Is(err, errPreFrameDroppedMalformed) {
		t.Fatalf("PreFrameDropped = %v, want the malformed file", err)
	}
}

// TestPreFrameDroppedParseStrict: the format's reader refuses everything
// its writer never writes.
func TestPreFrameDroppedParseStrict(t *testing.T) {
	h := preFrameDroppedHeader
	for _, b := range []string{
		"",
		"k3sm-preframe-dropped 2\n",
		h + "501 login 1",
		h + "501 login 0\n",
		h + "0501 login 1\n",
		h + "501 login 01\n",
		h + "501 nobody 1\n",
		h + "501  login 1\n",
		h + "501 login 1 x\n",
		h + "502 login 1\n501 login 1\n",
		h + "501 login 1\n501 login 1\n",
		h + "others login 1\n501 login 1\n",
		h + "others root 1\nothers login 1\n",
		h + "4294967296 login 1\n",
		h + "501 login 18446744073709551616\n",
		h + "501 login 1\n" + strings.Repeat(" ", preFrameDroppedMaxLine) + "\n",
	} {
		if _, err := parsePreFrameDropped([]byte(b)); !errors.Is(err, errPreFrameDroppedMalformed) {
			t.Errorf("parse %q = %v, want malformed", b, err)
		}
	}
	d := newPreFrameDropped()
	d.uids[preFrameKey{preFrameClassNoUID, PreFrameNoUID}] = ^uint64(0)
	d.uids[preFrameKey{preFrameClassRoot, 0}] = 1
	d.others[preFrameClassSystemHigh] = 7
	got, err := parsePreFrameDropped(encodePreFrameDropped(d))
	if err != nil || len(got.uids) != 2 || got.others[preFrameClassSystemHigh] != 7 {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if n := len(encodePreFrameDropped(d)); n > maxPreFrameDroppedSize {
		t.Fatalf("encoded %d bytes, over the cap", n)
	}
}
