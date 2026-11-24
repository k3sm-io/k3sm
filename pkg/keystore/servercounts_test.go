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
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
)

// restarted is s as a new server process sees it: the same directories and
// configuration, nothing held in memory.
func restarted(s *FileStore) *FileStore {
	s2 := *s
	s2.counts = newServerCounts()
	s2.audit = new(auditState)
	return &s2
}

// TestPreFrameDroppedParsesServerCounts: the server-counts file carries
// the post-frame count by uid, with an others line past the named uids,
// and the unaudited count on its others line alone; the parser refuses the
// unaudited count on a uid line.
func TestPreFrameDroppedParsesServerCounts(t *testing.T) {
	if !slices.Equal(countClasses[:len(preFrameClasses)], preFrameClasses) {
		t.Fatalf("countClasses %v does not start with the pre-frame classes %v", countClasses, preFrameClasses)
	}
	h := preFrameDroppedHeader
	good := h + "501 login 2\n501 post-frame 3\n502 post-frame 1\nothers post-frame 4\nothers unaudited 5\n"
	d, err := parsePreFrameDropped([]byte(good))
	if err != nil {
		t.Fatalf("parse %q: %v", good, err)
	}
	if got := string(encodePreFrameDropped(d)); got != good {
		t.Fatalf("round trip = %q, want %q", got, good)
	}
	want := PreFrameDroppedCounts{Refusals: 2, UIDs: 1, PostFrame: 8, PostFrameUIDs: 2, Unaudited: 5}
	if c := d.counts(); c != want {
		t.Fatalf("counts = %+v, want %+v", c, want)
	}
	for _, b := range []string{
		h + "501 unaudited 1\n",
		h + "others unaudited 1\nothers post-frame 1\n",
		h + "others post-frame 1\n501 post-frame 1\n",
		h + "501 post-frame 0\n",
		h + "501 postframe 1\n",
	} {
		if _, err := parsePreFrameDropped([]byte(b)); !errors.Is(err, errPreFrameDroppedMalformed) {
			t.Errorf("parse %q = %v, want malformed", b, err)
		}
	}
	// An unaudited count held under a uid key is written on its others line.
	d = newPreFrameDropped()
	d.uids[preFrameKey{countClassUnaudited, 7}] = 2
	if got := string(encodePreFrameDropped(d)); got != h+"others unaudited 2\n" {
		t.Fatalf("encoded %q, want the unaudited count on its others line", got)
	}
}

// TestPreFrameDroppedEncoderFitsWorstCase: the encoder's output parses and
// fits the file's bound with every named uid carrying every class a uid
// line may, the longest uids and counts, past the uid limit, and every
// others line.
func TestPreFrameDroppedEncoderFitsWorstCase(t *testing.T) {
	d := newPreFrameDropped()
	for i := range preFrameDroppedUIDs + 10 {
		for _, c := range countClasses {
			d.uids[preFrameKey{c, math.MaxUint32 - uint32(i)}] = math.MaxUint64
		}
	}
	for _, c := range countClasses {
		d.others[c] = math.MaxUint64
	}
	b := encodePreFrameDropped(d)
	if len(b) > maxPreFrameDroppedSize {
		t.Fatalf("encoded %d bytes, over the bound of %d", len(b), maxPreFrameDroppedSize)
	}
	got, err := parsePreFrameDropped(b)
	if err != nil {
		t.Fatalf("the encoder's worst case does not parse: %v", err)
	}
	if n := strings.Count(string(b), "\n"); n != 1+preFrameDroppedUIDs*(countClassesN-1)+countClassesN {
		t.Fatalf("encoded %d lines", n)
	}
	if got.others[countClassUnaudited] != math.MaxUint64 {
		t.Fatalf("the unaudited count read back as %d", got.others[countClassUnaudited])
	}
}

// TestUnauditedOpsSurvivesRestart: the unaudited count is persisted in the
// server-counts file as the store's ServerLogs writes it, read back by the
// next server's ServerLogs, and shown by the read-only doctor read.
func TestUnauditedOpsSurvivesRestart(t *testing.T) {
	s, _ := newServerLogsStore(t)
	droppedClock(s)
	l := s.ServerLogs()
	s.countUnaudited()
	s.countUnaudited()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := droppedFile(t, s), preFrameDroppedHeader+"others unaudited 2\n"; got != want {
		t.Fatalf("persisted %q, want %q", got, want)
	}
	s2 := restarted(s)
	if n := s2.UnauditedOps(); n != 0 {
		t.Fatalf("a store with no ServerLogs read %d", n)
	}
	l2 := s2.ServerLogs()
	t.Cleanup(func() { _ = l2.Close() })
	if n := s2.UnauditedOps(); n != 2 {
		t.Fatalf("UnauditedOps after a restart = %d, want 2", n)
	}
	s2.countUnaudited()
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	c, err := s2.PreFrameDropped(t.Context())
	if err != nil || c != (PreFrameDroppedCounts{Unaudited: 3}) {
		t.Fatalf("PreFrameDropped = %+v, %v; want 3 unaudited", c, err)
	}
}

// TestServerLogsPersistsPostFrameDropped: the post-frame count the bridge
// hands the store is written beside the pre-frame counts by the one
// writer, read back after a restart, never written as a pre-frame summary,
// and taken out once summarized.
func TestServerLogsPersistsPostFrameDropped(t *testing.T) {
	s, auditPath := newServerLogsStore(t)
	tick := droppedClock(s)
	ctx := t.Context()
	l := s.ServerLogs()
	restore := hideAudit(t, auditPath)
	if err := l.Dropped(ctx, 1001, 1); err == nil {
		t.Fatal("Dropped wrote with no audit log")
	}
	tick(preFrameDroppedEvery)
	s.AddPostFrameDropped(1001, 3)
	s.AddPostFrameDropped(1002, 1)
	if got, want := droppedFile(t, s), preFrameDroppedHeader+"1001 login 1\n1001 post-frame 3\n"; got != want {
		t.Fatalf("persisted %q, want %q (the second change waits a second)", got, want)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := droppedFile(t, s), preFrameDroppedHeader+"1001 login 1\n1001 post-frame 3\n1002 post-frame 1\n"; got != want {
		t.Fatalf("persisted at close %q, want %q", got, want)
	}
	restore()
	s2 := restarted(s)
	l2 := s2.ServerLogs()
	t.Cleanup(func() { _ = l2.Close() })
	if n := s2.PostFrameDropped(1001); n != 3 {
		t.Fatalf("PostFrameDropped(1001) after a restart = %d, want 3", n)
	}
	if n := l2.PendingDropped(1001); n != 1 {
		t.Fatalf("pre-frame pending for 1001 = %d, want 1: the post-frame count is not a pre-frame one", n)
	}
	if err := l2.Dropped(ctx, PreFrameNoUID, 0); err != nil {
		t.Fatal(err)
	}
	if log := string(readLog(t, s2, auditLogName)); strings.Contains(log, `"class":"post-frame"`) || !strings.Contains(log, `"class":"login"`) {
		t.Fatalf("the pre-frame summaries wrote %s, want the login count alone", log)
	}
	tick(preFrameDroppedEvery)
	s2.PostFrameSummarized(1001, 3)
	if got, want := droppedFile(t, s2), preFrameDroppedHeader+"1002 post-frame 1\n"; got != want {
		t.Fatalf("persisted after the summary %q, want %q", got, want)
	}
	c, err := s2.PreFrameDropped(ctx)
	if err != nil || c != (PreFrameDroppedCounts{PostFrame: 1, PostFrameUIDs: 1}) {
		t.Fatalf("PreFrameDropped = %+v, %v; want 1 post-frame for 1 uid", c, err)
	}
}
