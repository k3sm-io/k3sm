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
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// U24: every append preflights free space on the log's descriptor and
// refuses, retryably and writing nothing, below 1 MiB plus the line.
func TestLogAppendPreflightsFreeSpace(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	var asked int
	free := func(int) (uint64, error) { asked++; return logFreeMargin, nil }
	s.userFloor.(*fileFloorLog).log.freeSpace = free
	s.auditSink.(*fileAuditLog).log.freeSpace = free
	snap := treeSnapshot(t, server)
	floor, audit := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, errLogNoSpace) {
		t.Fatalf("put with too little free space: %v, want errLogNoSpace", err)
	}
	if asked == 0 {
		t.Fatal("free space was not asked")
	}
	if errors.Is(errLogNoSpace, ErrCorrupt) {
		t.Fatal("a refusal for space is damage")
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(floor, readLog(t, s, userFloorLogName)) || !bytes.Equal(audit, readLog(t, s, auditLogName)) {
		t.Fatal("a line was appended with too little free space")
	}
}

// A revocation's lines (rm's tombstone, a withdraw's floor line, and their
// audit lines) are exempt from the free-space margin: they keep only a
// minimal check, the line plus revokeFreeSlack, so a nearly full volume does
// not stop a revocation from being recorded. Below the minimal check the line
// is refused and the revocation is reported as after a commit.
func TestRevocationLinesSkipFreeMargin(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	userPut(t, u, "user/1001/other", "v")
	avail := uint64(logFreeMargin / 2)
	free := func(int) (uint64, error) { return avail, nil }
	s.userFloor.(*fileFloorLog).log.freeSpace = free
	s.auditSink.(*fileAuditLog).log.freeSpace = free
	floor, audit := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm below the free-space margin: %v, want its tombstone and audit line written", err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw below the free-space margin: %v, want its lines written", err)
	}
	if got := readLog(t, s, userFloorLogName); len(got) <= len(floor) {
		t.Fatal("no floor line was appended for the revocations")
	}
	if got := readLog(t, s, auditLogName); len(got) <= len(audit) {
		t.Fatal("no audit line was appended for the revocations")
	}
	// A grant is still held to the margin.
	if _, err := u.Put(ctx, "user/1001/third", KindOpaque, []byte("v")); !errors.Is(err, errLogNoSpace) {
		t.Fatalf("put below the margin: %v, want errLogNoSpace", err)
	}
	// Below the minimal check even a revocation's line is refused, and an
	// rm, which buries before it removes, removes nothing.
	avail = 64
	snap := readLog(t, s, userFloorLogName)
	err := u.Delete(ctx, "user/1001/other")
	if err == nil || errors.Is(err, errCommitted) || !errors.Is(err, errLogNoSpace) {
		t.Fatalf("rm with almost no space: %v, want it refused for space with nothing removed", err)
	}
	if !bytes.Equal(snap, readLog(t, s, userFloorLogName)) {
		t.Fatal("a tombstone was appended with almost no space")
	}
	if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "other", currentName)); err != nil {
		t.Fatalf("the entry's pointer after a refused rm: %v, want it kept", err)
	}
}

// A revocation's line for a key the floor already holds is never refused by
// the key bound, even with the floor at it.
func TestRevocationLineAtKeyBound(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	l := s.userFloor.(*fileFloorLog).log
	if err := s.userFloor.check(); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.maxKeys = l.state.keys
	l.mu.Unlock()
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw with the floor at its key bound: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm with the floor at its key bound: %v", err)
	}
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("current after rm: %v", err)
	}
}

// The revocation slack covers two 4 KiB blocks, as many as one line can
// newly touch when it straddles a block boundary, plus the longest line: a
// revocation's line is refused, with nothing removed, on a volume with two
// blocks free.
func TestRevokeFreeSlackCoversTwoBlocks(t *testing.T) {
	if revokeFreeSlack < 2*(4<<10)+maxLogLine {
		t.Fatalf("revokeFreeSlack is %d, want at least two 4 KiB blocks plus maxLogLine (%d)", revokeFreeSlack, 2*(4<<10)+maxLogLine)
	}
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	s.userFloor.(*fileFloorLog).log.freeSpace = func(int) (uint64, error) { return 2 * (4 << 10), nil }
	err := u.Delete(ctx, "user/1001/token")
	if err == nil || errors.Is(err, errCommitted) || !errors.Is(err, errLogNoSpace) {
		t.Fatalf("rm with two blocks free: %v, want it refused before any removal", err)
	}
	if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token", currentName)); err != nil {
		t.Fatalf("the entry's pointer after the refused rm: %v", err)
	}
}

// blockVolume is a fake volume both logs share: free space as an
// unprivileged writer sees it, which every append's reservation takes in
// whole logBlock blocks, as the file system allocates them.
type blockVolume struct{ avail uint64 }

func (v *blockVolume) install(t *testing.T, s *FileStore) {
	t.Helper()
	free := func(int) (uint64, error) { return v.avail, nil }
	reserve := func(_ *os.File, n int64) error {
		blocks := uint64(n+logBlock-1) / logBlock * logBlock
		if blocks > v.avail {
			return errors.New("injected: no space for the reservation")
		}
		v.avail -= blocks
		return nil
	}
	for _, l := range []*appendLog{s.userFloor.(*fileFloorLog).log, s.auditSink.(*fileAuditLog).log} {
		l.freeSpace, l.reserve = free, reserve
	}
}

// For every free-space value near the edge, an rm either is refused before
// anything is written, or its burial and its audit line both land: the
// burial's preflight covers its own block-rounded consumption and the
// audit append's preflight after it.
func TestRmBurialFreeSpaceCoversItsAuditLine(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	v := &blockVolume{}
	v.install(t, s)
	refused, landed := 0, 0
	for avail := uint64(revokeFreeSlack); avail <= revokeFreeSlack+3*logBlock+2*maxAppendLine; avail += 256 {
		name := fmt.Sprintf("e%d", avail)
		v.avail = 1 << 40
		userPut(t, u, "user/1001/"+name, "a value")
		v.avail = avail
		floorBefore, auditBefore := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
		err := u.Delete(ctx, "user/1001/"+name)
		floorAfter, auditAfter := readLog(t, s, userFloorLogName), readLog(t, s, auditLogName)
		buried := bytes.Contains(floorAfter[len(floorBefore):], []byte(" rm "))
		audited := false
		for _, l := range bytes.Split(auditAfter[len(auditBefore):], []byte{'\n'}) {
			if r, perr := parseAuditLine(l); perr == nil && r.Op == "rm" && (r.Result == auditResultOK || r.Result == auditResultCommitted) {
				audited = true
			}
		}
		if err != nil && !errors.Is(err, errCommitted) {
			if !errors.Is(err, errLogNoSpace) || buried || audited {
				t.Fatalf("free %d: a refused rm (%v) wrote: tombstones %v, a committed audit line %v", avail, err, buried, audited)
			}
			if _, lerr := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, name, currentName)); lerr != nil {
				t.Fatalf("free %d: the entry's pointer after a refused rm: %v", avail, lerr)
			}
			refused++
			continue
		}
		if !buried || !audited {
			t.Fatalf("free %d: rm (%v): buried %v, audited %v; want both", avail, err, buried, audited)
		}
		landed++
	}
	if refused == 0 || landed == 0 {
		t.Fatalf("the sweep met %d refusals and %d landings; want both, so it spans the edge", refused, landed)
	}
}
