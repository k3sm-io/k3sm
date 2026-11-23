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
	"strings"
	"testing"
)

// realLines puts and deletes in u's scope 1001 and returns the generations
// of its live token and its buried gone.
func realLines(t *testing.T, s *FileStore, server string, u *UserScope) (token, gone [generationSize]byte) {
	t.Helper()
	userPut(t, u, "user/1001/gone", "deleted later")
	gone = entryGen(t, server, "1001", "gone")
	if err := u.Delete(context.Background(), "user/1001/gone"); err != nil {
		t.Fatal(err)
	}
	return entryGen(t, server, "1001", "token"), gone
}

// assertRealKept fails unless the rebuilt floor holds token live and gone
// buried.
func assertRealKept(t *testing.T, s *FileStore, token, gone [generationSize]byte) {
	t.Helper()
	var haveToken, haveGone bool
	for _, r := range floorRecs(t, s) {
		haveToken = haveToken || (r.key.scope == "user/1001" && r.key.name == "token" && r.key.gen == token && !r.tomb)
		haveGone = haveGone || (r.key.scope == "user/1001" && r.key.name == "gone" && r.key.gen == gone && r.tomb)
	}
	if !haveToken || !haveGone {
		t.Fatalf("the rebuild lost a real line: token %v, gone's tombstone %v", haveToken, haveGone)
	}
}

// A flood of forged tombstones for uids with no scope at all, which
// rm-scope cannot list, does not wedge the rebuild: it keeps every real
// line, admits the absent scopes only within their share and the key
// bound, and counts the rest as absent scopes.
func TestRebuildForgedAbsentTombstoneFlood(t *testing.T) {
	s, server, u := fileLogScope(t)
	token, gone := realLines(t, s, server, u)
	var flood bytes.Buffer
	const forged = 300
	for i := range forged {
		line, err := tombLine(userScopeOf(uint32(6000+i%30)), fmt.Sprintf("t%d", i), [generationSize]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		flood.Write(line)
	}
	appendLogBytes(t, s, userFloorLogName, flood.Bytes())
	const bound = 12
	s.floorLog().maxKeys, s.floorLog().maxShare = bound, 4
	rep, _ := rebuild(t, s)
	// 3 real keys (the deliveries record, token, gone), 9 forged ones.
	if rep.Keys != bound || rep.AbsentScopes != forged-(bound-3) || rep.PastShare != 0 {
		t.Fatalf("the rebuild kept %d keys, %d absent and %d past the share, want %d, %d and 0", rep.Keys, rep.AbsentScopes, rep.PastShare, bound, forged-(bound-3))
	}
	assertRealKept(t, s, token, gone)
}

// A flood of forged live lines for one real uid, other generations with
// no entry, is trimmed to the uid's share, oldest first: its real lines,
// older, are kept, and the excess is counted as past the share.
func TestRebuildForgedLiveFloodOneRealUIDTrimmed(t *testing.T) {
	s, server, u := fileLogScope(t)
	token, gone := realLines(t, s, server, u)
	var flood bytes.Buffer
	const forged = 100
	for i := range forged {
		line, err := floorLine("user/1001", fmt.Sprintf("t%d", i), [generationSize]byte{byte(i)}, 7)
		if err != nil {
			t.Fatal(err)
		}
		flood.Write(line)
	}
	appendLogBytes(t, s, userFloorLogName, flood.Bytes())
	const share = 6
	s.floorLog().maxKeys, s.floorLog().maxShare = 1000, share
	rep, _ := rebuild(t, s)
	// The share holds the deliveries record, token, gone and 3 forged.
	if rep.Keys != share || rep.PastShare != forged-(share-3) {
		t.Fatalf("the rebuild kept %d keys and %d past the share, want %d and %d", rep.Keys, rep.PastShare, share, forged-(share-3))
	}
	assertRealKept(t, s, token, gone)
}

// A tombstone the writer took past the uid's share, as it takes a
// revocation's, survives the rebuild: dropping it would reopen a
// copy-back of the deleted entry.
func TestRebuildKeepsRevocationTombstonePastShare(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for i := range 4 {
		userPut(t, u, fmt.Sprintf("user/1001/e%d", i), "v")
	}
	gone := entryGen(t, server, "1001", "e0")
	l := syncedFloor(t, s)
	l.mu.Lock()
	l.maxShare = l.state.uidKeys[1001]
	l.mu.Unlock()
	if err := u.Delete(ctx, "user/1001/e0"); err != nil {
		t.Fatalf("rm at the share: %v, want the revocation path to take it", err)
	}
	// The scope's keys on disk alone fill the share at rebuild.
	s.floorLog().maxKeys, s.floorLog().maxShare = 1000, 2
	rep, _ := rebuild(t, s)
	kept := false
	for _, r := range floorRecs(t, s) {
		kept = kept || (r.key.scope == "user/1001" && r.key.name == "e0" && r.key.gen == gone && r.tomb)
	}
	if !kept || rep.PastShare != 0 {
		t.Fatalf("the rebuild kept the tombstone past the share: %v, %d past the share; want it kept and 0", kept, rep.PastShare)
	}
}

// A flood of forged tombstones for a present uid is never trimmed: past
// the key bound it ends in the one refusal, naming the uid's scope, and
// rm-scope of that scope lets the rebuild run.
func TestRebuildForgedTombstoneFloodPresentUIDRefusesThenRmScope(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	token, gone := realLines(t, s, server, u)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "x")
	var flood bytes.Buffer
	const forged = 40
	for i := range forged {
		line, err := tombLine("user/1002", fmt.Sprintf("t%d", i), [generationSize]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		flood.Write(line)
	}
	appendLogBytes(t, s, userFloorLogName, flood.Bytes())
	s.floorLog().maxKeys, s.floorLog().maxShare = 20, 4
	before := readLog(t, s, userFloorLogName)
	_, err := s.RebuildFloor(ctx, &attrRecorder{})
	if !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "the scopes with the most keys: user/1002") || !strings.Contains(err.Error(), "rm-scope") {
		t.Fatalf("a rebuild under a forged tombstone flood: %v, want the refusal naming user/1002 and rm-scope", err)
	}
	if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
		t.Fatal("the refused rebuild changed the floor")
	}
	// The flooded floor is past the steady-state reader's bound, so the
	// delivery record cannot be checked against it: removed and listed,
	// committed, deliveries not confirmed.
	if res, err := s.RemoveScope(ctx, 1002); !Committed(err) || !res.Recorded || !strings.Contains(err.Error(), "deliveries are not confirmed") {
		t.Fatalf("rm-scope user/1002: %v, %v; want listed, committed, deliveries not confirmed", res.Recorded, err)
	} else {
		checkRmScopeCommands(t, strings.ReplaceAll(err.Error(), "user/1002", "user/1001"))
	}
	rep, _ := rebuild(t, s)
	if rep.RemovedKeys == 0 {
		t.Fatalf("the rebuild after rm-scope dropped no removed keys: %+v", rep)
	}
	assertRealKept(t, s, token, gone)
}

// Absent scopes' tombstones are admitted in first-appearance order, with
// no share: the first uid seen gets all of its tombstones whatever the
// interleaving, and the next only what the key bound leaves.
func TestOldFloorReaderAbsentFirstAppearanceOrder(t *testing.T) {
	var b bytes.Buffer
	for i := range 6 {
		for _, uid := range []uint32{7001, 7002, 7003} {
			line, err := tombLine(userScopeOf(uid), fmt.Sprintf("t%d", i), [generationSize]byte{})
			if err != nil {
				t.Fatal(err)
			}
			b.Write(line)
		}
	}
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	o, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, 10, 10, 4, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for k := range o.buried {
		count[k.scope]++
	}
	if count["user/7001"] != 4 || count["user/7002"] != 4 || count["user/7003"] != 2 || o.absent != 18-10 {
		t.Fatalf("admitted %v, %d absent, want 4, 4, 2 (each uid up to the share, in first-appearance order) and 8", count, o.absent)
	}
}

// Real scopes alone past the key bound refuse, naming the scopes with the
// most keys, and rm-scope of one is the repair the text names.
func TestOldFloorReaderRefusesRealScopesPastBound(t *testing.T) {
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{"user/1001": true, "user/1002": true}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	for i := range 3 {
		in.disk[floorKey{"user/1001", fmt.Sprintf("a%d", i), [generationSize]byte{}}] = 1
		in.disk[floorKey{"user/1002", fmt.Sprintf("b%d", i), [generationSize]byte{}}] = 1
	}
	line, err := tombLine("user/1002", "extra", [generationSize]byte{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = readOldFloorFrom(bytes.NewReader(line), int64(len(line)), in, 6, 6, 8, maxLogLine)
	if err == nil || !strings.Contains(err.Error(), "user/1002 (4 keys)") || !strings.Contains(err.Error(), "rm-scope") {
		t.Fatalf("readOldFloorFrom: %v, want a refusal naming user/1002 (4 keys) and rm-scope", err)
	}
}

// Rebuild bounds what it collects from disk: once the keys or entry names
// of the scopes on disk pass the key bound it stops and refuses, before
// reading the old floor, naming the scopes with the most entries and
// rm-scope, and changes nothing.
func TestRebuildRefusesDiskPastBound(t *testing.T) {
	s, _, _ := fileLogScope(t)
	v := userScope(t, s, 1002)
	userPut(t, v, "user/1002/x", "x")
	userPut(t, v, "user/1002/y", "y")
	before := readLog(t, s, userFloorLogName)
	s.floorLog().maxKeys = 3
	_, err := s.RebuildFloor(context.Background(), &attrRecorder{})
	if !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), "the scopes with the most entries: user/") || !strings.Contains(err.Error(), "rm-scope") {
		t.Fatalf("a rebuild with more keys on disk than the bound: %v, want a refusal naming the top scopes and rm-scope", err)
	}
	if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
		t.Fatal("the refused rebuild changed the floor")
	}
}

// Absent scopes' live lines come only after every absent tombstone is in,
// per uid up to the share less its tombstones, in first-appearance order;
// with a tombstone left out, no absent live line is admitted.
func TestOldFloorReaderAbsentLiveAfterTombstones(t *testing.T) {
	var b bytes.Buffer
	add := func(line []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	for i := range 6 {
		add(floorLine(userScopeOf(7001), fmt.Sprintf("l%d", i), [generationSize]byte{}, 3))
		add(floorLine(userScopeOf(7002), fmt.Sprintf("l%d", i), [generationSize]byte{}, 3))
	}
	add(tombLine(userScopeOf(7002), "t", [generationSize]byte{}))
	read := func(bound int) map[string]int {
		in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{}, names: map[nameKey]bool{}, removed: map[string]int64{}}
		o, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, bound, bound, 4, maxLogLine)
		if err != nil {
			t.Fatal(err)
		}
		count := map[string]int{}
		for k := range o.maxSeq {
			count[k.scope]++
		}
		for k := range o.buried {
			count[k.scope+" tomb"]++
		}
		return count
	}
	if got := read(7); got["user/7002 tomb"] != 1 || got["user/7001"] != 4 || got["user/7002"] != 2 {
		t.Fatalf("admitted %v, want the tombstone, 4 live of 7001 and 2 of 7002", got)
	}
	b.Reset()
	add(tombLine(userScopeOf(7001), "t1", [generationSize]byte{}))
	add(tombLine(userScopeOf(7001), "t2", [generationSize]byte{}))
	add(floorLine(userScopeOf(7002), "l", [generationSize]byte{}, 3))
	if got := read(1); got["user/7001 tomb"] != 1 || got["user/7002"] != 0 {
		t.Fatalf("admitted %v, want one tombstone and no live line once a tombstone was left out", got)
	}
}

// headroomFloor gives s a floor at the key bound holding n real tombstones
// in the revocation headroom (of n keys): the writer's revocation path
// buries n generations the floor lacks past the key bound. It returns the
// buried keys.
func headroomFloor(t *testing.T, s *FileStore, n int) []floorKey {
	t.Helper()
	fl := s.userFloor.(*fileFloorLog)
	l := syncedFloor(t, s)
	l.mu.Lock()
	l.maxKeys, l.maxHeadroom = l.state.keys, n
	l.mu.Unlock()
	var buried []floorKey
	for i := range n {
		name := fmt.Sprintf("gone%d", i)
		if err := fl.bury("user/1001", name, guid(0x30+byte(i))); err != nil {
			t.Fatalf("tombstone %d in the headroom: %v", i, err)
		}
		buried = append(buried, floorKey{"user/1001", name, guid(0x30 + byte(i))})
	}
	if err := s.userFloor.check(); err != nil {
		t.Fatalf("the floor the writer filled to the headroom reads as damage: %v", err)
	}
	return buried
}

// A floor the writer produced with real tombstones between the key bound
// and the reader's key bound rebuilds and keeps every one: rule 1 is held
// to the reader's bound, not the key bound, and the new floor reads.
func TestRebuildKeepsTombstonesInHeadroom(t *testing.T) {
	s, _, _ := fileLogScope(t)
	buried := headroomFloor(t, s, 3)
	l := s.floorLog()
	if keys := l.keyBound() + len(buried); keys != l.readKeyBound() {
		t.Fatalf("the floor holds %d keys, want the reader's key bound %d", keys, l.readKeyBound())
	}
	rep, _ := rebuild(t, s)
	if rep.Keys != l.readKeyBound() || rep.Dropped+rep.OverLong+rep.PastShare+rep.AbsentScopes+rep.RemovedKeys != 0 {
		t.Fatalf("rebuild report %+v, want %d keys and nothing dropped", rep, l.readKeyBound())
	}
	if rep.Keys > l.readKeyBound() {
		t.Fatalf("the new floor holds %d keys, past the reader's key bound %d", rep.Keys, l.readKeyBound())
	}
	kept := map[floorKey]bool{}
	for _, r := range floorRecs(t, s) {
		if r.tomb {
			kept[r.key] = true
		}
	}
	for _, k := range buried {
		if !kept[k] {
			t.Fatalf("the rebuild dropped the headroom tombstone %v", k)
		}
	}
	if err := s.userFloor.check(); err != nil {
		t.Fatalf("the rebuilt floor reads as damage: %v", err)
	}
}

// Rule 1 past the reader's key bound refuses, naming the top scopes and
// rm-scope, and changes nothing.
func TestRebuildRefusesPastReadKeyBound(t *testing.T) {
	s, _, _ := fileLogScope(t)
	headroomFloor(t, s, 3)
	before := readLog(t, s, userFloorLogName)
	l := s.floorLog()
	keys := l.readKeyBound()
	l.maxHeadroom = 2
	bound := fmt.Sprintf("the reader's key bound of %d", l.readKeyBound())
	top := fmt.Sprintf("user/1001 (%d keys)", keys)
	_, err := s.RebuildFloor(context.Background(), &attrRecorder{})
	if !errors.Is(err, errRebuildRefused) || !strings.Contains(err.Error(), bound) || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), "rm-scope") {
		t.Fatalf("a rebuild with rule 1 past the reader's key bound: %v, want a refusal naming %q, %s and rm-scope", err, bound, top)
	}
	if !bytes.Equal(before, readLog(t, s, userFloorLogName)) {
		t.Fatal("the refused rebuild changed the floor")
	}
}

// The admitted keys never pass the reader's key bound: with rule 1 in the
// headroom, rules 2 and 3 admit nothing more, and with rule 1 under the key
// bound they stop at it.
func TestOldFloorReaderAdmitsAtMostReadBound(t *testing.T) {
	var b bytes.Buffer
	add := func(line []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	for i := range 5 {
		add(tombLine("user/1001", fmt.Sprintf("t%d", i), [generationSize]byte{}))
		add(floorLine("user/1001", fmt.Sprintf("l%d", i), [generationSize]byte{}, 2))
		add(tombLine(userScopeOf(7001), fmt.Sprintf("a%d", i), [generationSize]byte{}))
	}
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{"user/1001": true}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	for _, tc := range []struct{ keyBound, readBound, want int }{{4, 6, 5}, {8, 10, 8}} {
		o, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, tc.keyBound, tc.readBound, 100, maxLogLine)
		if err != nil {
			t.Fatalf("bounds %d/%d: %v", tc.keyBound, tc.readBound, err)
		}
		if _, keys := mergeFloor(o, in.disk); keys != tc.want || keys > tc.readBound {
			t.Fatalf("bounds %d/%d: %d keys, want %d", tc.keyBound, tc.readBound, keys, tc.want)
		}
	}
}

// Rule 3's absent-scope tombstones are admitted before rule 2's present
// scopes' other live lines: a flood of forged live lines for present uids,
// each up to its share and together past the key bound, never evicts an
// absent scope's real tombstones, even when they come last in the file;
// the flood is held to what the bound leaves and the rest counted past
// the share.
func TestOldFloorReaderPresentLiveFloodKeepsAbsentTombstones(t *testing.T) {
	var b bytes.Buffer
	add := func(line []byte, err error) {
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	const bound, share = 20, 4
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	for u := range uint32(10) {
		sc := userScopeOf(7101 + u)
		in.present[sc] = true
		for i := range share {
			add(floorLine(sc, fmt.Sprintf("forged%d", i), [generationSize]byte{}, 3))
		}
	}
	for i := range 5 {
		add(tombLine(userScopeOf(7200), fmt.Sprintf("t%d", i), [generationSize]byte{}))
	}
	o, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, bound, bound, share, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	tombs := 0
	for k := range o.buried {
		if k.scope == userScopeOf(7200) {
			tombs++
		}
	}
	if tombs != share {
		t.Fatalf("the absent scope kept %d of its 5 tombstones under a forged live flood, want its share, %d", tombs, share)
	}
	if len(o.maxSeq) != bound-share || o.pastShare != 10*share-(bound-share) {
		t.Fatalf("admitted %d forged live keys and counted %d past the share; want %d and %d", len(o.maxSeq), o.pastShare, bound-share, 10*share-(bound-share))
	}
}

// splitFloor is an old floor holding, first, live lines of present uids
// 7301 on with no entry (liveUIDs uids, live each) and then tombstones of
// absent uids 7401 on (tombUIDs uids, tombs each), with the rebuild input
// that marks the present ones present.
func splitFloor(t *testing.T, liveUIDs, live, tombUIDs, tombs int) ([]byte, rebuildInput) {
	t.Helper()
	var b bytes.Buffer
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	for u := range liveUIDs {
		sc := userScopeOf(7301 + uint32(u))
		in.present[sc] = true
		for i := range live {
			line, err := floorLine(sc, fmt.Sprintf("l%d", i), [generationSize]byte{}, 3)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(line)
		}
	}
	for u := range tombUIDs {
		for i := range tombs {
			line, err := tombLine(userScopeOf(7401+uint32(u)), fmt.Sprintf("t%d", i), [generationSize]byte{})
			if err != nil {
				t.Fatal(err)
			}
			b.Write(line)
		}
	}
	return b.Bytes(), in
}

// A flood of forged tombstones for absent, unlisted uids cannot crowd out
// a present scope's live lines with no entry directory (its rollback
// protection for an entry whose directory was removed outside rm): the
// room rule 1 leaves is split evenly, the live lines need less than their
// half and are all kept, and the tombstones take the rest.
func TestOldFloorReaderAbsentTombFloodKeepsPresentLive(t *testing.T) {
	const bound, share = 20, 4
	b, in := splitFloor(t, 3, 3, 50, share)
	o, err := readOldFloorFrom(bytes.NewReader(b), int64(len(b)), in, bound, bound, share, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.maxSeq) != 9 || o.pastShare != 0 {
		t.Fatalf("kept %d of the present scopes' 9 live lines (%d past the share) under a forged tombstone flood", len(o.maxSeq), o.pastShare)
	}
	if len(o.buried) != bound-9 || o.absent != 50*share-(bound-9) {
		t.Fatalf("admitted %d forged tombstones and counted %d absent; want %d and %d", len(o.buried), o.absent, bound-9, 50*share-(bound-9))
	}
}

// The mirror case: a flood of forged live lines for present uids cannot
// crowd out absent scopes' tombstones that fit their half; the live lines
// take the rest, and each class past its room is counted as dropped.
func TestOldFloorReaderPresentLiveFloodKeepsAbsentTombsHalf(t *testing.T) {
	const bound, share = 20, 4
	b, in := splitFloor(t, 50, share, 3, 3)
	o, err := readOldFloorFrom(bytes.NewReader(b), int64(len(b)), in, bound, bound, share, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.buried) != 9 || o.absent != 0 {
		t.Fatalf("kept %d of the absent scopes' 9 tombstones (%d absent) under a forged live flood", len(o.buried), o.absent)
	}
	if len(o.maxSeq) != bound-9 || o.pastShare != 50*share-(bound-9) {
		t.Fatalf("admitted %d forged live keys and counted %d past the share; want %d and %d", len(o.maxSeq), o.pastShare, bound-9, 50*share-(bound-9))
	}
	// Both classes past their halves: each gets half.
	b, in = splitFloor(t, 50, share, 50, share)
	o, err = readOldFloorFrom(bytes.NewReader(b), int64(len(b)), in, bound, bound, share, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.buried) != bound/2 || len(o.maxSeq) != bound/2 {
		t.Fatalf("two floods admitted %d tombstones and %d live keys, want %d each", len(o.buried), len(o.maxSeq), bound/2)
	}
}
