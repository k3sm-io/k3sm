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

// A flood of forged tombstones for one real uid is trimmed to the uid's
// share, oldest first: its real lines, older, are kept, and the excess is
// counted as past the share.
func TestRebuildForgedFloodOneRealUIDTrimmed(t *testing.T) {
	s, server, u := fileLogScope(t)
	token, gone := realLines(t, s, server, u)
	var flood bytes.Buffer
	const forged = 100
	for i := range forged {
		line, err := tombLine("user/1001", fmt.Sprintf("t%d", i), [generationSize]byte{byte(i)})
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

// Absent scopes are admitted in first-appearance order: the first uid
// seen gets its whole share whatever the interleaving, and the last only
// what is left.
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
	o, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, 10, 4, maxLogLine)
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for k := range o.buried {
		count[k.scope]++
	}
	if count["user/7001"] != 4 || count["user/7002"] != 4 || count["user/7003"] != 2 || o.absent != 18-10 {
		t.Fatalf("admitted %v, %d absent, want 4, 4, 2 and 8", count, o.absent)
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
	_, err = readOldFloorFrom(bytes.NewReader(line), int64(len(line)), in, 6, 8, maxLogLine)
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
