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
	"runtime"
	"strings"
	"testing"
)

// A floor past the steady-state reader's size bound, filled with junk,
// rebuilds: the rebuild streams it with no size bound, drops and counts the
// junk by class, and keeps every real tombstone.
func TestRebuildStreamsFloorPastReadBound(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	userPut(t, u, "user/1001/gone", "deleted later")
	gone := entryGen(t, server, "1001", "gone")
	if err := u.Delete(ctx, "user/1001/gone"); err != nil {
		t.Fatal(err)
	}
	// A small injected size bound: the hard cap is the floor as it stands,
	// and the smallest revocation budget, so logReadBound is about 3.3 MiB.
	s.logSoftCap, s.logHardCap = int64(len(readLog(t, s, userFloorLogName))), int64(len(readLog(t, s, userFloorLogName)))
	s.logRevokeBudget = minLogRevokeBudget
	var junk bytes.Buffer
	long := strings.Repeat("z", 3*maxLogLine) + "\n"
	garbage := "not a floor line\n"
	nLong, nGarbage := 0, 0
	for int64(junk.Len()) <= s.logReadBound() {
		junk.WriteString(long)
		nLong++
		for range 20 {
			junk.WriteString(garbage)
			nGarbage++
		}
	}
	appendLogBytes(t, s, userFloorLogName, junk.Bytes())
	if _, err := s.FloorDamage(ctx); !errors.Is(err, errLogTooLarge) {
		t.Fatalf("the steady-state reader read a floor past its size bound: %v, want errLogTooLarge", err)
	}
	rep, _ := rebuild(t, s)
	if rep.OverLong != nLong || rep.Dropped != nGarbage {
		t.Errorf("the rebuild counted %d over-long and %d unparseable lines, want %d and %d", rep.OverLong, rep.Dropped, nLong, nGarbage)
	}
	if !rep.Lost() {
		t.Error("the report says nothing was lost")
	}
	buried := false
	for _, r := range floorRecs(t, s) {
		if r.key.name == "gone" && r.key.gen == gone && r.tomb {
			buried = true
		}
	}
	if !buried {
		t.Fatal("the rebuilt floor lost the real tombstone")
	}
	if _, err := s.FloorDamage(ctx); err != nil {
		t.Fatalf("the rebuilt floor does not read: %v", err)
	}
}

// A flood of forged live keys for a scope that exists is trimmed to the
// uid's share, oldest first, and counted, and every real line (older) is
// kept.
func TestRebuildDropsForgedLiveFlood(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	userPut(t, u, "user/1001/gone", "deleted later")
	gone := entryGen(t, server, "1001", "gone")
	if err := u.Delete(ctx, "user/1001/gone"); err != nil {
		t.Fatal(err)
	}
	token := entryGen(t, server, "1001", "token")
	var flood bytes.Buffer
	const forged = 200
	for i := range forged {
		line, err := floorLine("user/1001", fmt.Sprintf("forged-%d", i), [generationSize]byte{byte(i)}, 7)
		if err != nil {
			t.Fatal(err)
		}
		flood.Write(line)
	}
	appendLogBytes(t, s, userFloorLogName, flood.Bytes())
	// The deliveries record, token and gone's tombstone are real: 3 keys,
	// and the injected key bound leaves room for 7 forged ones.
	const bound = 10
	s.floorLog().maxKeys = bound
	rep, _ := rebuild(t, s)
	if rep.Keys != bound || rep.PastShare != forged-(bound-3) {
		t.Errorf("the rebuild kept %d keys and dropped %d lines past the share, want %d and %d", rep.Keys, rep.PastShare, bound, forged-(bound-3))
	}
	var haveToken, haveGone bool
	for _, r := range floorRecs(t, s) {
		haveToken = haveToken || (r.key.name == "token" && r.key.gen == token && !r.tomb)
		haveGone = haveGone || (r.key.name == "gone" && r.key.gen == gone && r.tomb)
	}
	if !haveToken || !haveGone {
		t.Fatalf("the rebuild lost a real line: token %v, gone's tombstone %v", haveToken, haveGone)
	}
}

// The old-floor reader's memory is bounded by the key bound and one line,
// not the file's size: with a small injected key bound, a floor sixteen
// times larger leaves no more live heap behind, and a floor of over-long
// lines alone allocates no more in total.
func TestOldFloorReaderMemoryBounded(t *testing.T) {
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{"user/1001": true}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	const keyBound = 4
	floodOf := func(n int, forged bool) []byte {
		var b bytes.Buffer
		long := strings.Repeat("z", 2*maxLogLine) + "\n"
		for i := range n {
			if forged {
				line, err := floorLine("user/1001", fmt.Sprintf("f%d", i), [generationSize]byte{}, 1)
				if err != nil {
					t.Fatal(err)
				}
				b.Write(line)
				continue
			}
			b.WriteString(long)
		}
		return b.Bytes()
	}
	measure := func(b []byte) (total, live uint64, o *oldFloor) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		o, err := readOldFloorFrom(bytes.NewReader(b), int64(len(b)), in, keyBound, keyBound, maxLogLine)
		if err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		total = after.TotalAlloc - before.TotalAlloc
		runtime.GC()
		runtime.ReadMemStats(&after)
		if after.HeapAlloc > before.HeapAlloc {
			live = after.HeapAlloc - before.HeapAlloc
		}
		return total, live, o
	}
	smallLong, _, _ := measure(floodOf(256, false))
	bigLong, _, o := measure(floodOf(16*256, false))
	if o.overLong != 16*256 {
		t.Fatalf("counted %d over-long lines, want %d", o.overLong, 16*256)
	}
	if bigLong > smallLong+64<<10 {
		t.Errorf("reading 16 times the over-long lines allocated %d bytes against %d: the reader allocates in proportion to the file", bigLong, smallLong)
	}
	_, smallLive, small := measure(floodOf(1000, true))
	_, bigLive, big := measure(floodOf(16*1000, true))
	if len(small.maxSeq) != keyBound || len(big.maxSeq) != keyBound || big.pastShare != 16*1000-keyBound {
		t.Fatalf("admitted %d and %d keys, dropped %d past the share, want %d, %d and %d", len(small.maxSeq), len(big.maxSeq), big.pastShare, keyBound, keyBound, 16*1000-keyBound)
	}
	if bigLive > smallLive+64<<10 {
		t.Errorf("a floor of 16 times the forged lines kept %d bytes live against %d: the reader keeps memory in proportion to the file", bigLive, smallLive)
	}
}

// The keys of scopes on disk, each within its share, past the key bound
// refuse, naming the scopes with the most keys: the one refusal left.
func TestOldFloorReaderRefusesTombstonesPastBound(t *testing.T) {
	var b bytes.Buffer
	for i := range 5 {
		line, err := tombLine("user/1001", fmt.Sprintf("t%d", i), [generationSize]byte{})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	in := rebuildInput{disk: map[floorKey]uint64{}, present: map[string]bool{"user/1001": true}, names: map[nameKey]bool{}, removed: map[string]int64{}}
	_, err := readOldFloorFrom(bytes.NewReader(b.Bytes()), int64(b.Len()), in, 4, 8, maxLogLine)
	if err == nil || !strings.Contains(err.Error(), "user/1001 (5 keys)") {
		t.Fatalf("readOldFloorFrom: %v, want a refusal naming user/1001 (5 keys)", err)
	}
}
