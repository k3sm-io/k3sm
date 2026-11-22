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
	"strings"
	"testing"
)

// freshFloorVerdict reads the floor from scratch, as a new process would,
// under the same caps and key bound, and returns its verdict.
func freshFloorVerdict(t *testing.T, s *FileStore, maxKeys int) error {
	t.Helper()
	l := newFileFloorLog(s)
	l.log.maxKeys = maxKeys
	return l.check()
}

// U24: ordinary put and rm churn up to the floor's key bound never makes
// the floor damage. A grant past the bound is refused with ErrLogFull
// naming floor --rebuild and audit --rotate, before anything is written; a
// revocation of a key the floor holds (rm's tombstone, a withdraw's floor
// line) still goes through; and a reader from scratch never refuses the
// floor the writer produced.
func TestFloorKeyBoundChurnRefusesGrants(t *testing.T) {
	ctx := context.Background()
	const bound = 6
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	s.userFloor.(*fileFloorLog).log.maxKeys = bound
	var refused error
	for i := range 3 * bound {
		name := fmt.Sprintf("user/1001/k%d", i)
		_, err := u.Put(ctx, name, KindOpaque, []byte("v"))
		if err != nil {
			refused = err
			break
		}
		if err := u.Delete(ctx, name); err != nil {
			t.Fatalf("rm %s: %v", name, err)
		}
		if err := freshFloorVerdict(t, s, bound); err != nil {
			t.Fatalf("after churn %d the floor reads as damage: %v", i, err)
		}
	}
	if !errors.Is(refused, ErrLogFull) {
		t.Fatalf("a grant past the key bound: %v, want ErrLogFull", refused)
	}
	for _, want := range []string{"floor --rebuild", "audit --rotate", "key bound"} {
		if !strings.Contains(refused.Error(), want) {
			t.Fatalf("refusal %q does not say %q", refused, want)
		}
	}
	// The refused grant wrote nothing: no entry, no floor line.
	floorBefore := readLog(t, s, userFloorLogName)
	snap := treeSnapshot(t, server)
	if _, err := u.Put(ctx, "user/1001/another", KindOpaque, []byte("v")); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a second grant past the key bound: %v, want ErrLogFull", err)
	}
	checkTreeUnchanged(t, snap, treeSnapshot(t, server))
	if !bytes.Equal(floorBefore, readLog(t, s, userFloorLogName)) {
		t.Fatal("a refused grant appended to the floor")
	}
	if err := u.addDelivery(ctx, testDelivery(2)); !errors.Is(err, ErrLogFull) {
		t.Fatalf("deliver past the key bound: %v, want ErrLogFull", err)
	}
	// Revocations of keys the floor holds go through, whole.
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw past the key bound: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm of a key the floor holds, past the key bound: %v", err)
	}
	if err := freshFloorVerdict(t, s, bound); err != nil {
		t.Fatalf("the floor reads as damage after the revocations: %v", err)
	}
}

// The writer never adds a key past the bound itself: a tombstone for a
// generation the floor does not hold is a new key, refused with ErrLogFull
// once the floor is at its bound, and the floor still reads.
func TestFloorWriterRefusesKeyPastBound(t *testing.T) {
	s, _, _ := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog)
	fl.log.maxKeys = 4
	var err error
	for i := range 8 {
		if err = fl.bury("user/1001", fmt.Sprintf("n%d", i), guid(byte(i))); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrLogFull) {
		t.Fatalf("a new key past the bound: %v, want ErrLogFull", err)
	}
	if err := freshFloorVerdict(t, s, 4); err != nil {
		t.Fatalf("the writer made the floor damage: %v", err)
	}
	// A line for a key the floor holds still goes through.
	if err := fl.append("user/1001", "token", entryGenerationOf(t, s), 1); err != nil {
		t.Fatalf("a line for a held key at the bound: %v", err)
	}
}

// entryGenerationOf returns token's generation as the floor holds it.
func entryGenerationOf(t *testing.T, s *FileStore) [generationSize]byte {
	t.Helper()
	var gen [generationSize]byte
	if err := s.userFloor.(*fileFloorLog).read(func(st *logState) {
		for k := range st.maxSeq {
			if k.name == "token" {
				gen = k.gen
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	return gen
}

// At the default caps the key bound is at least the hard cap over the
// shortest line that adds a key (46 bytes), so the size cap is met first.
func TestFloorKeyBoundDerivedFromCaps(t *testing.T) {
	s, _, _ := fileLogScope(t)
	line, err := floorLine(userScopeOf(minScopeUID), "a", [generationSize]byte{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(line) != 46 {
		t.Fatalf("the shortest floor line is %d bytes, want 46", len(line))
	}
	if got, want := s.userFloor.(*fileFloorLog).log.keyBound(), int(defaultLogHardCap/46); got < want {
		t.Fatalf("key bound %d at the default caps, want at least %d", got, want)
	}
}

// A withdraw of an already withdrawn delivery whose floor already holds
// the record's sequence appends nothing to the floor.
func TestWithdrawRepeatAppendsNoFloorLine(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("repeat withdraw: %v", err)
	}
	if after := readLog(t, s, userFloorLogName); !bytes.Equal(before, after) {
		t.Fatalf("a no-op withdraw appended %q to the floor", after[len(before):])
	}
}

// U20: a withdraw over a floor it cannot verify never re-seals a record put
// back from a backup. With a delivery withdrawn after the backup, the backup
// restored, the floor's flag clear and the process's own mark gone (a
// restart), a withdraw is refused with errWithdrawUnsealed and the record
// on disk is the restored bytes; once the floor is flagged again, the copy
// stays refused below it, so the delivery withdrawn after the backup never
// reads as live.
func TestWithdrawUnverifiedFloorSealsNothing(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	backup := readDeliveriesBytes(t, server)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	putBackDeliveries(t, server, backup)
	s.logFlags = func(*os.File) (uint32, error) { return 0, nil }
	deliveriesSeen.mu.Lock()
	delete(deliveriesSeen.m, deliverySeqKey(s.dir, "user/1001", guid(0xA1)))
	deliveriesSeen.mu.Unlock()
	for _, n := range []int{2, 1} {
		err := u.withdrawDelivery(ctx, testDelivery(n).uid)
		if !errors.Is(err, errWithdrawUnsealed) || errors.Is(err, errCommitted) {
			t.Fatalf("withdraw %d over an unflagged floor and a restored record: %v, want errWithdrawUnsealed", n, err)
		}
		if !bytes.Equal(backup, readDeliveriesBytes(t, server)) {
			t.Fatalf("withdraw %d re-sealed the restored record", n)
		}
	}
	s.logFlags = flagged
	if d, err := u.lookupDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("the delivery withdrawn after the backup reads as %+v, %v; want the restored copy refused (ErrCorrupt)", d, err)
	}
}
