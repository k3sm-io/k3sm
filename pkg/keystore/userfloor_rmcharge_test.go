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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An rm whose removal fails after its tombstones were written is reported
// as after a commit, so it is audited as a revocation, and its text does
// not say nothing was removed.
func TestUserRmRemovalFailureIsCommitted(t *testing.T) {
	s, _, u := fileLogScope(t)
	s.step = failAt("delete token")
	err := u.Delete(context.Background(), "user/1001/token")
	if !errors.Is(err, errCommitted) || strings.Contains(err.Error(), "nothing removed") {
		t.Fatalf("rm with its removal failing after the tombstones: %v, want errCommitted naming no refusal", err)
	}
	if !bytes.Contains(readLog(t, s, auditLogName), []byte("rm")) {
		t.Fatal("the rm was not audited")
	}
}

// rm charges every tombstone line it writes against the revocation budget
// before the first: past the hard cap, with budget for fewer tombstones
// than the name has live generations, it is refused with no tombstone
// written, never part way.
func TestUserRmChargesEveryTombstone(t *testing.T) {
	s, _, u := fileLogScope(t)
	var b []byte
	for i := range 60 {
		line, err := floorLine("user/1001", "token", guid(byte(0x40+i)), 1)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, line...)
	}
	appendLogBytes(t, s, userFloorLogName, b)
	if err := os.Truncate(filepath.Join(s.dataRoot, logsDirName, auditDirName, auditLogName), 0); err != nil {
		t.Fatal(err)
	}
	before := readLog(t, s, userFloorLogName)
	s.logSoftCap, s.logHardCap = int64(len(before)), int64(len(before))
	s.logRevokeBudget = minLogRevokeBudget
	err := u.Delete(context.Background(), "user/1001/token")
	if !errors.Is(err, ErrLogFull) || errors.Is(err, errCommitted) {
		t.Fatalf("rm with budget for fewer tombstones than it needs: %v, want ErrLogFull before any", err)
	}
	if got := readLog(t, s, userFloorLogName); !bytes.Equal(got, before) {
		t.Fatalf("the refused rm wrote %d tombstone bytes", len(got)-len(before))
	}
}

// floorDeliverRoom judges the key bound only when the deliver's line adds a
// key: with the floor in its revocation headroom, past the key bound, a
// deliver whose delivery-record key the floor already holds still has room.
func TestFloorDeliverRoomExistingKeyPastBound(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	l := syncedFloor(t, s)
	l.mu.Lock()
	var gen [generationSize]byte
	found := false
	for k := range l.state.maxSeq {
		if k.scope == u.scope && k.name == deliveriesFloorName {
			gen, found = k.gen, true
		}
	}
	l.maxKeys, l.maxHeadroom = l.state.keys-1, 4
	l.mu.Unlock()
	if !found {
		t.Fatal("the floor holds no delivery-record key")
	}
	if err := s.floorDeliverRoom(u.scope, gen); err != nil {
		t.Fatalf("deliver room for a key the floor holds, past the key bound: %v, want room", err)
	}
	if err := s.floorDeliverRoom(u.scope, guid(0xEE)); !errors.Is(err, ErrLogFull) {
		t.Fatalf("deliver room for a new key past the key bound: %v, want ErrLogFull", err)
	}
}
