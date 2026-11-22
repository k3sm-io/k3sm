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
	"context"
	"errors"
	"fmt"
	"testing"
)

// syncedFloor reads s's file-backed floor so its state is current, and
// returns its log.
func syncedFloor(t *testing.T, s *FileStore) *appendLog {
	t.Helper()
	if err := s.userFloor.check(); err != nil {
		t.Fatal(err)
	}
	return s.userFloor.(*fileFloorLog).log
}

// plantFloorKeys appends n live floor lines for scope, each a new key.
func plantFloorKeys(t *testing.T, s *FileStore, scope, prefix string, n int) {
	t.Helper()
	var b []byte
	for i := range n {
		line, err := floorLine(scope, fmt.Sprintf("%s%d", prefix, i), guid(0x11), 1)
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, line...)
	}
	appendLogBytes(t, s, userFloorLogName, b)
}

// One uid at its lifetime key share (uidKeyShare at the default caps) is
// refused a grant that adds a key, before its first write, while
// another uid's grant still succeeds.
func TestFloorKeyShareRefusesOneUID(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	l := syncedFloor(t, s)
	share := l.keyShare()
	l.mu.Lock()
	held := l.state.uidKeys[1001]
	l.mu.Unlock()
	plantFloorKeys(t, s, "user/1001", "k", share-held)
	checkPutRefusedFirst(t, u, server, "user/1001/other", ErrLogFull)
	u2 := userScope(t, s, 1002)
	if _, err := u2.Put(ctx, "user/1002/token", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("another uid's put with uid 1001 at its key share: %v", err)
	}
}

// With grants at the global key bound, a tombstone for a generation the
// floor lacks is a new key in the revocation headroom, and lands; past the
// headroom it is refused.
func TestFloorTombstoneLandsInHeadroom(t *testing.T) {
	s, _, _ := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog)
	l := syncedFloor(t, s)
	l.mu.Lock()
	l.maxKeys, l.maxHeadroom = l.state.keys, 2
	l.mu.Unlock()
	if err := s.floorGrantRoom("user/1001", []string{"other"}, 0); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a grant at the global key bound: %v, want ErrLogFull", err)
	}
	for i := range 2 {
		if err := fl.bury("user/1001", fmt.Sprintf("gone%d", i), guid(0x22)); err != nil {
			t.Fatalf("tombstone %d for a generation the floor lacks, at the key bound: %v", i, err)
		}
	}
	if err := fl.bury("user/1001", "gone2", guid(0x22)); !errors.Is(err, ErrLogFull) {
		t.Fatalf("a tombstone past the headroom: %v, want ErrLogFull", err)
	}
	if err := s.userFloor.check(); err != nil {
		t.Fatalf("the floor reads as damage after the headroom filled: %v", err)
	}
}

// The reader's bound includes the revocation headroom: a floor that fills
// it reads, and one key more is damage.
func TestFloorReaderAcceptsHeadroom(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	l := syncedFloor(t, s)
	l.mu.Lock()
	l.maxKeys, l.maxHeadroom = l.state.keys, 3
	l.mu.Unlock()
	plantFloorKeys(t, s, "user/1002", "t", 3)
	if _, _, err := u.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current over a floor that fills the headroom: %v", err)
	}
	plantFloorKeys(t, s, "user/1002", "u", 1)
	if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorLogMalformed) {
		t.Fatalf("current over a floor one key past the headroom: %v, want errFloorLogMalformed", err)
	}
}
