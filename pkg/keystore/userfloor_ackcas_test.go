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
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
)

// ackReviewed acknowledges s's floor as root reviews it now: its size and
// unattributable damage count, then the compare-and-set.
func ackReviewed(t *testing.T, s *FileStore) error {
	t.Helper()
	size, damage, err := s.floorAckView(context.Background())
	if err != nil {
		t.Fatalf("floorAckView: %v", err)
	}
	return s.ackFloorDamage(context.Background(), size, damage)
}

// The acknowledgement is compare-and-set: a damaged line appended after
// root's review makes it refuse, writing nothing, and the put stays
// refused; acknowledged against the floor as it now stands, it lifts.
func TestFloorDamageAckRefusesChangedFloor(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage\n"))
	size, damage, err := s.floorAckView(ctx)
	if err != nil || damage != 1 {
		t.Fatalf("floorAckView: %d, %d, %v; want one unattributable line", size, damage, err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("\nmore garbage\n"))
	if err := s.ackFloorDamage(ctx, size, damage); !errors.Is(err, errAckStale) {
		t.Fatalf("an acknowledgement of a floor that changed after review: %v, want errAckStale", err)
	}
	if _, err := os.Lstat(s.dataRoot + "/" + floorAckName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused acknowledgement wrote the file: %v", err)
	}
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put after a refused acknowledgement: %v, want errFloorDegraded", err)
	}
	if err := s.ackFloorDamage(ctx, size+int64(len("\nmore garbage\n")), damage); !errors.Is(err, errAckStale) {
		t.Fatalf("an acknowledgement at the new size with the old damage count: %v, want errAckStale", err)
	}
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("an acknowledgement of the floor as it stands: %v", err)
	}
	if _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put after the acknowledgement: %v", err)
	}
}

// The acknowledgement's catch-up appends a live line for an entry whose
// put lost its floor line, but none for a generation a damaged line could
// name: that line could have been its tombstone.
func TestFloorDamageAckCatchUpSkipsAttributable(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected floor write failure") }
	for _, n := range []string{"named", "plain"} {
		if _, err := u.Put(ctx, "user/1001/"+n, KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
			t.Fatalf("put of %s whose floor line fails: %v, want errCommitted", n, err)
		}
	}
	fl.write = nil
	named, plain := entryGeneration(t, server, "named"), entryGeneration(t, server, "plain")
	// A skipped line whose generation is whole taints (named, gen), and
	// garbage is unattributable damage the acknowledgement lifts.
	appendLogBytes(t, s, userFloorLogName, fmt.Appendf(nil, "\nuser/1001 named %s 7\n\ngarbage\n", hex.EncodeToString(named[:])))
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	if live, err := s.userFloor.liveGens("user/1001", "plain"); err != nil || !slices.Contains(live, plain) {
		t.Fatalf("the acknowledgement's catch-up for an untainted lost line: %x, %v; want %x", live, err, plain)
	}
	if live, err := s.userFloor.liveGens("user/1001", "named"); err != nil || slices.Contains(live, named) {
		t.Fatalf("the acknowledgement's catch-up wrote a live line for a generation a damaged line names: %x, %v", live, err)
	}
}
