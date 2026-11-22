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
	"strings"
	"testing"
)

// forgetDeliveriesSeen drops the process's delivery-record marks for s's
// keystore, as a restart does.
func forgetDeliveriesSeen(s *FileStore) {
	deliveriesSeen.mu.Lock()
	defer deliveriesSeen.mu.Unlock()
	for k := range deliveriesSeen.m {
		if strings.HasPrefix(k, s.dir+"\x00") {
			delete(deliveriesSeen.m, k)
		}
	}
}

// The across-restart rollback: a withdraw whose floor line failed leaves
// the floor one behind the record. The next exclusive-lock operation that
// reads the authenticated record (here a withdraw of an unknown UID) appends
// the catch-up line, so after a restart, with the process's mark gone, the
// earlier record copied back at the floor's one-behind sequence is refused,
// not re-sealed.
func TestDeliveriesCatchUpSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	old := readDeliveriesBytes(t, server)
	fl := s.userFloor.(*fileFloorLog).log
	fl.freeSpace = func(int) (uint64, error) { return 64, nil }
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, errCommitted) {
		t.Fatalf("withdraw with its floor line refused: %v, want errCommitted", err)
	}
	fl.freeSpace = nil
	if err := u.withdrawDelivery(ctx, testDelivery(3).uid); !errors.Is(err, ErrNotFound) {
		t.Fatalf("withdraw of an unknown UID: %v, want ErrNotFound", err)
	}
	forgetDeliveriesSeen(s)
	putBackDeliveries(t, server, old)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw over the earlier copy put back after a restart: %v, want ErrCorrupt", err)
	}
	if d, _ := recordedDelivery(t, s, server, 1); d.withdrawn {
		t.Fatal("the copy put back was re-sealed")
	}
}

// A deliver refused after it read the record (here for a UID already
// recorded) still appends the catch-up line before it answers.
func TestDeliverCatchesUpFloor(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	old := readDeliveriesBytes(t, server)
	fl := s.userFloor.(*fileFloorLog).log
	fl.freeSpace = func(int) (uint64, error) { return 64, nil }
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, errCommitted) {
		t.Fatalf("withdraw with its floor line refused: %v, want errCommitted", err)
	}
	fl.freeSpace = nil
	if err := u.addDelivery(ctx, testDelivery(2)); !errors.Is(err, ErrExists) {
		t.Fatalf("deliver of a recorded UID: %v, want ErrExists", err)
	}
	forgetDeliveriesSeen(s)
	putBackDeliveries(t, server, old)
	if _, err := u.Delivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a read of the earlier copy put back after a restart: %v, want ErrCorrupt", err)
	}
}

// The restart case with no mutation in between: a withdraw whose floor line
// failed leaves the floor one behind the record; the process restarts (its
// mark gone) and, before it serves, catchUpUser appends the catch-up line,
// so the earlier record copied back is refused, not re-sealed.
func TestCatchUpUserAtStartSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	old := readDeliveriesBytes(t, server)
	fl := s.userFloor.(*fileFloorLog).log
	fl.freeSpace = func(int) (uint64, error) { return 64, nil }
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, errCommitted) {
		t.Fatalf("withdraw with its floor line refused: %v, want errCommitted", err)
	}
	fl.freeSpace = nil
	forgetDeliveriesSeen(s)
	if _, scopeErrs, err := s.catchUpUser(ctx); err != nil || scopeErrs != nil {
		t.Fatalf("catchUpUser: %v, %v", err, scopeErrs)
	}
	putBackDeliveries(t, server, old)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw over the earlier copy put back after a restart: %v, want ErrCorrupt", err)
	}
	if d, _ := recordedDelivery(t, s, server, 1); d.withdrawn {
		t.Fatal("the copy put back was re-sealed")
	}
}
