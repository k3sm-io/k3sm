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
	"os"
	"testing"
)

// quarantineScope1001 tears uid 1001's put line, restarts and starts the
// user scope, which quarantines 1001. It returns the restarted store.
func quarantineScope1001(t *testing.T, s *FileStore, u *UserScope) *FileStore {
	t.Helper()
	ctx := context.Background()
	fl := s.userFloor.(*fileFloorLog).log
	tornFloorWrite(fl)
	if _, err := u.Put(ctx, "user/1001/lost", KindOpaque, []byte("v")); !Committed(err) {
		t.Fatalf("put whose floor line tears: %v, want Committed", err)
	}
	fl.write = nil
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); !errors.Is(err, errCatchUpRefused) {
		t.Fatalf("start: %v, want the refused catch-up named", err)
	}
	if !s2.scopeQuarantined(1001) {
		t.Fatal("the scope is not quarantined")
	}
	return s2
}

// A quarantined scope's accessor refuses its grants and reads, and its rm
// and withdraw still run: quarantine never blocks a revocation.
func TestQuarantinedScopeRevokes(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	s2 := quarantineScope1001(t, s, u)
	u2, err := s2.UserScope(1001)
	if err != nil {
		t.Fatalf("UserScope of a quarantined uid: %v, want an accessor that still revokes", err)
	}
	if _, _, err := u2.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("current in a quarantined scope: %v, want errFloorDegraded", err)
	}
	if _, err := u2.Put(ctx, "user/1001/more", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put in a quarantined scope: %v, want errFloorDegraded", err)
	}
	if _, err := u2.List(ctx); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("list in a quarantined scope: %v, want errFloorDegraded", err)
	}
	if err := u2.Deliver(ctx, exportDelivery(testDelivery(2))); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("deliver in a quarantined scope: %v, want errFloorDegraded", err)
	}
	if _, err := u2.Delivery(ctx, testDelivery(1).uid); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("delivery lookup in a quarantined scope: %v, want errFloorDegraded", err)
	}
	if err := u2.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm in a quarantined scope: %v", err)
	}
	if err := u2.Delete(ctx, "user/1001/lost"); err != nil {
		t.Fatalf("rm of the entry whose line tore, in a quarantined scope: %v", err)
	}
	if err := u2.Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw in a quarantined scope: %v", err)
	}
}

// A volume too full for the start step's catch-up line is a transient
// error: the scope is named in the start error and still starts, never
// quarantined, and the next operation's catch-up runs once there is room.
func TestFullVolumeAtStartDoesNotQuarantine(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	fl := s.userFloor.(*fileFloorLog).log
	fl.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected failed floor write") }
	if _, err := u.Put(ctx, "user/1001/lost", KindOpaque, []byte("v")); !Committed(err) {
		t.Fatalf("put whose floor line failed: %v, want Committed", err)
	}
	fl.write = nil
	s2 := reopenStore(t, s)
	fl2 := s2.userFloor.(*fileFloorLog).log
	fl2.freeSpace = func(int) (uint64, error) { return 64, nil }
	err := s2.startUserScopes(ctx)
	if !s2.userScopesStarted.Load() {
		t.Fatalf("start: %v, and the user scope is not started", err)
	}
	if errors.Is(err, errCatchUpRefused) {
		t.Fatalf("start over a full volume: %v, want no refused catch-up", err)
	}
	if !errors.Is(err, errLogNoSpace) {
		t.Fatalf("start over a full volume: %v, want errLogNoSpace named", err)
	}
	if s2.scopeQuarantined(1001) {
		t.Fatal("a full volume quarantined the scope")
	}
	fl2.freeSpace = nil
	u2 := userScope(t, s2, 1001)
	if _, _, err := u2.Current(ctx, "user/1001/lost"); err != nil {
		t.Fatalf("current once there is room: %v", err)
	}
}

// A withdraw whose delivery record a torn floor line taints still runs:
// it only removes, so it cannot bring anything back. It seals the
// tombstone and writes the record's floor line, and a copy put back below
// what the floor still knows stays refused.
func TestWithdrawRunsUnderDeliveryRecordTaint(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	for _, n := range []int{1, 2, 3} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	older := readDeliveriesBytes(t, server)
	fl := s.userFloor.(*fileFloorLog).log
	tornFloorWrite(fl)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil && !Committed(err) {
		t.Fatalf("withdraw whose floor line tears: %v", err)
	}
	fl.write = nil
	putBackDeliveries(t, server, older)
	forgetDeliveriesSeen(s)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	u2 := userScope(t, s2, 1001)
	if _, err := u2.Delivery(ctx, testDelivery(3).uid); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("lookup under the taint: %v, want errFloorDegraded", err)
	}
	if err := u2.Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw under a delivery-record taint: %v", err)
	}
	if d, _ := recordedDelivery(t, s2, server, 1); !d.withdrawn {
		t.Fatal("the withdraw under a taint sealed no tombstone")
	}
	if err := u2.Withdraw(ctx, testDelivery(2).uid); err != nil {
		t.Fatalf("a second withdraw: %v", err)
	}
}
