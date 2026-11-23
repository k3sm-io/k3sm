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
	"testing"
)

// deliveryRecordUnknownUnderDamage leaves uid 1001's delivery record,
// delivery 1 withdrawn, at a generation the floor has no line for, while
// the floor holds unattributable damage: a live line for it is refused
// (liveRefused). It returns the record's floor key and sequence.
func deliveryRecordUnknownUnderDamage(t *testing.T) (*FileStore, *UserScope, floorKey, uint64) {
	t.Helper()
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	k := deliveriesFloorKey(t, s)
	_, seq := recordedDelivery(t, s, server, 1)
	var kept []byte
	for _, l := range bytes.SplitAfter(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if r, err := parseFloorLine(bytes.TrimSuffix(l, []byte{'\n'})); err == nil && r.key == k {
			continue
		}
		kept = append(kept, l...)
	}
	setFloorBytes(t, s, append(kept, "garbage\n"...))
	if refused, err := s.userFloor.(*fileFloorLog).liveRefused(k); err != nil || !refused {
		t.Fatalf("the record's live line under unattributable damage: %v, %v, want refused", refused, err)
	}
	return s, u, k, seq
}

// floorHoldsKey reports whether s's floor holds a line for k.
func floorHoldsKey(t *testing.T, s *FileStore, k floorKey) bool {
	t.Helper()
	for _, l := range bytes.Split(readLog(t, s, userFloorLogName), []byte{'\n'}) {
		if r, err := parseFloorLine(l); err == nil && r.key == k {
			return true
		}
	}
	return false
}

// Both delivery-record catch-up paths refuse a live line liveRefused
// refuses: catchUpDeliveryLine, and a withdraw repeated to catch the floor
// up to a withdrawn record.
func TestDeliveryCatchUpPathsCheckLiveRefused(t *testing.T) {
	t.Run("catchUpDeliveryLine", func(t *testing.T) {
		s, u, k, seq := deliveryRecordUnknownUnderDamage(t)
		if err := u.catchUpDeliveryLine(k.gen, deliveriesRead{seq: seq}); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("catch-up under damage: %v, want errFloorDegraded", err)
		}
		if floorHoldsKey(t, s, k) {
			t.Fatal("the catch-up wrote a live line liveRefused refuses")
		}
	})
	t.Run("withdraw", func(t *testing.T) {
		s, u, k, _ := deliveryRecordUnknownUnderDamage(t)
		if err := u.Withdraw(context.Background(), testDelivery(1).uid); err != nil && !errors.Is(err, errFloorDegraded) {
			t.Fatalf("a repeated withdraw under damage: %v", err)
		}
		if floorHoldsKey(t, s, k) {
			t.Fatal("the withdraw's catch-up wrote a live line liveRefused refuses")
		}
	})
}
