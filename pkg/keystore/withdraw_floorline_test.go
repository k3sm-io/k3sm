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
	"testing"
)

// A withdraw whose floor line failed leaves the floor one behind the
// record; the record's earlier copy put back then reads at the floor, but
// this process has written the later one, so the next withdraw refuses it
// rather than re-seal it and lose the tombstone: the record is checked
// against the larger of the floor and the process's own mark, always.
func TestWithdrawRefusesRollbackAfterFloorLineFailed(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	old := readDeliveriesBytes(t, server)
	fl, _ := userLogs(s)
	fl.failAppend = true
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !Committed(err) {
		t.Fatalf("withdraw with a failing floor append: %v, want Committed", err)
	}
	fl.failAppend = false
	putBackDeliveries(t, server, old)
	if err := u.withdrawDelivery(ctx, testDelivery(2).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw over the earlier copy put back: %v, want ErrCorrupt", err)
	}
	if d, _ := recordedDelivery(t, s, server, 1); d.withdrawn {
		t.Fatal("the copy put back was re-sealed")
	}
}

// A repeat withdraw that catches the floor up to the record is in the
// revocation class: past the hard cap it is admitted on the uid's
// revocation budget, and its floor line keeps only the revocation's
// free-space slack.
func TestRepeatWithdrawCatchUpIsRevocation(t *testing.T) {
	for _, tc := range []string{"past the hard cap", "below the free-space margin"} {
		t.Run(tc, func(t *testing.T) {
			ctx := context.Background()
			s, _, u := fileLogScope(t)
			if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
				t.Fatal(err)
			}
			fl := s.userFloor.(*fileFloorLog).log
			fl.freeSpace = func(int) (uint64, error) { return 64, nil }
			if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !Committed(err) {
				t.Fatalf("withdraw with its floor line refused: %v, want Committed", err)
			}
			before := readLog(t, s, userFloorLogName)
			switch tc {
			case "past the hard cap":
				fl.freeSpace = nil
				s.logSoftCap, s.logHardCap = 1, 1
			default:
				fl.freeSpace = func(int) (uint64, error) { return logFreeMargin / 2, nil }
			}
			if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
				t.Fatalf("repeat withdraw catching the floor up: %v, want it admitted and its line written", err)
			}
			if got := readLog(t, s, userFloorLogName); len(got) <= len(before) {
				t.Fatal("the repeat withdraw appended no floor line")
			}
		})
	}
}
