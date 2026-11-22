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
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stallLookups makes every GeneratedUID lookup time out: the directory
// service answers only after the test ends, and the deadline has passed.
func stallLookups(t *testing.T) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release); waitLookupsIdle(t) })
	setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
		<-release
		return guid(0xA1), nil
	})
	setSeam(t, &timerSeam, firesAt(new(time.Duration)))
}

// recordedDelivery returns delivery n of uid 1001's record, read off disk
// without the store, so without a GeneratedUID lookup.
func recordedDelivery(t *testing.T, s *FileStore, server string, n int) (delivery, uint64) {
	t.Helper()
	r, pt := openDeliveriesFile(t, s, server)
	ds, err := parseDeliveries(pt)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		if d.uid == testDelivery(n).uid {
			return d, r.version
		}
	}
	t.Fatalf("delivery %d is not recorded", n)
	return delivery{}, 0
}

// checkEntryGone fails unless uid 1001's entry name is gone from disk.
func checkEntryGone(t *testing.T, server, name string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, name)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("entry %s after rm: %v, want it gone", name, err)
	}
}

// U13, U109: revocation is unconditional. A withdraw and an rm go ahead
// while the GeneratedUID lookup times out, and while a Rewrap is half done
// (master.next present), where a put stays refused.
func TestRevocationIsUnconditional(t *testing.T) {
	ctx := context.Background()
	t.Run("the owner lookup times out", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		stallLookups(t)
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
			t.Fatalf("withdraw while the lookup times out: %v", err)
		}
		if d, _ := recordedDelivery(t, s, server, 1); !d.withdrawn {
			t.Fatal("the delivery is still live")
		}
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatalf("rm while the lookup times out: %v", err)
		}
		checkEntryGone(t, server, "token")
		if _, err := u.Put(ctx, "user/1001/token", KindOpaque, []byte("v")); !errors.Is(err, ErrScopeOwnerUnknown) {
			t.Fatalf("put while the lookup times out: %v, want ErrScopeOwnerUnknown", err)
		}
	})
	t.Run("master.next is present", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		plantNext(t, server, rewrapKey(7))
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
			t.Fatalf("withdraw with master.next present: %v", err)
		}
		if d, _ := recordedDelivery(t, s, server, 1); !d.withdrawn {
			t.Fatal("the delivery is still live")
		}
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatalf("rm with master.next present: %v", err)
		}
		checkEntryGone(t, server, "token")
		if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); !errors.Is(err, ErrRewrapInProgress) {
			t.Fatalf("put with master.next present: %v, want ErrRewrapInProgress", err)
		}
	})
}

// A floor that cannot be read does not stop a withdraw: the tombstone is
// written and its floor line appended. A floor line that could not be
// appended is appended by the next withdraw of the same UID, at the
// record's sequence, which the floor's max makes idempotent.
func TestWithdrawFloorFaults(t *testing.T) {
	ctx := context.Background()
	t.Run("floor read fails", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		fl, _ := userLogs(s)
		fl.failRead = true
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
			t.Fatalf("withdraw while the floor read fails: %v", err)
		}
		fl.failRead = false
		d, seq := recordedDelivery(t, s, server, 1)
		if !d.withdrawn {
			t.Fatal("the delivery is still live")
		}
		if got, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); got != seq {
			t.Fatalf("floor %d after the withdraw, want %d", got, seq)
		}
	})
	t.Run("floor append fails, then a repeat re-appends", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		fl, _ := userLogs(s)
		fl.failAppend = true
		err := u.withdrawDelivery(ctx, testDelivery(1).uid)
		if err == nil {
			t.Fatal("withdraw with a failing floor append reported nothing")
		}
		fl.failAppend = false
		d, seq := recordedDelivery(t, s, server, 1)
		if !d.withdrawn {
			t.Fatalf("withdraw with a failing floor append did not commit: %v", err)
		}
		if got, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); got != seq-1 {
			t.Fatalf("floor %d, want %d (the append failed)", got, seq-1)
		}
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
			t.Fatalf("repeat withdraw: %v", err)
		}
		if got, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); got != seq {
			t.Fatalf("floor %d after the repeat, want %d", got, seq)
		}
		if _, again := recordedDelivery(t, s, server, 1); again != seq {
			t.Fatalf("the repeat re-sealed the record (sequence %d, was %d)", again, seq)
		}
	})
}
