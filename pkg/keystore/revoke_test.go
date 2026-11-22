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
	"strings"
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

// A floor that cannot be read does not let a withdraw re-seal a record it
// cannot check: the withdraw is refused with errWithdrawUnsealed and seals
// nothing, and the floor is unchanged. A floor line that could not be
// appended is appended by the next withdraw of the same UID, at the
// record's sequence, which the floor's max makes idempotent.
func TestWithdrawFloorFaults(t *testing.T) {
	ctx := context.Background()
	t.Run("floor read fails", func(t *testing.T) {
		s, server, u := newDeliveryScope(t)
		if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
			t.Fatal(err)
		}
		_, before := recordedDelivery(t, s, server, 1)
		fl, _ := userLogs(s)
		fl.failRead = true
		if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, errWithdrawUnsealed) {
			t.Fatalf("withdraw while the floor read fails: %v, want errWithdrawUnsealed", err)
		}
		fl.failRead = false
		d, seq := recordedDelivery(t, s, server, 1)
		if d.withdrawn || seq != before {
			t.Fatalf("the record was re-sealed with the floor unreadable: sequence %d (was %d), withdrawn %v", seq, before, d.withdrawn)
		}
		if got, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); got != before {
			t.Fatalf("floor %d after the refused withdraw, want %d", got, before)
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

// putBackDeliveries writes b, an earlier copy of uid 1001's deliveries
// file, back over the live one, as a restore or a copy would.
func putBackDeliveries(t *testing.T, server string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(scopeDir(server, "1001"), deliveriesName), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// readDeliveriesBytes returns uid 1001's deliveries file as it is on disk.
func readDeliveriesBytes(t *testing.T, server string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(scopeDir(server, "1001"), deliveriesName))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A withdraw with the floor unreadable still refuses a record older than
// one this process has read or written: the tombstone at sequence N, then
// the copy at N-1 put back, then a withdraw of another UID must not
// re-seal the copy at N and so lose the tombstone.
func TestWithdrawRefusesRollbackBelowSeen(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	older := readDeliveriesBytes(t, server)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	_, tomb := recordedDelivery(t, s, server, 1)
	putBackDeliveries(t, server, older)
	fl, _ := userLogs(s)
	fl.failRead = true
	err := u.withdrawDelivery(ctx, testDelivery(2).uid)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw over a put-back copy with the floor unreadable: %v, want ErrCorrupt", err)
	}
	if !strings.Contains(err.Error(), "older than one this process has already read or written") {
		t.Fatalf("refusal %q does not name the rollback", err)
	}
	fl.failRead = false
	if d, seq := recordedDelivery(t, s, server, 1); seq != tomb-1 || d.withdrawn {
		t.Fatalf("the put-back copy was re-sealed: sequence %d (tombstone at %d), withdrawn %v", seq, tomb, d.withdrawn)
	}
	if got, _ := fl.floor("user/1001", deliveriesFloorName, guid(0xA1)); got != tomb {
		t.Fatalf("floor %d, want the tombstone's %d", got, tomb)
	}
	// With the floor readable again, the copy is refused as below it.
	if _, err := u.lookupDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read of the put-back copy: %v, want ErrCorrupt", err)
	}
}

// A withdraw of a record below a floor that can be read stays refused,
// naming floor --rebuild for a deliberate restore: the second residual of
// "Revocation always succeeds".
func TestWithdrawBelowReadableFloorRefused(t *testing.T) {
	ctx := context.Background()
	_, server, u := newDeliveryScope(t)
	for _, n := range []int{1, 2} {
		if err := u.addDelivery(ctx, testDelivery(n)); err != nil {
			t.Fatal(err)
		}
	}
	older := readDeliveriesBytes(t, server)
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
		t.Fatal(err)
	}
	putBackDeliveries(t, server, older)
	err := u.withdrawDelivery(ctx, testDelivery(2).uid)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw below a readable floor: %v, want ErrCorrupt", err)
	}
	for _, want := range []string{"is older than the user-scope floor", "restore the matched set", "sudo k3sm doctor"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err, want)
		}
	}
}

// rm refuses when the uid's live GeneratedUID is a real answer that differs
// from the scope's bound one: a recycled uid's new holder cannot delete the
// former owner's values. A lookup that fails or times out still lets rm go
// ahead, so revocation stays available.
func TestDeleteOwnerChanged(t *testing.T) {
	ctx := context.Background()
	t.Run("a real, different GeneratedUID refuses", func(t *testing.T) {
		_, server, u := newDeliveryScope(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xB2)})
		if err := u.Delete(ctx, "user/1001/token"); !errors.Is(err, ErrScopeOwnerChanged) {
			t.Fatalf("rm by a recycled uid: %v, want ErrScopeOwnerChanged", err)
		}
		if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")); err != nil {
			t.Fatalf("the former owner's entry after a refused rm: %v", err)
		}
	})
	t.Run("a lookup error proceeds", func(t *testing.T) {
		_, server, u := newDeliveryScope(t)
		fakeGUIDs(t, map[uint32][generationSize]byte{})
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatalf("rm while the lookup fails: %v", err)
		}
		checkEntryGone(t, server, "token")
	})
	t.Run("a lookup timeout proceeds", func(t *testing.T) {
		_, server, u := newDeliveryScope(t)
		stallLookups(t)
		if err := u.Delete(ctx, "user/1001/token"); err != nil {
			t.Fatalf("rm while the lookup times out: %v", err)
		}
		checkEntryGone(t, server, "token")
	})
}

// rm proceeds without the owner's answer only when a GeneratedUID lookup
// actually ran and failed or timed out. Refused one at once for capacity
// (the outstanding cap) or for a stuck earlier call for the uid, no lookup
// ran, and rm refuses with a retryable error, deleting nothing. Withdraw,
// pure revocation, proceeds in every case.
func TestRmLookupRefusalKinds(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name    string
		setup   func(t *testing.T)
		proceed bool
	}{
		{"a lookup that timed out", stallLookups, true},
		{"a lookup that failed", func(t *testing.T) {
			setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
				return [generationSize]byte{}, errors.New("directory service down")
			})
		}, true},
		{"the outstanding cap", func(t *testing.T) {
			stuckLookups(t)
			for uid := uint32(1); uid <= maxOutstandingLookups; uid++ {
				_, _ = lookupGeneratedUID(uid + 2000) // each times out and stays outstanding
			}
		}, false},
		{"a stuck call for the uid", func(t *testing.T) {
			stuckLookups(t)
			_, _ = lookupGeneratedUID(1001) // times out and stays outstanding
		}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, server, u := newDeliveryScope(t)
			if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
				t.Fatal(err)
			}
			tt.setup(t)
			err := u.Delete(ctx, "user/1001/token")
			if tt.proceed {
				if err != nil {
					t.Fatalf("rm after %s: %v", tt.name, err)
				}
				checkEntryGone(t, server, "token")
			} else {
				if !errors.Is(err, errLookupNotRun) || !strings.Contains(err.Error(), "try again") {
					t.Fatalf("rm after %s: %v, want the retryable errLookupNotRun", tt.name, err)
				}
				if _, err := os.Lstat(filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "token")); err != nil {
					t.Fatalf("a refused rm removed the entry: %v", err)
				}
			}
			if err := u.withdrawDelivery(ctx, testDelivery(1).uid); err != nil {
				t.Fatalf("withdraw after %s: %v", tt.name, err)
			}
			if d, _ := recordedDelivery(t, s, server, 1); !d.withdrawn {
				t.Fatal("the delivery is still live")
			}
		})
	}
}

// The delivery-record high-water mark is process-wide: a second FileStore on
// the same keystore, which has read nothing itself, still refuses to
// withdraw over an older copy put back below a sequence the first one wrote,
// when the floor cannot be read.
func TestDeliveriesSeenIsProcessWide(t *testing.T) {
	ctx := context.Background()
	s1, server, u1 := newDeliveryScope(t)
	path := filepath.Join(scopeDir(server, "1001"), deliveriesName)
	if err := u1.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	older, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := u1.addDelivery(ctx, testDelivery(2)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, older, 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := New(Config{Dir: s1.dir, MasterDir: s1.masterDir, UID: s1.uid, GID: s1.gid, DataRoot: s1.dataRoot, FloorUID: s1.floorUID, FloorGID: s1.floorGID})
	s2.userFloor, s2.auditSink = &memFloor{failRead: true}, &memAudit{}
	u2 := userScope(t, s2, 1001)
	if err := u2.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("withdraw on a second store over a copied-back record: %v, want ErrCorrupt from the shared mark", err)
	}
}
