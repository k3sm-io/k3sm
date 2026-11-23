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
	"math"
	"testing"
)

// sealDeliveriesAt re-seals uid 1001's delivery record, as it stands, at
// seq.
func sealDeliveriesAt(t *testing.T, s *FileStore, u *UserScope, seq uint64) {
	t.Helper()
	root, done, err := s.openLocked(context.Background(), false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	k, err := s.loadMaster()
	if err != nil {
		t.Fatal(err)
	}
	o, err := u.openScopeForRevoke(root, k)
	if err != nil {
		t.Fatal(err)
	}
	defer o.close()
	rd, err := u.readDeliveriesFloor(o, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := u.writeDeliveries(o.dir, o.key, o.gen, rd.ds, seq, false); err != nil {
		t.Fatal(err)
	}
}

// A delivery record at the last sequence is refused by a deliver and a
// withdraw that would seal a new one, as Rotate refuses a pointer at the
// last sequence: seq+1 would wrap to 0, and the record is left as it is.
func TestDeliveriesRecordAtLastSequence(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	sealDeliveriesAt(t, s, u, math.MaxUint64)
	before := readDeliveriesBytes(t, server)
	if err := u.addDelivery(ctx, testDelivery(2)); !errors.Is(err, ErrCorrupt) || errors.Is(err, errCommitted) {
		t.Fatalf("deliver over a record at the last sequence: %v, want ErrCorrupt before any write", err)
	}
	if err := u.withdrawDelivery(ctx, testDelivery(1).uid); !errors.Is(err, ErrCorrupt) || errors.Is(err, errCommitted) {
		t.Fatalf("withdraw over a record at the last sequence: %v, want ErrCorrupt before any write", err)
	}
	if !bytes.Equal(before, readDeliveriesBytes(t, server)) {
		t.Fatal("the record at the last sequence was re-sealed")
	}
}
