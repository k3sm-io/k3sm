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
	"fmt"
	"testing"
)

// overflowFloor appends to s's floor more distinct name taints than the
// taint set holds, each a line torn inside its name, then a burial of
// (user/1001, gone, gen) torn inside its generation as the last line.
func overflowFloor(t *testing.T, s *FileStore, gen [generationSize]byte) {
	t.Helper()
	var b bytes.Buffer
	for i := range maxTaintKeys + 1 {
		fmt.Fprintf(&b, "\nuser/1001 x%d\n", i)
	}
	l, err := tombLine("user/1001", "gone", gen)
	if err != nil {
		t.Fatal(err)
	}
	b.WriteByte('\n')
	b.Write(l[:len("user/1001 gone ")+2*generationSize+2])
	appendLogBytes(t, s, userFloorLogName, b.Bytes())
}

// Past the taint cap the floor overflows: every key, known generation or
// not, is refused for grants and reads, and an acknowledgement lifts none
// of it, since the overflow is never unattributable damage. The torn
// tombstone's key stays refused. rm and withdraw still run.
func TestFloorTaintOverflowRefusesEveryKey(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	tokenGen := entryGeneration(t, server, "token")
	gone := guid(0x61)
	overflowFloor(t, s, gone)
	check := func(when string) {
		t.Helper()
		if _, err := ff.floor("user/1001", "gone", gone); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: the torn tombstone's generation: %v, want errFloorDegraded", when, err)
		}
		if _, err := ff.floor("user/1001", "token", tokenGen); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: a known generation of an untainted name: %v, want errFloorDegraded", when, err)
		}
		if _, err := ff.floor("user/1002", "other", guid(0x62)); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: an unknown generation of another scope: %v, want errFloorDegraded", when, err)
		}
		if _, _, err := u.Current(ctx, "user/1001/token"); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: current of a known generation: %v, want errFloorDegraded", when, err)
		}
		if _, err := u.Put(ctx, "user/1001/fresh", KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: a put of a fresh name: %v, want errFloorDegraded", when, err)
		}
		if err := s.floorGrantRoom("user/1002", []string{"fresh"}, 0); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("%s: a grant in another scope: %v, want errFloorDegraded", when, err)
		}
	}
	check("overflowed")
	if err := ackReviewed(t, s); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	check("after the acknowledgement")
	if err := u.Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw over an overflowed floor: %v", err)
	}
	if err := u.Delete(ctx, "user/1001/token"); err != nil {
		t.Fatalf("rm over an overflowed floor: %v", err)
	}
}
