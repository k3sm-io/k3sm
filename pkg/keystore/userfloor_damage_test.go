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
	"path/filepath"
	"testing"

	"k3sm.io/apis/keystore/credential"
)

// floorDamage is the floor's damage count as root reads it.
func floorDamage(t *testing.T, s *FileStore) int {
	t.Helper()
	n, err := s.FloorDamage(context.Background())
	if err != nil {
		t.Fatalf("FloorDamage: %v", err)
	}
	return n
}

// deliveryFor is testDelivery for uid's scope.
func deliveryFor(uid uint32, n int) delivery {
	d := testDelivery(n)
	d.uid = fmt.Sprintf("00000000-0000-0000-%04d-%012d", uid%10000, n)
	d.entry = fmt.Sprintf("user/%d/token", uid)
	d.requestedBy = fmt.Sprintf("k3sm:local:%d", uid)
	d.items = []credential.Item{{Field: credential.FieldValue, Key: "token"}}
	return d
}

// U20: garbage appended to the floor with no newline (a torn or forged
// tail) is no outage for reads and revocations. The fragment is skipped and
// counted as damage; the next append writes a newline first, so the
// fragment is a line of its own; an rm and a withdraw of two uids each
// succeed after it, while a grant is refused before its first write
// (errFloorDegraded: the skipped line could have been a tombstone); and the
// tombstones written before it still refuse the copies they bury.
func TestFloorGarbageTailIsSkippedDamage(t *testing.T) {
	ctx := context.Background()
	s, server, u1 := fileLogScope(t)
	u2 := userScope(t, s, 1002)
	userPut(t, u2, "user/1002/token", "b")
	type held struct {
		u          *UserScope
		uid        uint32
		dir, saved string
	}
	var hs []held
	for _, h := range []held{{u: u1, uid: 1001}, {u: u2, uid: 1002}} {
		userPut(t, h.u, fmt.Sprintf("user/%d/old", h.uid), "old")
		h.dir = filepath.Join(scopeDir(server, fmt.Sprint(h.uid)), scopeEntriesName, "old")
		h.saved = filepath.Join(t.TempDir(), "old")
		copyTree(t, h.dir, h.saved)
		if err := h.u.Delete(ctx, fmt.Sprintf("user/%d/old", h.uid)); err != nil {
			t.Fatalf("rm before the garbage, uid %d: %v", h.uid, err)
		}
		if err := h.u.addDelivery(ctx, deliveryFor(h.uid, 1)); err != nil {
			t.Fatalf("deliver before the garbage, uid %d: %v", h.uid, err)
		}
		hs = append(hs, h)
	}
	garbage := []byte("\x00\xffnot a floor line user/1001 token")
	appendLogBytes(t, s, userFloorLogName, garbage)
	if _, _, err := u1.Current(ctx, "user/1001/token"); err != nil {
		t.Fatalf("current over a garbage tail: %v, want it served", err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("damage over a garbage tail is %d, want 1", n)
	}
	for _, h := range hs {
		if _, err := h.u.Put(ctx, fmt.Sprintf("user/%d/fresh", h.uid), KindOpaque, []byte("v")); !errors.Is(err, errFloorDegraded) {
			t.Fatalf("put after the garbage, uid %d: %v, want errFloorDegraded", h.uid, err)
		}
		entry := fmt.Sprintf("user/%d/token", h.uid)
		if err := h.u.Delete(ctx, entry); err != nil {
			t.Fatalf("rm after the garbage, uid %d: %v", h.uid, err)
		}
		if err := h.u.withdrawDelivery(ctx, deliveryFor(h.uid, 1).uid); err != nil {
			t.Fatalf("withdraw after the garbage, uid %d: %v", h.uid, err)
		}
	}
	if b := readLog(t, s, userFloorLogName); !bytes.Contains(b, append(garbage, '\n')) {
		t.Fatal("the next append did not close the garbage with a newline")
	}
	for _, h := range hs {
		restoreTree(t, h.saved, h.dir)
		_, _, err := h.u.Current(ctx, fmt.Sprintf("user/%d/old", h.uid))
		checkUserDeleted(t, "current of a copy buried before the garbage", err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("damage after the appends is %d, want 1 (the closed fragment, counted once)", n)
	}
}

// A torn line in the middle of the floor, closed by the next line's
// newline, is skipped: the lines on either side of it read, and it is
// counted as damage.
func TestFloorTornMiddleLineIsSkipped(t *testing.T) {
	s, _, _ := fileLogScope(t)
	a, err := floorLine("user/1001", "k1", guid(1), 5)
	if err != nil {
		t.Fatal(err)
	}
	torn, err := floorLine("user/1001", "k2", guid(1), 9)
	if err != nil {
		t.Fatal(err)
	}
	b, err := floorLine("user/1001", "k3", guid(1), 7)
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	buf = append(buf, a...)
	buf = append(buf, torn[:len(torn)/2]...)
	buf = append(buf, '\n')
	buf = append(buf, b...)
	appendLogBytes(t, s, userFloorLogName, buf)
	for _, c := range []struct {
		name string
		want uint64
	}{{"k1", 5}, {"k3", 7}} {
		got, err := s.userFloor.floor("user/1001", c.name, guid(1))
		if err != nil || got != c.want {
			t.Fatalf("floor of %s: %d, %v; want %d", c.name, got, err, c.want)
		}
	}
	// The torn line's key has no line the floor read: under damage it is
	// not trusted (the skipped line could have been its tombstone).
	if _, err := s.userFloor.floor("user/1001", "k2", guid(1)); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("floor of the torn line's key: %v, want errFloorDegraded", err)
	}
	if n := floorDamage(t, s); n != 1 {
		t.Fatalf("damage is %d, want 1", n)
	}
}
