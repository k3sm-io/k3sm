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
	"maps"
	"os"
	"path/filepath"
	"testing"
)

// TestUserScopeOffWhileMergePending: while a restore is staged (the floor
// moved aside, keystore-floor.json.pre-restore, in the data root) the user
// scope's start step and the server's store-directory step refuse, so the
// listener stays off and no store directory is made, and every user
// write verb this test drives (put, rotate, rm, withdraw) is refused with
// errMergePending, changing nothing; once keys floor merge has run, the
// start step passes and a user write lands.
func TestUserScopeOffWhileMergePending(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("v"))
	fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
	u := userScope(t, s, 1001)
	userPut(t, u, "user/1001/a", "v1")

	aside := maps.Clone(floorOf(t, server))
	aside["gone"] = floorEntry{Buried: []burial{{Generation: mgen(100), Deleted: 1}}}
	writeAsideFloor(t, server, aside)
	if err := s.StartUserScopes(ctx); !errors.Is(err, errMergePending) {
		t.Fatalf("the start step with a restore staged: %v, want errMergePending", err)
	}
	if err := s.EnsureDir(); !errors.Is(err, errMergePending) {
		t.Fatalf("the server's store-directory step with a restore staged: %v, want errMergePending", err)
	}
	if _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("v")); !errors.Is(err, errMergePending) {
		t.Fatalf("a user put with a restore staged: %v, want errMergePending", err)
	}
	if _, err := u.Rotate(ctx, "user/1001/a", []byte("v2")); !errors.Is(err, errMergePending) {
		t.Fatalf("a user rotate with a restore staged: %v, want errMergePending", err)
	}
	if err := u.Delete(ctx, "user/1001/a"); !errors.Is(err, errMergePending) {
		t.Fatalf("a user rm with a restore staged: %v, want errMergePending", err)
	}
	if err := u.Withdraw(ctx, "00000000-0000-4000-8000-000000000000"); !errors.Is(err, errMergePending) {
		t.Fatalf("a user withdraw with a restore staged: %v, want errMergePending", err)
	}
	if v, val, err := u.Current(ctx, "user/1001/a"); err != nil || v.Version != 1 || string(val) != "v1" {
		t.Fatalf("a after the refused writes: %+v %q %v, want version 1 unchanged", v, val, err)
	}
	if _, _, err := u.Current(ctx, "user/1001/b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("b after the refused put: %v, want ErrNotFound", err)
	}

	if _, err := mergeStaged(t, s, ctx, MergeOptions{}); err != nil {
		t.Fatalf("keys floor merge: %v", err)
	}
	if err := s.StartUserScopes(ctx); err != nil {
		t.Fatalf("the start step after the merge: %v", err)
	}
	userPut(t, u, "user/1001/b", "v")
	if err := u.Delete(ctx, "user/1001/a"); err != nil {
		t.Fatalf("a user rm after the merge: %v", err)
	}
}

// TestUserScopeDeliverRefusedWhileMergePending: while a restore is staged,
// a user deliver is refused with errMergePending and writes nothing: the
// scope's delivery record is byte for byte what it was, and the delivery is
// not recorded, so the reconciler, which writes Secrets only from recorded
// deliveries (and itself holds every sweep while a restore is staged,
// TestDeliveryRefusedWhileMergePending), has none to write. Once keys
// floor merge has run, the same deliver lands.
func TestUserScopeDeliverRefusedWhileMergePending(t *testing.T) {
	ctx := context.Background()
	s, server, u := newDeliveryScope(t)
	record := filepath.Join(scopeDir(server, "1001"), deliveriesName)
	before, beforeErr := os.ReadFile(record)
	aside := maps.Clone(floorOf(t, server))
	aside["gone"] = floorEntry{Buried: []burial{{Generation: mgen(100), Deleted: 1}}}
	writeAsideFloor(t, server, aside)
	d := testDelivery(1)
	if err := u.Deliver(ctx, exportDelivery(d)); !errors.Is(err, errMergePending) {
		t.Fatalf("a user deliver with a restore staged: %v, want errMergePending", err)
	}
	after, afterErr := os.ReadFile(record)
	if !bytes.Equal(before, after) || (beforeErr == nil) != (afterErr == nil) {
		t.Fatalf("the delivery record changed under a refused deliver: %d bytes (%v) became %d (%v)", len(before), beforeErr, len(after), afterErr)
	}
	if _, err := u.Delivery(ctx, d.uid); err == nil {
		t.Fatal("the refused delivery is recorded")
	}
	if _, err := mergeStaged(t, s, ctx, MergeOptions{}); err != nil {
		t.Fatalf("keys floor merge: %v", err)
	}
	if err := u.Deliver(ctx, exportDelivery(d)); err != nil {
		t.Fatalf("a user deliver after the merge: %v", err)
	}
	if _, err := u.Delivery(ctx, d.uid); err != nil {
		t.Fatalf("the delivery after the merge: %v", err)
	}
}
