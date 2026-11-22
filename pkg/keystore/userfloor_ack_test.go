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
	"path/filepath"
	"testing"
)

// After root acknowledges the floor's damage, unattributable damage before
// the watermark no longer refuses a put, a tainted key stays refused, a new
// damaged line past the watermark counts again, and an acknowledgement for
// another file (a different inode) is ignored. Only root acknowledges.
func TestFloorDamageAckLiftsOnlyUnattributable(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	ff := s.userFloor.(*fileFloorLog)
	appendLogBytes(t, s, userFloorLogName, []byte("\ngarbage\nuser/1001 gone 0123\n"))
	put := func(name string) error {
		_, err := u.Put(ctx, "user/1001/"+name, KindOpaque, []byte("v"))
		return err
	}
	if err := put("a"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put over unattributable damage: %v, want errFloorDegraded", err)
	}
	euid := s.euid
	s.euid = func() int { return int(s.floorUID) + 1 }
	if err := s.ackFloorDamage(ctx); !errors.Is(err, errAckNotRoot) {
		t.Fatalf("an acknowledgement by a caller that is not root: %v, want errAckNotRoot", err)
	}
	s.euid = euid
	if err := s.ackFloorDamage(ctx); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	if err := put("a"); err != nil {
		t.Fatalf("put after the acknowledgement: %v", err)
	}
	if _, err := ff.floor("user/1001", "gone", guid(0x01)); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("a tainted key after the acknowledgement: %v, want errFloorDegraded", err)
	}
	if err := put("gone"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("a put of the tainted name after the acknowledgement: %v, want errFloorDegraded", err)
	}
	appendLogBytes(t, s, userFloorLogName, []byte("\nmore garbage\n"))
	if err := put("b"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put over damage past the watermark: %v, want errFloorDegraded", err)
	}
	if err := s.ackFloorDamage(ctx); err != nil {
		t.Fatalf("ackFloorDamage: %v", err)
	}
	if err := put("b"); err != nil {
		t.Fatalf("put after the second acknowledgement: %v", err)
	}
	p := filepath.Join(s.dataRoot, floorAckName)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	a, err := parseFloorAck(b)
	if err != nil {
		t.Fatalf("the acknowledgement written does not parse: %v", err)
	}
	a.ino++
	if err := os.WriteFile(p, a.encode(), floorFileMode); err != nil {
		t.Fatal(err)
	}
	if err := put("c"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put under a stale acknowledgement: %v, want errFloorDegraded", err)
	}
	a.ino--
	if err := os.WriteFile(p, a.encode(), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := put("c"); !errors.Is(err, errFloorDegraded) {
		t.Fatalf("put under an other-writable acknowledgement: %v, want errFloorDegraded", err)
	}
}
