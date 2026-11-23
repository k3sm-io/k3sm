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
	"os"
	"slices"
	"testing"
)

// A put committed without its floor line is caught up by the next
// operation on its scope, under the store lock, with no restart: a put of
// another name, and a withdraw, each append the lost live line once.
func TestRuntimeCatchUpRestoresLostEntryLine(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	if err := u.addDelivery(ctx, testDelivery(1)); err != nil {
		t.Fatal(err)
	}
	fl := s.userFloor.(*fileFloorLog).log
	lose := func(name string) [generationSize]byte {
		t.Helper()
		fl.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected floor write failure") }
		defer func() { fl.write = nil }()
		if _, err := u.Put(ctx, "user/1001/"+name, KindOpaque, []byte("v")); !errors.Is(err, errCommitted) {
			t.Fatalf("put of %s whose floor line fails: %v, want errCommitted", name, err)
		}
		return entryGeneration(t, server, name)
	}
	isLive := func(name string, gen [generationSize]byte) bool {
		t.Helper()
		live, err := s.userFloor.liveGens("user/1001", name)
		if err != nil {
			t.Fatal(err)
		}
		return slices.Contains(live, gen)
	}
	g1 := lose("lost1")
	if isLive("lost1", g1) {
		t.Fatal("the lost put has a live floor line")
	}
	if _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put of another name: %v", err)
	}
	if !isLive("lost1", g1) {
		t.Fatal("the next put on the scope did not catch up the lost entry's floor line")
	}
	g2 := lose("lost2")
	if err := u.Withdraw(ctx, testDelivery(1).uid); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !isLive("lost2", g2) {
		t.Fatal("the next withdraw on the scope did not catch up the lost entry's floor line")
	}
	if _, err := u.Put(ctx, "user/1001/third", KindOpaque, []byte("v")); err != nil {
		t.Fatal(err)
	}
	line, err := floorLine("user/1001", "lost2", g2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(readLog(t, s, userFloorLogName), line); n != 1 {
		t.Fatalf("the caught-up entry's live line is in the floor %d times, want once", n)
	}
}
