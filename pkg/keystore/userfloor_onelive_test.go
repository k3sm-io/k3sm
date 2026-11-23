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

// assertOneLivePerName fails when the floor holds a name with more than one
// live (unburied) generation.
func assertOneLivePerName(t *testing.T, s *FileStore, after string) {
	t.Helper()
	ff := s.userFloor.(*fileFloorLog)
	var names []nameKey
	if err := ff.read(func(st *logState) {
		for nk := range st.firstGen {
			names = append(names, nk)
		}
	}); err != nil {
		t.Fatal(err)
	}
	for _, nk := range names {
		live, err := ff.liveGens(nk.scope, nk.name)
		if err != nil {
			t.Fatal(err)
		}
		if len(live) > 1 {
			t.Fatalf("after %s: %s %s has %d live floor generations %x, want at most one", after, nk.scope, nk.name, len(live), live)
		}
	}
}

// U20: no server path leaves a name with two live floor generations (put
// is create-only and user rotate does not exist yet): put, rm, a put after rm, rm of an absent tree, a
// deliver and a withdraw, and the start step's catch-up across a restart
// each leave at most one, so a burial's floor share is the one live
// generation plus the authenticated, pointer and tree generations it caps.
func TestServerPathsLeaveOneLiveGeneration(t *testing.T) {
	ctx := context.Background()
	s, _, u := fileLogScope(t)
	assertOneLivePerName(t, s, "setup")
	steps := []struct {
		name string
		fn   func() error
	}{
		{"put", func() error { _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("1")); return err }},
		{"rm", func() error { return u.Delete(ctx, "user/1001/a") }},
		{"put after rm", func() error { _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("3")); return err }},
		{"rm again", func() error { return u.Delete(ctx, "user/1001/a") }},
		{"rm of an absent tree", func() error { err := u.Delete(ctx, "user/1001/a"); return ignoreNotFound(err) }},
		{"put a third time", func() error { _, err := u.Put(ctx, "user/1001/a", KindOpaque, []byte("4")); return err }},
		{"deliver", func() error { return u.addDelivery(ctx, testDelivery(1)) }},
		{"second deliver", func() error { return u.addDelivery(ctx, testDelivery(2)) }},
		{"withdraw", func() error { return u.withdrawDelivery(ctx, testDelivery(1).uid) }},
	}
	for _, st := range steps {
		if err := st.fn(); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		assertOneLivePerName(t, s, st.name)
	}
	forgetDeliveriesSeen(s)
	s2 := reopenStore(t, s)
	if err := s2.startUserScopes(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	assertOneLivePerName(t, s2, "the start step's catch-up")
}

func ignoreNotFound(err error) error {
	if err == nil || errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
