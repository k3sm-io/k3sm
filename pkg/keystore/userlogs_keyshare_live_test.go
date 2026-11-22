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
	"fmt"
	"testing"
)

// The per-uid key share counts only keys whose latest line is live: a uid's
// put/rm churn, twice its share over, costs it no share once each key is
// buried, and its next put succeeds; a uid at its live share is still
// refused. The global key count, buried keys included, is unchanged.
func TestFloorKeyShareCountsLiveKeys(t *testing.T) {
	ctx := context.Background()
	s, server, u := fileLogScope(t)
	l := syncedFloor(t, s)
	const room = 3
	l.mu.Lock()
	held := l.state.uidKeys[1001]
	l.maxKeys, l.maxShare = l.state.keys+100, held+room
	keys0 := l.state.keys
	l.mu.Unlock()
	for i := range 2 * room {
		name := fmt.Sprintf("user/1001/churn%d", i)
		if _, err := u.Put(ctx, name, KindOpaque, []byte("v")); err != nil {
			t.Fatalf("churn put %d: %v", i, err)
		}
		if err := u.Delete(ctx, name); err != nil {
			t.Fatalf("churn rm %d: %v", i, err)
		}
	}
	if _, err := u.Put(ctx, "user/1001/after", KindOpaque, []byte("v")); err != nil {
		t.Fatalf("put after churn twice the share over: %v, want it to succeed", err)
	}
	syncedFloor(t, s)
	l.mu.Lock()
	keys := l.state.keys
	l.mu.Unlock()
	if want := keys0 + 2*room + 1; keys != want {
		t.Fatalf("the floor's global key count is %d, want %d with buried keys counted", keys, want)
	}
	plantFloorKeys(t, s, "user/1001", "live", room-1)
	checkPutRefusedFirst(t, u, server, "user/1001/other", ErrLogFull)
}
