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
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// maxExclusiveHold is the design's bound on the work one server exclusive
// hold does (docs/design/keystore.md § "Lock modes and fairness").
const maxExclusiveHold = 50 * time.Millisecond

// U108: on synctest's clock, with a GeneratedUID lookup that takes its
// whole 250 ms deadline, no exclusive hold of a server operation (a minting
// put, a put, rotate, rotate from a version, deliver, withdraw, rm) lasts
// more than 50 ms: the lookup runs before the lock and its one answer is
// used for the hold. Each operation looked the uid up under the lock, up to
// three times for a minting deliver, before the hoist. The shared holds of
// list and read-for-exec are reported too, and held to the same bound.
func TestExclusiveHoldBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx := context.Background()
		s, _ := newMasteredStore(t)
		var (
			mu    sync.Mutex
			holds []time.Duration
		)
		s.holdObserver = func(exclusive bool, held time.Duration) {
			mu.Lock()
			holds = append(holds, held)
			mu.Unlock()
		}
		fakeGUIDs(t, nil)
		setSeam(t, &generatedUIDSeam, func(uint32) ([generationSize]byte, error) {
			time.Sleep(generatedUIDDeadline) // a slow directory service
			return guid(0xA1), nil
		})
		u := userScope(t, s, 1001)
		ops := []struct {
			name string
			run  func() error
		}{
			{"put minting the scope", func() error { _, err := u.Put(ctx, "user/1001/token", KindOpaque, []byte("one")); return err }},
			{"put", func() error { _, err := u.Put(ctx, "user/1001/b", KindOpaque, []byte("b")); return err }},
			{"rotate", func() error { _, err := u.Rotate(ctx, "user/1001/token", []byte("two")); return err }},
			{"rotate from", func() error { _, err := u.RotateFrom(ctx, "user/1001/token", 1); return err }},
			{"deliver", func() error { return u.addDelivery(ctx, testDelivery(1)) }},
			{"withdraw", func() error { return u.withdrawDelivery(ctx, testDelivery(1).uid) }},
			{"list", func() error { _, err := u.List(ctx); return err }},
			{"read-for-exec", func() error { _, _, err := u.ReadForExec(ctx, "user/1001/token"); return err }},
			{"rm", func() error { return u.Delete(ctx, "user/1001/b") }},
		}
		for _, op := range ops {
			mu.Lock()
			holds = nil
			mu.Unlock()
			if err := op.run(); err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			mu.Lock()
			for _, h := range holds {
				if h > maxExclusiveHold {
					t.Errorf("%s held the store lock for %s on the clock, past %s", op.name, h, maxExclusiveHold)
				}
			}
			if len(holds) == 0 {
				t.Errorf("%s took no store lock hold the observer saw", op.name)
			}
			mu.Unlock()
		}
	})
}
