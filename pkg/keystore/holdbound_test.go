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
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// bubbleWait waits d on the clock of the synctest bubble it is called in,
// where time is fake and the wait costs no wall time. It is only called
// inside synctest.Test.
func bubbleWait(d time.Duration) { <-time.NewTimer(d).C }

// U108: on synctest's clock, with a GeneratedUID lookup that takes its
// whole 250 ms deadline, no store lock hold of a server operation (a
// minting put, a put, rotate, rotate from a version, deliver, withdraw,
// list, read-for-exec, rm) contains a lookup or any other wait the clock
// sees: each hold spans zero fake time, because the lookup runs before
// the lock and its one answer is used for the hold. Before the hoist each
// operation looked the uid up under the lock, up to three times for a
// minting deliver. The fake clock does not count CPU or file work, so
// this bounds no hold's work: the walk and listing tests check that put
// and rotate holds walk nothing, and the work itself is measured
// (K3SM_KEYSTORE_MEASURE), not checked.
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
			bubbleWait(generatedUIDDeadline) // a slow directory service
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
				if h != 0 {
					t.Errorf("%s held the store lock for %s on the clock, want none: a wait the clock sees ran inside the hold", op.name, h)
				}
			}
			if len(holds) == 0 {
				t.Errorf("%s took no store lock hold the observer saw", op.name)
			}
			mu.Unlock()
		}
	})
}

// U89 and U108 on synctest's clock: uid A rotates an entry padded with
// thousands of files, in a server just started (no usage figure), and
// while A's rotation holds the store lock exclusive uid B's rm waits for
// it; B is served within its LockWait once A's hold ends. The figure is
// built by a walk before the lock, so A's hold walks nothing (the counted
// walk seam), and its orphan check reads only the version above the
// pointer, leaving a file planted further up unread. A's hold is given
// fake work at its sync step so B's wait is seen.
func TestRotateHoldServesOtherUIDWithinLockWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const (
			padFiles = 2000
			lockWait = 100 * time.Millisecond
			work     = 20 * time.Millisecond
		)
		ctx := context.Background()
		s, server := newMasteredStore(t)
		s.lockWait = lockWait
		fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1), 1002: guid(0xA2)})
		a := userScope(t, s, 1001)
		b, err := s.UserScope(1002)
		if err != nil {
			t.Fatal(err)
		}
		userPut(t, a, "user/1001/big", "one")
		userPut(t, b, "user/1002/gone", "v")
		big := filepath.Join(scopeDir(server, "1001"), scopeEntriesName, "big")
		for i := range padFiles {
			if err := os.WriteFile(filepath.Join(big, "pad-"+strconv.Itoa(i)), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		planted := filepath.Join(big, versionName(9))
		if err := os.WriteFile(planted, []byte("junk"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.usage.forget(1001) // a server just started holds no figure
		under, outside := countUsageLstats(s)
		var (
			mu        sync.Mutex
			exclusive []time.Duration
		)
		s.holdObserver = func(ex bool, held time.Duration) {
			if ex {
				mu.Lock()
				exclusive = append(exclusive, held)
				mu.Unlock()
			}
		}
		inHold, release := make(chan struct{}), make(chan struct{})
		s.step = func(name string) error {
			if name == "sync "+versionName(2) {
				close(inHold)
				<-release
			}
			return nil
		}
		rotated := make(chan error, 1)
		go func() {
			_, err := a.Rotate(ctx, "user/1001/big", []byte("two"))
			rotated <- err
		}()
		<-inHold
		var (
			rmErr         error
			asked, served time.Time
		)
		rmDone := make(chan struct{})
		go func() {
			asked = time.Now()
			rmErr = b.Delete(ctx, "user/1002/gone")
			served = time.Now()
			close(rmDone)
		}()
		synctest.Wait() // B's rm is blocked on the store lock A holds
		select {
		case <-rmDone:
			t.Fatalf("uid B's rm ended (%v) while uid A held the store lock exclusive", rmErr)
		default:
		}
		bubbleWait(work)
		close(release)
		if err := <-rotated; err != nil {
			t.Fatalf("uid A's rotate: %v", err)
		}
		<-rmDone
		if rmErr != nil {
			t.Fatalf("uid B's rm behind uid A's rotate: %v", rmErr)
		}
		if w := served.Sub(asked); w < work || w > lockWait {
			t.Fatalf("uid B's rm was served after %s, want it to wait out A's %s hold and no more than its %s LockWait", w, work, lockWait)
		}
		mu.Lock()
		defer mu.Unlock()
		long := false
		for _, h := range exclusive {
			long = long || h >= work
		}
		if !long {
			t.Fatalf("no exclusive hold of %s or more was seen (%v): uid A's rotate did not hold the lock while B waited", work, exclusive)
		}
		if under.Load() != 0 || outside.Load() < padFiles {
			t.Fatalf("uid A's rotate walked %d files under the lock and %d before it, want none under it and the scope before it", under.Load(), outside.Load())
		}
		if got, err := os.ReadFile(planted); err != nil || string(got) != "junk" {
			t.Fatalf("the orphan check read past the version above the pointer: %q, %v", got, err)
		}
	})
}
