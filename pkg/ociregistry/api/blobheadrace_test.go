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

package api

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// orphanBlobs pushes a tagged image into f's "app", so the half-repository
// brake does not hold, and n unreferenced blobs aged two grace periods, and
// returns the blobs' digests.
func (f *fixture) orphanBlobs(t *testing.T, grace time.Duration, n int) []digest.Digest {
	t.Helper()
	f.image(t, "app", "kept", "kept-layer")
	var ds []digest.Digest
	for i := range n {
		ds = append(ds, f.pushBlob(t, "app", []byte("orphan-"+string(rune('a'+i)))))
	}
	f.age(t, "app", time.Now().Add(-2*grace), ds...)
	return ds
}

// blobHeld reports whether repo still holds blob d.
func (f *fixture) blobHeld(t *testing.T, repo string, d digest.Digest) bool {
	t.Helper()
	n, err := ref.ParseName(repo)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.st.StatBlob(n, d)
	return err == nil
}

// TestBlobHeadBetweenMarkAndDelete runs blob HEADs between a deleting sweep's
// unlocked mark, which has planned to reap the blob, and its locked pass, and
// requires every HEAD to answer 200 or 404 and no blob a HEAD answered 200 for
// to be reaped by that sweep.
//
// The first case is deterministic and is the one that pins the repository
// lock around the HEAD's touch (store.TouchBlob's WithLock): the HEAD has
// opened the blob and is about to write its mtime when the sweep goes on, and
// the touch finishes only once the sweep is blocked on the lock, or, without
// the lock, once the sweep has returned. With the lock the sweep's locked
// re-plan sees the fresh mtime and keeps the blob; without it the sweep reaps
// the blob under the open descriptor and the HEAD still answers 200, which
// this case fails on. The second case races many HEADs against the locked
// pass with no ordering at all, for the race detector.
func TestBlobHeadBetweenMarkAndDelete(t *testing.T) {
	const grace = time.Hour

	t.Run("a HEAD whose touch straddles the locked pass keeps the blob", func(t *testing.T) {
		f := newFixture(t)
		d := f.orphanBlobs(t, grace, 1)[0]
		c := f.deletingCollector(t, grace)

		sweepCtx := newLockWaitCtx()
		swept := make(chan struct{})
		inTouch := make(chan struct{})
		var touchOnce sync.Once
		// The touch reads the store clock after it opened the blob and
		// before it writes the mtime: hold it there until the sweep is
		// blocked on the lock, or has finished.
		f.st.SetClock(func() time.Time {
			touchOnce.Do(func() {
				close(inTouch)
				select {
				case <-sweepCtx.waiting:
				case <-swept:
				}
			})
			return time.Now()
		})
		headed := make(chan int, 1)
		var markOnce sync.Once
		c.SetAfterMark(func(ref.Name) {
			markOnce.Do(func() {
				go func() { headed <- f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil).Code }()
				// Wait for the HEAD to reach its touch.
				<-inTouch
			})
		})
		var sweepErr error
		go func() {
			defer close(swept)
			_, sweepErr = c.Sweep(sweepCtx)
		}()
		code := <-headed
		<-swept
		if sweepErr != nil {
			t.Fatal(sweepErr)
		}
		if code != http.StatusOK {
			t.Fatalf("HEAD between the mark and the locked pass: status %d, want 200", code)
		}
		if !f.blobHeld(t, "app", d) {
			t.Fatal("the sweep reaped a blob a HEAD answered 200 for")
		}
	})

	t.Run("racing HEADs answer 200 or 404 and a 200 is never reaped", func(t *testing.T) {
		base := newFixture(t)
		ds := base.orphanBlobs(t, grace, 2)
		const heads = 8
		for range 4 {
			f := base.clone(t)
			c := f.deletingCollector(t, grace)
			var wg sync.WaitGroup
			var mu sync.Mutex
			codes := map[digest.Digest][]int{}
			var markOnce sync.Once
			start := make(chan struct{})
			c.SetAfterMark(func(ref.Name) {
				markOnce.Do(func() {
					for i := range heads {
						d := ds[i%len(ds)]
						wg.Go(func() {
							<-start
							code := f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil).Code
							mu.Lock()
							codes[d] = append(codes[d], code)
							mu.Unlock()
						})
					}
					close(start)
				})
			})
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}
			wg.Wait()
			for _, d := range ds {
				for _, code := range codes[d] {
					if code != http.StatusOK && code != http.StatusNotFound {
						t.Errorf("HEAD of %s during the sweep: status %d, want 200 or 404", d, code)
					}
				}
				if slices.Contains(codes[d], http.StatusOK) && !f.blobHeld(t, "app", d) {
					t.Errorf("the sweep reaped %s after a HEAD answered 200 for it; statuses %v", d, codes[d])
				}
			}
		}
	})
}
