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
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
)

// sweepAt runs one deleting sweep of f's store whose clock reads at.
func (f *fixture) sweepAt(t *testing.T, grace time.Duration, at time.Time) {
	t.Helper()
	started := false
	now := func() time.Time {
		if !started {
			started = true
			return at.Add(-2 * grace)
		}
		return at
	}
	c, err := gc.New(f.st, gc.Options{Grace: grace, Now: now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := gc.WriteMarker(f.st, at); err != nil {
		t.Fatal(err)
	}
	deletingSweep(t, c)
}

// TestBlobHeadWindowIsBounded pins how long a blob HEAD that answered 200
// protects the blob from the collector: at least half the grace, a full grace
// when the HEAD touched it, and no longer. A sweep past that reaps the blob,
// so a client whose manifest PUT comes later finds it gone.
func TestBlobHeadWindowIsBounded(t *testing.T) {
	const grace = time.Hour

	t.Run("a touched blob is kept for one grace after the HEAD and reaped past it", func(t *testing.T) {
		f := newFixture(t)
		d := f.orphanBlobs(t, grace, 1)[0]
		old := f.mtime(t, "app", d)
		want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
		touched := f.mtime(t, "app", d)
		if !touched.After(old) {
			t.Fatalf("mtime %s after a HEAD past the half-grace, want later than %s", touched, old)
		}
		f.sweepAt(t, grace, touched.Add(grace-time.Second))
		if !f.blobHeld(t, "app", d) {
			t.Fatal("a sweep inside one grace of the HEAD's touch reaped the blob")
		}
		f.sweepAt(t, grace, touched.Add(grace+time.Second))
		if f.blobHeld(t, "app", d) {
			t.Fatal("a sweep past one grace of the HEAD's touch kept the blob")
		}
	})

	t.Run("a HEAD inside the half-grace writes nothing and protects only what is left", func(t *testing.T) {
		f := newFixture(t)
		d := f.orphanBlobs(t, grace, 1)[0]
		headAt := time.Now()
		young := headAt.Add(-grace/2 + time.Minute)
		f.age(t, "app", young, d)
		want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
		if got := f.mtime(t, "app", d); !got.Equal(young) {
			t.Fatalf("mtime %s after a HEAD inside the half-grace, want %s", got, young)
		}
		f.sweepAt(t, grace, headAt.Add(grace/2))
		if !f.blobHeld(t, "app", d) {
			t.Fatal("a sweep half a grace after the HEAD reaped the blob")
		}
		// Past the blob's own grace, which ends before one grace after the HEAD.
		f.sweepAt(t, grace, young.Add(grace+time.Second))
		if f.blobHeld(t, "app", d) {
			t.Fatal("a sweep past the blob's grace kept it: the HEAD extended a window it did not touch")
		}
	})
}
