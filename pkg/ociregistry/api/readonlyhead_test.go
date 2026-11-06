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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestReadOnlyHeadWrites pins that a blob HEAD, a read, writes: a principal
// allowed only to read, refused every write, takes the repository lock and
// restarts the grace of a blob it names, and the inode it refreshes is the
// one every repository that links the blob shares. So pull-only access can
// keep a blob alive in each of those repositories. Without the HEAD the same
// sweep reaps the blob from both, so the test is not vacuous.
func TestReadOnlyHeadWrites(t *testing.T) {
	const grace = time.Hour
	readOnly := func(_ *http.Request, v Verb, _ ref.Name) error {
		if v != VerbRead {
			return errorf(http.StatusForbidden, codeDenied, "read only")
		}
		return nil
	}
	// setup pushes a blob into "app", mounts it into "other" (a second link
	// to the same inode), keeps a tagged image in each so the half brake does
	// not hold, ages the blob past the grace, and returns the writer's
	// fixture, a read-only server over the same store and the blob.
	setup := func(t *testing.T) (*fixture, *fixture, digest.Digest) {
		f := newFixture(t)
		d := f.orphanBlobs(t, grace, 1)[0]
		f.image(t, "other", "kept", "other-layer")
		want(t, f.do(http.MethodPost, "/v2/other/blobs/uploads/?mount="+d.String()+"&from=app", nil), http.StatusCreated, "")
		f.age(t, "app", time.Now().Add(-2*grace), d)
		r := fixtureOver(t, f.workDir(), func(c *Config) { c.Authorize = readOnly })
		want(t, r.do(http.MethodPost, "/v2/app/blobs/uploads/", nil), http.StatusForbidden, codeDenied)
		return f, r, d
	}

	t.Run("a read-only HEAD takes the lock and keeps the shared blob in every repository", func(t *testing.T) {
		f, r, d := setup(t)
		old := f.mtime(t, "other", d)
		release := f.holdLock(t, "app")
		headCtx := newLockWaitCtx()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- r.serve(req(http.MethodHead, "/v2/app/blobs/"+d.String(), nil).WithContext(headCtx)) }()
		// Wait for the HEAD to block on the repository lock.
		<-headCtx.waiting
		select {
		case w := <-done:
			t.Fatalf("the read-only HEAD answered %d while the repository lock was held", w.Code)
		default:
		}
		release()
		want(t, <-done, http.StatusOK, "")
		if got := f.mtime(t, "other", d); !got.After(old) {
			t.Fatalf("mtime of the link in other %s after a read-only HEAD in app, want later than %s", got, old)
		}
		deletingSweep(t, f.deletingCollector(t, grace))
		for _, repo := range []string{"app", "other"} {
			if !f.blobHeld(t, repo, d) {
				t.Errorf("the sweep reaped the blob from %s after a read-only HEAD in app", repo)
			}
		}
	})

	t.Run("without the HEAD the sweep reaps the blob from every repository", func(t *testing.T) {
		f, _, d := setup(t)
		deletingSweep(t, f.deletingCollector(t, grace))
		for _, repo := range []string{"app", "other"} {
			if f.blobHeld(t, repo, d) {
				t.Errorf("the sweep kept the unreferenced blob in %s", repo)
			}
		}
	})
}
