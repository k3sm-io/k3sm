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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// handlerTransport answers every request by calling h through a recorder, so
// a real client stack runs and no socket is opened.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.h.ServeHTTP(rec, r)
	}()
	select {
	case <-done:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	resp := rec.Result()
	resp.Request = r
	return resp, nil
}

// mountWatch records the mount requests a client makes.
type mountWatch struct {
	h      http.Handler
	mu     sync.Mutex
	mounts []string
}

func (m *mountWatch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Query().Has("mount") {
		m.mu.Lock()
		m.mounts = append(m.mounts, r.URL.Query().Get("from"))
		m.mu.Unlock()
	}
	m.h.ServeHTTP(w, r)
}

// testGGCRPushPull pushes an image and an index with go-containerregistry,
// pulls them back by tag and digest, and copies the image to a second
// repository, which go-containerregistry does by cross-repository mount.
func testGGCRPushPull(t *testing.T, srv http.Handler) {
	watch := &mountWatch{h: srv}
	opts := []remote.Option{remote.WithContext(t.Context()), remote.WithTransport(handlerTransport{watch})}
	img, err := random.Image(256, 3)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := name.NewTag("registry.test/team/app:v1", name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(tag, img, opts...); err != nil {
		t.Fatalf("push: %v", err)
	}
	want, _ := img.Digest()
	got, err := remote.Image(tag, opts...)
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if d, _ := got.Digest(); d != want {
		t.Fatalf("pulled %s, pushed %s", d, want)
	}
	layers, err := got.Layers()
	if err != nil || len(layers) != 3 {
		t.Fatalf("layers %d, %v", len(layers), err)
	}
	for _, l := range layers {
		rc, err := l.Compressed()
		if err != nil {
			t.Fatal(err)
		}
		// Reading to the end verifies the layer digest.
		if _, err := io.Copy(io.Discard, rc); err != nil {
			t.Fatalf("read layer: %v", err)
		}
		rc.Close()
	}

	idx, err := random.Index(128, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	itag, _ := name.NewTag("registry.test/team/multi:v1", name.Insecure)
	if err := remote.WriteIndex(itag, idx, opts...); err != nil {
		t.Fatalf("push index: %v", err)
	}
	pulled, err := remote.Index(itag, opts...)
	if err != nil {
		t.Fatalf("pull index: %v", err)
	}
	im, err := pulled.IndexManifest()
	if err != nil || len(im.Manifests) != 2 {
		t.Fatalf("index children %v, %v", im, err)
	}
	child, err := name.NewDigest("registry.test/team/multi@"+im.Manifests[0].Digest.String(), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Image(child, opts...); err != nil {
		t.Fatalf("pull a child by digest: %v", err)
	}

	copyTag, _ := name.NewTag("registry.test/team/copy:v1", name.Insecure)
	// One job: go-containerregistry updates its mount scopes without a lock
	// when uploads that mount run in parallel (a data race inside the
	// library; the k3sm push path sets the scopes up front instead).
	if err := remote.Write(copyTag, got, append(opts, remote.WithJobs(1))...); err != nil {
		t.Fatalf("copy: %v", err)
	}
	watch.mu.Lock()
	mounts := strings.Join(watch.mounts, ",")
	watch.mu.Unlock()
	if !strings.Contains(mounts, "team/app") {
		t.Errorf("the copy made mount requests from %q, want team/app", mounts)
	}
	if _, err := remote.Image(copyTag, opts...); err != nil {
		t.Fatalf("pull the copy: %v", err)
	}
}
