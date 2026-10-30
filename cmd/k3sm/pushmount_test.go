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

package main

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// opaqueIndex hides every method of an index but the ImageIndex interface,
// so a child that is a bare layer cannot be enumerated.
type opaqueIndex struct{ ggcrv1.ImageIndex }

// TestSameRegistryMountsCompleteness pins which shapes the walk can enumerate.
// A shape it cannot is reported incomplete, which is what makes the push
// fail closed.
func TestSameRegistryMountsCompleteness(t *testing.T) {
	repo, err := name.NewRepository("127.0.0.1:6450/team/myapp")
	if err != nil {
		t.Fatal(err)
	}
	img, err := random.Image(64, 2)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := random.Layer(64, "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	withLayer := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: layer})
	cases := []struct {
		name string
		t    any
		want bool
	}{
		{"an image", img, true},
		{"an index of images", mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: img}), true},
		{"an index whose layer child it can fetch", withLayer, true},
		{"an index whose layer child it cannot fetch", opaqueIndex{withLayer}, false},
		{"an unknown type", struct{}{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, complete, err := sameRegistryMounts(repo, tc.t)
			if err != nil {
				t.Fatal(err)
			}
			if complete != tc.want {
				t.Errorf("complete = %v, want %v", complete, tc.want)
			}
		})
	}
}

// TestWithMountScopesFailsClosed pins that a push whose source the walk
// cannot enumerate runs with one job: at most one blob request is ever in
// flight, so no layer upload can read the writer's client while another
// replaces it. A shape the walk enumerates keeps parallel uploads, which
// shows the measurement can see concurrency at all.
func TestWithMountScopesFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		shape   func(img ggcrv1.Image) any
		maxWant func(n int) bool
		want    string
	}{
		{"an unknown shape uploads one blob at a time", func(ggcrv1.Image) any { return struct{}{} }, func(n int) bool { return n == 1 }, "1"},
		{"an enumerable image uploads in parallel", func(img ggcrv1.Image) any { return img }, func(n int) bool { return n > 1 }, "more than 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New()
			reg.AcceptWrites = true
			c := &concurrencyWatch{inner: reg.Handler()}
			// Served in process (handlerTransport): no socket is opened.
			ref, err := name.NewTag("registry.invalid:5000/team/myapp:v1", name.Insecure)
			if err != nil {
				t.Fatal(err)
			}
			img, err := random.Image(64, 6)
			if err != nil {
				t.Fatal(err)
			}
			opts, err := withMountScopes(t.Context(), ref, tc.shape(img), []remote.Option{remote.WithContext(t.Context()), remote.WithTransport(handlerTransport{c})})
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(ref, img, opts...); err != nil {
				t.Fatalf("push: %v", err)
			}
			if n := c.peak(); !tc.maxWant(n) {
				t.Errorf("at most %d blob requests were in flight at once, want %s", n, tc.want)
			}
		})
	}
}

// concurrencyWatch records the most blob requests in flight at once, holding
// each briefly so concurrent ones overlap.
type concurrencyWatch struct {
	inner http.Handler

	mu       sync.Mutex
	inFlight int
	max      int
}

func (c *concurrencyWatch) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if strings.Contains(req.URL.Path, "/blobs/") {
		c.mu.Lock()
		c.inFlight++
		c.max = max(c.max, c.inFlight)
		c.mu.Unlock()
		defer func() {
			c.mu.Lock()
			c.inFlight--
			c.mu.Unlock()
		}()
		time.Sleep(30 * time.Millisecond)
	}
	c.inner.ServeHTTP(w, req)
}

func (c *concurrencyWatch) peak() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.max
}
