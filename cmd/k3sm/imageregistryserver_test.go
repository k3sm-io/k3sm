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
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// newRegistryServer is the k3sm registry server over a fresh store, served in
// process.
func newRegistryServer(t *testing.T) http.Handler {
	t.Helper()
	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Config{Store: st, GCGrace: time.Hour, Authorize: api.AllowAll, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// TestImageVerbsAgainstTheRegistryServer runs the image verbs' registry paths
// against the k3sm registry server instead of the fake: image ls and image df
// give the golden documents, and a push with mount scopes lands and pulls.
func TestImageVerbsAgainstTheRegistryServer(t *testing.T) {
	t.Run("image ls and df match the golden documents", func(t *testing.T) {
		f := newImageFixture(t, true)
		srv := newRegistryServer(t)
		if err := f.reg.PushTo(srv); err != nil {
			t.Fatal(err)
		}
		f.env.transport = handlerTransport{srv}
		checkGolden(t, "image_ls.golden.json", runImageReport(t, f.env, "ls", "-o", "json"))
		checkGolden(t, "image_df.golden.json", runImageReport(t, f.env, "df", "-o", "json"))
	})
	t.Run("a push with mount scopes lands, and a copy mounts", func(t *testing.T) {
		srv := newRegistryServer(t)
		opts := []remote.Option{remote.WithContext(t.Context()), remote.WithTransport(handlerTransport{srv})}
		ref, err := name.NewTag("registry.invalid:5000/team/myapp:v1", name.Insecure)
		if err != nil {
			t.Fatal(err)
		}
		img, err := random.Image(64, 4)
		if err != nil {
			t.Fatal(err)
		}
		pushOpts, err := withMountScopes(t.Context(), ref, img, opts)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(ref, img, pushOpts...); err != nil {
			t.Fatalf("push: %v", err)
		}
		pulled, err := remote.Image(ref, opts...)
		if err != nil {
			t.Fatalf("pull: %v", err)
		}
		dst, _ := name.NewTag("registry.invalid:5000/team/other:v1", name.Insecure)
		copyOpts, err := withMountScopes(t.Context(), dst, pulled, opts)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(dst, pulled, copyOpts...); err != nil {
			t.Fatalf("copy: %v", err)
		}
		got, err := remote.Image(dst, opts...)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := img.Digest()
		if d, _ := got.Digest(); d != want {
			t.Errorf("copy is %s, want %s", d, want)
		}
	})
}
