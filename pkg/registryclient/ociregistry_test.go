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

package registryclient_test

import (
	"context"
	"slices"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/api"
	"k3sm.io/k3sm/pkg/ociregistry/store"
	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// TestClientAgainstTheRegistryServer runs the client over the k3sm registry
// server itself (in process, no socket), holding the content the fake serves
// in the other tests: the catalog, tag lists and Describe agree.
func TestClientAgainstTheRegistryServer(t *testing.T) {
	reg := registrytest.New()
	shared := []byte("shared base layer")
	single := reg.Image("app", "v1", darwn, shared, []byte("app layer"))
	reg.Image("app", "v2", darwn, shared, []byte("app layer 2"))
	a := reg.Image("team/multi", "", arm64, shared, []byte("arm layer"))
	b := reg.Image("team/multi", "", amd64, shared, []byte("amd layer"))
	att := reg.Image("team/multi", "", attes, []byte("provenance"))
	idx := reg.Index("team/multi", "v1", a, b, att)

	st, err := store.OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := api.New(api.Config{Store: st, Authorize: api.AllowAll, FreeSpace: func() (uint64, error) { return 1 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.PushTo(srv); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, srv, registryclient.Options{})
	ctx := context.Background()
	repos, err := c.Catalog(ctx)
	if err != nil || !slices.Equal(repos, []string{"app", "team/multi"}) {
		t.Fatalf("Catalog = %v, %v", repos, err)
	}
	tags, err := c.Tags(ctx, "app")
	if err != nil || !slices.Equal(tags, []string{"v1", "v2"}) {
		t.Fatalf("Tags = %v, %v", tags, err)
	}
	for _, tc := range []struct {
		repo, digest string
		platforms    []string
	}{
		{"app", single.Digest, []string{"darwin/arm64"}},
		{"team/multi", idx.Digest, []string{"linux/arm64/v8", "linux/amd64"}},
	} {
		img, err := c.Describe(ctx, tc.repo, "v1")
		if err != nil {
			t.Fatalf("Describe %s: %v", tc.repo, err)
		}
		if img.Digest != tc.digest || !slices.Equal(img.Platforms, tc.platforms) {
			t.Errorf("Describe %s = %s %v, want %s %v", tc.repo, img.Digest, img.Platforms, tc.digest, tc.platforms)
		}
	}
	if d, err := c.ManifestDigest(ctx, "app", "v2"); err != nil || d == "" {
		t.Errorf("ManifestDigest = %q, %v", d, err)
	}
}
