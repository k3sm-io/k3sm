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
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

// TestRegistryCachedDescriberMatchesUncached: a cached describer answers what
// an uncached one does, cold and warm, and a warm describe is one HEAD.
func TestRegistryCachedDescriberMatchesUncached(t *testing.T) {
	for _, omit := range []bool{false, true} {
		name := "head reports the digest"
		if omit {
			name = "head reports no digest, the tag is read"
		}
		t.Run(name, func(t *testing.T) {
			reg := registrytest.New()
			reg.OmitHeadDigest = omit
			a := reg.Image("tools/multi", "", registryclient.Platform{OS: "linux", Architecture: "arm64"}, []byte("base"), []byte("arm"))
			b := reg.Image("tools/multi", "", registryclient.Platform{OS: "linux", Architecture: "amd64"}, []byte("base"), []byte("amd"))
			reg.Index("tools/multi", "v1", a, b)
			c := newClient(t, reg.Handler(), registryclient.Options{})
			ctx := context.Background()
			want, err := c.Describe(ctx, "tools/multi", "v1")
			if err != nil {
				t.Fatal(err)
			}
			cache, err := registryclient.OpenDirCache(t.TempDir(), c.Host())
			if err != nil {
				t.Fatal(err)
			}
			for _, run := range []string{"cold", "warm"} {
				reg.ResetRequests()
				got, err := c.NewCachedDescriber(cache).Describe(ctx, "tools/multi", "v1")
				if err != nil {
					t.Fatalf("%s: %v", run, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%s describe = %+v; want %+v", run, got, want)
				}
			}
			if n := reg.Requests(http.MethodHead, registrytest.ClassManifestTag); n != 1 {
				t.Errorf("warm run sent %d HEADs; want 1", n)
			}
			wantGets := 0
			if omit {
				wantGets = 1
			}
			if n := reg.Requests(http.MethodGet, registrytest.ClassManifestTag); n != wantGets {
				t.Errorf("warm run read the tag's manifest %d times; want %d", n, wantGets)
			}
			if n := reg.Requests(http.MethodGet, registrytest.ClassManifestDigest) + reg.Requests(http.MethodGet, registrytest.ClassBlob); n != 0 {
				t.Errorf("warm run read %d manifests or blobs by digest; want 0", n)
			}
		})
	}
}

// TestRegistryCachedDescriberDeletedTag: a tag gone by the HEAD is ErrNotFound.
func TestRegistryCachedDescriberDeletedTag(t *testing.T) {
	reg := registrytest.New()
	reg.Image("app", "v1", registryclient.Platform{OS: "darwin", Architecture: "arm64"}, []byte("l"))
	c := newClient(t, reg.Handler(), registryclient.Options{})
	cache, err := registryclient.OpenDirCache(t.TempDir(), c.Host())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.NewCachedDescriber(cache).Describe(context.Background(), "app", "gone"); !errors.Is(err, registryclient.ErrNotFound) {
		t.Errorf("describe a deleted tag = %v; want ErrNotFound", err)
	}
}

// TestRegistryDirCache: entries live at <root>/<host>/<repository>@<digest>.json
// with private modes, a malformed name is never a path, and a root that
// cannot be created is an error the caller may ignore.
func TestRegistryDirCache(t *testing.T) {
	root := t.TempDir()
	const digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	desc := registryclient.Description{Digest: digest, Platforms: []string{"linux/arm64"}, SizeBytes: 3, Blobs: map[string]int64{digest: 3}}
	c, err := registryclient.OpenDirCache(root, "127.0.0.1:6450")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Store("tools/multi", digest, desc); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, "127.0.0.1:6450", "tools", "multi@"+digest+".json")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("entry mode %v; want 0600", fi.Mode().Perm())
	}
	for _, d := range []string{filepath.Join(root, "127.0.0.1:6450"), filepath.Dir(p)} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v; want a 0700 directory", d, fi.Mode().Perm(), err)
		}
	}
	if got, ok := c.Load("tools/multi", digest); !ok || !reflect.DeepEqual(got, desc) {
		t.Errorf("Load = %+v, %v; want %+v", got, ok, desc)
	}
	for _, bad := range [][2]string{{"../escape", digest}, {"tools/multi", "sha256:../../x"}, {"tools/multi", "md5:abc"}} {
		if err := c.Store(bad[0], bad[1], desc); err == nil {
			t.Errorf("Store(%q, %q) was accepted", bad[0], bad[1])
		}
		if _, ok := c.Load(bad[0], bad[1]); ok {
			t.Errorf("Load(%q, %q) hit", bad[0], bad[1])
		}
	}
	for _, host := range []string{"", "..", "a/b"} {
		if _, err := registryclient.OpenDirCache(root, host); err == nil {
			t.Errorf("OpenDirCache host %q was accepted", host)
		}
	}
	file := filepath.Join(root, "a-file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := registryclient.OpenDirCache(filepath.Join(file, "under"), "h:1"); err == nil {
		t.Error("a cache root under a file was opened")
	}
}
