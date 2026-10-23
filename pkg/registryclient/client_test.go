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
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/registryclient"
	"k3sm.io/k3sm/pkg/registryclient/registrytest"
)

func newClient(t *testing.T, h http.Handler, opts registryclient.Options) *registryclient.Client {
	t.Helper()
	opts.Transport = handlerTransport{h}
	c, err := registryclient.New("http://registry.test", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// handlerTransport answers every request by calling h through a recorder, so
// the client stack runs unchanged and no socket is opened. It honours the
// request context, which a blocked handler needs to see cancelled.
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

var (
	arm64 = registryclient.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	amd64 = registryclient.Platform{OS: "linux", Architecture: "amd64"}
	darwn = registryclient.Platform{OS: "darwin", Architecture: "arm64"}
	attes = registryclient.Platform{OS: "unknown", Architecture: "unknown"}
)

func TestCatalogAndTagsFollowPagination(t *testing.T) {
	reg := registrytest.New()
	reg.PageSize = 2
	for _, r := range []string{"a", "b/c", "d", "e"} {
		reg.Image(r, "v1", darwn, []byte(r))
		reg.Image(r, "v2", darwn, []byte(r+"2"))
		reg.Image(r, "v3", darwn, []byte(r+"3"))
	}
	c := newClient(t, reg.Handler(), registryclient.Options{})
	ctx := context.Background()
	repos, err := c.Catalog(ctx)
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if want := []string{"a", "b/c", "d", "e"}; !slices.Equal(repos, want) {
		t.Errorf("Catalog = %v; want %v", repos, want)
	}
	tags, err := c.Tags(ctx, "b/c")
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if want := []string{"v1", "v2", "v3"}; !slices.Equal(tags, want) {
		t.Errorf("Tags = %v; want %v", tags, want)
	}
}

func TestDescribe(t *testing.T) {
	reg := registrytest.New()
	shared := []byte("shared base layer")
	single := reg.Image("app", "v1", darwn, shared, []byte("app layer"))
	a := reg.Image("multi", "", arm64, shared, []byte("arm layer"))
	b := reg.Image("multi", "", amd64, shared, []byte("amd layer"))
	att := reg.Image("multi", "", attes, []byte("provenance"))
	idx := reg.Index("multi", "v1", a, b, att)
	c := newClient(t, reg.Handler(), registryclient.Options{})

	tests := []struct {
		name          string
		repo, tag     string
		wantDigest    string
		wantPlatforms []string
		wantBlobs     int
	}{
		{"single platform reads its platform from the config", "app", "v1", single.Digest, []string{"darwin/arm64"}, 4},                   // manifest, config, 2 layers
		{"an index lists its platforms, attestations excluded", "multi", "v1", idx.Digest, []string{"linux/arm64/v8", "linux/amd64"}, 11}, // index, 3 manifests, 3 configs, the shared layer once, 3 own layers
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img, err := c.Describe(context.Background(), tc.repo, tc.tag)
			if err != nil {
				t.Fatalf("Describe: %v", err)
			}
			if img.Digest != tc.wantDigest {
				t.Errorf("Digest = %s; want %s", img.Digest, tc.wantDigest)
			}
			if !slices.Equal(img.Platforms, tc.wantPlatforms) {
				t.Errorf("Platforms = %v; want %v", img.Platforms, tc.wantPlatforms)
			}
			if len(img.Blobs) != tc.wantBlobs {
				t.Errorf("Blobs = %d entries %v; want %d", len(img.Blobs), img.Blobs, tc.wantBlobs)
			}
			var content int64
			for d, s := range img.Blobs {
				if d != img.Digest && !isManifest(t, c, tc.repo, d) {
					content += s
				}
			}
			if img.SizeBytes != content {
				t.Errorf("SizeBytes = %d; want the distinct config+layer sum %d", img.SizeBytes, content)
			}
		})
	}
}

// isManifest reports whether digest names a manifest in repo.
func isManifest(t *testing.T, c *registryclient.Client, repo, digest string) bool {
	t.Helper()
	_, err := c.Manifest(context.Background(), repo, digest)
	return err == nil
}

func TestManifestRefusals(t *testing.T) {
	reg := registrytest.New()
	reg.Image("app", "v1", darwn, []byte("x"))
	lying := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		reg.Handler().ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("0", 64))
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
	status := func(code int) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
	}
	tests := []struct {
		name    string
		h       http.Handler
		repo    string
		ref     string
		wantIs  error
		wantMsg string
	}{
		{"a reported digest the bytes do not match", lying, "app", "v1", registryclient.ErrDigestMismatch, ""},
		{"a missing tag", reg.Handler(), "app", "v9", registryclient.ErrNotFound, ""},
		{"an anonymous read refused", status(http.StatusUnauthorized), "app", "v1", registryclient.ErrUnauthorized, ""},
		{"a server error", status(http.StatusInternalServerError), "app", "v1", nil, "500"},
		{"a repository that could escape the path", reg.Handler(), "../x", "v1", nil, "invalid repository"},
		{"a malformed tag", reg.Handler(), "app", "v1/../../x", nil, "invalid tag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, tc.h, registryclient.Options{})
			_, err := c.Manifest(context.Background(), tc.repo, tc.ref)
			if err == nil {
				t.Fatal("Manifest succeeded")
			}
			if tc.wantIs != nil && !errors.Is(err, tc.wantIs) {
				t.Errorf("err = %v; want errors.Is %v", err, tc.wantIs)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v; want one containing %q", err, tc.wantMsg)
			}
		})
	}
}

func TestPaginationNeverLeavesTheHost(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<http://elsewhere.test/v2/_catalog?last=a>; rel="next"`)
		_, _ = w.Write([]byte(`{"repositories":["a"]}`))
	})
	c := newClient(t, h, registryclient.Options{})
	if _, err := c.Catalog(context.Background()); err == nil || !strings.Contains(err.Error(), "elsewhere.test") {
		t.Errorf("Catalog err = %v; want a refusal naming the other host", err)
	}
}

func TestRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	defer close(release)
	c, err := registryclient.New("http://registry.test", registryclient.Options{Timeout: 50 * time.Millisecond, Transport: handlerTransport{h}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := c.Catalog(context.Background()); err == nil {
		t.Fatal("Catalog succeeded against a server that never answers")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the timeout took %v to fire", d)
	}
}

func TestNewValidatesTheBaseURL(t *testing.T) {
	for _, base := range []string{"ftp://x", "http://", "http://h:1/path", "::"} {
		if _, err := registryclient.New(base, registryclient.Options{}); err == nil {
			t.Errorf("New(%q) succeeded", base)
		}
	}
	c, err := registryclient.New("https://127.0.0.1:6450/", registryclient.Options{})
	if err != nil || c.Host() != "127.0.0.1:6450" {
		t.Errorf("New = %v, %v; want host 127.0.0.1:6450", c, err)
	}
}
