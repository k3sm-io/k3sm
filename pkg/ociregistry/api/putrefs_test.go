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
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// artifactBody is an image manifest with a config type that is neither an OCI
// image config nor the empty descriptor, naming the blobs cfg and layer.
func artifactBody(t *testing.T, cfg, layer []byte, subject *ispec.Descriptor) []byte {
	t.Helper()
	m := ispec.Manifest{
		MediaType: ispec.MediaTypeImageManifest,
		Config:    ispec.Descriptor{MediaType: "application/vnd.example.config+json", Digest: dg(cfg), Size: int64(len(cfg))},
		Layers:    []ispec.Descriptor{{MediaType: "application/vnd.example.blob", Digest: dg(layer), Size: int64(len(layer))}},
		Subject:   subject,
	}
	m.SchemaVersion = 2
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestPutArtifactManifestRefusesAReapedBlob pins that an artifact manifest
// names its blobs under the same rule as an image: a config or layer the
// collector reaped, before the PUT or between the handler's first check and
// the repository lock, refuses the PUT with MANIFEST_BLOB_UNKNOWN and leaves no
// row. A HEAD hit restarts the blob's grace, so the same PUT then succeeds and
// the test is not satisfied by a PUT that refuses everything.
func TestPutArtifactManifestRefusesAReapedBlob(t *testing.T) {
	const grace = time.Hour
	cfg, layer := []byte("artifact-config"), []byte("artifact-layer")
	for _, tc := range []struct {
		name string
		lost []byte
	}{
		{"config", cfg},
		{"layer", layer},
	} {
		t.Run(tc.name+"/reaped before the PUT", func(t *testing.T) {
			f := newFixture(t)
			// A tagged image keeps most of the repository referenced, so the
			// sweep's half-repository brake does not hold.
			f.image(t, "app", "kept", "kept-layer")
			f.pushBlob(t, "app", cfg)
			f.pushBlob(t, "app", layer)
			lost := dg(tc.lost)
			f.age(t, "app", time.Now().Add(-2*grace), lost)
			deletingSweep(t, f.deletingCollector(t, grace))
			f.fileGone(t, "app", lost)

			body := artifactBody(t, cfg, layer, nil)
			w := f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body)
			want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
			if !strings.Contains(w.Body.String(), lost.String()) {
				t.Errorf("refusal does not name %s: %s", lost, w.Body.String())
			}
			if f.hasRow(t, "app", dg(body)) {
				t.Error("index names an artifact whose blob was reaped")
			}
		})
		t.Run(tc.name+"/reaped between the first check and the lock", func(t *testing.T) {
			f := newFixture(t)
			f.pushBlob(t, "app", cfg)
			f.pushBlob(t, "app", layer)
			lost := dg(tc.lost)
			f.srv.manifestChecked = func() {
				if err := os.Remove(f.blobFile("app", lost)); err != nil {
					t.Error(err)
				}
			}
			body := artifactBody(t, cfg, layer, nil)
			w := f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body)
			want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
			if !strings.Contains(w.Body.String(), lost.String()) {
				t.Errorf("refusal does not name %s: %s", lost, w.Body.String())
			}
			if f.hasRow(t, "app", dg(body)) {
				t.Error("index names an artifact whose blob went before the write")
			}
		})
		t.Run(tc.name+"/a HEAD hit survives the sweep and the PUT lands", func(t *testing.T) {
			f := newFixture(t)
			f.image(t, "app", "kept", "kept-layer")
			f.pushBlob(t, "app", cfg)
			f.pushBlob(t, "app", layer)
			kept := dg(tc.lost)
			f.age(t, "app", time.Now().Add(-2*grace), kept)
			c := f.deletingCollector(t, grace)
			want(t, f.do(http.MethodHead, "/v2/app/blobs/"+kept.String(), nil), http.StatusOK, "")
			deletingSweep(t, c)
			body := artifactBody(t, cfg, layer, nil)
			want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
			want(t, f.do(http.MethodGet, "/v2/app/blobs/"+kept.String(), nil), http.StatusOK, "")
		})
	}
	t.Run("a non-distributable layer is still not required", func(t *testing.T) {
		f := newFixture(t)
		f.pushBlob(t, "app", cfg)
		m := ispec.Manifest{
			MediaType: ispec.MediaTypeImageManifest,
			Config:    ispec.Descriptor{MediaType: "application/vnd.example.config+json", Digest: dg(cfg), Size: int64(len(cfg))},
			Layers:    []ispec.Descriptor{{MediaType: mediaTypeNonDistributableGzip, Digest: digest.FromString("elsewhere"), Size: 9}},
		}
		m.SchemaVersion = 2
		body, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
	})
}

// indexBody is an OCI index of children and, when set, a subject.
func indexBody(t *testing.T, subject *ispec.Descriptor, children ...digest.Digest) []byte {
	t.Helper()
	idx := ispec.Index{MediaType: ispec.MediaTypeImageIndex, Subject: subject}
	idx.SchemaVersion = 2
	for _, d := range children {
		idx.Manifests = append(idx.Manifests, ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: d, Size: 1})
	}
	body, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestPutIndexAllowsAMissingChildAndFreshensPresentOnes pins the index rule.
// The distribution spec lets a registry refuse a child it does not hold but
// does not require it, and an index pushed before or without some children
// stays accepted. A child the repository does hold gets its grace restarted
// under the repository lock, by the rule a HEAD follows: never while half the
// grace is left.
func TestPutIndexAllowsAMissingChildAndFreshensPresentOnes(t *testing.T) {
	const grace = time.Hour
	withGrace := func(c *Config) { c.GCGrace = grace }
	missing := digest.FromString("never pushed")

	t.Run("a missing child is accepted and a stale present child is freshened", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		old := time.Now().Add(-2 * grace)
		f.age(t, "app", old, child)
		body := indexBody(t, nil, missing, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if !f.hasRow(t, "app", dg(body)) {
			t.Error("no row for the index")
		}
		if got := f.mtime(t, "app", child); !got.After(old) || time.Since(got) > grace/2 {
			t.Errorf("present child mtime %s, want a restarted grace", got)
		}
		f.fileGone(t, "app", missing)
	})
	t.Run("a child inside its half-grace is not written", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		at := time.Now().Add(-grace / 4).Truncate(time.Second)
		f.age(t, "app", at, child)
		f.st.SetFutimes(func(*os.File, time.Time) error {
			t.Error("a child inside its half-grace was touched")
			return nil
		})
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if got := f.mtime(t, "app", child); !got.Equal(at) {
			t.Errorf("mtime %s, want %s", got, at)
		}
	})
	t.Run("the touch runs under the repository lock", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), child)
		touched := 0
		f.st.SetFutimes(func(*os.File, time.Time) error {
			touched++
			if !f.lockHeld(t, "app") {
				t.Error("touched a child without the repository lock")
			}
			return nil
		})
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if touched == 0 {
			t.Error("the stale child was not touched")
		}
	})
	t.Run("a failed touch is logged and the PUT lands", func(t *testing.T) {
		var logs bytes.Buffer
		var mu sync.Mutex
		f := newFixture(t, withGrace, func(c *Config) {
			c.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, nil))
		})
		child := dg(f.image(t, "app", "", "child-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), child)
		calls := 0
		f.st.SetFutimes(func(*os.File, time.Time) error { calls++; return syscall.EROFS })
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if !f.hasRow(t, "app", dg(body)) {
			t.Error("no row for the index after a failed touch")
		}
		// As for a HEAD, the object is not asked again inside the window.
		want(t, f.pushManifest(t, "app", "v2", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if calls != 1 {
			t.Errorf("futimes called %d times over two PUTs, want 1", calls)
		}
		mu.Lock()
		got := logs.String()
		mu.Unlock()
		if n := strings.Count(got, "grace touch failed"); n != 1 || !strings.Contains(got, child.String()) {
			t.Errorf("logged %d failed touches, want 1 naming %s; log:\n%s", n, child, got)
		}
	})
	t.Run("a failed touch does not excuse a required blob", func(t *testing.T) {
		f := newFixture(t, withGrace)
		cfg, layer := []byte("artifact-config"), []byte("artifact-layer")
		f.pushBlob(t, "app", cfg)
		subject := dg(f.image(t, "app", "", "subject-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), subject)
		f.st.SetFutimes(func(*os.File, time.Time) error { return syscall.EROFS })
		body := artifactBody(t, cfg, layer, &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: subject, Size: 1})
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusBadRequest, codeManifestBlobUnknown)
	})
	t.Run("a child named twice, and as the subject, is touched once", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), child)
		calls := 0
		// The seam leaves the mtime old, so every repeat would reach it.
		f.st.SetFutimes(func(*os.File, time.Time) error { calls++; return nil })
		body := indexBody(t, &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: child, Size: 1}, child, child, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if calls != 1 {
			t.Errorf("futimes called %d times, want 1", calls)
		}
	})
	t.Run("the touch runs once for a PUT with tags", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), child)
		calls := 0
		f.st.SetFutimes(func(*os.File, time.Time) error { calls++; return nil })
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", dg(body).String()+"?tag=a&tag=b&tag=c", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if calls != 1 {
			t.Errorf("futimes called %d times over a digest and three tags, want 1", calls)
		}
	})
	t.Run("past the cap the rest are skipped with one log line", func(t *testing.T) {
		var logs bytes.Buffer
		var mu sync.Mutex
		f := newFixture(t, withGrace, func(c *Config) {
			c.Logger = slog.New(slog.NewTextHandler(&lockedWriter{w: &logs, mu: &mu}, nil))
		})
		first := dg(f.image(t, "app", "", "first-layer"))
		last := dg(f.image(t, "app", "", "last-layer"))
		old := time.Now().Add(-2 * grace).Truncate(time.Second)
		f.age(t, "app", old, first, last)
		children := []digest.Digest{first}
		for i := range maxManifestTouches + 4 {
			children = append(children, digest.FromString(strconv.Itoa(i)))
		}
		children = append(children, last)
		body := indexBody(t, nil, children...)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if got := f.mtime(t, "app", first); !got.After(old) {
			t.Errorf("the first child inside the cap has mtime %s", got)
		}
		if got := f.mtime(t, "app", last); !got.Equal(old) {
			t.Errorf("a child past the cap has mtime %s, want %s", got, old)
		}
		mu.Lock()
		got := logs.String()
		mu.Unlock()
		if n := strings.Count(got, "grace touch skipped"); n != 1 {
			t.Errorf("logged the cap %d times, want 1; log:\n%s", n, got)
		}
		if !strings.Contains(got, "skipped=6") {
			t.Errorf("the log does not count the 6 skipped; log:\n%s", got)
		}
	})
	t.Run("the subject is inside the cap whatever the index holds", func(t *testing.T) {
		f := newFixture(t, withGrace)
		subject := dg(f.image(t, "app", "", "subject-layer"))
		old := time.Now().Add(-2 * grace).Truncate(time.Second)
		f.age(t, "app", old, subject)
		children := make([]digest.Digest, 0, maxManifestTouches+1)
		for i := range maxManifestTouches + 1 {
			children = append(children, digest.FromString(strconv.Itoa(i)))
		}
		body := indexBody(t, &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: subject, Size: 1}, children...)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		if got := f.mtime(t, "app", subject); !got.After(old) {
			t.Errorf("the subject has mtime %s", got)
		}
	})
	t.Run("a child reaped between the first check and the lock is still accepted", func(t *testing.T) {
		f := newFixture(t, withGrace)
		child := dg(f.image(t, "app", "", "child-layer"))
		f.age(t, "app", time.Now().Add(-2*grace), child)
		f.srv.manifestChecked = func() {
			if err := os.Remove(f.blobFile("app", child)); err != nil {
				t.Error(err)
			}
		}
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
	})
	t.Run("the collector keeps a freshened child after the index is gone", func(t *testing.T) {
		f := newFixture(t, withGrace)
		f.image(t, "app", "kept", "kept-layer")
		childBody := f.image(t, "app", "", "child-layer")
		child := dg(childBody)
		var m ispec.Manifest
		if err := json.Unmarshal(childBody, &m); err != nil {
			t.Fatal(err)
		}
		f.age(t, "app", time.Now().Add(-2*grace), child, m.Config.Digest, m.Layers[0].Digest)
		c := f.deletingCollector(t, grace)
		body := indexBody(t, nil, child)
		want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageIndex, body), http.StatusCreated, "")
		want(t, f.do(http.MethodDelete, "/v2/app/manifests/v1", nil), http.StatusAccepted, "")
		deletingSweep(t, c)
		want(t, f.do(http.MethodGet, "/v2/app/manifests/"+child.String(), nil), http.StatusOK, "")
	})
}

// TestPutManifestSubjectIsNotRequiredAndIsFreshened pins the subject rule. The
// spec says a registry MUST accept a manifest whose subject it does not hold,
// so a referrer may arrive first, and that holds even when the subject goes
// between the first check and the lock. A subject the repository holds gets a
// restarted grace, for a referrer and for an index alike: the collector does
// not follow a subject, so nothing else keeps an untagged subject young.
func TestPutManifestSubjectIsNotRequiredAndIsFreshened(t *testing.T) {
	const grace = time.Hour
	withGrace := func(c *Config) { c.GCGrace = grace }
	cfg, layer := []byte("artifact-config"), []byte("artifact-layer")
	subjectOf := func(d digest.Digest) *ispec.Descriptor {
		return &ispec.Descriptor{MediaType: ispec.MediaTypeImageManifest, Digest: d, Size: 1}
	}
	push := func(t *testing.T, f *fixture, kind string, subject digest.Digest) *ispec.Descriptor {
		t.Helper()
		sd := subjectOf(subject)
		var body []byte
		mt := ispec.MediaTypeImageManifest
		if kind == "index" {
			body, mt = indexBody(t, sd), ispec.MediaTypeImageIndex
		} else {
			f.pushBlob(t, "app", cfg)
			f.pushBlob(t, "app", layer)
			body = artifactBody(t, cfg, layer, sd)
		}
		w := f.pushManifest(t, "app", dg(body).String(), mt, body)
		want(t, w, http.StatusCreated, "")
		if got := w.Header().Get("OCI-Subject"); got != subject.String() {
			t.Errorf("OCI-Subject %q, want %s", got, subject)
		}
		return sd
	}
	for _, kind := range []string{"artifact", "index"} {
		t.Run(kind+"/a missing subject is accepted", func(t *testing.T) {
			f := newFixture(t, withGrace)
			missing := digest.FromString("subject pushed later")
			push(t, f, kind, missing)
			f.fileGone(t, "app", missing)
		})
		t.Run(kind+"/a subject reaped between the first check and the lock is accepted", func(t *testing.T) {
			f := newFixture(t, withGrace)
			subject := dg(f.image(t, "app", "", "subject-layer"))
			f.srv.manifestChecked = func() {
				if err := os.Remove(f.blobFile("app", subject)); err != nil {
					t.Error(err)
				}
			}
			push(t, f, kind, subject)
		})
		t.Run(kind+"/a stale subject survives the next sweep", func(t *testing.T) {
			f := newFixture(t, withGrace)
			f.image(t, "app", "kept", "kept-layer")
			subjectBody := f.image(t, "app", "", "subject-layer")
			subject := dg(subjectBody)
			var m ispec.Manifest
			if err := json.Unmarshal(subjectBody, &m); err != nil {
				t.Fatal(err)
			}
			f.age(t, "app", time.Now().Add(-2*grace), subject, m.Config.Digest, m.Layers[0].Digest)
			c := f.deletingCollector(t, grace)
			push(t, f, kind, subject)
			deletingSweep(t, c)
			want(t, f.do(http.MethodGet, "/v2/app/manifests/"+subject.String(), nil), http.StatusOK, "")
			for _, d := range []digest.Digest{m.Config.Digest, m.Layers[0].Digest} {
				want(t, f.do(http.MethodGet, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
			}
		})
	}
}

// TestPutManifestDoesNotHonourInlineData pins that a config's inline data does
// not stand in for its blob, for an artifact's config and for the empty
// descriptor: the PUT is refused until the blob is pushed.
func TestPutManifestDoesNotHonourInlineData(t *testing.T) {
	inline := []byte("inline-config")
	for _, tc := range []struct {
		name   string
		config ispec.Descriptor
		blob   []byte
	}{
		{"an artifact config", ispec.Descriptor{MediaType: "application/vnd.example.config+json", Digest: dg(inline), Size: int64(len(inline)), Data: inline}, inline},
		{"the empty descriptor", ispec.DescriptorEmptyJSON, ispec.DescriptorEmptyJSON.Data},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			m := ispec.Manifest{MediaType: ispec.MediaTypeImageManifest, Config: tc.config, Layers: []ispec.Descriptor{}}
			m.SchemaVersion = 2
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusBadRequest, codeManifestBlobUnknown)
			f.pushBlob(t, "app", tc.blob)
			want(t, f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body), http.StatusCreated, "")
		})
	}
}
