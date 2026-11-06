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
	"encoding/json"
	"net/http"
	"os"
	"strings"
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
