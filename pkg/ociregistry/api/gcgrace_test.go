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
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestBlobHeadKeepsTheBlobForTheManifestPut pins the server contract between
// a pushing client and the online garbage collector: a client HEADs each blob,
// skips the upload of every blob the HEAD finds, and PUTs the manifest. A
// sweep that runs between the HEADs and the PUT must not reap a blob the HEAD
// reported present, however old and unreferenced it was, and the PUT must
// succeed with the blobs kept. Without the HEAD the same sweep reaps them and
// the PUT is refused with MANIFEST_BLOB_UNKNOWN, never committed.
func TestBlobHeadKeepsTheBlobForTheManifestPut(t *testing.T) {
	const grace = time.Hour
	for _, tc := range []struct {
		name string
		head bool
	}{
		{"a HEAD hit survives the sweep", true},
		{"without a HEAD the sweep reaps and the PUT is refused", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// A tagged image keeps half of the repository referenced, so the
			// sweep's half-repository brake does not hold.
			f.image(t, "app", "kept", "kept-layer")
			cfg := []byte(`{"architecture":"arm64","os":"linux","seed":"orphan"}`)
			layers := [][]byte{[]byte("orphan-layer")}
			needs := []digest.Digest{f.pushBlob(t, "app", cfg)}
			for _, l := range layers {
				needs = append(needs, f.pushBlob(t, "app", l))
			}
			// The blobs are left from a push that never PUT its manifest,
			// two grace periods ago.
			old := time.Now().Add(-2 * grace)
			for _, d := range needs {
				p := filepath.Join(f.root, "app", "blobs", d.Algorithm().String(), d.Encoded())
				if err := os.Chtimes(p, old, old); err != nil {
					t.Fatal(err)
				}
			}
			// A collector that started two grace periods ago and has already
			// run its report-only first sweep.
			start := time.Now().Add(-2 * grace)
			now := func() time.Time { return start }
			c, err := gc.New(f.st, gc.Options{Grace: grace, Now: func() time.Time { return now() }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			now = time.Now
			if err := os.WriteFile(filepath.Join(f.st.StateDir(), gc.MarkerName), []byte("ran\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			if tc.head {
				for _, d := range needs {
					want(t, f.do(http.MethodHead, "/v2/app/blobs/"+d.String(), nil), http.StatusOK, "")
				}
			}
			if _, err := c.Sweep(context.Background()); err != nil {
				t.Fatal(err)
			}

			m := ispec.Manifest{
				MediaType: ispec.MediaTypeImageManifest,
				Config:    ispec.Descriptor{MediaType: ispec.MediaTypeImageConfig, Digest: needs[0], Size: int64(len(cfg))},
			}
			for i, l := range layers {
				m.Layers = append(m.Layers, ispec.Descriptor{MediaType: ispec.MediaTypeImageLayerGzip, Digest: needs[i+1], Size: int64(len(l))})
			}
			m.SchemaVersion = 2
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			w := f.pushManifest(t, "app", "v1", ispec.MediaTypeImageManifest, body)
			if !tc.head {
				want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
				for _, r := range f.rows(t, "app") {
					if r.Digest == dg(body) {
						t.Errorf("index names a manifest whose blobs were reaped: %v", r)
					}
				}
				return
			}
			want(t, w, http.StatusCreated, "")
			n, err := ref.ParseName("app")
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range needs {
				if _, err := f.st.StatBlob(n, d); err != nil {
					t.Errorf("blob %s the HEAD reported present is gone after the PUT: %v", d, err)
				}
			}
		})
	}
}
