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
	"errors"
	"net/http"
	"testing"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/gc"
	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestPutAcceptsOnlyWhatTheCollectorReads pushes bodies the server's own
// decoding and the collector's used to read differently. Each refused body
// would have stopped every sweep of its repository from then on, for as long
// as its row stayed; each accepted body must leave a sweep clean.
func TestPutAcceptsOnlyWhatTheCollectorReads(t *testing.T) {
	const grace = time.Hour
	f := newFixture(t)
	cfg := f.pushBlob(t, "app", []byte(`{"seed":"shapes"}`))
	config := `"config":{"mediaType":"` + ispec.MediaTypeImageConfig + `","digest":"` + cfg.String() + `","size":17}`
	index, manifest := ispec.MediaTypeImageIndex, ispec.MediaTypeImageManifest
	for _, tc := range []struct {
		name, mediaType, body string
		status                int
	}{
		{"index with only a schemaVersion", index, `{"schemaVersion":2}`, http.StatusBadRequest},
		{"index with null manifests", index, `{"schemaVersion":2,"manifests":null}`, http.StatusBadRequest},
		{"docker list with only a schemaVersion", mediaTypeDockerManifestList, `{"schemaVersion":2}`, http.StatusBadRequest},
		{"a config, then a null config", manifest, `{"schemaVersion":2,` + config + `,"config":null,"layers":[]}`, http.StatusBadRequest},
		{"manifest with a manifests string", manifest, `{"schemaVersion":2,` + config + `,"layers":[],"manifests":"x"}`, http.StatusBadRequest},
		{"index with a layers number", index, `{"schemaVersion":2,"manifests":[],"layers":5}`, http.StatusBadRequest},
		{"index with a config string", index, `{"schemaVersion":2,"manifests":[],"config":"x"}`, http.StatusBadRequest},
		{"index with empty manifests", index, `{"schemaVersion":2,"manifests":[]}`, http.StatusCreated},
		{"index naming its type and no manifests", index, `{"schemaVersion":2,"mediaType":"` + index + `"}`, http.StatusCreated},
		{"manifest with a config", manifest, `{"schemaVersion":2,` + config + `,"layers":[]}`, http.StatusCreated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			code := ""
			if tc.status != http.StatusCreated {
				code = codeManifestInvalid
			}
			want(t, f.pushManifest(t, "app", "v1", tc.mediaType, body), tc.status, code)
			want(t, f.pushManifest(t, "app", dg(body).String(), tc.mediaType, body), tc.status, code)
			if _, err := f.deletingCollector(t, grace).Sweep(context.Background()); err != nil {
				t.Fatalf("a sweep after the PUT: %v", err)
			}
		})
	}
}

// TestStoredUnreadableRowClearsOnDelete is the recovery the user guide gives
// for a row stored before the server refused its shape: deleting the tag lets
// the repository's sweeps run again.
func TestStoredUnreadableRowClearsOnDelete(t *testing.T) {
	const grace = time.Hour
	f := newFixture(t)
	if _, err := f.st.PutManifest(context.Background(), mustName(t, "app"), ref.Reference{Tag: "old"}, ispec.MediaTypeImageIndex, []byte(`{"schemaVersion":2}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.deletingCollector(t, grace).Sweep(context.Background()); !errors.Is(err, gc.ErrUnreadable) {
		t.Fatalf("sweep over the stored row: %v, want ErrUnreadable", err)
	}
	want(t, f.do(http.MethodDelete, "/v2/app/manifests/old", nil), http.StatusAccepted, "")
	if _, err := f.deletingCollector(t, grace).Sweep(context.Background()); err != nil {
		t.Fatalf("sweep after the delete: %v", err)
	}
}

func mustName(t *testing.T, s string) ref.Name {
	t.Helper()
	n, err := ref.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
