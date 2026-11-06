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
	"net/http"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestManifestReadCapIsTheCollectorsCap ties the manifest GET and HEAD read
// cap to store.MaxManifestSize, the cap the collector reads manifests under and
// by which it treats a blob over it, with no row, as no manifest. That rule
// holds only while the server serves no manifest over the cap, so the rows are
// written through the store, past the PUT check: a body of exactly the cap is
// served, and one byte more is not, by tag or by digest.
func TestManifestReadCapIsTheCollectorsCap(t *testing.T) {
	at := func(size int) []byte {
		head := `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageIndex + `","manifests":[],"annotations":{"pad":"`
		tail := `"}}`
		return []byte(head + strings.Repeat("x", size-len(head)-len(tail)) + tail)
	}
	f := newFixture(t)
	n, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tag    string
		size   int
		served bool
	}{
		{"at-cap", store.MaxManifestSize, true},
		{"over-cap", store.MaxManifestSize + 1, false},
	} {
		desc, err := f.st.PutManifest(context.Background(), n, ref.Reference{Tag: tc.tag}, ispec.MediaTypeImageIndex, at(tc.size))
		if err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, r := range []string{tc.tag, desc.Digest.String()} {
				w := f.do(method, "/v2/app/manifests/"+r, nil)
				if ok := w.Code == http.StatusOK; ok != tc.served {
					t.Errorf("%s %s (%d bytes): status %d, served %v, want served %v", method, r, tc.size, w.Code, ok, tc.served)
				}
			}
		}
	}
}
