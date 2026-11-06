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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestTagsListDefaultPageIsBounded: a tag list without n answers one default
// page with a Link, and following the Links reaches every tag exactly once.
func TestTagsListDefaultPageIsBounded(t *testing.T) {
	const total = 20000
	f := newFixture(t)
	n, _ := ref.ParseName("app")
	body := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	desc, err := f.st.PutManifest(t.Context(), n, ref.Reference{Tag: "t00000"}, ispec.MediaTypeImageIndex, body)
	if err != nil {
		t.Fatal(err)
	}
	idx := ispec.Index{MediaType: ispec.MediaTypeImageIndex}
	idx.SchemaVersion = 2
	var want []string
	for i := range total {
		tag := fmt.Sprintf("t%05d", i)
		want = append(want, tag)
		row := desc
		row.Annotations = map[string]string{ispec.AnnotationRefName: tag}
		idx.Manifests = append(idx.Manifests, row)
	}
	raw, _ := json.Marshal(idx)
	if err := os.WriteFile(filepath.Join(f.root, "app", "index.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	slices.Sort(want)

	var got []string
	path, pages := "/v2/app/tags/list", 0
	for path != "" {
		tags, h := f.tagsOf(t, "app", strings.TrimPrefix(path, "/v2/app/tags/list"))
		if len(tags) > defaultPage {
			t.Fatalf("page %d holds %d tags, more than the default %d", pages, len(tags), defaultPage)
		}
		got = append(got, tags...)
		path = nextLink(t, h)
		if pages++; pages == 1 && path == "" {
			t.Fatal("the first page has no Link")
		}
		if pages > total {
			t.Fatal("paging does not end")
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%d tags over %d pages, want %d exactly once in order", len(got), pages, len(want))
	}
	if tags, h := f.tagsOf(t, "app", "?n=3"); len(tags) != 3 || h.Get("Link") == "" {
		t.Errorf("explicit n=3: %d tags, Link %q", len(tags), h.Get("Link"))
	}
}
