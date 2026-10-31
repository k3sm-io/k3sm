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

package gc

import (
	"encoding/json"
	"errors"
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// FuzzParseRefs holds parseRefs to its fail-closed contract over arbitrary
// bodies (a manifest body is pushed by a client): it never panics, a refusal
// is ErrUnreadable, and an accepted body is schemaVersion 2 of a known media
// type, or carries no mediaType and has a config or a manifests array, with
// an image manifest always naming its config. The corpus under
// testdata/fuzz/FuzzParseRefs holds one body of every accepted shape and the
// refused near misses.
func FuzzParseRefs(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"layers":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseRefs(dgS, b)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("refused %q with %v, not ErrUnreadable", b, err)
			}
			return
		}
		if !json.Valid(b) {
			t.Fatalf("accepted invalid JSON %q", b)
		}
		if r.SchemaVersion != 2 {
			t.Fatalf("accepted schemaVersion %d: %q", r.SchemaVersion, b)
		}
		switch r.MediaType {
		case ispec.MediaTypeImageManifest, mediaTypeDockerManifest:
			if r.Config == nil {
				t.Fatalf("accepted an image manifest without a config: %q", b)
			}
		case ispec.MediaTypeImageIndex, mediaTypeDockerManifestList:
		case "":
			if r.Config == nil && r.Manifests == nil {
				t.Fatalf("accepted a body of no known shape: %q", b)
			}
		default:
			t.Fatalf("accepted mediaType %q: %q", r.MediaType, b)
		}
	})
}
