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
	"errors"
	"slices"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	dgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	dgC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	dgS = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// named lists every digest r references, in a fixed order.
func named(r refs) []digest.Digest {
	var out []digest.Digest
	if r.Config != nil {
		out = append(out, r.Config.Digest)
	}
	for _, l := range slices.Concat(r.Layers, r.Manifests) {
		out = append(out, l.Digest)
	}
	if r.Subject != nil {
		out = append(out, r.Subject.Digest)
	}
	return out
}

func TestParseRefsKnownTypes(t *testing.T) {
	desc := func(mt, d string) string { return `{"mediaType":"` + mt + `","digest":"` + d + `","size":1}` }
	cfg := desc(ispec.MediaTypeImageConfig, dgA)
	layer := desc(ispec.MediaTypeImageLayerGzip, dgB)
	child := desc(ispec.MediaTypeImageManifest, dgC)
	sub := desc(ispec.MediaTypeImageManifest, dgS)
	for _, tc := range []struct {
		name string
		body string
		want []digest.Digest
	}{
		{"oci manifest", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageManifest + `","config":` + cfg + `,"layers":[` + layer + `]}`, []digest.Digest{dgA, dgB}},
		{"oci manifest with a subject", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageManifest + `","config":` + cfg + `,"layers":[],"subject":` + sub + `}`, []digest.Digest{dgA, dgS}},
		{"oci manifest without a mediaType", `{"schemaVersion":2,"config":` + cfg + `,"layers":[` + layer + `]}`, []digest.Digest{dgA, dgB}},
		{"docker v2 manifest", `{"schemaVersion":2,"mediaType":"` + mediaTypeDockerManifest + `","config":` + cfg + `,"layers":[` + layer + `]}`, []digest.Digest{dgA, dgB}},
		{"oci index", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageIndex + `","manifests":[` + child + `]}`, []digest.Digest{dgC}},
		{"oci index without a mediaType", `{"schemaVersion":2,"manifests":[` + child + `]}`, []digest.Digest{dgC}},
		{"empty oci index", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageIndex + `","manifests":[]}`, nil},
		{"docker manifest list", `{"schemaVersion":2,"mediaType":"` + mediaTypeDockerManifestList + `","manifests":[` + child + `]}`, []digest.Digest{dgC}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseRefs(dgS, []byte(tc.body))
			if err != nil {
				t.Fatalf("parseRefs: %v", err)
			}
			if got := named(r); !slices.Equal(got, tc.want) {
				t.Fatalf("refs %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseRefsFailsClosed covers bodies whose references the collector
// cannot know: each must be ErrUnreadable, never an empty set of refs.
func TestParseRefsFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"docker schema1", `{"schemaVersion":1,"name":"app","tag":"v1","architecture":"arm64","fsLayers":[{"blobSum":"` + dgB + `"}],"history":[{"v1Compatibility":"{}"}]}`},
		{"docker schema1 signed", `{"schemaVersion":1,"mediaType":"application/vnd.docker.distribution.manifest.v1+prettyjws","fsLayers":[{"blobSum":"` + dgB + `"}]}`},
		{"docker schema1 fsLayers at schemaVersion 2", `{"schemaVersion":2,"config":{"digest":"` + dgA + `"},"fsLayers":[{"blobSum":"` + dgB + `"}]}`},
		{"docker schema1 fsLayers under an oci mediaType", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageManifest + `","config":{"digest":"` + dgA + `"},"fsLayers":[{"blobSum":"` + dgB + `"}]}`},
		{"docker schema1 fsLayers beside a manifests array", `{"schemaVersion":2,"manifests":[],"fsLayers":[{"blobSum":"` + dgB + `"}]}`},
		{"docker schema1 empty fsLayers", `{"schemaVersion":2,"config":{"digest":"` + dgA + `"},"fsLayers":[]}`},
		{"unknown mediaType", `{"schemaVersion":2,"mediaType":"application/vnd.example.manifest.v1+json","config":{"digest":"` + dgA + `"},"parts":[{"digest":"` + dgB + `"}]}`},
		{"oci artifact manifest", `{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","blobs":[{"digest":"` + dgB + `"}]}`},
		{"oci artifact manifest at schemaVersion 2", `{"schemaVersion":2,"mediaType":"application/vnd.oci.artifact.manifest.v1+json","blobs":[{"digest":"` + dgB + `"}]}`},
		{"no mediaType, unrecognised body", `{"schemaVersion":2,"blobs":[{"digest":"` + dgB + `"}]}`},
		{"no mediaType, null manifests", `{"schemaVersion":2,"manifests":null}`},
		{"no schemaVersion", `{"mediaType":"` + ispec.MediaTypeImageManifest + `","config":{"digest":"` + dgA + `"}}`},
		{"schemaVersion 3", `{"schemaVersion":3,"mediaType":"` + ispec.MediaTypeImageManifest + `","config":{"digest":"` + dgA + `"}}`},
		{"image manifest without a config", `{"schemaVersion":2,"mediaType":"` + ispec.MediaTypeImageManifest + `","layers":[{"digest":"` + dgB + `"}]}`},
		{"empty object", `{}`},
		{"malformed json", `{"schemaVersion":2,"mediaType":`},
		{"not an object", `[1,2,3]`},
		{"empty body", ``},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := parseRefs(dgS, []byte(tc.body))
			if !errors.Is(err, ErrUnreadable) {
				t.Fatalf("parseRefs: refs %v, err %v, want ErrUnreadable", named(r), err)
			}
		})
	}
}
