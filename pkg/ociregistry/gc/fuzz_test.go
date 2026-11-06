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

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
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

// FuzzScanDigests holds the scan an unreadable child goes through to its
// contract over arbitrary bodies: it never panics, and it returns only digests
// ref.ParseDigest accepts.
func FuzzScanDigests(f *testing.F) {
	f.Add([]byte(`{"config":{"digest":"` + dgA + `"},"config":null,"n":1e999}`))
	f.Add([]byte(`[[[[{"a":"` + dgA + `",}`))
	f.Add([]byte("\x1f\x8bnot json"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, d := range scanDigests(b) {
			if _, err := ref.ParseDigest(d.String()); err != nil {
				t.Fatalf("returned %q from %q: %v", d, b, err)
			}
		}
	})
}

// FuzzParseInScan holds the brake's count to what the collector follows: every
// digest an accepted body's parse would follow (config, layers, index children,
// subject) is one the scan of the same body returns. The brake counts the scan,
// so a body whose parse followed a digest the scan missed would let the brake
// miss what a manifest uses. The corpus under testdata/fuzz/FuzzParseInScan
// holds the shapes where the two read JSON differently: repeated keys, keys in
// another case, and escaped strings.
func FuzzParseInScan(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"` + dgA + `"},"layers":[{"digest":"` + dgS + `"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := parseBody(b)
		if err != nil {
			return
		}
		var followed []digest.Digest
		if r.Config != nil {
			followed = append(followed, r.Config.Digest)
		}
		if r.Subject != nil {
			followed = append(followed, r.Subject.Digest)
		}
		for _, l := range r.Layers {
			followed = append(followed, l.Digest)
		}
		for _, m := range r.Manifests {
			followed = append(followed, m.Digest)
		}
		scanned := map[digest.Digest]bool{}
		for _, d := range scanDigests(b) {
			scanned[d] = true
		}
		for _, d := range followed {
			p, err := ref.ParseDigest(d.String())
			if err != nil {
				continue // no blob can have it
			}
			if !scanned[p] {
				t.Fatalf("the parse follows %s, which the scan of %q does not return", p, b)
			}
		}
	})
}
