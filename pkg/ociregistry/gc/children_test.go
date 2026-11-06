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
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// indexBody is an image index naming children.
func indexBody(t *testing.T, children ...ispec.Descriptor) []byte {
	t.Helper()
	b, err := json.Marshal(ispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ispec.MediaTypeImageIndex, Manifests: children})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keeper pushes a tagged image with enough layers that reaping one orphan is
// below the half brake.
func (e *env) keeper(t *testing.T, n ref.Name) image {
	t.Helper()
	return e.push(t, n, "keep", "keep "+n.String(), []byte(n.String()+"1"), []byte(n.String()+"2"), []byte(n.String()+"3"), []byte(n.String()+"4"))
}

// TestIndexChildThatIsNoManifestDoesNotStopTheSweep names, as an index's child,
// a blob that was never pushed as a manifest. Anyone who can push can do this,
// and a child need not exist at PUT, so the blob can arrive after the index and
// the descriptor can claim any media type. The child has no row, so it is no
// manifest this store accepted: the sweep keeps the blob, follows nothing from
// it, and goes on.
func TestIndexChildThatIsNoManifestDoesNotStopTheSweep(t *testing.T) {
	for _, tc := range []struct {
		name, mediaType string
		body            []byte
	}{
		{"binary under a layer media type", ispec.MediaTypeImageLayerGzip, []byte("\x1f\x8bnot json")},
		{"binary under a manifest media type", ispec.MediaTypeImageManifest, []byte("\x1f\x8bnot json")},
		{"json with no shape under an index media type", ispec.MediaTypeImageIndex, []byte(`{"schemaVersion":2}`)},
		{"a schema1 body under a manifest media type", ispec.MediaTypeImageManifest, []byte(`{"schemaVersion":1,"fsLayers":[]}`)},
		{"larger than any manifest", ispec.MediaTypeImageLayer, bytes.Repeat([]byte("x"), store.MaxManifestSize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			child := e.blob(t, n, tc.body)
			child.MediaType = tc.mediaType
			idx := e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
			}
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
			if !e.has(n, child.Digest) || !e.has(n, idx.Digest) {
				t.Error("the sweep reaped the index or the blob it names")
			}
		})
	}
}

// TestChildDigestThatNamesNoBlobDoesNotStopTheSweep stores a manifest with a
// manifests field the server's image-manifest decoding ignores, naming a digest
// no blob can have. It names nothing, so there is nothing to protect.
func TestChildDigestThatNamesNoBlobDoesNotStopTheSweep(t *testing.T) {
	for _, bad := range []string{"not-a-digest", "sha256:short", "../../index.json", ""} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			img := e.keeper(t, n)
			body, err := json.Marshal(struct {
				SchemaVersion int                `json:"schemaVersion"`
				Config        ispec.Descriptor   `json:"config"`
				Layers        []ispec.Descriptor `json:"layers"`
				Manifests     []ispec.Descriptor `json:"manifests"`
			}{2, img.config, img.layers, []ispec.Descriptor{{MediaType: ispec.MediaTypeImageManifest, Digest: digest.Digest(bad)}}})
			if err != nil {
				t.Fatal(err)
			}
			e.putManifest(t, n, "odd", ispec.MediaTypeImageManifest, body)
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(0)
			rep, err := c.Sweep(e.ctx)
			if err != nil || len(rep.Failed) != 0 {
				t.Fatalf("sweep: %+v, %v; want no failure", rep, err)
			}
			if e.has(n, orphan.Digest) {
				t.Error("the orphan survived")
			}
		})
	}
}

// TestChildWithARowStaysFailClosed is the other side of the rule: a child the
// index.json holds a row for was stored as a manifest, so a body the collector
// cannot read may name content it cannot see, and the repository's sweep stops.
func TestChildWithARowStaysFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration
	}{
		{"past the grace", -2 * time.Hour},
		{"inside the grace", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := name(t, "app")
			e.clk.set(-2 * time.Hour)
			e.keeper(t, n)
			orphan := e.blob(t, n, []byte("orphan"))
			c := e.collector(t, -3*time.Hour)
			e.ran(t)
			e.clk.set(tc.at)
			child := e.putManifest(t, n, "", ispec.MediaTypeImageIndex, []byte(`{"schemaVersion":2}`))
			e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
			e.clk.set(0)

			rep, err := c.Sweep(e.ctx)
			if !errors.Is(err, ErrUnreadable) || !slices.Equal(rep.Failed, []string{"app"}) {
				t.Fatalf("sweep: %+v, %v; want ErrUnreadable for app", rep, err)
			}
			if !e.has(n, orphan.Digest) {
				t.Error("a sweep over a child it could not read deleted the orphan")
			}
		})
	}
}

// TestRowlessChildThatParsesIsStillFollowed pins that only an unreadable body
// is a leaf: a blob that does read as a manifest keeps what it names, row or no
// row.
func TestRowlessChildThatParsesIsStillFollowed(t *testing.T) {
	e := newEnv(t)
	n := name(t, "app")
	e.clk.set(-2 * time.Hour)
	e.keeper(t, n)
	cfg := e.blob(t, n, []byte(`{"seed":"rowless"}`))
	layer := e.blob(t, n, []byte("rowless layer"))
	child := e.blob(t, n, manifestBody(t, cfg, []ispec.Descriptor{layer}, nil))
	child.MediaType = ispec.MediaTypeImageManifest
	e.putManifest(t, n, "idx", ispec.MediaTypeImageIndex, indexBody(t, child))
	orphan := e.blob(t, n, []byte("orphan"))
	c := e.collector(t, -3*time.Hour)
	e.ran(t)
	e.clk.set(0)

	e.sweep(t, c)
	if e.has(n, orphan.Digest) {
		t.Error("the orphan survived")
	}
	for _, d := range []digest.Digest{child.Digest, cfg.Digest, layer.Digest} {
		if !e.has(n, d) {
			t.Errorf("%s was reaped; the rowless child names it", d)
		}
	}
}
