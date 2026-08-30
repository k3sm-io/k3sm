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

package oci

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TestBuildLayerMediaTypeMatchesBytes is B192's gate. It builds a fixture
// image and, for every layer, proves the declared media type matches what is
// actually on the wire in BOTH directions — gzip magic bytes iff a "+gzip"
// media type, genuine tar shape iff the plain "v1.tar" media type — then
// opens the blob exactly as a strict reader would: trusting the label, no
// sniffing, no fallback (the shape of runtimed's LayerApplier, which has no
// gunzip path). It is red at main: BuildLayer there declares
// types.OCIUncompressedLayer but ggcr still gzip-compresses the bytes, so the
// blob is gzip under an uncompressed label and the strict tar.Reader fails
// with "invalid header" on the first entry.
func TestBuildLayerMediaTypeMatchesBytes(t *testing.T) {
	t.Parallel()

	ctxDir := t.TempDir()
	// A body long enough that a gzip-vs-plain-tar mixup is not masked by an
	// archive small enough for both readers to accidentally succeed.
	body := strings.Repeat("payload-bytes-for-the-media-type-gate ", 200)
	if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	df, err := Parse(strings.NewReader("FROM scratch\nCOPY app /app"))
	if err != nil {
		t.Fatal(err)
	}
	bc, err := NewContext(ctxDir)
	if err != nil {
		t.Fatal(err)
	}
	img, err := Build(Request{Dockerfile: df, Context: bc, TmpDir: t.TempDir()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) == 0 {
		t.Fatal("build produced no layers")
	}

	for i, l := range layers {
		mt, err := l.MediaType()
		if err != nil {
			t.Fatalf("layer %d: MediaType: %v", i, err)
		}
		declaredGzip := strings.HasSuffix(string(mt), "+gzip")

		// Sniff the ACTUAL bytes independently of the label.
		rc, err := l.Compressed()
		if err != nil {
			t.Fatalf("layer %d: Compressed: %v", i, err)
		}
		var head [2]byte
		n, _ := io.ReadFull(rc, head[:])
		rc.Close()
		if n < 2 {
			t.Fatalf("layer %d: blob too short to sniff (%d bytes)", i, n)
		}
		actualGzip := head[0] == 0x1f && head[1] == 0x8b

		// Both directions of the equivalence, asserted separately so a failure
		// names which direction broke.
		if actualGzip && !declaredGzip {
			t.Errorf("layer %d: bytes are gzip (magic %#x %#x) but media type %q does not say +gzip", i, head[0], head[1], mt)
		}
		if declaredGzip && !actualGzip {
			t.Errorf("layer %d: media type %q declares +gzip but bytes are not gzip (magic %#x %#x)", i, mt, head[0], head[1])
		}

		t.Run("strict-reader-round-trip", func(t *testing.T) {
			// Open the blob exactly as the manifest labels it — trust mt, do
			// not sniff, do not fall back. This is what a spec-conformant
			// strict reader with no gunzip path does.
			rc, err := l.Compressed()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()

			var r io.Reader = rc
			if declaredGzip {
				gr, err := gzip.NewReader(rc)
				if err != nil {
					t.Fatalf("blob labelled %q but gzip.NewReader failed: %v", mt, err)
				}
				defer gr.Close()
				r = gr
			}

			tr := tar.NewReader(r)
			entries := 0
			for {
				_, err := tr.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("strict tar read failed on the blob labelled %q: %v", mt, err)
				}
				entries++
			}
			if entries == 0 {
				t.Fatal("strict reader found no tar entries")
			}
		})

		// For a genuinely uncompressed layer, the manifest's layer digest and
		// the config's diff_id must be the SAME hash — that coincidence is
		// exactly what "uncompressed" means, and it is the property this
		// package's determinism claim (pkg/oci/doc.go, "# Determinism") rests
		// on. It does not hold for a +gzip layer (digest is over the gzip
		// bytes, diffID over the tar), so this assertion is scoped to the
		// uncompressed media type only.
		if mt == types.OCIUncompressedLayer {
			t.Run("diff_id-equals-blob-digest", func(t *testing.T) {
				digest, err := l.Digest()
				if err != nil {
					t.Fatal(err)
				}
				diffID, err := l.DiffID()
				if err != nil {
					t.Fatal(err)
				}
				if digest != diffID {
					t.Errorf("uncompressed layer: digest %s != diffID %s (they must coincide)", digest, diffID)
				}
			})
		}
	}
}
