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
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// TestBuildLayerMediaTypeMatchesBytes pins this contract. It builds a fixture
// image and, for every layer, proves the declared media type matches what is
// actually on the wire in BOTH directions — gzip magic bytes iff a "+gzip"
// media type, genuine tar shape iff the plain "v1.tar" media type — then
// opens the blob exactly as a strict reader would: trusting the label, no
// sniffing, no fallback (the shape of runtimed's LayerApplier, which has no
// gunzip path for a plain-tar label). It pins the fix for a layer that declared
// an uncompressed media type over gzip bytes.
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
	}
}

// buildGzipFixture builds one COPY layer from a fixed context and returns the
// image.
func buildGzipFixture(t *testing.T) ggcrv1.Image {
	t.Helper()
	ctxDir := t.TempDir()
	body := strings.Repeat("compressible-payload ", 4096)
	if err := os.WriteFile(filepath.Join(ctxDir, "app"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ctxDir, "data"), []byte("data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	df, err := Parse(strings.NewReader("FROM scratch\nCOPY app data /opt/"))
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
	return img
}

func sha256Of(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestBuildLayerIsPinnedGzip pins the stored form of every layer: it is gzip
// under the tar+gzip media type; the manifest descriptor's digest and size are
// those of the stored gzip bytes; gunzipping them reproduces exactly the tar
// whose sha256 the config records as the diff_id; the gzip header carries no
// name, comment, extra field or mtime; and two builds of the same context give
// identical layer and manifest digests.
func TestBuildLayerIsPinnedGzip(t *testing.T) {
	t.Parallel()

	img := buildGzipFixture(t)
	manifest, err := img.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	layers, err := img.Layers()
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 1 || len(manifest.Layers) != 1 || len(cfg.RootFS.DiffIDs) != 1 {
		t.Fatalf("want one layer, got %d layers, %d descriptors, %d diff_ids", len(layers), len(manifest.Layers), len(cfg.RootFS.DiffIDs))
	}
	desc := manifest.Layers[0]

	if desc.MediaType != types.OCILayer {
		t.Errorf("manifest layer media type = %q, want %q", desc.MediaType, types.OCILayer)
	}

	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Of(stored); got != desc.Digest.String() {
		t.Errorf("descriptor digest %s is not the sha256 of the stored bytes (%s)", desc.Digest, got)
	}
	if int64(len(stored)) != desc.Size {
		t.Errorf("descriptor size %d, stored bytes %d", desc.Size, len(stored))
	}

	zr, err := gzip.NewReader(bytes.NewReader(stored))
	if err != nil {
		t.Fatalf("stored layer is not gzip: %v", err)
	}
	if zr.Name != "" || zr.Comment != "" || zr.Extra != nil || !zr.ModTime.IsZero() || zr.OS != layerGzipOS {
		t.Errorf("gzip header not pinned: name=%q comment=%q extra=%v mtime=%v os=%d", zr.Name, zr.Comment, zr.Extra, zr.ModTime, zr.OS)
	}
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip stored layer: %v", err)
	}
	if got := sha256Of(plain); got != cfg.RootFS.DiffIDs[0].String() {
		t.Errorf("gunzip of the stored layer hashes to %s, config diff_id is %s", got, cfg.RootFS.DiffIDs[0])
	}
	if len(stored) >= len(plain) {
		t.Errorf("gzip layer (%d bytes) is not smaller than its tar (%d bytes)", len(stored), len(plain))
	}

	// Uncompressed() must serve the same tar the diff_id names.
	urc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	viaLayer, err := io.ReadAll(urc)
	if cerr := urc.Close(); cerr != nil {
		t.Errorf("close Uncompressed: %v", cerr)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(viaLayer, plain) {
		t.Error("Uncompressed() differs from gunzip of Compressed()")
	}

	again := buildGzipFixture(t)
	d1, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := again.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Errorf("two builds of the same context: manifest digests %s and %s", d1, d2)
	}
	m2, err := again.Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m2.Layers[0].Digest != desc.Digest {
		t.Errorf("two builds of the same context: layer digests %s and %s", desc.Digest, m2.Layers[0].Digest)
	}
}
