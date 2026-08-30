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

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// loadTarEntry is one regular file in a fixture archive.
type loadTarEntry struct {
	name string
	body string
}

// buildLoadTar renders entries as an uncompressed tar. The fixtures are hand-rolled
// rather than produced by an image library on purpose: the gate is about the
// METADATA the CLI reads out of an operator-supplied archive, so the bytes of
// that metadata have to be pinned here where a reader can see them.
func buildLoadTar(t *testing.T, entries []loadTarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(e.body)),
		}); err != nil {
			t.Fatalf("tar header %s: %v", e.name, err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatalf("tar body %s: %v", e.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// dockerSaveFixture is a `docker save`-shaped archive carrying the given tags.
func dockerSaveFixture(t *testing.T, tags ...string) []byte {
	t.Helper()
	repoTags, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal tags: %v", err)
	}
	manifest := fmt.Sprintf(`[{"Config":"config.json","RepoTags":%s,"Layers":["layer.tar"]}]`, repoTags)
	return buildLoadTar(t, []loadTarEntry{
		{name: "config.json", body: `{"architecture":"arm64","os":"darwin"}`},
		{name: "layer.tar", body: strings.Repeat("payload-bytes\n", 512)},
		{name: "manifest.json", body: manifest},
	})
}

// ociLayoutFixture is a tarred OCI image layout. An empty refName omits the
// ref.name annotation, which is the case that must fall back to --reference.
func ociLayoutFixture(t *testing.T, refName string) []byte {
	t.Helper()
	annotations := ""
	if refName != "" {
		annotations = fmt.Sprintf(`,"annotations":{"org.opencontainers.image.ref.name":%q}`, refName)
	}
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{`+
		`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"digest":"sha256:%s","size":123%s}]}`, strings.Repeat("ab", 32), annotations)
	return buildLoadTar(t, []loadTarEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: index},
		{name: "blobs/sha256/" + strings.Repeat("ab", 32), body: strings.Repeat("blob-bytes\n", 512)},
	})
}

// writeFixture drops archive bytes on disk and returns the path.
func writeFixture(t *testing.T, archive []byte) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "k3l")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "archive.tar")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func sha256Ref(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestImageLoadDockerSaveAndOCILayout is the gate for `k3sm image load` and
// `k3sm image import`: the CLI is a STREAMING CLIENT of the daemon's LoadImage
// RPC. It proves the first frame carries the metadata the daemon needs
// (reference, format, advisory digest and size) with no chunk, that every
// archive byte reaches the daemon unaltered, that the daemon's rejection is
// what the operator sees, and that a streaming ingest is not bounded by the
// metadata-sized call deadline.
func TestImageLoadDockerSaveAndOCILayout(t *testing.T) {
	dockerSave := dockerSaveFixture(t, "example.test/app:v1")
	layout := ociLayoutFixture(t, "example.test/app:v2")
	layoutNoRef := ociLayoutFixture(t, "")
	multiTag := dockerSaveFixture(t, "example.test/app:v1", "example.test/app:latest")

	tests := []struct {
		name       string
		archive    []byte
		args       func(sock, path string) []string
		loadResp   *runtimev1.LoadImageResponse
		loadErr    error
		wantFormat runtimev1.LoadImageFormat
		wantRef    string
		wantOut    []string
		wantErr    string
	}{
		{
			name:    "docker-save streams with the reference the archive names",
			archive: dockerSave,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			loadResp: &runtimev1.LoadImageResponse{
				Images: []*runtimev1.Image{{
					ManifestDescriptor: &runtimev1.Descriptor{Digest: "sha256:manifestdigest"},
					Manifest:           &runtimev1.ImageManifest{Reference: "example.test/app:v1"},
				}},
				ReceivedBytes: int64(len(dockerSave)),
			},
			wantFormat: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
			wantRef:    "example.test/app:v1",
			wantOut:    []string{"example.test/app:v1", "sha256:manifestdigest"},
		},
		{
			name:    "OCI layout streams with the reference the layout annotates",
			archive: layout,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			loadResp: &runtimev1.LoadImageResponse{
				Images: []*runtimev1.Image{{
					ManifestDescriptor: &runtimev1.Descriptor{Digest: "sha256:layoutdigest"},
					Manifest:           &runtimev1.ImageManifest{Reference: "example.test/app:v2"},
				}},
				ReceivedBytes: int64(len(layout)),
			},
			wantFormat: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
			wantRef:    "example.test/app:v2",
			wantOut:    []string{"example.test/app:v2", "sha256:layoutdigest"},
		},
		{
			name:    "--reference overrides what the archive claims",
			archive: dockerSave,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path, "--reference", "other.test/app:pinned"}
			},
			loadResp:   &runtimev1.LoadImageResponse{ReceivedBytes: int64(len(dockerSave))},
			wantFormat: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_DOCKER_SAVE,
			wantRef:    "other.test/app:pinned",
		},
		{
			name:    "an unannotated layout requires --reference",
			archive: layoutNoRef,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			wantErr: "--reference",
		},
		{
			name:    "an unannotated layout is loadable with --reference",
			archive: layoutNoRef,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path, "--reference", "example.test/app:named"}
			},
			loadResp:   &runtimev1.LoadImageResponse{ReceivedBytes: int64(len(layoutNoRef))},
			wantFormat: runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
			wantRef:    "example.test/app:named",
		},
		{
			name:    "a multi-tag docker-save archive is refused, never silently narrowed",
			archive: multiTag,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			wantErr: "more than one tag",
		},
		{
			name:    "an OCI layout handed to load names the right verb",
			archive: layout,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			wantErr: "k3sm image import",
		},
		{
			name:    "a docker-save archive handed to import names the right verb",
			archive: dockerSave,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			wantErr: "k3sm image load",
		},
		{
			name:    "a digest mismatch from the daemon fails the command",
			archive: dockerSave,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			loadErr: status.Error(codes.InvalidArgument,
				"image: blob sha256:aaaa hashed to sha256:bbbb"),
			wantErr: "hashed to sha256:bbbb",
		},
		{
			name:    "an in-band typed rejection fails the command",
			archive: dockerSave,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			loadResp: &runtimev1.LoadImageResponse{Error: &rpcstatus.Status{
				Code:    int32(codes.FailedPrecondition),
				Message: "image: the store lease could not be taken",
			}},
			wantErr: "the store lease could not be taken",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeImagesDaemon{loadResp: tc.loadResp, loadErr: tc.loadErr}
			sock := serveFakeImages(t, fake)
			path := writeFixture(t, tc.archive)

			out, err := runImageCmd(t, tc.args(sock, path))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("command succeeded; want an error containing %q\n%s", tc.wantErr, out)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v; want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("image load: %v", err)
			}
			if fake.loadFirst == nil {
				t.Fatalf("the daemon was never streamed to — the CLI did not act as a client")
			}
			if got := fake.loadFirst.GetReference(); got != tc.wantRef {
				t.Errorf("first-frame reference = %q; want %q", got, tc.wantRef)
			}
			if got := fake.loadFirst.GetFormat(); got != tc.wantFormat {
				t.Errorf("first-frame format = %v; want %v", got, tc.wantFormat)
			}
			if got := fake.loadFirst.GetSize(); got != int64(len(tc.archive)) {
				t.Errorf("first-frame advisory size = %d; want %d", got, len(tc.archive))
			}
			if got, want := fake.loadFirst.GetDigest(), sha256Ref(tc.archive); got != want {
				t.Errorf("first-frame advisory digest = %q; want %q", got, want)
			}
			// The metadata frame carries no payload: a daemon that reads the
			// first frame for metadata must not have to also treat it as content.
			if len(fake.loadFirst.GetChunk()) != 0 {
				t.Errorf("the metadata frame carried %d chunk bytes; it must carry none", len(fake.loadFirst.GetChunk()))
			}
			if !bytes.Equal(fake.loadBody, tc.archive) {
				t.Errorf("the daemon received %d bytes; want the archive's %d, byte-identical",
					len(fake.loadBody), len(tc.archive))
			}
			if fake.loadChunks < 1 {
				t.Errorf("the archive arrived in %d chunk frames; want at least one", fake.loadChunks)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
		})
	}

	// A streaming ingest must not inherit the metadata-call deadline: a
	// multi-GB archive over a unix socket outlives two minutes routinely, and a
	// deadline that kills it mid-stream wastes every byte already sent.
	t.Run("load and import get a streaming-sized deadline; ls keeps the metadata one", func(t *testing.T) {
		archive := writeFixture(t, dockerSave)
		lsOpts, err := parseImageArgs([]string{"ls"}, io.Discard)
		if err != nil {
			t.Fatalf("parse ls: %v", err)
		}
		for _, sub := range []string{"load", "import"} {
			o, err := parseImageArgs([]string{sub, archive}, io.Discard)
			if err != nil {
				t.Fatalf("parse %s: %v", sub, err)
			}
			if o.archive != archive {
				t.Errorf("%s archive = %q; want %q", sub, o.archive, archive)
			}
			if o.timeout <= lsOpts.timeout {
				t.Errorf("%s default timeout %v is not longer than ls's %v", sub, o.timeout, lsOpts.timeout)
			}
			// An explicit flag still wins — the streaming default is a default.
			explicit, err := parseImageArgs([]string{sub, archive, "--timeout", "45s"}, io.Discard)
			if err != nil {
				t.Fatalf("parse %s --timeout: %v", sub, err)
			}
			if explicit.timeout != 45*time.Second {
				t.Errorf("%s --timeout 45s = %v; want 45s", sub, explicit.timeout)
			}
		}
		if lsOpts.timeout != 2*time.Minute {
			t.Errorf("ls default timeout = %v; want 2m", lsOpts.timeout)
		}
	})

	t.Run("a subcommand needing an archive says so", func(t *testing.T) {
		for _, sub := range []string{"load", "import"} {
			if _, err := parseImageArgs([]string{sub}, io.Discard); err == nil ||
				!strings.Contains(err.Error(), "archive") {
				t.Errorf("%s with no path: err = %v; want one naming the archive argument", sub, err)
			}
		}
	})
}
