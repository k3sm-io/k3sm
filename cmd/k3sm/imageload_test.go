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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k3sm.io/k3sm/pkg/oci"
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

// dockerSaveMultiImageFixture is a `docker save` archive whose manifest.json
// carries TWO entries — the docker-save mirror of a multi-manifest layout.
func dockerSaveMultiImageFixture(t *testing.T, tags ...string) []byte {
	t.Helper()
	entries := make([]string, 0, len(tags))
	for _, tag := range tags {
		entries = append(entries, fmt.Sprintf(
			`{"Config":"config.json","RepoTags":[%q],"Layers":["layer.tar"]}`, tag))
	}
	return buildLoadTar(t, []loadTarEntry{
		{name: "config.json", body: `{"architecture":"arm64","os":"darwin"}`},
		{name: "layer.tar", body: strings.Repeat("payload-bytes\n", 512)},
		{name: "manifest.json", body: "[" + strings.Join(entries, ",") + "]"},
	})
}

// ociLayoutFixture is a tarred OCI image layout indexing ONE image. An empty
// refName omits the ref.name annotation, which is the case that must fall back
// to --reference.
func ociLayoutFixture(t *testing.T, refName string) []byte {
	t.Helper()
	return ociLayoutFixtureN(t, refName)
}

// ociLayoutFixtureN is a tarred OCI image layout indexing one manifest per
// refName — zero of them for an empty layout, several for the multi-image
// archive v1 refuses. The count is the variable the refusal turns on, so it is
// the fixture's parameter.
func ociLayoutFixtureN(t *testing.T, refNames ...string) []byte {
	t.Helper()
	digest := strings.Repeat("ab", 32)
	manifests := make([]string, 0, len(refNames))
	for _, refName := range refNames {
		annotations := ""
		if refName != "" {
			annotations = fmt.Sprintf(`,"annotations":{"org.opencontainers.image.ref.name":%q}`, refName)
		}
		manifests = append(manifests, fmt.Sprintf(`{`+
			`"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
			`"digest":"sha256:%s","size":123%s}`, digest, annotations))
	}
	index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[%s]}`, strings.Join(manifests, ","))
	return buildLoadTar(t, []loadTarEntry{
		{name: "oci-layout", body: `{"imageLayoutVersion":"1.0.0"}`},
		{name: "index.json", body: index},
		{name: "blobs/sha256/" + digest, body: strings.Repeat("blob-bytes\n", 512)},
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

// TestImageLoadRefusesBeforeUpload pins the archives `k3sm image load` and
// `k3sm image import` refuse, and that each refusal happens before anything is
// uploaded to the cluster registry or pulled into this node's cache. Asserting
// only on the error would pass just as well if the archive had been uploaded
// and then rejected, which is a different (and worse) behaviour on a multi-GB
// file. A successful ingest is pinned by TestBuildRecordsIntoRegistryNotNodeStore.
func TestImageLoadRefusesBeforeUpload(t *testing.T) {
	dockerSave := dockerSaveFixture(t, "example.test/app:v1")
	layout := ociLayoutFixture(t, "example.test/app:v2")
	layoutNoRef := ociLayoutFixture(t, "")
	multiTag := dockerSaveFixture(t, "example.test/app:v1", "example.test/app:latest")
	multiManifest := ociLayoutFixtureN(t, "example.test/app:v1", "example.test/app:v2")
	multiImage := dockerSaveMultiImageFixture(t, "example.test/app:v1", "example.test/other:v1")
	emptyLayout := ociLayoutFixtureN(t)

	tests := []struct {
		name    string
		archive []byte
		args    func(sock, path string) []string
		wantErr string
	}{
		{
			name:    "an unannotated layout requires --reference",
			archive: layoutNoRef,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			wantErr: "--reference",
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
			name:    "a multi-image docker-save archive is refused, never silently narrowed",
			archive: multiImage,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "load", path}
			},
			wantErr: "contains 2 images",
		},
		{
			name:    "a multi-image OCI layout is refused, never silently narrowed",
			archive: multiManifest,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			wantErr: "indexes 2 images",
		},
		{
			name:    "a layout indexing nothing is refused",
			archive: emptyLayout,
			args: func(sock, path string) []string {
				return []string{"--socket", sock, "import", path}
			},
			wantErr: "indexes no image",
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeImagesDaemon{}
			sock := serveFakeImages(t, fake)
			path := writeFixture(t, tc.archive)
			pushes := &registryPushes{}
			old := ingestPusher
			ingestPusher = pushes.push
			t.Cleanup(func() { ingestPusher = old })

			out, err := runImageCmd(t, tc.args(sock, path))
			if err == nil {
				t.Fatalf("command succeeded; want an error containing %q\n%s", tc.wantErr, out)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want one containing %q", err, tc.wantErr)
			}
			if len(pushes.targets) != 0 || fake.loadCalls != 0 || fake.pullCalls != 0 {
				t.Errorf("the archive was acted on before the CLI refused it: pushes %v, loads %d, pulls %d",
					pushes.targets, fake.loadCalls, fake.pullCalls)
			}
		})
	}

	t.Run("a warm pull the daemon refuses fails the command and names the registry", func(t *testing.T) {
		workDir := withNodeRegistry(t)
		img, err := random.Image(64, 1)
		if err != nil {
			t.Fatal(err)
		}
		saveTar := filepath.Join(t.TempDir(), "save.tar")
		if err := (oci.TarballSink{Path: saveTar}).Write(t.Context(), name.MustParseReference("app:v1").(name.Tag), img); err != nil {
			t.Fatalf("write docker-save: %v", err)
		}
		fake := &fakeImagesDaemon{pullErr: status.Error(codes.FailedPrecondition, "disk pressure")}
		sock := serveFakeImages(t, fake)
		pushes := &registryPushes{}
		old := ingestPusher
		ingestPusher = pushes.push
		t.Cleanup(func() { ingestPusher = old })

		_, err = runImageCmd(t, []string{"--socket", sock, "--work-dir", workDir, "load", saveTar})
		if err == nil {
			t.Fatal("a refused warm pull reported success")
		}
		for _, want := range []string{"is in the cluster registry", "registry-k3sm:6450/app:v1", "disk pressure"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error does not contain %q: %v", want, err)
			}
		}
		if len(pushes.targets) != 1 {
			t.Errorf("pushes = %v, want the upload to have happened first", pushes.targets)
		}
	})

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
			if o.timeout != 0 {
				t.Errorf("%s default timeout = %v; want none (each request is idle-bounded instead)", sub, o.timeout)
			}
			// An explicit flag still sets an overall deadline.
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
