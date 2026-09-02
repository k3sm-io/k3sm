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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestImagePushFromStore is the gate for push's store-reference form: a first
// argument that is no path on disk is exported from THIS NODE's store with the
// same verified SaveImage stream `k3sm image save` uses, and then uploaded by
// the identical layout path.
//
// The registry is an in-process one on loopback — a real HTTP registry, not a
// stub — so the manifest and every blob genuinely have to arrive for the
// pull-back to validate.
func TestImagePushFromStore(t *testing.T) {
	empty := t.TempDir()
	t.Setenv("HOME", empty)
	t.Setenv("DOCKER_CONFIG", empty)
	t.Setenv(registryTokenEnv, "")

	t.Run("exports from the store and uploads the layout", func(t *testing.T) {
		host, _ := startRegistry(t, "")
		layout := fixtureLayout(t, "example.test/app:v1", "store-push-payload")
		want := layoutDigest(t, layout)
		archive := tarLayout(t, layout)

		fake := &fakeImagesDaemon{
			saveChunks:   [][]byte{archive[:len(archive)/2], archive[len(archive)/2:]},
			saveTerminal: &runtimev1.SaveImageResponse{Digest: want, SentBytes: int64(len(archive))},
		}
		sock := serveFakeImages(t, fake)
		target := host + "/team/app:v1"

		out, err := runImageCmd(t, []string{"--socket", sock, "push", "example.test/app:v1", target})
		if err != nil {
			t.Fatalf("push from the store: %v", err)
		}
		if fake.gotSave == nil {
			t.Fatalf("the daemon was never asked for the image")
		}
		if fake.gotSave.GetReference() != "example.test/app:v1" {
			t.Errorf("the daemon was asked for %q", fake.gotSave.GetReference())
		}
		if !strings.Contains(out, want) {
			t.Errorf("push printed no digest\ngot:\n%s", out)
		}
		assertRegistryHolds(t, target, want)
	})

	// The verified export is upstream of the upload for a reason: a truncated
	// archive must never be published under a reference someone will later pin.
	t.Run("a truncated export is never uploaded", func(t *testing.T) {
		host, probe := startRegistry(t, "")
		layout := fixtureLayout(t, "example.test/app:v1", "truncated-payload")
		archive := tarLayout(t, layout)

		fake := &fakeImagesDaemon{saveChunks: [][]byte{archive[:len(archive)/2]}}
		sock := serveFakeImages(t, fake)

		out, err := runImageCmd(t, []string{"--socket", sock, "push", "example.test/app:v1", host + "/team/app:v1"})
		if err == nil {
			t.Fatalf("a truncated export was pushed: %s", out)
		}
		if !strings.Contains(err.Error(), "exporting it from this node's store failed") {
			t.Errorf("error = %v, want it to name the failed export", err)
		}
		// Nothing may have reached the registry — not even a blob upload that a
		// later manifest would complete.
		if len(probe.headers()) > 0 {
			t.Errorf("the failed push still contacted the registry %d time(s)", len(probe.headers()))
		}
	})
}

// TestPushSourceDiscrimination pins how push's first argument is classified. A
// mistyped directory must NOT become a store lookup, because the layout form is
// the primary one and its errors are the ones an operator can act on.
func TestPushSourceDiscrimination(t *testing.T) {
	dir := t.TempDir()
	// A relative directory that EXISTS must classify as a layout, so the check
	// runs from a scratch cwd rather than the package directory.
	t.Chdir(t.TempDir())
	const existingRelative = "probe-layout"
	if err := os.Mkdir(existingRelative, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	tests := []struct {
		name   string
		source string
		want   bool
	}{
		{name: "an absolute path is always a layout", source: dir, want: false},
		{name: "a missing absolute path is still a layout", source: filepath.Join(dir, "gone"), want: false},
		{name: "a ./ path is always a layout", source: "./layout", want: false},
		{name: "a ../ path is always a layout", source: "../layout", want: false},
		{name: "an existing relative directory is a layout", source: existingRelative, want: false},
		{name: "a tagged reference is a store ref", source: "example.test/app:v1", want: true},
		{name: "a bare name that is no path is a store ref", source: "alpine:3.20", want: true},
		{name: "an unparseable reference is not a store ref", source: "NOT A REF", want: false},
		{name: "the empty source is not a store ref", source: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pushSourceIsStoreRef(tc.source); got != tc.want {
				t.Errorf("pushSourceIsStoreRef(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

// TestExtractOCILayout pins the unpacker's refusals. An OCI layout is an index,
// a marker and a tree of content-addressed blobs, so a link or a device node in
// one is either a bug or an attempt at something — and with no link type
// accepted, symlink escape and hardlink aliasing stop being defenses this code
// has to get right.
func TestExtractOCILayout(t *testing.T) {
	tests := []struct {
		name    string
		entries []tar.Header
		wantErr string
	}{
		{
			name: "a traversing entry is refused",
			entries: []tar.Header{
				{Name: "../escaped", Typeflag: tar.TypeReg, Size: 0},
			},
			wantErr: "outside the layout",
		},
		{
			name: "a symlink is refused",
			entries: []tar.Header{
				{Name: "blobs/sha256/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
			},
			wantErr: "not a regular file or a directory",
		},
		{
			name: "a device node is refused",
			entries: []tar.Header{
				{Name: "dev/null", Typeflag: tar.TypeChar},
			},
			wantErr: "not a regular file or a directory",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(dir, "in.tar")
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			for _, hdr := range tc.entries {
				h := hdr
				if err := tw.WriteHeader(&h); err != nil {
					t.Fatal(err)
				}
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			err := extractOCILayout(archive, filepath.Join(dir, "out"))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("extractOCILayout = %v, want one containing %q", err, tc.wantErr)
			}
			// Nothing may have escaped the destination on the way to the refusal.
			if _, statErr := os.Stat(filepath.Join(dir, "escaped")); statErr == nil {
				t.Errorf("an entry landed outside the layout directory")
			}
		})
	}

	t.Run("round-trips a real layout", func(t *testing.T) {
		layout := fixtureLayout(t, "example.test/app:v1", "round-trip-payload")
		want := layoutDigest(t, layout)
		dir := t.TempDir()
		archive := filepath.Join(dir, "layout.tar")
		if err := os.WriteFile(archive, tarLayout(t, layout), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "out")
		if err := extractOCILayout(archive, out); err != nil {
			t.Fatalf("extractOCILayout: %v", err)
		}
		if got := layoutDigest(t, out); got != want {
			t.Errorf("the extracted layout holds %s, want %s", got, want)
		}
	})
}

// tarLayout packs an OCI layout directory into the tarred layout SaveImage
// streams, so the gate feeds the push path exactly the archive shape the daemon
// emits.
func tarLayout(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		t.Fatalf("tar the layout: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
