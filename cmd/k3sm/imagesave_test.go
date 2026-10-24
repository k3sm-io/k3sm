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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestSaveImageArchiveVerifiesTheStream is the gate for the node-store export
// `k3sm image push` uses for a source named in this node's store. The
// load-bearing claim is the TRUNCATION one: the wire's terminal frame is the
// only thing that tells a complete archive from a short one, so an export that
// ends without it, or that disagrees about the byte count, must leave NO file
// behind. A tar short by one layer still opens, and the first thing that would
// notice is a pod that cannot start.
func TestSaveImageArchiveVerifiesTheStream(t *testing.T) {
	digest := "sha256:" + strings.Repeat("4d", 32)
	body := []byte("oci-layout-archive-bytes")

	// chunked splits the fixture archive so the client's frame handling, not
	// just a single-frame path, is what the gate exercises.
	chunked := [][]byte{body[:10], body[10:]}

	// save runs one export against fake into target.
	save := func(t *testing.T, fake *fakeImagesDaemon, target string) (savedArchive, error) {
		t.Helper()
		sock := serveFakeImages(t, fake)
		cc, closer, err := dialRuntimed(t.Context(), sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { closer.Close() })
		return saveImageArchive(t.Context(), runtimev1.NewImagesClient(cc), &runtimev1.SaveImageRequest{
			Reference: "example.test/app:v1",
			Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
		}, target, sock)
	}

	t.Run("writes the archive and reports the digest", func(t *testing.T) {
		fake := &fakeImagesDaemon{
			saveChunks:   chunked,
			saveTerminal: &runtimev1.SaveImageResponse{Digest: digest, SentBytes: int64(len(body))},
		}
		dir := t.TempDir()
		target := filepath.Join(dir, "app.tar")
		saved, err := save(t, fake, target)
		if err != nil {
			t.Fatalf("save: %v", err)
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read the saved archive: %v", err)
		}
		if string(got) != string(body) || saved.digest != digest {
			t.Errorf("archive = %q digest = %q, want %q %q", got, saved.digest, body, digest)
		}
		assertOnlyFile(t, dir, "app.tar")
	})

	t.Run("refuses a truncated archive and leaves nothing behind", func(t *testing.T) {
		tests := []struct {
			name string
			fake *fakeImagesDaemon
			want error
			text string
		}{
			{
				// The stream simply stops. Without the terminal frame this is
				// indistinguishable from a complete archive by inspection, which
				// is exactly why the frame exists.
				name: "no terminal frame",
				fake: &fakeImagesDaemon{saveChunks: chunked},
				want: errSaveTruncated,
				text: "no terminal frame",
			},
			{
				name: "the byte count disagrees",
				fake: &fakeImagesDaemon{
					saveChunks:   chunked,
					saveTerminal: &runtimev1.SaveImageResponse{Digest: digest, SentBytes: int64(len(body)) + 99},
				},
				want: errSaveTruncated,
				text: "arrived",
			},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "app.tar")

				_, err := save(t, tc.fake, target)
				if err == nil {
					t.Fatalf("save of a truncated export succeeded")
				}
				if !errors.Is(err, tc.want) {
					t.Errorf("error = %v, want one wrapping %v", err, tc.want)
				}
				if !strings.Contains(err.Error(), tc.text) {
					t.Errorf("error = %v, want one containing %q", err, tc.text)
				}
				assertEmptyDir(t, dir)
			})
		}
	})

	t.Run("a mid-transfer failure is the daemon's reason, and no file", func(t *testing.T) {
		fake := &fakeImagesDaemon{
			saveChunks: chunked,
			saveTerminal: &runtimev1.SaveImageResponse{
				Error: status.New(codes.Internal, "a layer blob is missing from the store").Proto(),
			},
		}
		dir := t.TempDir()
		target := filepath.Join(dir, "app.tar")

		_, err := save(t, fake, target)
		if err == nil {
			t.Fatalf("save succeeded despite a terminal error frame")
		}
		if !strings.Contains(err.Error(), "a layer blob is missing from the store") {
			t.Errorf("error = %v, want the daemon's reason", err)
		}
		assertEmptyDir(t, dir)
	})

	t.Run("a terminal frame with no digest is refused", func(t *testing.T) {
		fake := &fakeImagesDaemon{
			saveChunks:   chunked,
			saveTerminal: &runtimev1.SaveImageResponse{SentBytes: int64(len(body))},
		}
		dir := t.TempDir()
		_, err := save(t, fake, filepath.Join(dir, "app.tar"))
		if err == nil || !strings.Contains(err.Error(), "no digest") {
			t.Errorf("error = %v, want the missing-digest refusal", err)
		}
		assertEmptyDir(t, dir)
	})

	// The staging-then-rename is what makes this true: a failed export must not
	// replace a good archive with a short one.
	t.Run("a failed save does not clobber an existing archive", func(t *testing.T) {
		fake := &fakeImagesDaemon{saveChunks: chunked}
		dir := t.TempDir()
		target := filepath.Join(dir, "app.tar")
		if err := os.WriteFile(target, []byte("the previous good archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := save(t, fake, target); err == nil {
			t.Fatalf("a truncated save succeeded")
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("the previous archive is gone: %v", err)
		}
		if string(got) != "the previous good archive" {
			t.Errorf("the previous archive was replaced with %q", got)
		}
		assertOnlyFile(t, dir, "app.tar")
	})

	t.Run("surfaces a transport refusal", func(t *testing.T) {
		fake := &fakeImagesDaemon{saveErr: status.Error(codes.NotFound,
			"SaveImage: example.test/app:v1 is not in the local index")}
		dir := t.TempDir()
		_, err := save(t, fake, filepath.Join(dir, "app.tar"))
		if err == nil || !strings.Contains(err.Error(), "is not in the local index") {
			t.Errorf("error = %v", err)
		}
		assertEmptyDir(t, dir)
	})
}

// assertEmptyDir proves a failed export left nothing at all — neither the target
// nor the staging file, which would otherwise accumulate one per failure.
func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("a failed save left %v behind; a partial archive must be discarded", names)
	}
}

// assertOnlyFile proves the staging file was cleaned up on the success path too.
func assertOnlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != name {
		got := make([]string, 0, len(entries))
		for _, e := range entries {
			got = append(got, e.Name())
		}
		t.Errorf("directory holds %v, want exactly [%s]", got, name)
	}
}
