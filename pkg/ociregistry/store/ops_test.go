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

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenWorkDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenRefusesStateInsideRoot(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root, filepath.Join(root, "state")); err == nil {
		t.Fatal("Open accepted a state dir inside the store root")
	}
	if _, err := Open("relative", t.TempDir()); err == nil {
		t.Fatal("Open accepted a relative root")
	}
}

// TestLinkOrKeep: a blob that exists is never replaced, so the inode another
// repository shares keeps its bytes and its links.
func TestLinkOrKeep(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	a, b := name(t, "a"), name(t, "b")
	body := []byte("blob bytes")
	d := digest.FromBytes(body)
	if err := s.PutBlob(ctx, a, d, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if err := s.MountBlob(ctx, b, a, d); err != nil {
		t.Fatal(err)
	}
	pa, _ := s.blobPath(a, d)
	pb, _ := s.blobPath(b, d)
	if !sameInode(t, pa, pb) {
		t.Fatal("a mount is not a hardlink")
	}
	// The same digest committed again into b: the existing inode stays.
	if err := s.PutBlob(ctx, b, d, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if !sameInode(t, pa, pb) {
		t.Fatal("a second commit replaced a shared blob")
	}
	if ups, _ := s.Uploads(b); len(ups) != 0 {
		t.Fatalf("finished uploads left behind: %+v", ups)
	}
}

func TestMountUnavailable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	d := digest.FromString("absent")
	err := s.MountBlob(ctx, name(t, "dst"), name(t, "src"), d)
	if !errors.Is(err, ErrMountUnavailable) {
		t.Fatalf("MountBlob from a repository without the blob = %v", err)
	}
}

func TestCommitDigestMismatchKeepsSession(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	id, err := s.NewUpload(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, n, id, 0, bytes.NewReader([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AppendUpload(ctx, n, id, 1, bytes.NewReader([]byte("x"))); !errors.Is(err, ErrOffsetMismatch) {
		t.Fatalf("a chunk at the wrong offset = %v", err)
	}
	if err := s.CommitUpload(ctx, n, id, digest.FromString("other")); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("CommitUpload with the wrong digest = %v", err)
	}
	if size, err := s.UploadSize(ctx, n, id); err != nil || size != 3 {
		t.Fatalf("session after a refused commit = %d, %v", size, err)
	}
	if _, err := s.StatBlob(n, digest.FromString("other")); !errors.Is(err, ErrBlobUnknown) {
		t.Fatalf("StatBlob of an uncommitted blob = %v", err)
	}
	if err := s.CancelUpload(ctx, n, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UploadSize(ctx, n, id); !errors.Is(err, ErrUploadUnknown) {
		t.Fatalf("UploadSize after cancel = %v", err)
	}
}

func TestStoreRefusesSymlinks(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(s.Root(), "evil")); err != nil {
		t.Fatal(err)
	}
	n := name(t, "evil/app")
	if err := s.PutBlob(ctx, n, digest.FromString("x"), bytes.NewReader([]byte("x"))); !errors.Is(err, ref.ErrSymlink) {
		t.Fatalf("PutBlob through a symlink = %v", err)
	}
	if _, err := s.Index(n); !errors.Is(err, ref.ErrSymlink) {
		t.Fatalf("Index through a symlink = %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatalf("the store wrote outside its root: %v", entryNames(ents))
	}

	// A symlinked blob inside a real repository is refused, not followed.
	app := name(t, "app")
	body := []byte("real")
	d := digest.FromBytes(body)
	if err := s.PutBlob(ctx, app, d, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	fake := digest.FromString("fake")
	p, _ := s.blobPath(app, fake)
	if err := os.Symlink(filepath.Join(outside, "secret"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenBlob(app, fake); !errors.Is(err, ref.ErrSymlink) {
		t.Fatalf("OpenBlob of a symlink = %v", err)
	}
	repos, err := s.Repositories()
	if err != nil || len(repos) != 1 || repos[0] != app {
		t.Fatalf("Repositories() = %v, %v", repos, err)
	}
}

func TestDeleteRows(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	body := []byte(`{"schemaVersion":2}`)
	for _, tag := range []string{"a", "b"} {
		if _, err := s.PutManifest(ctx, n, reference(t, tag), "application/vnd.oci.image.manifest.v1+json", body); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.DeleteTag(ctx, n, "a"); err != nil {
		t.Fatal(err)
	}
	if tags, _ := s.Tags(n); len(tags) != 1 || tags[0] != "b" {
		t.Fatalf("Tags after a tag delete = %v", tags)
	}
	if err := s.DeleteDigest(ctx, n, digest.FromBytes(body)); err != nil {
		t.Fatal(err)
	}
	if idx, _ := s.Index(n); len(idx.Manifests) != 0 {
		t.Fatalf("rows after a digest delete = %+v", idx.Manifests)
	}
	if err := s.DeleteTag(ctx, n, "a"); !errors.Is(err, ErrManifestUnknown) {
		t.Fatalf("DeleteTag of a missing tag = %v", err)
	}
}
