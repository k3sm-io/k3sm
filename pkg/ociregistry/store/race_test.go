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
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// TestLateChunkNeverReachesPublishedBlob reproduces, deterministically, a
// chunk whose request opened the session before a commit and took the session
// lock after it. The commit links the session inode into blobs/ and a mount
// shares it with another repository; the late chunk must fail as a gone
// session and both blobs keep their bytes.
func TestLateChunkNeverReachesPublishedBlob(t *testing.T) {
	for _, finish := range []string{"commit", "cancel"} {
		t.Run(finish, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			n, other := name(t, "app"), name(t, "other")
			body := []byte("published bytes")
			d := digest.FromBytes(body)
			id, err := s.NewUpload(ctx, n)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.AppendUpload(ctx, n, id, 0, bytes.NewReader(body)); err != nil {
				t.Fatal(err)
			}

			// The first session open after this point (the late chunk's)
			// parks between its open and its flock until released.
			opened, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			s.uploadOpened = func(string) {
				if calls.Add(1) == 1 {
					close(opened)
					<-release
				}
			}
			late := make(chan error, 1)
			go func() {
				_, err := s.AppendUpload(ctx, n, id, -1, strings.NewReader("LATE CHUNK"))
				late <- err
			}()
			<-opened

			switch finish {
			case "commit":
				if err := s.CommitUpload(ctx, n, id, d); err != nil {
					t.Fatal(err)
				}
				if err := s.MountBlob(ctx, other, n, d); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				if err := s.CancelUpload(ctx, n, id); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if err := <-late; !errors.Is(err, ErrUploadUnknown) {
				t.Errorf("late chunk after %s = %v, want ErrUploadUnknown", finish, err)
			}
			if finish == "commit" {
				for _, r := range []ref.Name{n, other} {
					p, _ := s.blobPath(r, d)
					if got, _ := os.ReadFile(p); !bytes.Equal(got, body) {
						t.Errorf("blob %s in %s is %q after a late chunk", d, r, got)
					}
				}
			}
		})
	}
}

// corruptBlob plants wrong bytes as blob d of n, as its own inode, and also
// links that inode into share so a replacement can be seen not to touch it.
func corruptBlob(t *testing.T, s *Store, n, share ref.Name, d digest.Digest) string {
	t.Helper()
	ctx := context.Background()
	for _, r := range []ref.Name{n, share} {
		if err := s.Init(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	p, _ := s.blobPath(n, d)
	q, _ := s.blobPath(share, d)
	for _, dir := range []string{filepath.Dir(p), filepath.Dir(q)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, q); err != nil {
		t.Fatal(err)
	}
	return q
}

func noTemps(t *testing.T, s *Store, n ref.Name) {
	t.Helper()
	p, _ := s.blobPath(n, digest.FromString(""))
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("leftover %s in %s", e.Name(), filepath.Dir(p))
		}
	}
}

// TestKeepVerifiesExisting: link-or-keep keeps an existing blob only when it
// hashes to the digest. A corrupt one is replaced by rename, and the corrupt
// inode, still linked elsewhere, is left byte for byte as it was.
func TestKeepVerifiesExisting(t *testing.T) {
	ctx := context.Background()
	body := []byte("the real blob")
	d := digest.FromBytes(body)

	t.Run("commit replaces a corrupt blob", func(t *testing.T) {
		s := newStore(t)
		n, share := name(t, "app"), name(t, "share")
		q := corruptBlob(t, s, n, share, d)
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		p, _ := s.blobPath(n, d)
		if got, _ := os.ReadFile(p); !bytes.Equal(got, body) {
			t.Fatalf("blob after commit = %q", got)
		}
		if got, _ := os.ReadFile(q); string(got) != "corrupt" {
			t.Fatalf("the shared corrupt inode was modified: %q", got)
		}
		noTemps(t, s, n)
	})

	t.Run("mount replaces a corrupt blob from a verified source", func(t *testing.T) {
		s := newStore(t)
		src, n, share := name(t, "src"), name(t, "app"), name(t, "share")
		if err := s.PutBlob(ctx, src, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		corruptBlob(t, s, n, share, d)
		if err := s.MountBlob(ctx, n, src, d); err != nil {
			t.Fatal(err)
		}
		p, _ := s.blobPath(n, d)
		ps, _ := s.blobPath(src, d)
		if !sameInode(t, p, ps) {
			t.Fatal("the mount did not link the verified source")
		}
		noTemps(t, s, n)
	})

	t.Run("mount from a corrupt source over a corrupt blob fails", func(t *testing.T) {
		s := newStore(t)
		src, n, share := name(t, "src"), name(t, "app"), name(t, "share")
		corruptBlob(t, s, src, name(t, "share2"), d)
		corruptBlob(t, s, n, share, d)
		if err := s.MountBlob(ctx, n, src, d); !errors.Is(err, ErrDigestMismatch) {
			t.Fatalf("MountBlob = %v, want ErrDigestMismatch", err)
		}
		noTemps(t, s, n)
	})

	t.Run("a good existing blob is kept", func(t *testing.T) {
		s := newStore(t)
		n := name(t, "app")
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		p, _ := s.blobPath(n, d)
		before, _ := os.Stat(p)
		if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		after, _ := os.Stat(p)
		if !os.SameFile(before, after) {
			t.Fatal("a good blob was replaced")
		}
	})
}

func TestManifestRefusesOversizeDescriptor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := name(t, "app")
	body := []byte(`{"schemaVersion":2}`)
	desc, err := s.PutManifest(ctx, n, reference(t, "v1"), "application/vnd.oci.image.manifest.v1+json", body)
	if err != nil {
		t.Fatal(err)
	}
	desc.Size = MaxManifestSize + 1
	err = s.updateIndex(ctx, n, func(rows []ispec.Descriptor) ([]ispec.Descriptor, bool, error) {
		rows[0].Size = desc.Size
		return rows, true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Manifest(n, reference(t, "v1")); err == nil {
		t.Fatal("Manifest read a descriptor above the cap")
	}
}

// TestSymlinkAtEveryElement plants a symlink in place of each element on the
// way to a repository's files, pointing at a copy outside the store, and runs
// every operation that reaches that element. Each must fail, and the copy
// outside must be unchanged.
func TestSymlinkAtEveryElement(t *testing.T) {
	ctx := context.Background()
	body := []byte("blob body")
	d := digest.FromBytes(body)
	elems := []string{
		"org", "org/team", "org/team/app",
		"org/team/app/blobs", "org/team/app/blobs/sha256", "org/team/app/blobs/sha256/" + d.Encoded(),
		"org/team/app/.uploads", "org/team/app/.uploads/<session>",
		"org/team/app/index.json", "org/team/app/oci-layout",
	}
	for _, elem := range elems {
		t.Run(elem, func(t *testing.T) {
			s := newStore(t)
			n := name(t, "org/team/app")
			if err := s.PutBlob(ctx, n, d, bytes.NewReader(body)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.PutManifest(ctx, n, reference(t, "v1"), "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2}`)); err != nil {
				t.Fatal(err)
			}
			id, err := s.NewUpload(ctx, n)
			if err != nil {
				t.Fatal(err)
			}
			rel := strings.ReplaceAll(elem, "<session>", id)
			p := filepath.Join(s.Root(), filepath.FromSlash(rel))
			outside := filepath.Join(t.TempDir(), "moved")
			if err := os.Rename(p, outside); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, p); err != nil {
				t.Fatal(err)
			}
			before := treeSum(t, outside)

			ops := map[string]func() error{
				"Index":    func() error { _, err := s.Index(n); return err },
				"Tags":     func() error { _, err := s.Tags(n); return err },
				"Manifest": func() error { _, _, err := s.Manifest(n, reference(t, "v1")); return err },
				"OpenBlob": func() error {
					f, err := s.OpenBlob(n, d)
					if err == nil {
						f.Close()
					}
					return err
				},
				"UploadSize": func() error { _, err := s.UploadSize(ctx, n, id); return err },
				"Append": func() error {
					_, err := s.AppendUpload(ctx, n, id, -1, strings.NewReader("x"))
					return err
				},
				"PutBlob": func() error {
					return s.PutBlob(ctx, n, digest.FromString("new"), strings.NewReader("new"))
				},
				"PutManifest": func() error {
					_, err := s.PutManifest(ctx, n, reference(t, "v2"), "application/vnd.oci.image.manifest.v1+json", []byte(`{"schemaVersion":2,"x":1}`))
					return err
				},
			}
			// Which operations reach which element.
			reaches := func(op string) bool {
				switch {
				case strings.HasSuffix(rel, "/oci-layout"), strings.HasSuffix(rel, "/index.json"):
					return op == "Index" || op == "Tags" || op == "Manifest" || op == "PutManifest"
				case strings.Contains(rel, "/.uploads/"):
					return op == "UploadSize" || op == "Append"
				case strings.HasSuffix(rel, "/.uploads"):
					return op == "UploadSize" || op == "Append" || op == "PutBlob" || op == "PutManifest"
				case strings.Contains(rel, "/blobs/sha256/"):
					return op == "OpenBlob" // the planted blob is not the manifest's
				case strings.Contains(rel, "/blobs"):
					return op == "OpenBlob" || op == "Manifest" || op == "PutBlob"
				default:
					return true
				}
			}
			for op, f := range ops {
				if !reaches(op) {
					continue
				}
				if err := f(); err == nil {
					t.Errorf("%s through a symlink at %s succeeded", op, rel)
				}
			}
			if after := treeSum(t, outside); after != before {
				t.Errorf("the store changed %s through a symlink at %s", outside, rel)
			}
		})
	}
}

// treeSum hashes every path and file body under p (p itself if a file).
func treeSum(t *testing.T, p string) [32]byte {
	t.Helper()
	h := sha256.New()
	err := filepath.Walk(p, func(q string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		h.Write([]byte(q))
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(q)
			if err != nil {
				return err
			}
			h.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
