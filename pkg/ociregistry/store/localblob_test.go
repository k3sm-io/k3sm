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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/runtimed/pkg/image"
)

// putLocalBlob writes b into repo and returns its digest.
func putLocalBlob(t *testing.T, s *Store, repo string, b []byte) digest.Digest {
	t.Helper()
	d := digest.FromBytes(b)
	if err := s.PutBlob(context.Background(), name(t, repo), d, bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	return d
}

// blobFile is the on-disk path of d in repo, resolved through the store.
func blobFile(t *testing.T, s *Store, repo string, d digest.Digest) string {
	t.Helper()
	p, err := s.blobPath(name(t, repo), d)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// treeSnapshot lists every path under root with its size and mtime, so a test
// can assert that a read left the store exactly as it was.
func treeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		out[p] = fmt.Sprint(fi.Mode(), fi.ModTime().UnixNano(), fi.Size())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLocalBlobSourceOpensStoreBlob(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "registry")
	s := openAt(t, root)
	body := []byte("a layer the registry already holds\n")
	d := putLocalBlob(t, s, "apps/web", body)
	if err := s.MountBlob(context.Background(), name(t, "apps/api"), name(t, "apps/web"), d); err != nil {
		t.Fatal(err)
	}
	before := treeSnapshot(t, work)

	src := NewLocalBlobSource(root)
	f, size, err := src.OpenBlob(d.String())
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	defer f.Close()
	if size != int64(len(body)) {
		t.Fatalf("size = %d, want %d", size, len(body))
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("content = %q, want %q", got, body)
	}
	if _, err := f.Write([]byte("x")); err == nil {
		t.Fatal("the returned file is writable; it must be opened read-only")
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Lstat(blobFile(t, s, "apps/web", d))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, want) {
		t.Fatal("the returned file is not the store's blob inode")
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("the returned descriptor is not close-on-exec")
	}

	// Reading created, changed and locked nothing, anywhere in the work dir.
	after := treeSnapshot(t, work)
	if len(after) != len(before) {
		t.Fatalf("the store tree changed: %d entries before, %d after", len(before), len(after))
	}
	for p, v := range before {
		if after[p] != v {
			t.Fatalf("%s changed: %q -> %q", p, v, after[p])
		}
	}
	// A writer still takes the repository lock at once.
	if err := s.WithLock(context.Background(), name(t, "apps/web"), func(*Locked) error { return nil }); err != nil {
		t.Fatalf("the store's lock is held after a read: %v", err)
	}
}

func TestLocalBlobSourceRefusesBadDigestAndSymlink(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "registry")
	s := openAt(t, root)
	body := []byte("layer bytes\n")
	d := putLocalBlob(t, s, "apps/web", body)
	src := NewLocalBlobSource(root)

	hex := d.Encoded()
	for _, tc := range []struct {
		name, digest string
	}{
		{"empty", ""},
		{"no algorithm", hex},
		{"uppercase hex", "sha256:" + strings.ToUpper(hex)},
		{"uppercase algorithm", "SHA256:" + hex},
		{"sha512", digest.SHA512.FromBytes(body).String()},
		{"short", "sha256:" + hex[:63]},
		{"long", "sha256:" + hex + "0"},
		{"non-hex", "sha256:" + hex[:63] + "g"},
		{"traversal", "sha256:../../../../" + hex[:46]},
		{"separator", "sha256/" + hex},
		{"trailing newline", d.String() + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _, err := src.OpenBlob(tc.digest)
			if f != nil {
				f.Close()
				t.Fatal("returned a file for an invalid digest")
			}
			if !errors.Is(err, image.ErrBlobNotLocal) {
				t.Fatalf("err = %v, want ErrBlobNotLocal", err)
			}
		})
	}

	t.Run("symlinked blob", func(t *testing.T) {
		// A link whose target holds the right bytes is refused all the same:
		// the store never follows a symlink.
		outside := filepath.Join(work, "outside")
		if err := os.WriteFile(outside, body, 0o600); err != nil {
			t.Fatal(err)
		}
		p := blobFile(t, s, "apps/web", d)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, p); err != nil {
			t.Fatal(err)
		}
		f, _, err := src.OpenBlob(d.String())
		if f != nil {
			f.Close()
			t.Fatal("returned a file through a symlink")
		}
		if !errors.Is(err, ref.ErrSymlink) {
			t.Fatalf("err = %v, want ErrSymlink", err)
		}
		if errors.Is(err, image.ErrBlobNotLocal) {
			t.Fatalf("err = %v: a refusal must not read as \"not held\"", err)
		}

		// A regular copy in another repository is still offered.
		other := putLocalBlob(t, s, "apps/zzz", body)
		f, size, err := src.OpenBlob(other.String())
		if err != nil {
			t.Fatalf("OpenBlob with a regular copy elsewhere: %v", err)
		}
		defer f.Close()
		if size != int64(len(body)) {
			t.Fatalf("size = %d, want %d", size, len(body))
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.Lstat(blobFile(t, s, "apps/zzz", d))
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(fi, want) {
			t.Fatal("returned a file other than the regular copy")
		}
	})

	t.Run("directory component swapped for a symlink", func(t *testing.T) {
		// A decoy directory outside the store holds a file under the blob's
		// own name with the blob's own bytes. The store's sha256 directory is
		// replaced by a symlink to it: before the call, which the path walk
		// refuses, and after the walk, which only the open can refuse.
		b := []byte("swapped component\n")
		bd := putLocalBlob(t, s, "apps/swap", b)
		p := blobFile(t, s, "apps/swap", bd)
		algDir := filepath.Dir(p)
		decoy := filepath.Join(t.TempDir(), "decoy")
		if err := os.Mkdir(decoy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(decoy, filepath.Base(p)), b, 0o600); err != nil {
			t.Fatal(err)
		}
		decoyInfo, err := os.Stat(filepath.Join(decoy, filepath.Base(p)))
		if err != nil {
			t.Fatal(err)
		}
		real := filepath.Join(t.TempDir(), "real-sha256")
		swap := func() {
			if err := os.Rename(algDir, real); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoy, algDir); err != nil {
				t.Fatal(err)
			}
		}
		restore := func() {
			if err := os.Remove(algDir); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(real, algDir); err != nil {
				t.Fatal(err)
			}
		}
		refused := func(t *testing.T, src *LocalBlobSource) {
			t.Helper()
			f, _, err := src.OpenBlob(bd.String())
			if f != nil {
				defer f.Close()
				if fi, serr := f.Stat(); serr == nil && os.SameFile(fi, decoyInfo) {
					t.Fatal("returned the decoy behind the swapped directory")
				}
				t.Fatal("returned a file through a symlinked directory component")
			}
			if !errors.Is(err, ref.ErrSymlink) {
				t.Fatalf("err = %v, want ErrSymlink", err)
			}
			if errors.Is(err, image.ErrBlobNotLocal) {
				t.Fatalf("err = %v: a refusal must not read as \"not held\"", err)
			}
		}

		t.Run("before the walk", func(t *testing.T) {
			swap()
			defer restore()
			refused(t, NewLocalBlobSource(root))
		})
		t.Run("after the walk", func(t *testing.T) {
			if runtime.GOOS != "darwin" {
				t.Skip("O_NOFOLLOW_ANY is darwin's")
			}
			src := NewLocalBlobSource(root)
			swapped := false
			setLocalBlobResolved(src, func(path string) {
				if path == p && !swapped {
					swapped = true
					swap()
				}
			})
			defer func() {
				if swapped {
					restore()
				}
			}()
			refused(t, src)
			if !swapped {
				t.Fatal("the seam never ran for the blob's path")
			}
		})
	})

	t.Run("non-regular blob", func(t *testing.T) {
		b := []byte("fifo stand-in\n")
		bd := putLocalBlob(t, s, "apps/fifo", b)
		p := blobFile(t, s, "apps/fifo", bd)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		f, _, err := src.OpenBlob(bd.String())
		if f != nil {
			f.Close()
			t.Fatal("returned a non-regular file")
		}
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("err = %v, want ErrNotRegular", err)
		}
	})
}

func TestLocalBlobSourceMissingIsNotLocal(t *testing.T) {
	work := t.TempDir()
	root := filepath.Join(work, "registry")
	absent := digest.FromBytes([]byte("never pushed\n")).String()

	t.Run("no store yet", func(t *testing.T) {
		_, _, err := NewLocalBlobSource(root).OpenBlob(absent)
		if !errors.Is(err, image.ErrBlobNotLocal) {
			t.Fatalf("err = %v, want ErrBlobNotLocal", err)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the source created the store root: %v", err)
		}
	})

	t.Run("digest held nowhere", func(t *testing.T) {
		s := openAt(t, root)
		putLocalBlob(t, s, "apps/web", []byte("something else\n"))
		_, _, err := NewLocalBlobSource(root).OpenBlob(absent)
		if !errors.Is(err, image.ErrBlobNotLocal) {
			t.Fatalf("err = %v, want ErrBlobNotLocal", err)
		}
	})

	t.Run("empty store", func(t *testing.T) {
		empty := filepath.Join(t.TempDir(), "registry")
		openAt(t, empty)
		_, _, err := NewLocalBlobSource(empty).OpenBlob(absent)
		if !errors.Is(err, image.ErrBlobNotLocal) {
			t.Fatalf("err = %v, want ErrBlobNotLocal", err)
		}
	})
}
