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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/runtimed/pkg/image"
)

// LocalBlobSource offers the blobs of the store rooted at a directory to the
// node's image cache (image.LocalBlobSource), so a blob the registry already
// holds on the cache's volume is cloned instead of fetched.
//
// It is read-only by construction: every call goes through a Reader, which
// creates nothing, and opens read-only; it takes no repository lock, so it can neither change the store nor hold up a push or a GC. A store
// root that does not exist yet (the registry has not started) holds nothing.
//
// The store keeps one blob file per repository (shared by hard link when the
// same digest is in several), so a digest is looked up in each repository in
// name order and the first regular file found is returned.
//
// In the shipped layout the registry, the runtime that calls this and native
// pods all run as the same uid, so file ownership protects nothing here. Two
// other controls do. The clone's re-hash is the integrity control: the cache
// trusts nothing this source returns, clones the descriptor, and commits only
// a clone whose bytes hash to the digest. The pod sandbox's deny on the
// server work dir, which holds the store, keeps pods out of the store.
type LocalBlobSource struct {
	root string
	// resolved, when set, runs between resolving a blob's path and opening
	// it: a test seam for a path component swapped after the walk.
	resolved func(path string)
}

var _ image.LocalBlobSource = (*LocalBlobSource)(nil)

// NewLocalBlobSource returns the LocalBlobSource for the store rooted at root.
// The root is not opened until a blob is asked for.
func NewLocalBlobSource(root string) *LocalBlobSource {
	return &LocalBlobSource{root: root}
}

// Root returns the store root the source reads.
func (l *LocalBlobSource) Root() string { return l.root }

// OpenBlob returns the store's file for dgst, opened O_RDONLY|O_NOFOLLOW|
// O_CLOEXEC, and its size from fstat. dgst must be "sha256:" and 64 lowercase
// hex digits; anything else, a store that does not exist, and a digest no
// repository holds all return an error matching image.ErrBlobNotLocal. A
// symlink or a non-regular file where the blob should be is refused with an
// error that does not, so the cache reports it; a regular copy in another
// repository is still returned.
func (l *LocalBlobSource) OpenBlob(dgst string) (*os.File, int64, error) {
	d, ok := parseLocalDigest(dgst)
	if !ok {
		return nil, 0, fmt.Errorf("local blob %.80q: not a sha256 digest: %w", dgst, image.ErrBlobNotLocal)
	}
	r, err := OpenReader(l.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, fmt.Errorf("local blob %s: no store at %s: %w", d, l.root, image.ErrBlobNotLocal)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("local blob %s: %w", d, err)
	}
	repos, err := r.Repositories()
	if err != nil {
		return nil, 0, fmt.Errorf("local blob %s: list repositories: %w", d, err)
	}
	var refused error
	for _, n := range repos {
		f, size, err := openLocalBlob(r, n, d, l.resolved)
		if err == nil {
			return f, size, nil
		}
		if errors.Is(err, ErrBlobUnknown) || errors.Is(err, os.ErrNotExist) {
			continue
		}
		if refused == nil {
			refused = fmt.Errorf("local blob %s in %s: %w", d, n, err)
		}
	}
	if refused != nil {
		return nil, 0, refused
	}
	return nil, 0, fmt.Errorf("local blob %s: %w", d, image.ErrBlobNotLocal)
}

// openLocalBlob opens d in n at the path the store's own layout resolves
// (which refuses a symlink anywhere below the root) and returns the file with
// its fstat size. The open adds O_NONBLOCK to O_RDONLY|O_NOFOLLOW|O_CLOEXEC so
// a FIFO planted where the blob should be cannot block it waiting for a
// writer; the flag is cleared once fstat shows a regular file.
//
// The open is an openat relative to a descriptor of the store root, so only
// the components below the root are checked (the root's own parents may be
// symlinks: /var is one on macOS). On darwin it uses O_NOFOLLOW_ANY in place
// of O_NOFOLLOW, so a directory component swapped for a symlink after the walk
// is refused at the open, the same way as a symlinked blob.
func openLocalBlob(r *Reader, n ref.Name, d digest.Digest, resolved func(string)) (*os.File, int64, error) {
	p, err := r.s.blobPath(n, d)
	if err != nil {
		return nil, 0, err
	}
	if resolved != nil {
		resolved(p)
	}
	rel, err := filepath.Rel(r.s.root, p)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, 0, fmt.Errorf("local blob %s in %s: path %s is outside the store root", d, n, p)
	}
	rootFD, err := unix.Open(r.s.root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, 0, fmt.Errorf("%w: %s", ref.ErrSymlink, r.s.root)
	}
	if err != nil {
		return nil, 0, &os.PathError{Op: "open", Path: r.s.root, Err: err}
	}
	fd, err := unix.Openat(rootFD, rel, unix.O_RDONLY|noFollow|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	unix.Close(rootFD)
	if errors.Is(err, unix.ELOOP) {
		return nil, 0, fmt.Errorf("%w: %s", ref.ErrSymlink, p)
	}
	if errors.Is(err, unix.ENOENT) {
		return nil, 0, fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, n)
	}
	if err != nil {
		return nil, 0, &os.PathError{Op: "open", Path: p, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, 0, &os.PathError{Op: "fstat", Path: p, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, 0, fmt.Errorf("%w: blob %s in %s", ErrNotRegular, d, n)
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return nil, 0, &os.PathError{Op: "fcntl", Path: p, Err: err}
	}
	return os.NewFile(uintptr(fd), p), st.Size, nil
}

// parseLocalDigest accepts exactly "sha256:" followed by 64 lowercase hex
// digits: the only digests the image cache stores.
func parseLocalDigest(s string) (digest.Digest, bool) {
	const prefix = "sha256:"
	if len(s) != len(prefix)+64 || s[:len(prefix)] != prefix {
		return "", false
	}
	for i := len(prefix); i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return digest.Digest(s), true
}
