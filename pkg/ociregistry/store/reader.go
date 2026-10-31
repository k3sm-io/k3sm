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
	"fmt"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// Reader is a read-only view of a store. Unlike Open it creates nothing, not
// the root and not the state directory, and it has no method that writes, so
// a process that only inspects the store (which may run as another user than
// the server) cannot leave a file or directory the server then cannot use.
type Reader struct {
	s *Store
}

// OpenReader opens the store rooted at root for reading. root must be
// absolute, exist, be a directory and not be a symlink.
func OpenReader(root string) (*Reader, error) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("open store for reading: root %q must be absolute", root)
	}
	fi, err := os.Lstat(root)
	if err != nil {
		return nil, fmt.Errorf("open store for reading: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("open store for reading: %w: %s", ref.ErrSymlink, root)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("open store for reading: %w: %s is not a directory", ErrNotRegular, root)
	}
	return &Reader{s: &Store{root: root}}, nil
}

// Root returns the store root.
func (r *Reader) Root() string { return r.s.root }

// Repositories is Store.Repositories.
func (r *Reader) Repositories() ([]ref.Name, error) { return r.s.Repositories() }

// Index is Store.Index.
func (r *Reader) Index(n ref.Name) (ispec.Index, error) { return r.s.Index(n) }

// Manifest is Store.Manifest.
func (r *Reader) Manifest(n ref.Name, rf ref.Reference) (ispec.Descriptor, []byte, error) {
	return r.s.Manifest(n, rf)
}

// OpenBlob is Store.OpenBlob.
func (r *Reader) OpenBlob(n ref.Name, d digest.Digest) (*os.File, error) { return r.s.OpenBlob(n, d) }
