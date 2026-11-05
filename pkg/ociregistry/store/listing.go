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
	"slices"
	"strings"
	"syscall"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// WalkRepositories calls fn for each repository whose name sorts after after,
// in lexical order, until fn returns false. It skips what Repositories skips,
// and it never reads a directory whose whole subtree sorts at or before after,
// so a page of the catalog costs the directories on the path to the cursor and
// the page, not the whole root.
func (s *Store) WalkRepositories(after string, fn func(ref.Name) bool) error {
	if _, err := s.walkRepos(s.root, "", after, fn); err != nil {
		return fmt.Errorf("list repositories: %w", err)
	}
	return nil
}

// walkRepos walks dir, whose repository-name prefix is prefix ("" or ending in
// "/"). It reports false when fn stopped the walk.
func (s *Store) walkRepos(dir, prefix, after string, fn func(ref.Name) bool) (bool, error) {
	if s.dirRead != nil {
		s.dirRead(dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	// A child c is itself at c and its subtree at c+"/", so a walk in
	// lexical order visits each at its own key ('-' and '.' sort before '/',
	// so "a-b" falls between the repository "a" and the names under "a/").
	type step struct {
		key, base string
		subtree   bool
	}
	steps := make([]step, 0, 2*len(ents))
	for _, e := range ents {
		base := e.Name()
		if !e.IsDir() || base == blobsDir || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") {
			continue
		}
		if _, err := ref.NameFromDir(s.root, filepath.Join(dir, base)); err != nil {
			continue
		}
		steps = append(steps, step{prefix + base, base, false}, step{prefix + base + "/", base, true})
	}
	slices.SortFunc(steps, func(a, b step) int { return strings.Compare(a.key, b.key) })
	for _, st := range steps {
		p := filepath.Join(dir, st.base)
		if !st.subtree {
			if st.key > after && isRepoDir(p) {
				n, _ := ref.NameFromDir(s.root, p) // checked above
				if !fn(n) {
					return false, nil
				}
			}
			continue
		}
		if after > st.key && !strings.HasPrefix(after, st.key) {
			continue // every name in the subtree sorts before the cursor
		}
		more, err := s.walkRepos(p, st.key, after, fn)
		if err != nil || !more {
			return more, err
		}
	}
	return true, nil
}

// IndexVersion identifies one content of a repository's index.json. Every
// index write is a new file renamed into place, so a changed index has a new
// inode as well as a new modification time.
type IndexVersion struct {
	Ino     uint64
	Size    int64
	ModTime int64 // nanoseconds since the epoch
}

func versionOf(fi os.FileInfo) IndexVersion {
	v := IndexVersion{Size: fi.Size(), ModTime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		v.Ino = st.Ino
	}
	return v
}

// IndexVersionOf stats n's index.json without reading it.
func (s *Store) IndexVersionOf(n ref.Name) (IndexVersion, error) {
	dir, ok, err := s.exists(n)
	if err != nil {
		return IndexVersion{}, err
	}
	if !ok {
		return IndexVersion{}, fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	fi, err := os.Lstat(filepath.Join(dir, indexFile))
	if err != nil {
		return IndexVersion{}, fmt.Errorf("stat index: %w", err)
	}
	return versionOf(fi), nil
}

// IndexAt returns n's index.json and the version it was read at, both taken
// from one open descriptor.
func (s *Store) IndexAt(n ref.Name) (ispec.Index, IndexVersion, error) {
	dir, ok, err := s.exists(n)
	if err != nil {
		return ispec.Index{}, IndexVersion{}, err
	}
	if !ok {
		return ispec.Index{}, IndexVersion{}, fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	p := filepath.Join(dir, indexFile)
	f, err := openRegular(p, os.O_RDONLY)
	if err != nil {
		return ispec.Index{}, IndexVersion{}, fmt.Errorf("read index: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return ispec.Index{}, IndexVersion{}, fmt.Errorf("read index: %w", err)
	}
	idx, err := decodeIndex(f, p)
	if err != nil {
		return ispec.Index{}, IndexVersion{}, err
	}
	return idx, versionOf(fi), nil
}
