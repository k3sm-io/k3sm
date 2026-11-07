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

package hf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/opencontainers/go-digest"

	"k3sm.io/k3sm/pkg/modelpack"
)

// MaxTotalBytes is the most an import downloads in all.
const MaxTotalBytes = 1 << 40

// Free space an import keeps in reserve beyond the files it plans to
// download: a twentieth of their size, and at least this much.
const minFreeMarginBytes = 1 << 30

// ErrNoSpace is a scratch directory whose file system cannot hold the
// files an import plans to download, with the margin.
var ErrNoSpace = errors.New("not enough free space for the download")

// ErrUnknownSHA256Path is a caller's sha256 for a path the repository does
// not have at the commit.
var ErrUnknownSHA256Path = errors.New("--sha256 names a file the repository does not have")

// ImportOptions configures one Import.
type ImportOptions struct {
	// ScratchDir is the directory the import's own scratch directory is
	// created in; os.TempDir() when empty. The scratch directory is removed
	// when Import returns.
	ScratchDir string
	// SHA256 maps a file's path to the sha256 (64 lowercase hex digits) its
	// content must also have, beyond the Hub's own hash.
	SHA256 map[string]string
	// Push receives the built artifact once every file is verified. It is
	// called at most once, and never after a refusal. A nil Push builds and
	// verifies only.
	Push func(ctx context.Context, a *modelpack.Artifact) error
	// Fetched, when set, is called after each file is downloaded and
	// verified.
	Fetched func(path string, size int64)
}

// Result is a finished import.
type Result struct {
	// Commit is the 40-hex commit the revision resolved to.
	Commit string
	// Artifact is what was pushed. Its layers' bytes were read from the
	// scratch directory, which is gone: use its manifest and digest only.
	Artifact *modelpack.Artifact
	// Bytes is how many content bytes were downloaded.
	Bytes int64
}

// Import imports ref: it resolves the revision to a commit, lists the tree
// at that commit, checks every name (modelpack.CheckPaths) and the bounds,
// downloads and verifies every file into a fresh scratch directory, builds
// the ModelPack artifact with the source (hf://<org>/<name>) and the commit
// recorded on its manifest, and hands it to o.Push. Nothing is pushed unless
// every file verified.
func (c *Client) Import(ctx context.Context, ref Ref, o ImportOptions) (*Result, error) {
	commit, err := c.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	entries, err := c.Tree(ctx, ref.Repo, commit)
	if err != nil {
		return nil, err
	}
	files, total, err := planFiles(entries, o.SHA256)
	if err != nil {
		return nil, fmt.Errorf("import %s@%s: %w", Scheme+ref.Repo, commit, err)
	}

	dir, err := os.MkdirTemp(o.ScratchDir, "k3sm-hf-import-")
	if err != nil {
		return nil, fmt.Errorf("scratch directory: %w", err)
	}
	defer os.RemoveAll(dir)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("scratch directory: %w", err)
	}
	defer root.Close()
	if err := c.checkSpace(dir, total); err != nil {
		return nil, fmt.Errorf("import %s@%s: %w", Scheme+ref.Repo, commit, err)
	}
	for _, f := range files {
		if err := c.download(ctx, root, ref.Repo, commit, f); err != nil {
			return nil, fmt.Errorf("import %s@%s: %w", Scheme+ref.Repo, commit, err)
		}
		if o.Fetched != nil {
			o.Fetched(f.Path, f.Size)
		}
	}

	a, err := modelpack.Build(ctx, dir, modelpack.WithSource(Scheme+ref.Repo, commit))
	if err != nil {
		return nil, fmt.Errorf("import %s@%s: %w", Scheme+ref.Repo, commit, err)
	}
	if err := matchLayers(a, files); err != nil {
		return nil, fmt.Errorf("import %s@%s: %w", Scheme+ref.Repo, commit, err)
	}
	if o.Push != nil {
		if err := o.Push(ctx, a); err != nil {
			return nil, err
		}
	}
	return &Result{Commit: commit, Artifact: a, Bytes: total}, nil
}

// checkSpace refuses a download of total bytes into dir unless the file
// system has room for it plus the margin. It runs before the first byte is
// fetched, so a model that cannot fit costs no transfer.
func (c *Client) checkSpace(dir string, total int64) error {
	free, err := c.freeSpace(dir)
	if err != nil {
		return fmt.Errorf("measure free space for the download: %w", err)
	}
	need := uint64(total) + max(uint64(total)/20, minFreeMarginBytes)
	if free < need {
		return fmt.Errorf("%s has %d bytes free; the files need %d bytes and %d are kept in reserve (choose another directory with --scratch-dir): %w", dir, free, total, need-uint64(total), ErrNoSpace)
	}
	return nil
}

// planFiles picks the files out of the listing, checks their names and
// bounds before any byte is fetched, attaches the caller's sha256s, and
// returns them sorted by path with their total size.
func planFiles(entries []Entry, sums map[string]string) ([]file, int64, error) {
	var files []file
	var paths []string
	var total int64
	for _, e := range entries {
		if e.Type != entryFile {
			continue
		}
		total += e.Size
		if total > MaxTotalBytes {
			return nil, 0, fmt.Errorf("more than %d bytes in all: %w", int64(MaxTotalBytes), ErrSizeMismatch)
		}
		files = append(files, file{Entry: e, sha256: sums[e.Path]})
		paths = append(paths, e.Path)
	}
	slices.Sort(paths)
	if _, err := modelpack.CheckPaths(paths); err != nil {
		return nil, 0, err
	}
	for p, s := range sums {
		if !isLowerHex(s, 64) {
			return nil, 0, fmt.Errorf("--sha256 for %s: %q is not 64 lowercase hex digits", p, s)
		}
		if _, ok := slices.BinarySearch(paths, p); !ok {
			return nil, 0, fmt.Errorf("%s: %w", p, ErrUnknownSHA256Path)
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, total, nil
}

// matchLayers checks the built artifact against the listing once more: the
// same files, the listed sizes, and for each LFS file the Hub's sha256 as
// the layer digest. It catches a scratch file changed after it verified.
func matchLayers(a *modelpack.Artifact, files []file) error {
	if len(a.Layers) != len(files) {
		return fmt.Errorf("built %d layers from %d files: %w", len(a.Layers), len(files), ErrSizeMismatch)
	}
	for i, l := range a.Layers {
		f := files[i]
		if l.Path != f.Path || l.Descriptor.Size != f.Size {
			return fmt.Errorf("%s: built as %s (%d bytes), listed %d bytes: %w", f.Path, l.Path, l.Descriptor.Size, f.Size, ErrSizeMismatch)
		}
		if f.LFS != nil && l.Descriptor.Digest != digest.NewDigestFromEncoded(digest.SHA256, f.LFS.OID) {
			return fmt.Errorf("%s: layer %s, the Hub names sha256:%s: %w", f.Path, l.Descriptor.Digest, f.LFS.OID, ErrHashMismatch)
		}
	}
	return nil
}
