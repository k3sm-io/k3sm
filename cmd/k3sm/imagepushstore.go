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
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// pushSourceIsStoreRef reports whether push's first argument names an image in
// THIS NODE's store rather than an OCI layout directory on disk.
//
// The discriminator is deliberately not "does it look like a reference": bare
// words parse as references (`layuot` is docker.io/library/layuot:latest), so a
// mistyped directory would silently become a store lookup. The rule is instead:
//
//   - anything spelled as a path — absolute, or ./ or ../ rooted — is ALWAYS a
//     layout directory, so a missing one still gets the layout error that names
//     the tar mistake;
//   - anything that EXISTS on disk is what it is, directory or not, for the same
//     reason;
//   - only a name that is neither, and that parses as a reference, is a store
//     ref.
//
// The layout-directory form stays primary in every sense: it is the documented
// spelling, it needs no daemon, and it is what an ambiguous argument resolves to.
func pushSourceIsStoreRef(source string) bool {
	if source == "" {
		return false
	}
	if filepath.IsAbs(source) || source == "." || source == ".." ||
		strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
		return false
	}
	if _, err := os.Stat(source); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	_, err := name.ParseReference(source)
	return err == nil
}

// stageStoreImage exports a store image into a temporary OCI layout directory so
// the ordinary layout-push path can upload it, and returns the directory plus
// the cleanup that removes it.
//
// It goes through SaveImage rather than reading the store, for the same reason
// every other verb here is an RPC client: the store is the daemon's, the CLI
// generally cannot read it, and a second reader of a live store races the writer
// it is trying to reason about. The export is verified against the daemon's own
// digest and byte count before a single blob is uploaded, so a truncated export
// can never be published under a reference someone will later pin.
func stageStoreImage(ctx context.Context, client runtimev1.ImagesClient, o imageOptions) (dir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "k3sm-push")
	if err != nil {
		return "", nil, fmt.Errorf("create a staging directory: %w", err)
	}
	// Held in a local rather than read back out of the named return: an error
	// path returns a nil cleanup, and a deferred call through the named result
	// would then panic on exactly the failure it exists to clean up after.
	remove := func() { _ = os.RemoveAll(tmp) }
	defer func() {
		if err != nil {
			remove()
		}
	}()

	reference, digest := imageTarget(o.layoutDir)
	archive := filepath.Join(tmp, "image.tar")
	if _, err = saveImageArchive(ctx, client, &runtimev1.SaveImageRequest{
		Reference: reference,
		Platform:  o.platform,
		Digest:    digest,
		Format:    runtimev1.LoadImageFormat_LOAD_IMAGE_FORMAT_OCI_LAYOUT,
	}, archive, o.socket); err != nil {
		return "", nil, fmt.Errorf("%s is no directory on disk, and exporting it from this node's store failed: %w", o.layoutDir, err)
	}
	layoutDir := filepath.Join(tmp, "layout")
	if err = extractOCILayout(archive, layoutDir); err != nil {
		return "", nil, err
	}
	// The tar is not needed once it is unpacked, and a large image would
	// otherwise sit on disk twice for the length of the upload.
	if rmErr := os.Remove(archive); rmErr != nil {
		return "", nil, fmt.Errorf("remove the staged archive: %w", rmErr)
	}
	return layoutDir, remove, nil
}

// extractOCILayout unpacks a tarred OCI image layout into dest.
//
// It accepts regular files and directories and REFUSES everything else. That is
// not a portability compromise: an OCI layout is an index, a marker and a tree of
// content-addressed blobs, so a symlink, a hardlink or a device node in one is
// either a bug or an attempt at something, and refusing is the only reading of
// both that cannot go wrong. With no link types accepted, symlink escape and
// hardlink aliasing stop being defenses this function has to get right — the one
// remaining traversal vector, a `..` or absolute entry name, is REFUSED rather
// than rewritten, and the joined path is re-checked on top of that.
func extractOCILayout(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("open the exported archive: %w", err)
	}
	defer f.Close()
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return fmt.Errorf("create the layout directory: %w", err)
	}
	root := dest + string(os.PathSeparator)

	tr := tar.NewReader(f)
	for {
		hdr, rerr := tr.Next()
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("read the exported archive: %w", rerr)
		}
		// REFUSED, not sanitized. Rooting a traversing name would silently
		// rewrite it, and an entry whose name does not mean what it says is a
		// broken archive whichever way it is read. The joined path is re-checked
		// afterwards anyway, for a name this side has not thought of.
		clean := path.Clean(hdr.Name)
		if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("the exported archive names an entry outside the layout: %q", hdr.Name)
		}
		rel := strings.TrimPrefix(clean, "./")
		if rel == "" || rel == "." {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if !strings.HasPrefix(target, root) {
			return fmt.Errorf("the exported archive names an entry outside the layout: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return fmt.Errorf("create %s: %w", rel, err)
			}
		case tar.TypeReg:
			if err := writeLayoutFile(target, tr); err != nil {
				return fmt.Errorf("write %s: %w", rel, err)
			}
		default:
			return fmt.Errorf("the exported archive holds %q, which is not a regular file or a directory; an OCI layout is neither", hdr.Name)
		}
	}
	return nil
}

// writeLayoutFile writes one extracted entry, creating its parent directories.
// The mode is the staging directory's own — this tree exists for the length of
// one upload and is read by this process alone, so the archive's modes are not
// reproduced.
func writeLayoutFile(target string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, r); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
