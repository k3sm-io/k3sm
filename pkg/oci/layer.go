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

package oci

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// ErrBadEntryName reports an in-image path that no unpacker should ever be asked
// to create.
var ErrBadEntryName = errors.New("oci: invalid entry name")

// The normalization contract. These constants are the whole reason a layer
// digest is a function of the CONTENT rather than of the machine that built it —
// tar.FileInfoHeader would otherwise copy the host's mtime, uid, gid, uname and
// gname straight into the header, and thence into the digest.
//
// Changing any of them re-digests every image k3sm has ever built, so they are
// stated here once and asserted by the acceptance gate.
const (
	// entryUID/entryGID own every entry. A published image must not carry the
	// builder's account identity.
	entryUID = 0
	entryGID = 0

	// modeFile / modeExec / modeDir are the only three modes emitted. The
	// executable bit is the single source-derived bit that survives, because it
	// is semantically load-bearing for a native payload.
	modeFile = 0o644
	modeExec = 0o755
	modeDir  = 0o755
	modeLink = 0o777
)

// epoch is the fixed timestamp written to every tar header and to the image
// config. A wall-clock stamp would make the image digest differ on every build
// while the layer digest stayed stable — satisfying the letter of a
// "deterministic layers" criterion while producing an artifact that is not
// reproducible at all.
var epoch = time.Unix(0, 0).UTC()

// BuildLayer writes the selected entries as a normalized tar and returns it as a
// layer. It is the single home of the normalization contract above.
//
// The tar is materialized once into tmpDir and the returned layer re-reads that
// file. This is load-bearing, not an optimization: go-containerregistry calls a
// layer's opener once to compute the digest and again to write the bytes out, so
// an opener that re-walked the build context would hash one filesystem snapshot
// and ship another — a digest that does not describe the shipped bytes voids the
// property the whole content-addressed store is built on.
func BuildLayer(entries []entry, tmpDir string) (ggcrv1.Layer, error) {
	f, err := os.CreateTemp(tmpDir, "layer-*.tar")
	if err != nil {
		return nil, fmt.Errorf("stage layer: %w", err)
	}
	path := f.Name()
	defer f.Close()

	if err := writeTar(f, entries); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync layer: %w", err)
	}

	// Uncompressed: the digest then depends only on this package's tar output,
	// never on compress/flate's byte-level behavior, which carries no
	// cross-version compatibility promise.
	return tarball.LayerFromFile(path, tarball.WithMediaType(types.OCIUncompressedLayer))
}

// writeTar emits the normalized archive. Entries arrive pre-sorted by in-image
// name (see selectEntries), so ordering is content-determined.
func writeTar(w io.Writer, entries []entry) error {
	tw := tar.NewWriter(w)
	seen := make(map[string]bool, len(entries)*2)

	for _, e := range entries {
		if err := checkEntryName(e.name); err != nil {
			return err
		}
		if err := writeParents(tw, e.name, seen); err != nil {
			return err
		}
		if seen[e.name] {
			continue
		}
		seen[e.name] = true

		hdr := &tar.Header{
			Name:       e.name,
			Uid:        entryUID,
			Gid:        entryGID,
			Uname:      "",
			Gname:      "",
			ModTime:    epoch,
			Format:     tar.FormatPAX,
			PAXRecords: nil,
			Xattrs:     nil, //nolint:staticcheck // pinned nil: Darwin xattrs (com.apple.quarantine, resource forks) are host state, never image content
		}
		switch {
		case e.dir:
			hdr.Typeflag, hdr.Name, hdr.Mode = tar.TypeDir, e.name+"/", modeDir
		case e.link != "":
			hdr.Typeflag, hdr.Linkname, hdr.Mode = tar.TypeSymlink, e.link, modeLink
		default:
			hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeReg, e.size, modeFile
			if e.mode&0o111 != 0 {
				hdr.Mode = modeExec
			}
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("write header %s: %w", e.name, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if err := copyBody(tw, e); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close layer tar: %w", err)
	}
	return nil
}

// copyBody streams one regular file into the archive, refusing a file that grew
// or shrank since it was selected. A short or over-long body would otherwise be
// silently absorbed into a valid-looking archive.
func copyBody(tw *tar.Writer, e entry) error {
	f, size, err := openRegular(e.host)
	if err != nil {
		return err
	}
	defer f.Close()
	if size != e.size {
		return fmt.Errorf("%s changed size during the build (%d → %d)", e.name, e.size, size)
	}
	n, err := io.Copy(tw, io.LimitReader(f, e.size))
	if err != nil {
		return fmt.Errorf("write %s: %w", e.name, err)
	}
	if n != e.size {
		return fmt.Errorf("%s: short read (%d of %d bytes)", e.name, n, e.size)
	}
	return nil
}

// writeParents emits an explicit directory entry for every ancestor of name, so
// an unpacker never has to infer one (and never has to choose a mode for it).
func writeParents(tw *tar.Writer, name string, seen map[string]bool) error {
	parts := strings.Split(name, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		if err := tw.WriteHeader(&tar.Header{
			Name:     dir + "/",
			Typeflag: tar.TypeDir,
			Mode:     modeDir,
			Uid:      entryUID,
			Gid:      entryGID,
			ModTime:  epoch,
			Format:   tar.FormatPAX,
		}); err != nil {
			return fmt.Errorf("write parent dir %s: %w", dir, err)
		}
	}
	return nil
}

// checkEntryName refuses names that make an emitted image hostile to whoever
// unpacks it. k3sm's own read path is hardened, but a pushed image is somebody
// else's untrusted input — a builder that can be made to emit a traversing entry
// or a whiteout is a tar-bomb factory.
func checkEntryName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("empty: %w", ErrBadEntryName)
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("%q is absolute: %w", name, ErrBadEntryName)
	case strings.Contains(name, `\`):
		return fmt.Errorf("%q contains a backslash: %w", name, ErrBadEntryName)
	case strings.ContainsRune(name, 0):
		return fmt.Errorf("%q contains NUL: %w", name, ErrBadEntryName)
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return fmt.Errorf("%q traverses upward: %w", name, ErrBadEntryName)
		}
		// An OCI whiteout marker is honored as a DELETION by any unpacker,
		// including the vm-path unpacker. A build must not be able to emit one.
		if strings.HasPrefix(part, ".wh.") {
			return fmt.Errorf("%q is an OCI whiteout marker: %w", name, ErrBadEntryName)
		}
	}
	return nil
}
