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

package executor

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Compressed snapshots, the analog of k3s's --etcd-snapshot-compress: a snapshot is
// written as a zip archive holding exactly one member, the plain snapshot, deflated.
// k3s uses the same container, so a compressed snapshot is recognizable by the same
// tools.
//
// Compression is a property of the FILE ON DISK and of nothing else. The bytes a
// restore installs (the kine state.db, or the snapshot handed to etcdutl) are the
// decompressed member, byte for byte what a plain snapshot of the same instant holds,
// so the running control plane never reads a compressed byte and the datastore's
// encoding does not change.
//
// A restore decides the format by content, never by name: a file that opens with the
// zip local-header magic is decompressed, anything else is the plain format it always
// was. The member is inflated into a temporary file through a reader capped at
// maxDecompressedSnapshotBytes, so a hostile or corrupt archive cannot fill the disk,
// and the existing verification then runs on the decompressed bytes before anything
// is replaced. A truncated archive has no central directory and is refused by the zip
// reader; a corrupt member fails the CRC-32 check at its end. Either way the datastore
// is untouched.

// zipLocalHeaderMagic opens every zip archive that has at least one member
// (PK\x03\x04, the local file header signature).
var zipLocalHeaderMagic = []byte("PK\x03\x04")

// compressedSnapshotExt is the suffix a generated compressed snapshot name carries.
// It is a naming convention for the operator and for retention, never what a restore
// trusts.
const compressedSnapshotExt = ".zip"

// maxDecompressedSnapshotBytes caps how many bytes a restore inflates out of a
// compressed snapshot. 8 GiB is etcd's documented upper bound for a backend quota
// (--quota-backend-bytes); k3sm runs its members at etcd's 2 GiB default, so no
// snapshot a k3sm etcd member produced can come near it, and a single-server kine
// SQLite datastore that size is far past anything one Mac's control plane holds. It is
// the bound on the disk a deflate bomb can claim, not a size the datastore is expected
// to reach. A variable only so a test can trip it without writing gigabytes.
var maxDecompressedSnapshotBytes int64 = 8 << 30

// Compressed snapshot failures.
var (
	// ErrSnapshotArchive reports a compressed snapshot that cannot be read: truncated,
	// corrupt (a CRC mismatch), or not holding exactly one regular member. Nothing was
	// changed.
	ErrSnapshotArchive = errors.New("executor: the compressed snapshot is not a readable single-member zip archive")
	// ErrSnapshotTooLarge reports a compressed snapshot whose member inflates past
	// maxDecompressedSnapshotBytes. Nothing was changed.
	ErrSnapshotTooLarge = errors.New("executor: the compressed snapshot inflates past the size limit")
)

// isCompressedSnapshot reports whether path starts with the zip local-header magic.
// It reads at most four bytes.
func isCompressedSnapshot(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, len(zipLocalHeaderMagic))
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	return bytes.Equal(head[:n], zipLocalHeaderMagic), nil
}

// compressedSnapshotName is the generated name of a compressed snapshot whose plain
// name is plain: a trailing .db is replaced, anything else gets the suffix appended.
func compressedSnapshotName(plain string) string {
	return strings.TrimSuffix(plain, ".db") + compressedSnapshotExt
}

// plainStagingPath is where a compressed save builds and verifies the plain snapshot
// before compressing it into dst. It never collides with dst's own dst+".tmp", and for
// a scheduled name (<name>.zip) it is <name>.tmp, which the schedule's start-up sweep
// of its own partial files recognizes.
func plainStagingPath(dst string) string {
	if base, ok := strings.CutSuffix(dst, compressedSnapshotExt); ok {
		return base + ".tmp"
	}
	return dst + ".plain.tmp"
}

// compressSnapshotFile writes plain into dst as a one-member zip archive, through
// dst+".tmp" (0600, O_EXCL), and re-reads the archive (the member's CRC-32 and size)
// before it takes dst's name. plain is left for the caller to remove.
func compressSnapshotFile(plain, dst string) error {
	in, err := os.Open(plain)
	if err != nil {
		return fmt.Errorf("open %s: %w", plain, err)
	}
	defer func() { _ = in.Close() }()
	fi, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", plain, err)
	}
	tmp := dst + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear stale partial snapshot %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	werr := writeSnapshotZip(f, in, memberName(dst), fi.ModTime())
	if werr == nil {
		werr = f.Sync()
	}
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("compress the snapshot into %s: %w", tmp, werr)
	}
	n, err := inflateSnapshot(tmp, io.Discard, fi.Size())
	if err == nil && n != fi.Size() {
		err = fmt.Errorf("%w: the archive holds %d bytes, the snapshot %d", ErrSnapshotArchive, n, fi.Size())
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("the compressed snapshot just written did not read back: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install snapshot %s: %w", dst, err)
	}
	return nil
}

// memberName is the archive member's name: the plain snapshot's basename.
func memberName(dst string) string {
	base := filepath.Base(dst)
	if b, ok := strings.CutSuffix(base, compressedSnapshotExt); ok && b != "" {
		return b
	}
	return base
}

// writeSnapshotZip writes r into w as the archive's single deflated member.
func writeSnapshotZip(w io.Writer, r io.Reader, name string, mod time.Time) error {
	zw := zip.NewWriter(w)
	mw, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: mod.UTC()})
	if err != nil {
		return err
	}
	if _, err := io.Copy(mw, r); err != nil {
		return err
	}
	return zw.Close()
}

// inflateSnapshot copies the single member of the archive at path into w, reading at
// most limit bytes of it, and returns how many bytes it wrote. It refuses an archive
// that does not hold exactly one regular member, a member that declares or inflates to
// more than limit, and a member whose CRC-32 does not match (which archive/zip reports
// at the member's end, so the whole member is always read).
func inflateSnapshot(path string, w io.Writer, limit int64) (int64, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrSnapshotArchive, path, err)
	}
	defer func() { _ = zr.Close() }()
	if len(zr.File) != 1 {
		return 0, fmt.Errorf("%w: %s holds %d members, want exactly one", ErrSnapshotArchive, path, len(zr.File))
	}
	m := zr.File[0]
	if !m.Mode().IsRegular() {
		return 0, fmt.Errorf("%w: %s: member %q is not a regular file", ErrSnapshotArchive, path, m.Name)
	}
	if m.UncompressedSize64 > uint64(limit) {
		return 0, fmt.Errorf("%w: %s declares %d bytes, the limit is %d", ErrSnapshotTooLarge, path, m.UncompressedSize64, limit)
	}
	rc, err := m.Open()
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrSnapshotArchive, path, err)
	}
	defer func() { _ = rc.Close() }()
	// One byte past the limit is read so an over-long member is told apart from one
	// that ends exactly at it; the header is not trusted for this.
	n, err := io.Copy(w, io.LimitReader(rc, limit+1))
	if err != nil {
		return n, fmt.Errorf("%w: %s: %w", ErrSnapshotArchive, path, err)
	}
	if n > limit {
		return n, fmt.Errorf("%w: %s inflates past %d bytes", ErrSnapshotTooLarge, path, limit)
	}
	return n, nil
}

// decompressedSnapshot is a restore's view of its input: the plain snapshot it
// verifies and installs, and the cleanup of any temporary copy made to get it.
type decompressedSnapshot struct {
	// path is the plain snapshot: the input itself, or the inflated temporary copy.
	path string
	// compressed reports whether the input was an archive.
	compressed bool
	cleanup    func()
}

// openSnapshotInput resolves a restore input to a plain snapshot. A plain input is
// returned as is. A compressed one is inflated into a 0600 temporary file in dir (the
// volume the restore writes to anyway), after a free-space check against the size the
// archive declares; the caller verifies that file and must call cleanup.
func openSnapshotInput(path, dir string) (*decompressedSnapshot, error) {
	nothing := func() {}
	zipped, err := isCompressedSnapshot(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSnapshotNotFound, path, err)
	}
	if !zipped {
		return &decompressedSnapshot{path: path, cleanup: nothing}, nil
	}
	declared, err := declaredSnapshotSize(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	if err := requireSnapshotSpace(dir, declared); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".k3sm-snapshot-inflate-*.tmp")
	if err != nil {
		return nil, fmt.Errorf("create a temporary file for the decompressed snapshot: %w", err)
	}
	tmp := f.Name()
	cleanup := func() { _ = os.Remove(tmp) }
	_, ierr := inflateSnapshot(path, f, maxDecompressedSnapshotBytes)
	if ierr == nil {
		ierr = f.Sync()
	}
	if err := f.Close(); ierr == nil {
		ierr = err
	}
	if ierr != nil {
		cleanup()
		return nil, fmt.Errorf("%w — nothing was changed", ierr)
	}
	return &decompressedSnapshot{path: tmp, compressed: true, cleanup: cleanup}, nil
}

// declaredSnapshotSize is the uncompressed size the archive's single member declares,
// refused past maxDecompressedSnapshotBytes before a byte is inflated. The inflation
// itself is capped regardless; this only lets the free-space check and the refusal of
// an honest oversized archive happen first.
func declaredSnapshotSize(path string) (uint64, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w — nothing was changed", ErrSnapshotArchive, path, err)
	}
	defer func() { _ = zr.Close() }()
	if len(zr.File) != 1 {
		return 0, fmt.Errorf("%w: %s holds %d members, want exactly one — nothing was changed", ErrSnapshotArchive, path, len(zr.File))
	}
	n := zr.File[0].UncompressedSize64
	if n > uint64(maxDecompressedSnapshotBytes) {
		return 0, fmt.Errorf("%w: %s declares %d bytes, the limit is %d — nothing was changed", ErrSnapshotTooLarge, path, n, maxDecompressedSnapshotBytes)
	}
	return n, nil
}
