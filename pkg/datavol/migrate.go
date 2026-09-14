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

package datavol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// PreVolumeSuffix names the copy of the old data root Migrate leaves behind
// after a successful move: /var/lib/k3sm.pre-volume. It is the operator's
// rollback, and `k3sm status` warns while it exists.
const PreVolumeSuffix = ".pre-volume"

// stateDBPath is the kine datastore inside the data root, relative to it. It
// is the one file Migrate hashes end to end: everything else is content the
// cluster can rebuild, and this is not.
const stateDBPath = "server/db/state.db"

// MigrateSystem is the privileged-filesystem seam Migrate needs, defined here
// at the consumer. pkg/install implements it with ditto(1) and os; tests
// implement it with real copies into temp dirs.
type MigrateSystem interface {
	// CopyTree copies the whole tree at src into dst, preserving ownership,
	// modes, extended attributes and ACLs. APFS cloning cannot cross volume
	// boundaries, so this is always a full byte copy.
	CopyTree(src, dst string) error
	// Rename moves old to new on the same filesystem.
	Rename(old, new string) error
	// RemoveAll deletes path and everything under it.
	RemoveAll(path string) error
}

// MigrateOptions govern what happens to the old data root after the copy.
type MigrateOptions struct {
	// RemoveOld deletes the .pre-volume copy once the migration has been
	// verified. It is required for an encrypted volume and optional
	// otherwise.
	RemoveOld bool
}

// Stats are what the migration cost, so the operator can judge the downtime of
// the next one.
type Stats struct {
	// Files is the number of regular files copied.
	Files int
	// Bytes is their total size.
	Bytes uint64
	// CopyDuration is how long the copy took.
	CopyDuration time.Duration
	// VerifyDuration is how long verification took.
	VerifyDuration time.Duration
}

var (
	// ErrPreVolumeExists is returned when a previous migration's copy is
	// still beside the data root. Overwriting it would destroy the only
	// rollback the operator has.
	ErrPreVolumeExists = errors.New("a previous copy of the data root is still in place")
	// ErrEncryptedNeedsRemoveOld is returned when an encrypted volume would
	// be left beside a plaintext copy of the same data. An encrypted volume
	// next to an unencrypted duplicate is not encryption.
	ErrEncryptedNeedsRemoveOld = errors.New("migrating onto an encrypted data volume requires removing the old data root")
	// ErrCopyMismatch is returned when the copy does not match the original.
	// The new volume is destroyed and the data root is left untouched.
	ErrCopyMismatch = errors.New("the copy of the data root does not match the original")
)

// Migrate moves an existing plain data root onto the volume rec describes.
//
// It is fail-safe by construction: everything happens on a staging mount
// first, the copy is verified against the original before anything is moved,
// and the original is only ever RENAMED aside, never deleted in place. Any
// failure before the rename leaves the data root exactly as it was and takes
// the half-filled volume with it.
//
// The caller has already stopped the daemons; Migrate does not, because
// stopping and restarting launchd jobs is pkg/install's business.
func Migrate(ctx context.Context, deps Deps, fsys dataroot.FS, sys MigrateSystem, rec dataroot.Record, dataRoot, staging string, o MigrateOptions) (Stats, error) {
	if err := deps.validate(); err != nil {
		return Stats{}, err
	}
	if sys == nil {
		return Stats{}, fmt.Errorf("%w: no MigrateSystem", errMissingSeam)
	}
	if rec.Encrypted && !o.RemoveOld {
		return Stats{}, fmt.Errorf("data volume %s is encrypted: %w", rec.Name, ErrEncryptedNeedsRemoveOld)
	}

	preVolume := dataRoot + PreVolumeSuffix
	if _, err := fsys.Stat(preVolume); err == nil {
		return Stats{}, fmt.Errorf("%s: %w", preVolume, ErrPreVolumeExists)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return Stats{}, fmt.Errorf("look for %s: %w", preVolume, err)
	}

	if err := deps.Volumes.Mount(ctx, rec.UUID, staging); err != nil {
		return Stats{}, fmt.Errorf("mount the data volume %s at %s: %w", rec.UUID, staging, err)
	}

	// Exclude the staging mount BEFORE anything is written to it, so neither
	// Spotlight nor Time Machine ever sees the datastore go by.
	logger := slog.Default()
	if err := deps.Indexing.SpotlightOff(ctx, staging); err != nil {
		logger.Warn("could not disable Spotlight on the staging mount", "mountpoint", staging, "err", err)
	}
	if err := deps.Indexing.TimeMachineExclude(ctx, staging); err != nil {
		logger.Warn("could not exclude the staging mount from Time Machine", "mountpoint", staging, "err", err)
	}

	started := time.Now()
	if err := sys.CopyTree(dataRoot, staging); err != nil {
		return Stats{}, discard(ctx, deps, rec.UUID, staging, fmt.Errorf("copy %s to %s: %w", dataRoot, staging, err))
	}
	stats := Stats{CopyDuration: time.Since(started)}

	started = time.Now()
	src, err := walkTree(dataRoot)
	if err != nil {
		return Stats{}, discard(ctx, deps, rec.UUID, staging, err)
	}
	dst, err := walkTree(staging)
	if err != nil {
		return Stats{}, discard(ctx, deps, rec.UUID, staging, err)
	}
	if err := compareTrees(src, dst); err != nil {
		return Stats{}, discard(ctx, deps, rec.UUID, staging, fmt.Errorf("%w: %v", ErrCopyMismatch, err))
	}
	if err := compareStateDB(dataRoot, staging); err != nil {
		return Stats{}, discard(ctx, deps, rec.UUID, staging, fmt.Errorf("%w: %v", ErrCopyMismatch, err))
	}
	stats.VerifyDuration = time.Since(started)
	stats.Files = src.files
	stats.Bytes = src.bytes

	if err := deps.Volumes.Unmount(ctx, staging); err != nil {
		return Stats{}, fmt.Errorf("unmount the staging mount %s: %w", staging, err)
	}
	if err := sys.Rename(dataRoot, preVolume); err != nil {
		return Stats{}, fmt.Errorf("move %s aside to %s: %w", dataRoot, preVolume, err)
	}
	if o.RemoveOld {
		if err := sys.RemoveAll(preVolume); err != nil {
			return Stats{}, fmt.Errorf("remove the old data root %s: %w", preVolume, err)
		}
	}
	return stats, nil
}

// discard unwinds a failed migration: the staging mount goes away and the
// volume with it, so nothing changed and a re-run starts clean. The data root
// itself has not been touched at this point, which is what the returned error
// tells the operator.
func discard(ctx context.Context, deps Deps, uuid, staging string, cause error) error {
	if err := deps.Volumes.Unmount(ctx, staging); err != nil {
		return fmt.Errorf("%w (and the staging mount %s could not be unmounted: %v)", cause, staging, err)
	}
	if err := deps.Volumes.DeleteVolume(ctx, uuid); err != nil {
		return fmt.Errorf("%w (and the new volume %s could not be removed: %v)", cause, uuid, err)
	}
	return cause
}

// treeSummary is what verification compares: how much is there, and the
// metadata of every regular file, keyed by its path relative to the tree root.
type treeSummary struct {
	files int
	bytes uint64
	meta  map[string]fileMeta
}

// fileMeta is the per-file metadata ditto(1) is expected to preserve.
type fileMeta struct {
	size int64
	mode fs.FileMode
	uid  uint32
	gid  uint32
}

// walkTree summarises the tree at root. It reads the real filesystem rather
// than the FS seam: verification is about what is actually on the two volumes,
// and a seam that could lie about it would make the check worthless.
func walkTree(root string) (treeSummary, error) {
	out := treeSummary{meta: map[string]fileMeta{}}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == MarkerName {
			// The marker is written by k3sm on the destination, never
			// present on the source; it is not part of the copy.
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		m := fileMeta{size: fi.Size(), mode: fi.Mode().Perm()}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st != nil {
			m.uid, m.gid = st.Uid, st.Gid
		}
		out.meta[rel] = m
		out.files++
		out.bytes += uint64(fi.Size())
		return nil
	})
	if err != nil {
		return treeSummary{}, fmt.Errorf("walk %s: %w", root, err)
	}
	return out, nil
}

// compareTrees reports the first difference between the two summaries.
func compareTrees(src, dst treeSummary) error {
	if src.files != dst.files {
		return fmt.Errorf("%d files at the source, %d at the destination", src.files, dst.files)
	}
	if src.bytes != dst.bytes {
		return fmt.Errorf("%d bytes at the source, %d at the destination", src.bytes, dst.bytes)
	}
	for rel, want := range src.meta {
		got, ok := dst.meta[rel]
		if !ok {
			return fmt.Errorf("%s is missing from the destination", rel)
		}
		switch {
		case got.size != want.size:
			return fmt.Errorf("%s is %d bytes at the source, %d at the destination", rel, want.size, got.size)
		case got.mode != want.mode:
			return fmt.Errorf("%s is mode %v at the source, %v at the destination", rel, want.mode, got.mode)
		case got.uid != want.uid || got.gid != want.gid:
			return fmt.Errorf("%s is owned by %d:%d at the source, %d:%d at the destination", rel, want.uid, want.gid, got.uid, got.gid)
		}
	}
	return nil
}

// compareStateDB hashes the kine datastore on both sides when the source has
// one. Counts and sizes prove the shape of the copy; only a hash proves the
// bytes, and this is the one file whose bytes cannot be rebuilt.
func compareStateDB(src, dst string) error {
	srcPath := filepath.Join(src, stateDBPath)
	if _, err := os.Stat(srcPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", srcPath, err)
	}
	dstPath := filepath.Join(dst, stateDBPath)
	want, err := hashFile(srcPath)
	if err != nil {
		return err
	}
	got, err := hashFile(dstPath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s hashes %s at the source and %s at the destination", stateDBPath, want, got)
	}
	return nil
}

// hashFile returns the hex sha256 of the file at path.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
