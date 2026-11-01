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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// Layout names inside a repository directory, and the state directory's lock
// subdirectory.
const (
	layoutFile  = "oci-layout"
	indexFile   = "index.json"
	blobsDir    = "blobs"
	uploadsDir  = ".uploads"
	locksDir    = "locks"
	fileMode    = 0o600
	dirMode     = 0o700
	maxIndexLen = 64 << 20
	// MaxManifestSize is the largest manifest body the store reads: the
	// registry's 4 MiB manifest cap.
	MaxManifestSize = 4 << 20
)

// layoutBody is oci-layout's content, as zot writes it.
var layoutBody = []byte(`{"imageLayoutVersion":"1.0.0"}`)

// Sentinel errors.
var (
	// ErrRepositoryUnknown is a repository with no layout in the store.
	ErrRepositoryUnknown = errors.New("repository unknown")
	// ErrManifestUnknown is a tag or digest no index.json row names.
	ErrManifestUnknown = errors.New("manifest unknown")
	// ErrBlobUnknown is a blob the repository does not hold.
	ErrBlobUnknown = errors.New("blob unknown")
	// ErrUploadUnknown is an upload session that does not exist.
	ErrUploadUnknown = errors.New("upload unknown")
	// ErrDigestMismatch is content whose digest is not the one claimed.
	ErrDigestMismatch = errors.New("digest mismatch")
	// ErrOffsetMismatch is a chunk that does not start at the session's length.
	ErrOffsetMismatch = errors.New("upload offset mismatch")
	// ErrUploadTooLarge is a chunk that would take a session past its size
	// limit.
	ErrUploadTooLarge = errors.New("upload too large")
	// ErrMountUnavailable is a mount that cannot be a link: the source does not
	// hold the blob, or it is on another volume. The caller falls back to an
	// upload session.
	ErrMountUnavailable = errors.New("mount unavailable")
	// ErrNotRegular is a store entry that should be a regular file or a
	// directory and is not.
	ErrNotRegular = errors.New("unexpected file type in the store")
)

// Store is the on-disk registry store. Its methods are safe for concurrent use
// by goroutines and by processes: index.json changes are serialised by a flock
// per repository, upload sessions by a flock on the session file.
type Store struct {
	root  string
	state string
	// now is the clock blob mtimes are touched with (a seam for tests).
	now func() time.Time
	// uploadOpened, when set, runs between an upload session's open and its
	// flock (a seam for tests that interleave two session operations).
	uploadOpened func(id string)
	// indexRemoved, when set, runs in RemoveLayout right after index.json is
	// removed; an error stops the removal there (a seam for crash tests).
	indexRemoved func() error
}

// Open opens the store rooted at root, with server state under state. It
// creates both directories (0700) when they are missing and creates nothing
// else in root (the store id, IDFile, is written later, by EnsureID). state
// must not be inside root, and root must not be a symlink.
func Open(root, state string) (*Store, error) {
	root, state = filepath.Clean(root), filepath.Clean(state)
	if !filepath.IsAbs(root) || !filepath.IsAbs(state) {
		return nil, fmt.Errorf("open store: root %q and state %q must be absolute", root, state)
	}
	if rel, err := filepath.Rel(root, state); err == nil && !strings.HasPrefix(rel, "..") {
		return nil, fmt.Errorf("open store: state dir %s is inside the store root %s", state, root)
	}
	for _, d := range []string{root, filepath.Join(state, locksDir)} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, fmt.Errorf("open store: %w", err)
		}
	}
	if err := ref.NoSymlinks(root, root); err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return &Store{root: root, state: state, now: time.Now}, nil
}

// OpenWorkDir opens the store of a k3sm work dir: <workDir>/registry, with
// state in <workDir>/registry-state.
func OpenWorkDir(workDir string) (*Store, error) {
	return Open(filepath.Join(workDir, "registry"), filepath.Join(workDir, "registry-state"))
}

// Root returns the store root.
func (s *Store) Root() string { return s.root }

// repoDir resolves n's directory, refusing a symlink on the way.
func (s *Store) repoDir(n ref.Name) (string, error) {
	return n.ResolveDir(s.root)
}

// path resolves a path inside n's directory, refusing a symlink anywhere from
// the root to the final element.
func (s *Store) path(n ref.Name, elems ...string) (string, error) {
	dir, err := s.repoDir(n)
	if err != nil {
		return "", err
	}
	p := filepath.Join(append([]string{dir}, elems...)...)
	if err := ref.NoSymlinks(s.root, p); err != nil {
		return "", err
	}
	return p, nil
}

// exists reports whether n is a repository: its directory holds oci-layout,
// index.json and a blobs directory (zot's own test).
func (s *Store) exists(n ref.Name) (string, bool, error) {
	dir, err := s.repoDir(n)
	if err != nil {
		return "", false, err
	}
	return dir, isRepoDir(dir), nil
}

func isRepoDir(dir string) bool {
	for name, wantDir := range map[string]bool{layoutFile: false, indexFile: false, blobsDir: true} {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || fi.IsDir() != wantDir || (!wantDir && !fi.Mode().IsRegular()) {
			return false
		}
	}
	return true
}

// Repositories lists every repository in the store, sorted. It descends into
// directories that are not repositories (a nested name's parents) and skips
// layout directories, dot and underscore entries (zot's _sessions), symlinks
// and any directory whose path is not a valid name.
func (s *Store) Repositories() ([]ref.Name, error) {
	var out []ref.Name
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == s.root {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		if base == blobsDir || strings.HasPrefix(base, ".") || strings.HasPrefix(base, "_") {
			return fs.SkipDir
		}
		n, err := ref.NameFromDir(s.root, p)
		if err != nil {
			return fs.SkipDir
		}
		if isRepoDir(p) {
			out = append(out, n)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}
	slices.SortFunc(out, func(a, b ref.Name) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// Index returns n's index.json.
func (s *Store) Index(n ref.Name) (ispec.Index, error) {
	dir, ok, err := s.exists(n)
	if err != nil {
		return ispec.Index{}, err
	}
	if !ok {
		return ispec.Index{}, fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	return readIndex(dir)
}

func readIndex(dir string) (ispec.Index, error) {
	b, err := readRegular(filepath.Join(dir, indexFile), maxIndexLen)
	if err != nil {
		return ispec.Index{}, fmt.Errorf("read index: %w", err)
	}
	var idx ispec.Index
	if err := json.Unmarshal(b, &idx); err != nil {
		return ispec.Index{}, fmt.Errorf("parse %s: %w", filepath.Join(dir, indexFile), err)
	}
	return idx, nil
}

// readRegular reads a regular file of at most limit bytes without following a
// final symlink.
func readRegular(p string, limit int64) ([]byte, error) {
	f, err := openRegular(p, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("read %s: larger than %d bytes", p, limit)
	}
	return b, nil
}

// openRegular opens p with O_NOFOLLOW and refuses anything but a regular file.
func openRegular(p string, flag int) (*os.File, error) {
	f, err := os.OpenFile(p, flag|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s", ref.ErrSymlink, p)
		}
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%w: %s", ErrNotRegular, p)
	}
	return f, nil
}

// Tags returns n's tags, sorted lexically and unique.
func (s *Store) Tags(n ref.Name) ([]string, error) {
	idx, err := s.Index(n)
	if err != nil {
		return nil, err
	}
	var tags []string
	for _, d := range idx.Manifests {
		if t, ok := d.Annotations[ispec.AnnotationRefName]; ok {
			tags = append(tags, t)
		}
	}
	slices.Sort(tags)
	return slices.Compact(tags), nil
}

// Resolve returns the index.json row a reference names: the row carrying the
// tag, or the first row with the digest.
func (s *Store) Resolve(n ref.Name, r ref.Reference) (ispec.Descriptor, error) {
	idx, err := s.Index(n)
	if err != nil {
		return ispec.Descriptor{}, err
	}
	for _, d := range idx.Manifests {
		if r.Digest != "" && d.Digest == r.Digest {
			return d, nil
		}
		if r.Tag != "" && d.Annotations[ispec.AnnotationRefName] == r.Tag {
			return d, nil
		}
	}
	return ispec.Descriptor{}, fmt.Errorf("%w: %s in %s", ErrManifestUnknown, r, n)
}

// Manifest returns the descriptor and body of the manifest r names. The body
// is checked against the descriptor's digest and size.
func (s *Store) Manifest(n ref.Name, r ref.Reference) (ispec.Descriptor, []byte, error) {
	d, err := s.Resolve(n, r)
	if err != nil {
		return ispec.Descriptor{}, nil, err
	}
	if d.Size < 0 || d.Size > MaxManifestSize {
		return ispec.Descriptor{}, nil, fmt.Errorf("manifest %s in %s: size %d is outside 0..%d", d.Digest, n, d.Size, MaxManifestSize)
	}
	p, err := s.blobPath(n, d.Digest)
	if err != nil {
		return ispec.Descriptor{}, nil, err
	}
	b, err := readRegular(p, d.Size)
	if errors.Is(err, os.ErrNotExist) {
		return ispec.Descriptor{}, nil, fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d.Digest, n)
	}
	if err != nil {
		return ispec.Descriptor{}, nil, err
	}
	if int64(len(b)) != d.Size || d.Digest.Algorithm().FromBytes(b) != d.Digest {
		return ispec.Descriptor{}, nil, fmt.Errorf("%w: manifest %s in %s", ErrDigestMismatch, d.Digest, n)
	}
	return d, b, nil
}

// newID mints an upload session id: a random (version 4) UUID, lowercase.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint upload id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// lock takes the repository's flock, waiting until ctx is done.
func (s *Store) lock(ctx context.Context, n ref.Name) (func(), error) {
	sum := sha256.Sum256([]byte(n.String()))
	p := filepath.Join(s.state, locksDir, hex.EncodeToString(sum[:]))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return nil, fmt.Errorf("open repository lock: %w", err)
	}
	if err := flock(ctx, f); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock repository %s: %w", n, err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) // closing releases it too
		f.Close()
	}, nil
}

// flock takes an exclusive flock on f, polling so ctx can end the wait.
func flock(ctx context.Context, f *os.File) error {
	wait := time.Millisecond
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 50*time.Millisecond)
	}
}

// syncDir syncs a directory so a rename or link in it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}

// mkdirs creates dir and its missing parents under the root with mode 0700,
// one element at a time, refusing a symlink on the way.
func (s *Store) mkdirs(dir string) error {
	if err := ref.NoSymlinks(s.root, dir); err != nil {
		return err
	}
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return err
	}
	cur := s.root
	for _, e := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, e)
		err := os.Mkdir(cur, dirMode)
		if err == nil {
			continue
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create %s: %w", cur, err)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrNotRegular, cur)
		}
	}
	return nil
}

// Init creates n's layout when it is missing: the directories, oci-layout,
// an empty index.json, blobs/ and .uploads/. It never rewrites a file that
// exists.
func (s *Store) Init(ctx context.Context, n ref.Name) error {
	dir, err := s.repoDir(n)
	if err != nil {
		return err
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.initLocked(dir); err != nil {
		return fmt.Errorf("init %s: %w", n, err)
	}
	return nil
}

// initLocked is Init's body; the caller holds the repository lock. Every
// write that creates a path inside a repository (a session, a blob link)
// runs it under the same lock hold, so GC, which removes an empty
// repository's layout under that lock, never leaves a write in a directory
// that is no longer a repository.
func (s *Store) initLocked(dir string) error {
	if isRepoDir(dir) {
		return s.mkdirs(filepath.Join(dir, uploadsDir))
	}
	for _, d := range []string{dir, filepath.Join(dir, blobsDir), filepath.Join(dir, uploadsDir)} {
		if err := s.mkdirs(d); err != nil {
			return err
		}
	}
	if err := s.createFile(filepath.Join(dir, layoutFile), layoutBody); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, indexFile)); errors.Is(err, os.ErrNotExist) {
		if err := s.writeIndex(dir, ispec.Index{Versioned: specsVersioned}); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return syncDir(dir)
}

// createFile writes body to p unless p exists, durably.
func (s *Store) createFile(p string, body []byte) error {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := fullSync(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// writeIndex replaces dir's index.json: a temp file under .uploads,
// F_FULLFSYNC, rename, directory sync. The caller holds the repository lock.
func (s *Store) writeIndex(dir string, idx ispec.Index) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("encode index: %w", err)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, uploadsDir, id)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return fmt.Errorf("stage index: %w", err)
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = fullSync(f)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(dir, indexFile))
	}
	if werr != nil {
		_ = os.Remove(tmp) // best effort; a leftover is an idle upload GC reaps
		return fmt.Errorf("write index: %w", werr)
	}
	return syncDir(dir)
}

// specsVersioned is schemaVersion 2.
var specsVersioned = ispecVersioned()

// updateIndex applies change to n's index.json under the repository lock and
// writes it back when change reports a difference.
func (s *Store) updateIndex(ctx context.Context, n ref.Name, change func([]ispec.Descriptor) ([]ispec.Descriptor, bool, error)) error {
	dir, ok, err := s.exists(n)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return err
	}
	defer unlock()
	idx, err := readIndex(dir)
	if err != nil {
		return err
	}
	rows, changed, err := change(slices.Clone(idx.Manifests))
	if err != nil || !changed {
		return err
	}
	idx.Manifests = rows
	return s.writeIndex(dir, idx)
}
