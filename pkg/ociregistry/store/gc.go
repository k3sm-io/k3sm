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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// tempPrefix starts the name a verified source is linked under, in tempsDir,
// before it is renamed over a blob. A file with it is never a blob.
const tempPrefix = ".tmp-"

// tempName returns a new temp path in repo's tempsDir,
// making the directory when it is missing. The caller holds repo's lock and
// removes the name when it does not rename it. A tempsDir that is not a directory,
// a symlink included, fails it.
func (s *Store) tempName(repo string) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(repo, tempsDir)
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := s.mkdirs(dir); err != nil {
			return "", err
		}
		if err := syncDir(repo); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case !fi.IsDir():
		return "", fmt.Errorf("%w: %s is not a directory", ErrNotRegular, dir)
	}
	return filepath.Join(dir, tempPrefix+id), nil
}

// SetClock replaces the clock blob mtimes are touched with. It exists for
// callers that inject a clock (GC tests); call it before the store is in use.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// SetFutimes replaces the call TouchBlob sets a blob's times with. It exists
// for callers that fake a failing touch (server tests); call it before the
// store is in use.
func (s *Store) SetFutimes(fn func(f *os.File, t time.Time) error) { s.futimes = fn }

// StateDir returns the server state directory.
func (s *Store) StateDir() string { return s.state }

// Blob is a blob file in a repository's blobs/<algorithm>/.
type Blob struct {
	Digest  digest.Digest
	Size    int64
	ModTime time.Time
}

// Temp is a .tmp-<uuid> file: a link a blob replacement made and a crash left
// before its rename. It is in tempsDir, with no Algorithm, or, from a build that
// linked beside the blob, in blobs/<Algorithm>/.
type Temp struct {
	Algorithm string
	Name      string
	ModTime   time.Time
}

// Path is the temp's path inside its repository.
func (t Temp) Path() string {
	if t.Algorithm == "" {
		return filepath.Join(tempsDir, t.Name)
	}
	return filepath.Join(blobsDir, t.Algorithm, t.Name)
}

// Session is an upload session file with its link count. A count above one is
// a session whose commit linked it into blobs/ and stopped before removing
// it.
type Session struct {
	ID      string
	ModTime time.Time
	Links   uint64
}

// Contents is what a repository directory holds for GC: its blobs, its temp
// links and its upload sessions. Unknown counts entries that are none of
// these (left alone, and they keep the repository from being removed).
type Contents struct {
	Blobs    []Blob
	Temps    []Temp
	Sessions []Session
	Unknown  int
	// IndexModTime is index.json's mtime: when the rows last changed.
	IndexModTime time.Time
}

// Contents lists n's blobs, temp links and upload sessions without the lock.
func (s *Store) Contents(n ref.Name) (Contents, error) {
	dir, ok, err := s.exists(n)
	if err != nil {
		return Contents{}, err
	}
	if !ok {
		return Contents{}, fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	return contents(dir)
}

func contents(dir string) (Contents, error) {
	var c Contents
	ifi, err := os.Lstat(filepath.Join(dir, indexFile))
	if err != nil {
		return Contents{}, fmt.Errorf("stat index: %w", err)
	}
	c.IndexModTime = ifi.ModTime()
	algs, err := os.ReadDir(filepath.Join(dir, blobsDir))
	if err != nil {
		return Contents{}, fmt.Errorf("list blobs: %w", err)
	}
	for _, a := range algs {
		if !a.IsDir() {
			c.Unknown++
			continue
		}
		ents, err := os.ReadDir(filepath.Join(dir, blobsDir, a.Name()))
		if err != nil {
			return Contents{}, fmt.Errorf("list blobs: %w", err)
		}
		for _, e := range ents {
			fi, err := e.Info()
			if errors.Is(err, os.ErrNotExist) {
				continue // removed meanwhile
			}
			if err != nil {
				return Contents{}, err
			}
			switch {
			case !fi.Mode().IsRegular():
				c.Unknown++
			case isTempName(e.Name()) && isAlgorithm(a.Name()):
				c.Temps = append(c.Temps, Temp{Algorithm: a.Name(), Name: e.Name(), ModTime: fi.ModTime()})
			default:
				d, err := ref.ParseDigest(a.Name() + ":" + e.Name())
				if err != nil {
					c.Unknown++
					continue
				}
				c.Blobs = append(c.Blobs, Blob{Digest: d, Size: fi.Size(), ModTime: fi.ModTime()})
			}
		}
	}
	if err := tempContents(dir, &c); err != nil {
		return Contents{}, err
	}
	ents, err := os.ReadDir(filepath.Join(dir, uploadsDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Contents{}, fmt.Errorf("list uploads: %w", err)
	}
	for _, e := range ents {
		fi, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Contents{}, err
		}
		if _, err := ref.ParseUploadID(e.Name()); err != nil || !fi.Mode().IsRegular() {
			c.Unknown++
			continue
		}
		c.Sessions = append(c.Sessions, Session{ID: e.Name(), ModTime: fi.ModTime(), Links: nlink(fi)})
	}
	slices.SortFunc(c.Blobs, func(a, b Blob) int { return strings.Compare(a.Digest.String(), b.Digest.String()) })
	return c, nil
}

// tempContents adds what tempsDir holds to c. A tempsDir that is not a directory
// is one unknown entry and is not followed.
func tempContents(dir string, c *Contents) error {
	temps := filepath.Join(dir, tempsDir)
	fi, err := os.Lstat(temps)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list temps: %w", err)
	}
	if !fi.IsDir() {
		c.Unknown++
		return nil
	}
	ents, err := os.ReadDir(temps)
	if err != nil {
		return fmt.Errorf("list temps: %w", err)
	}
	for _, e := range ents {
		fi, err := e.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue // removed meanwhile
		}
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() || !isTempName(e.Name()) {
			c.Unknown++
			continue
		}
		c.Temps = append(c.Temps, Temp{Name: e.Name(), ModTime: fi.ModTime()})
	}
	return nil
}

// isAlgorithm reports whether name is a digest algorithm the store holds.
func isAlgorithm(name string) bool {
	return name == digest.SHA256.String() || name == digest.SHA512.String()
}

// isTempName reports whether name is .tmp-<uuid>.
func isTempName(name string) bool {
	id, ok := strings.CutPrefix(name, tempPrefix)
	if !ok {
		return false
	}
	_, err := ref.ParseUploadID(id)
	return err == nil
}

// Locked is a repository whose lock the holder of this value holds. Its
// methods run only inside WithLock's callback.
type Locked struct {
	s   *Store
	n   ref.Name
	dir string
}

// WithLock runs fn with n's repository lock held. Every store write that
// creates or touches a blob of n takes the same lock, so what fn reads is not
// changed by this store until fn returns, apart from upload session contents,
// which have their own lock.
func (s *Store) WithLock(ctx context.Context, n ref.Name, fn func(*Locked) error) error {
	dir, err := s.repoDir(n)
	if err != nil {
		return err
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return err
	}
	defer unlock()
	if !isRepoDir(dir) {
		return fmt.Errorf("%w: %s", ErrRepositoryUnknown, n)
	}
	return fn(&Locked{s: s, n: n, dir: dir})
}

// Index re-reads index.json.
func (l *Locked) Index() (ispec.Index, error) { return readIndex(l.dir) }

// Contents re-lists the repository.
func (l *Locked) Contents() (Contents, error) { return contents(l.dir) }

// SetRows replaces index.json's rows, keeping the rest of the index.
func (l *Locked) SetRows(rows []ispec.Descriptor) error {
	idx, err := readIndex(l.dir)
	if err != nil {
		return err
	}
	idx.Manifests = rows
	return l.s.writeIndex(l.dir, idx)
}

// StatBlob re-states blob d.
func (l *Locked) StatBlob(d digest.Digest) (Blob, error) {
	p, err := l.s.blobPath(l.n, d)
	if err != nil {
		return Blob{}, err
	}
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Blob{}, fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, l.n)
	}
	if err != nil {
		return Blob{}, err
	}
	if !fi.Mode().IsRegular() {
		return Blob{}, fmt.Errorf("%w: %s", ErrNotRegular, p)
	}
	return Blob{Digest: d, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

// TouchBlob sets blob d's mtime to now, and fails with ErrBlobUnknown when the
// repository does not hold it. A sweep re-states a candidate under the same
// lock before it deletes, so it sees the fresh mtime.
func (l *Locked) TouchBlob(d digest.Digest) error {
	p, err := l.s.blobPath(l.n, d)
	if err != nil {
		return err
	}
	f, err := openRegular(p, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, l.n)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := l.s.setTimes(f, l.s.now()); err != nil {
		return fmt.Errorf("touch blob %s in %s: %w", d, l.n, err)
	}
	return nil
}

// RemoveBlob removes blob d's name from the repository. The inode stays
// while another repository links it.
func (l *Locked) RemoveBlob(d digest.Digest) error {
	if _, err := l.StatBlob(d); err != nil {
		return err
	}
	p, err := l.s.blobPath(l.n, d)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// RemoveTemp removes a .tmp-<uuid> link. Under the lock no blob replacement of
// this repository is in flight, so any temp link found is a crash's.
func (l *Locked) RemoveTemp(t Temp) error {
	if !isTempName(t.Name) || (t.Algorithm != "" && !isAlgorithm(t.Algorithm)) {
		return fmt.Errorf("remove temp %s/%s: not a temp link", t.Algorithm, t.Name)
	}
	p, err := l.s.path(l.n, t.Path())
	if err != nil {
		return err
	}
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegular, p)
	}
	return os.Remove(p)
}

// SessionVerdict is what ReapSession found.
type SessionVerdict int

// The session verdicts.
const (
	// SessionKept is a live session: single link, written after the cutoff.
	SessionKept SessionVerdict = iota
	// SessionBusy is a session another operation holds the lock of.
	SessionBusy
	// SessionGone is a session that no longer exists.
	SessionGone
	// SessionCommitted is a session whose inode a commit linked into blobs/
	// and did not remove; it is removed (the blob keeps the inode).
	SessionCommitted
	// SessionIdle is a session not written since the cutoff; it is removed.
	SessionIdle
)

// ReapSession removes upload session id when it is abandoned: its inode has
// more than one link (a commit stopped between its link and its removal), or
// it was last written at or before idleBefore. It takes the session's flock
// without waiting, so a session an upload operation holds is never touched,
// and re-checks after the flock that the path still names the opened inode.
func (l *Locked) ReapSession(id string, idleBefore time.Time) (SessionVerdict, error) {
	p, err := l.s.uploadPath(l.n, id)
	if err != nil {
		return SessionKept, err
	}
	f, err := openRegular(p, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return SessionGone, nil
	}
	if err != nil {
		return SessionKept, err
	}
	defer f.Close()
	if l.s.uploadOpened != nil {
		l.s.uploadOpened(id)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return SessionBusy, nil
		}
		return SessionKept, fmt.Errorf("lock upload %s: %w", id, err)
	}
	fst, err := f.Stat()
	if err != nil {
		return SessionKept, err
	}
	lst, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return SessionGone, nil
	}
	if err != nil {
		return SessionKept, err
	}
	if !os.SameFile(fst, lst) {
		return SessionGone, nil
	}
	v := SessionKept
	switch {
	case nlink(fst) > 1:
		v = SessionCommitted
	case !fst.ModTime().After(idleBefore):
		v = SessionIdle
	}
	if v == SessionKept {
		return v, nil
	}
	if err := os.Remove(p); err != nil {
		return SessionKept, fmt.Errorf("remove upload %s: %w", id, err)
	}
	return v, nil
}

// RemoveLayout removes an empty repository's layout: oci-layout, index.json,
// blobs/, .uploads/ and .temps/. It removes nothing and reports false unless
// index.json has no rows, was last written at or before idleBefore, and the
// directory holds no blob, temp link, session or unknown entry. The directory
// itself stays, since another repository's name may nest under it.
func (l *Locked) RemoveLayout(idleBefore time.Time) (bool, error) {
	idx, err := readIndex(l.dir)
	if err != nil {
		return false, err
	}
	c, err := contents(l.dir)
	if err != nil {
		return false, err
	}
	if len(idx.Manifests) > 0 || c.IndexModTime.After(idleBefore) || len(c.Blobs) > 0 || len(c.Temps) > 0 || len(c.Sessions) > 0 || c.Unknown > 0 {
		return false, nil
	}
	algs, err := os.ReadDir(filepath.Join(l.dir, blobsDir))
	if err != nil {
		return false, err
	}
	// index.json goes first: from then on the directory is not a repository.
	for _, f := range []string{indexFile, layoutFile} {
		if err := os.Remove(filepath.Join(l.dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("remove %s layout: %w", l.n, err)
		}
		if f == indexFile && l.s.indexRemoved != nil {
			if err := l.s.indexRemoved(); err != nil {
				return false, err
			}
		}
	}
	dirs := []string{filepath.Join(l.dir, uploadsDir), filepath.Join(l.dir, tempsDir)}
	for _, a := range algs {
		dirs = append(dirs, filepath.Join(l.dir, blobsDir, a.Name()))
	}
	dirs = append(dirs, filepath.Join(l.dir, blobsDir))
	for _, d := range dirs {
		if err := os.Remove(d); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("remove %s layout: %w", l.n, err)
		}
	}
	return true, syncDir(l.dir)
}

// ReapHalfRemovedLayouts removes the layout a stopped RemoveLayout left: a
// directory holding oci-layout and no index.json, so no longer listed as a
// repository. It returns the names it reaped. Each candidate is found without
// the lock, then re-read under its repository lock, and reaped only when it
// still holds oci-layout, no index.json, no blob, no upload and no entry the
// store does not recognise: blobs/ may hold only empty algorithm directories
// and .uploads/ and .temps/ must be empty. Directories of nested names are left
// alone.
//
// A push builds a layout under the same lock (initLocked): directories,
// oci-layout, then an index.json staged in .uploads and renamed in. The state
// "oci-layout and no index.json" therefore exists for a live push only while
// it holds the lock, which this method needs to look; and the staged file sits
// in .uploads, which keeps the layout from being reaped even then.
func (s *Store) ReapHalfRemovedLayouts(ctx context.Context) ([]ref.Name, error) {
	var cands []ref.Name
	err := filepath.WalkDir(s.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == s.root || !d.IsDir() {
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
		if halfRemoved(p) {
			cands = append(cands, n)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list half-removed layouts: %w", err)
	}
	var out []ref.Name
	for _, n := range cands {
		if s.halfFound != nil {
			s.halfFound(n)
		}
		ok, err := s.reapHalfRemoved(ctx, n)
		if err != nil {
			return out, fmt.Errorf("reap half-removed layout %s: %w", n, err)
		}
		if ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// halfRemoved reports whether dir holds a regular oci-layout and no index.json.
func halfRemoved(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, layoutFile))
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	_, err = os.Lstat(filepath.Join(dir, indexFile))
	return errors.Is(err, os.ErrNotExist)
}

func (s *Store) reapHalfRemoved(ctx context.Context, n ref.Name) (bool, error) {
	dir, err := s.repoDir(n)
	if err != nil {
		return false, err
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return false, err
	}
	defer unlock()
	if !halfRemoved(dir) {
		return false, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	rm := []string{filepath.Join(dir, layoutFile)}
	var algs []string
	for _, e := range ents {
		switch {
		case e.Name() == layoutFile, e.IsDir() && e.Name() != blobsDir && e.Name() != uploadsDir && e.Name() != tempsDir:
			// oci-layout, or a nested repository name's directory
		case e.Name() == tempsDir && e.IsDir():
			sub, err := os.ReadDir(filepath.Join(dir, tempsDir))
			if err != nil || len(sub) > 0 {
				return false, err
			}
			rm = append(rm, filepath.Join(dir, tempsDir))
		case e.Name() == uploadsDir && e.IsDir():
			sub, err := os.ReadDir(filepath.Join(dir, uploadsDir))
			if err != nil || len(sub) > 0 {
				return false, err
			}
			rm = append(rm, filepath.Join(dir, uploadsDir))
		case e.Name() == blobsDir && e.IsDir():
			sub, err := os.ReadDir(filepath.Join(dir, blobsDir))
			if err != nil {
				return false, err
			}
			for _, a := range sub {
				ae, err := os.ReadDir(filepath.Join(dir, blobsDir, a.Name()))
				if !a.IsDir() || err != nil || len(ae) > 0 {
					return false, nil
				}
				algs = append(algs, filepath.Join(dir, blobsDir, a.Name()))
			}
			algs = append(algs, filepath.Join(dir, blobsDir))
		default:
			return false, nil // a file or kind the store does not recognise
		}
	}
	rm = append(rm, algs...)
	for _, d := range rm {
		if err := os.Remove(d); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return true, syncDir(dir)
}
