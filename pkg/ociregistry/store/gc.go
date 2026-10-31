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

// tempPrefix starts the name replaceBlob links a verified source under before
// renaming it over a blob. A file with it is never a blob.
const tempPrefix = ".tmp-"

// SetClock replaces the clock blob mtimes are touched with. It exists for
// callers that inject a clock (GC tests); call it before the store is in use.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// StateDir returns the server state directory.
func (s *Store) StateDir() string { return s.state }

// Blob is a blob file in a repository's blobs/<algorithm>/.
type Blob struct {
	Digest  digest.Digest
	Size    int64
	ModTime time.Time
}

// Temp is a .tmp-<uuid> file in blobs/<algorithm>/: a link replaceBlob made
// and a crash left before its rename.
type Temp struct {
	Algorithm string
	Name      string
	ModTime   time.Time
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
			case isTempName(e.Name()):
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

// RemoveTemp removes a .tmp-<uuid> link. Under the lock no replaceBlob of
// this repository is in flight, so any temp link found is a crash's.
func (l *Locked) RemoveTemp(t Temp) error {
	if !isTempName(t.Name) || !isAlgorithm(t.Algorithm) {
		return fmt.Errorf("remove temp %s/%s: not a temp link", t.Algorithm, t.Name)
	}
	p, err := l.s.path(l.n, blobsDir, t.Algorithm, t.Name)
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
// blobs/ and .uploads/. It removes nothing and reports false unless
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
	}
	dirs := []string{filepath.Join(l.dir, uploadsDir)}
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
