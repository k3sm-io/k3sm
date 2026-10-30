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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
)

// blobPath resolves blobs/<algorithm>/<hex> in n.
func (s *Store) blobPath(n ref.Name, d digest.Digest) (string, error) {
	if _, err := ref.ParseDigest(d.String()); err != nil {
		return "", err
	}
	return s.path(n, blobsDir, d.Algorithm().String(), d.Encoded())
}

// StatBlob returns the size of blob d in n.
func (s *Store) StatBlob(n ref.Name, d digest.Digest) (int64, error) {
	f, err := s.OpenBlob(n, d)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// OpenBlob opens blob d in n for reading. The caller closes it.
func (s *Store) OpenBlob(n ref.Name, d digest.Digest) (*os.File, error) {
	p, err := s.blobPath(n, d)
	if err != nil {
		return nil, err
	}
	f, err := openRegular(p, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, n)
	}
	return f, err
}

// Upload is an upload session as the store holds it.
type Upload struct {
	ID      string
	Size    int64
	ModTime time.Time
}

// uploadPath resolves .uploads/<id> in n.
func (s *Store) uploadPath(n ref.Name, id string) (string, error) {
	if _, err := ref.ParseUploadID(id); err != nil {
		return "", err
	}
	return s.path(n, uploadsDir, id)
}

// Uploads lists n's upload sessions, sorted by id. A file in .uploads whose
// name is not a session id (none is, as the store writes) is skipped.
func (s *Store) Uploads(n ref.Name) ([]Upload, error) {
	dir, err := s.path(n, uploadsDir)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list uploads of %s: %w", n, err)
	}
	var out []Upload
	for _, e := range ents {
		if _, err := ref.ParseUploadID(e.Name()); err != nil || !e.Type().IsRegular() {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue // removed meanwhile
		}
		out = append(out, Upload{ID: e.Name(), Size: fi.Size(), ModTime: fi.ModTime()})
	}
	slices.SortFunc(out, func(a, b Upload) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// NewUpload starts an upload session in n, creating the repository's layout
// when it is missing, and returns its id.
func (s *Store) NewUpload(ctx context.Context, n ref.Name) (string, error) {
	if err := s.Init(ctx, n); err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	p, err := s.uploadPath(n, id)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return "", fmt.Errorf("start upload in %s: %w", n, err)
	}
	return id, f.Close()
}

// openUpload opens session id of n and takes its flock.
func (s *Store) openUpload(ctx context.Context, n ref.Name, id string, flag int) (*os.File, error) {
	p, err := s.uploadPath(n, id)
	if err != nil {
		return nil, err
	}
	f, err := openRegular(p, flag)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s in %s", ErrUploadUnknown, id, n)
	}
	if err != nil {
		return nil, err
	}
	if err := flock(ctx, f); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock upload %s: %w", id, err)
	}
	return f, nil
}

// UploadSize returns session id's length, which is its offset.
func (s *Store) UploadSize(ctx context.Context, n ref.Name, id string) (int64, error) {
	f, err := s.openUpload(ctx, n, id, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// AppendUpload appends r to session id and returns its new length. offset is
// where the chunk starts and must be the session's length; a negative offset
// appends wherever the session ends.
func (s *Store) AppendUpload(ctx context.Context, n ref.Name, id string, offset int64, r io.Reader) (int64, error) {
	f, err := s.openUpload(ctx, n, id, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if offset >= 0 && offset != fi.Size() {
		return fi.Size(), fmt.Errorf("%w: chunk at %d, session at %d", ErrOffsetMismatch, offset, fi.Size())
	}
	w, err := io.Copy(f, r)
	if err != nil {
		return fi.Size() + w, fmt.Errorf("append to upload %s: %w", id, err)
	}
	return fi.Size() + w, nil
}

// CommitUpload finishes session id as blob want: the content is hashed, made
// durable, and linked into blobs/ (link-or-keep), then the session file is
// removed. A digest mismatch leaves the session in place.
func (s *Store) CommitUpload(ctx context.Context, n ref.Name, id string, want digest.Digest) error {
	if _, err := ref.ParseDigest(want.String()); err != nil {
		return err
	}
	f, err := s.openUpload(ctx, n, id, os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	v := want.Verifier()
	if _, err := io.Copy(v, f); err != nil {
		return fmt.Errorf("hash upload %s: %w", id, err)
	}
	if !v.Verified() {
		return fmt.Errorf("%w: upload %s is not %s", ErrDigestMismatch, id, want)
	}
	if err := fullSync(f); err != nil {
		return fmt.Errorf("sync upload %s: %w", id, err)
	}
	src, err := s.uploadPath(n, id)
	if err != nil {
		return err
	}
	if err := s.linkBlob(n, src, want); err != nil {
		return err
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("remove finished upload %s: %w", id, err)
	}
	return nil
}

// CancelUpload removes session id.
func (s *Store) CancelUpload(ctx context.Context, n ref.Name, id string) error {
	f, err := s.openUpload(ctx, n, id, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	p, err := s.uploadPath(n, id)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// PutBlob stores r as blob want in n in one pass: a session, the whole body,
// the commit. A failed upload leaves no session behind.
func (s *Store) PutBlob(ctx context.Context, n ref.Name, want digest.Digest, r io.Reader) error {
	if _, err := ref.ParseDigest(want.String()); err != nil {
		return err
	}
	id, err := s.NewUpload(ctx, n)
	if err != nil {
		return err
	}
	_, err = s.AppendUpload(ctx, n, id, 0, r)
	if err == nil {
		err = s.CommitUpload(ctx, n, id, want)
	}
	if err != nil {
		_ = s.CancelUpload(ctx, n, id) // best effort; GC reaps an idle session
		return err
	}
	return nil
}

// writeBlob stores body as blob d in n (the caller computed d from body).
func (s *Store) writeBlob(ctx context.Context, n ref.Name, d digest.Digest, body []byte) error {
	return s.PutBlob(ctx, n, d, bytes.NewReader(body))
}

// MountBlob makes blob d of repository from a blob of n by link(2): the same
// inode, no copy. It returns ErrMountUnavailable when from does not hold the
// blob or the link crosses volumes, so the caller falls back to an upload.
func (s *Store) MountBlob(ctx context.Context, n, from ref.Name, d digest.Digest) error {
	src, err := s.blobPath(from, d)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(src)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s holds no %s", ErrMountUnavailable, from, d)
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", ErrNotRegular, src)
	}
	if err := s.Init(ctx, n); err != nil {
		return err
	}
	err = s.linkBlob(n, src, d)
	if errors.Is(err, unix.EXDEV) || errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrMountUnavailable, err)
	}
	return err
}

// linkBlob links src to blob d of n unless the blob exists (link-or-keep),
// syncs blobs/<algorithm>, and touches the blob inode's mtime, so GC's grace
// counts from now even for an inode shared with an older blob.
func (s *Store) linkBlob(n ref.Name, src string, d digest.Digest) error {
	dst, err := s.blobPath(n, d)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	if err := s.mkdirs(dir); err != nil {
		return err
	}
	if err := os.Link(src, dst); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("link blob %s into %s: %w", d, n, err)
	}
	f, err := openRegular(dst, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("blob %s in %s: %w", d, n, err)
	}
	defer f.Close()
	now := unix.NsecToTimeval(s.now().UnixNano())
	if err := unix.Futimes(int(f.Fd()), []unix.Timeval{now, now}); err != nil {
		return fmt.Errorf("touch blob %s in %s: %w", d, n, err)
	}
	return syncDir(dir)
}
