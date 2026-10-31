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
	"syscall"
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

// TouchBlob sets blob d's mtime in n to now, under n's repository lock, and
// fails with ErrBlobUnknown when n does not hold it. A blob HEAD calls it, so
// a client that saw the blob present and then PUTs a manifest naming it finds
// it still there: GC re-stats a candidate under the same lock before it
// deletes, so it either sees the fresh mtime (and keeps the blob for a grace
// period) or removed the blob first (and the HEAD answers 404). An absent blob
// is answered without the lock, so a probe of a repository that does not
// exist creates no lock file.
func (s *Store) TouchBlob(ctx context.Context, n ref.Name, d digest.Digest) error {
	if _, err := s.StatBlob(n, d); err != nil {
		return err
	}
	err := s.WithLock(ctx, n, func(l *Locked) error {
		p, err := s.blobPath(n, d)
		if err != nil {
			return err
		}
		f, err := openRegular(p, os.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, n)
		}
		if err != nil {
			return err
		}
		defer f.Close()
		now := unix.NsecToTimeval(s.now().UnixNano())
		if err := unix.Futimes(int(f.Fd()), []unix.Timeval{now, now}); err != nil {
			return fmt.Errorf("touch blob %s in %s: %w", d, n, err)
		}
		return nil
	})
	if errors.Is(err, ErrRepositoryUnknown) {
		// GC removed the layout between the stat and the lock.
		return fmt.Errorf("%w: %s in %s", ErrBlobUnknown, d, n)
	}
	return err
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
// when it is missing, and returns its id. The session file is created under
// the repository lock.
func (s *Store) NewUpload(ctx context.Context, n ref.Name) (string, error) {
	dir, err := s.repoDir(n)
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := s.initLocked(dir); err != nil {
		return "", fmt.Errorf("init %s: %w", n, err)
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

// openUpload opens session id of n, takes its flock, and then checks that the
// descriptor is still the session: the path names the same inode (dev and
// ino), and that inode has exactly one link. A session committed or cancelled
// while this call waited for the lock fails with ErrUploadUnknown; without the
// check a chunk would be appended to the published blob the commit linked from
// the same inode, which other repositories share. It returns the file and the
// session path.
//
// shared relaxes the single-link rule, and only for the two operations that
// never write the inode: a commit retried after a commit that linked the
// session into blobs/ but did not remove it, and a cancel of such a session.
// Both only hash, link and unlink; an append always requires one link.
func (s *Store) openUpload(ctx context.Context, n ref.Name, id string, flag int, shared bool) (*os.File, string, error) {
	p, err := s.uploadPath(n, id)
	if err != nil {
		return nil, "", err
	}
	f, err := openRegular(p, flag)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("%w: %s in %s", ErrUploadUnknown, id, n)
	}
	if err != nil {
		return nil, "", err
	}
	if s.uploadOpened != nil {
		s.uploadOpened(id)
	}
	if err := flock(ctx, f); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("lock upload %s: %w", id, err)
	}
	if err := checkSession(f, p, shared); err != nil {
		f.Close()
		return nil, "", fmt.Errorf("%w: %s in %s: %v", ErrUploadUnknown, id, n, err)
	}
	return f, p, nil
}

// checkSession requires that p still names f's inode and, unless shared, that
// the inode has a single link (no blob shares it yet).
func checkSession(f *os.File, p string, shared bool) error {
	fst, err := f.Stat()
	if err != nil {
		return err
	}
	lst, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !lst.Mode().IsRegular() || !os.SameFile(fst, lst) {
		return errors.New("the session path no longer names the opened file")
	}
	if !shared && nlink(fst) != 1 {
		return fmt.Errorf("the session file has %d links", nlink(fst))
	}
	return nil
}

func nlink(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// UploadSize returns session id's length, which is its offset.
func (s *Store) UploadSize(ctx context.Context, n ref.Name, id string) (int64, error) {
	f, _, err := s.openUpload(ctx, n, id, os.O_RDONLY, false)
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
// appends wherever the session ends. The session's length is not limited; a
// caller serving untrusted bodies uses AppendUploadLimit.
func (s *Store) AppendUpload(ctx context.Context, n ref.Name, id string, offset int64, r io.Reader) (int64, error) {
	return s.AppendUploadLimit(ctx, n, id, offset, -1, r)
}

// AppendUploadLimit is AppendUpload for a session that may never be longer
// than limit bytes (no limit when limit is negative). At most the bytes that
// fit are read from r; when r holds more, the chunk is refused with
// ErrUploadTooLarge and the session is cut back to the length it had before
// the chunk, so no byte past the limit, and none of the refused chunk, stays
// on disk.
func (s *Store) AppendUploadLimit(ctx context.Context, n ref.Name, id string, offset, limit int64, r io.Reader) (int64, error) {
	f, _, err := s.openUpload(ctx, n, id, os.O_WRONLY|os.O_APPEND, false)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	if offset >= 0 && offset != size {
		return size, fmt.Errorf("%w: chunk at %d, session at %d", ErrOffsetMismatch, offset, size)
	}
	if limit < 0 {
		w, err := io.Copy(f, r)
		if err != nil {
			return size + w, fmt.Errorf("append to upload %s: %w", id, err)
		}
		return size + w, nil
	}
	room := max(limit-size, 0)
	w, err := io.Copy(f, io.LimitReader(r, room))
	if err != nil {
		return size + w, fmt.Errorf("append to upload %s: %w", id, err)
	}
	if w == room {
		var probe [1]byte
		k, perr := io.ReadFull(r, probe[:])
		if k > 0 {
			if err := f.Truncate(size); err != nil {
				return size + w, fmt.Errorf("cut back oversized upload %s: %w", id, err)
			}
			return size, fmt.Errorf("%w: session %s would pass %d bytes", ErrUploadTooLarge, id, limit)
		}
		if perr != io.EOF && perr != io.ErrUnexpectedEOF {
			return size + w, fmt.Errorf("append to upload %s: %w", id, perr)
		}
	}
	return size + w, nil
}

// CommitUpload finishes session id as blob want: the content is hashed, made
// durable, and linked into blobs/ (link-or-keep), then the session file is
// removed. A digest mismatch leaves the session in place.
//
// A session a previous commit already linked into blobs/ (its inode has two
// links because the session file was not removed) is committed again by the
// same steps: it is re-hashed, link-or-keep finds the blob in place, and the
// session name is unlinked. Nothing writes to the shared inode.
func (s *Store) CommitUpload(ctx context.Context, n ref.Name, id string, want digest.Digest) error {
	return s.commitUpload(ctx, n, id, want, -1)
}

// CommitHashedUpload is CommitUpload for a caller that hashed the session's
// bytes as they streamed in: size is how many bytes that hash covered, and the
// caller has checked that they hash to want. The file is not read again when
// it is still exactly size bytes and has one link; otherwise (another writer
// appended, or the session is already shared with a blob) it is re-hashed as
// CommitUpload does. The caller's hash is trusted only for bytes this process
// wrote under the session's flock.
func (s *Store) CommitHashedUpload(ctx context.Context, n ref.Name, id string, want digest.Digest, size int64) error {
	if size < 0 {
		return fmt.Errorf("commit upload %s: negative hashed size %d", id, size)
	}
	return s.commitUpload(ctx, n, id, want, size)
}

// commitUpload is the commit; hashed is the length the caller's streamed hash
// covered, or -1 when there is none.
func (s *Store) commitUpload(ctx context.Context, n ref.Name, id string, want digest.Digest, hashed int64) error {
	if _, err := ref.ParseDigest(want.String()); err != nil {
		return err
	}
	f, src, err := s.openUpload(ctx, n, id, os.O_RDWR, true)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if hashed < 0 || hashed != fi.Size() || nlink(fi) != 1 {
		v := want.Verifier()
		if _, err := io.Copy(v, f); err != nil {
			return fmt.Errorf("hash upload %s: %w", id, err)
		}
		if !v.Verified() {
			return fmt.Errorf("%w: upload %s is not %s", ErrDigestMismatch, id, want)
		}
	}
	if err := fullSync(f); err != nil {
		return fmt.Errorf("sync upload %s: %w", id, err)
	}
	// Link by path only while the path still names the inode just hashed.
	if err := checkSession(f, src, true); err != nil {
		return fmt.Errorf("%w: %s in %s: %v", ErrUploadUnknown, id, n, err)
	}
	if err := s.linkBlob(ctx, n, src, fi, true, want); err != nil {
		return err
	}
	if err := os.Remove(src); err != nil {
		return fmt.Errorf("remove finished upload %s: %w", id, err)
	}
	return nil
}

// CancelUpload removes session id. A session already linked into blobs/ by a
// commit that did not finish is cancelled too: only the session name is
// unlinked, and the blob keeps the inode.
func (s *Store) CancelUpload(ctx context.Context, n ref.Name, id string) error {
	f, p, err := s.openUpload(ctx, n, id, os.O_RDONLY, true)
	if err != nil {
		return err
	}
	defer f.Close()
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
// inode, no copy. The source blob is trusted as it stands: it was verified
// against d when it was committed (or when link-or-keep replaced it), and blob
// files are never written in place, so a mount does not hash it again. It
// returns ErrMountUnavailable when from does not hold the blob or the link
// crosses volumes, so the caller falls back to an upload.
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
	err = s.linkBlob(ctx, n, src, fi, false, d)
	if errors.Is(err, unix.EXDEV) || errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %v", ErrMountUnavailable, err)
	}
	return err
}

// linkBlob makes blob d of n the inode srcFi describes, reached by path src,
// unless n already holds a good copy of d (link-or-keep). srcVerified says
// whether the caller has hashed src's inode against d.
//
// After the link attempt the destination is checked by inode:
//   - it is srcFi's inode: the link is ours; it is synced;
//   - it is another inode (the blob existed, or src was swapped between the
//     caller's check and the link): its content is hashed, and it is kept only
//     when it is d. A destination that is not d is replaced atomically by a
//     link of the verified source under a temp name in the same directory and
//     a rename over it; no blob file is ever written in place, so every other
//     repository sharing the bad inode keeps exactly what it had.
//
// It then touches the blob inode's mtime (futimes on the descriptor), so GC's
// grace counts from now even for an inode shared with an older blob, and
// syncs blobs/<algorithm>.
//
// All of it runs under n's repository lock, creating n's layout first when it
// is missing. GC re-stats a candidate and deletes it under the same lock, so a
// blob this call links or keeps is either touched before GC looks at it or
// linked anew after GC removed the old name; it is never deleted after this
// call returns on the strength of a stat taken before the touch.
func (s *Store) linkBlob(ctx context.Context, n ref.Name, src string, srcFi os.FileInfo, srcVerified bool, d digest.Digest) error {
	dst, err := s.blobPath(n, d)
	if err != nil {
		return err
	}
	repo, err := s.repoDir(n)
	if err != nil {
		return err
	}
	unlock, err := s.lock(ctx, n)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.initLocked(repo); err != nil {
		return fmt.Errorf("init %s: %w", n, err)
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
	defer func() { f.Close() }()
	dfi, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(dfi, srcFi) {
		ok, err := verifyFile(f, d)
		if err != nil {
			return fmt.Errorf("verify blob %s in %s: %w", d, n, err)
		}
		if !ok {
			if err := s.replaceBlob(src, srcFi, srcVerified, dst, d); err != nil {
				return fmt.Errorf("replace corrupt blob %s in %s: %w", d, n, err)
			}
			f.Close()
			if f, err = openRegular(dst, os.O_RDONLY); err != nil {
				return err
			}
		}
	}
	if err := fullSync(f); err != nil {
		return fmt.Errorf("sync blob %s in %s: %w", d, n, err)
	}
	now := unix.NsecToTimeval(s.now().UnixNano())
	if err := unix.Futimes(int(f.Fd()), []unix.Timeval{now, now}); err != nil {
		return fmt.Errorf("touch blob %s in %s: %w", d, n, err)
	}
	return syncDir(dir)
}

// verifyFile hashes f from its start against d.
func verifyFile(f *os.File, d digest.Digest) (bool, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	v := d.Verifier()
	if _, err := io.Copy(v, f); err != nil {
		return false, err
	}
	return v.Verified(), nil
}

// replaceBlob points dst at the source inode: a link under a temp name
// (.tmp-<uuid>) in dst's directory, checked to be that inode (and, when the caller has not
// hashed it, hashed now), then renamed over dst.
func (s *Store) replaceBlob(src string, srcFi os.FileInfo, srcVerified bool, dst string, d digest.Digest) error {
	id, err := newID()
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(dst), ".tmp-"+id)
	if err := os.Link(src, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp) // gone after the rename; removed on any failure
	t, err := openRegular(tmp, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer t.Close()
	tfi, err := t.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(tfi, srcFi) {
		return errors.New("the source changed while it was linked")
	}
	if !srcVerified {
		ok, err := verifyFile(t, d)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: the source does not hash to %s either", ErrDigestMismatch, d)
		}
	}
	return os.Rename(tmp, dst)
}
