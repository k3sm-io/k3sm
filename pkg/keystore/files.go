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

package keystore

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// This file is the store's file access. Every directory the store uses is
// opened as an os.Root, so no name inside it, and no symlink planted under it,
// resolves outside it. That matters because a root-run verb writes into
// directories the service user owns, and a process running as that user could
// otherwise turn a name into a symlink and point root's write elsewhere. The
// two directories opened by path (the entries' directory and cred/) sit in the
// server work dir, server/. The service user owns server/, so it can replace
// either name with a symlink, which is the last component openDir checks; it
// cannot replace server/ itself, whose entry is in the data root, root:wheel
// 0755, so nothing above that last component needs the check.

const (
	// dirMode is the mode of every directory the store creates.
	dirMode fs.FileMode = 0o700
	// fileMode is the mode of every file the store creates.
	fileMode fs.FileMode = 0o600
	// lockName is the store-wide lock file, in the entries' directory.
	lockName = ".lock"
	// lockTimeout bounds every wait for the lock.
	lockTimeout = 10 * time.Second
	// maxDirNames bounds how many names a listing of one directory accepts.
	// Any process running as the service user can fill a store directory, and
	// the store lists one while holding the lock, so past the bound the listing
	// fails rather than grow without one. It is twice maxVersion, so an entry
	// directory at the version limit, with its own files, still lists.
	maxDirNames = 2 * maxVersion
	// dirBatch is how many names one read of a directory returns.
	dirBatch = 256
)

var (
	// errLockTimeout reports that the store lock was not acquired within the
	// bound. Any process running as the service user can hold the lock, so
	// the wait is bounded rather than indefinite.
	errLockTimeout = errors.New("the keystore is locked by another operation; try again")
	// errBadFile marks a file that is the wrong shape to be read: a symlink,
	// not a regular file, or over its size bound. A reader turns it into its
	// own refusal; any other read error is an I/O failure and stays one.
	errBadFile = errors.New("not a readable regular file")
)

// openDir opens the directory at path as a root and checks it (see
// checkRoot). With create set, a missing directory is first created at
// dirMode and handed to the service user; its parent must exist. A missing
// directory is an error matching fs.ErrNotExist.
func (s *FileStore) openDir(path string, create bool) (*os.Root, error) {
	if create {
		if err := s.mkdirOwned(path); err != nil {
			return nil, err
		}
	}
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (mode %s)", path, named.Mode())
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if err := s.checkRoot(root, named); err != nil {
		_ = root.Close() // the open is abandoned; its close has nothing to report
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return root, nil
}

// openDirForRm is openDir for rm-scope only, never for a serving path,
// and never creating: the keystore directory at path must be the service
// user's, but its mode is not judged. The service user can set it, and a
// mode check would let the principal being revoked veto its revocation,
// as with .user and the scope directory (openScopeDirForRm).
func (s *FileStore) openDirForRm(path string) (*os.Root, error) {
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (mode %s)", path, named.Mode())
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil && !os.SameFile(named, opened) {
		err = errors.New("changed while it was opened")
	}
	if err == nil {
		err = s.checkOwned(opened, fs.ModePerm)
	}
	if err != nil {
		_ = root.Close() // the open is abandoned; its close has nothing to report
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return root, nil
}

// openSubdir is openDir for the directory name inside parent, created with
// mkdirAt, so the open never leaves parent.
func (s *FileStore) openSubdir(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if _, err := s.mkdirAt(parent, name); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	named, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !named.IsDir() {
		return nil, fmt.Errorf("%s is not a directory (mode %s)", name, named.Mode())
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if err := s.checkRoot(root, named); err != nil {
		_ = root.Close() // the open is abandoned; its close has nothing to report
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return root, nil
}

// checkRoot checks an opened directory: it must be the very directory Lstat
// saw as named, so a swap between the two cannot substitute another (and
// OpenRoot, which follows a symlink, did not), owned by the store's uid, and
// granting nothing to group or others.
func (s *FileStore) checkRoot(root *os.Root, named fs.FileInfo) error {
	opened, err := root.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(named, opened) {
		return errors.New("changed while it was opened")
	}
	return s.checkOwned(opened, dirMode)
}

// mkdirOwned creates the directory at path at dirMode, handed to the service
// user, with mkdirAt through a root opened on its parent, never by its full
// path. An existing directory is left as it is for the caller's check. The
// parent is opened by path: it is the server work dir, which the openDir note
// above covers.
//
// A crash, or a failed chown, between the Mkdir and the handover leaves the
// directory owned by root, which the caller's check then refuses on every
// retry; the refusal names the owner, and a chown to the service user
// recovers it.
func (s *FileStore) mkdirOwned(path string) error {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open the parent of %s: %w", path, err)
	}
	defer func() { _ = parent.Close() }() // the mkdir is all it is for
	_, err = s.mkdirAt(parent, filepath.Base(path))
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	return nil
}

// mkdirAt creates the directory name inside parent (mkdirat, so no symlink in
// a path redirects it), hands it to the service user, and returns its info,
// for a caller that opens it again to check it reached the same directory.
//
// Before the handover it opens the name without following a symlink and
// requires, on that descriptor, a directory owned by the euid that made it,
// empty, and the same file an Lstat of the name saw after the mkdir. That
// Lstat is not atomic with the mkdir, so a directory swapped in before it is
// the one it sees: the owner and emptiness checks are what refuse such a
// directory, and the identity check refuses only a swap between the Lstat and
// the open. A directory that fails any check may be another entry or one the
// service user prepared, so it is refused as ErrCorrupt and nothing is chowned
// or chmodded. Once checked, any extended ACL it inherited from parent is
// removed on the descriptor (removeExtendedACL; a no-op where the build reads
// no ACL), before the handover. An existing name is an error matching
// fs.ErrExist. Once handed over, parent is fsynced, so the new name is
// durable.
func (s *FileStore) mkdirAt(parent *os.Root, name string) (fs.FileInfo, error) {
	if err := parent.Mkdir(name, dirMode); err != nil {
		return nil, err
	}
	s.dirMade(name)
	made, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("stat the new directory %s: %w", name, err)
	}
	if !made.IsDir() {
		return nil, fmt.Errorf("%w: the new directory %s was replaced after its mkdir (mode %s)", ErrCorrupt, name, made.Mode())
	}
	f, opened, err := openNoFollow(parent, name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		// A name that no longer holds the directory the mkdir made (a symlink,
		// which os.Root may refuse as escaping, or anything else swapped in)
		// is the swap this guards against, not an I/O failure.
		if now, lerr := parent.Lstat(name); errors.Is(err, errBadFile) || lerr != nil || !os.SameFile(made, now) {
			return nil, fmt.Errorf("%w: the new directory %s was replaced after its mkdir: %w", ErrCorrupt, name, err)
		}
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	if err := s.checkNewDir(f, made, opened); err != nil {
		return nil, fmt.Errorf("%w: the new directory %s %w", ErrCorrupt, name, err)
	}
	// An inheritable ACL entry on parent is copied onto the new directory,
	// and while root owns it one granting add_subdirectory lets its grantee
	// move it to another parent: it is removed on the descriptor before
	// anything else is done with the directory.
	if err := removeExtendedACL(int(f.Fd())); err != nil {
		return nil, fmt.Errorf("the new directory %s: %w", name, err)
	}
	if err := s.own(f, dirMode); err != nil {
		return nil, err
	}
	// The new name is made durable before anything is written under it: a
	// power loss could otherwise keep entries while losing the master
	// directory, which is ErrMasterMissing for good.
	if err := syncDir(parent); err != nil {
		return nil, err
	}
	if err := s.step("mkdir " + name); err != nil {
		return nil, err
	}
	return opened, nil
}

// checkNewDir checks the directory open on f is one mkdirAt may hand over:
// the same file as made, a directory, owned by the euid that made it, and
// empty.
func (s *FileStore) checkNewDir(f *os.File, made, opened fs.FileInfo) error {
	if !made.IsDir() || !opened.IsDir() || !os.SameFile(made, opened) {
		return errors.New("was replaced after its mkdir")
	}
	st, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return errors.New("has no known owner")
	}
	if euid := s.euid(); int64(st.Uid) != int64(euid) {
		return fmt.Errorf("is owned by uid %d, not by its creator, uid %d", st.Uid, euid)
	}
	names, err := f.Readdirnames(1)
	if len(names) > 0 {
		return errors.New("is not empty")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("could not be listed: %w", err)
	}
	return nil
}

// own applies the service user's ownership and mode to an open file or
// directory. A non-root process giving a file to its own uid and group is a
// no-op chown.
func (s *FileStore) own(f *os.File, mode fs.FileMode) error {
	return s.ownAs(f, s.uid, s.gid, mode)
}

// ownAs is own with the owner given.
func (s *FileStore) ownAs(f *os.File, uid, gid uint32, mode fs.FileMode) error {
	if err := s.chown(f, int(uid), int(gid)); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", f.Name(), uid, gid, err)
	}
	if err := f.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", f.Name(), mode, err)
	}
	return nil
}

// checkOwned refuses fi unless it is owned by the store's uid and its mode
// grants no more than want.
func (s *FileStore) checkOwned(fi fs.FileInfo, want fs.FileMode) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return errors.New("owner unknown")
	}
	if st.Uid != s.uid {
		return fmt.Errorf("owned by uid %d, want %d", st.Uid, s.uid)
	}
	if perm := fi.Mode().Perm(); perm&^want != 0 {
		return fmt.Errorf("mode %04o grants more than %04o", perm, want)
	}
	return nil
}

// writeFile replaces name inside root with data, durably: a fresh temporary
// file is created beside it, handed to the service user at fileMode on its
// descriptor, written and fsynced, then renamed over name, and the directory
// is fsynced. A reader sees the old file or the new one, never a partial
// file, and never one at a wider mode or another owner. A crash before the
// rename leaves the temporary file, which no reader opens.
func (s *FileStore) writeFile(root *os.Root, name string, data []byte) error {
	return s.writeFileAs(root, name, data, s.uid, s.gid, fileMode)
}

// writeFileAs is writeFile with the owner and mode given, for the one file
// the store keeps outside the service user's tree: the root-owned floor.
func (s *FileStore) writeFileAs(root *os.Root, name string, data []byte, uid, gid uint32, mode fs.FileMode) error {
	if err := s.renameInto(root, name, data, uid, gid, mode); err != nil {
		return err
	}
	return syncDir(root)
}

// renameInto is writeFileAs up to and including the rename, without the
// directory fsync: a nil return means name now holds data. A writer whose
// rename is its commit point (a current pointer) calls it so that it can
// tell a failed rename, which committed nothing, from a failed fsync after
// it, which did.
func (s *FileStore) renameInto(root *os.Root, name string, data []byte, uid, gid uint32, mode fs.FileMode) error {
	var suffix [tempSuffixSize]byte
	if err := s.readRandom(suffix[:]); err != nil {
		return fmt.Errorf("name a temporary file: %w", err)
	}
	tmp := tempName(name, suffix)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, fileMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = root.Remove(tmp) // best effort: a leftover temporary file is ignored by every reader
		}
	}()
	err = s.ownAs(f, uid, gid, mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = s.step("write " + name)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmp, name, err)
	}
	renamed = true
	return nil
}

// tempSuffixSize is the size of the random part of a temporary file's name.
const tempSuffixSize = 8

// tempName is the name writeFile gives the temporary file for name:
// ".<name>.<hex suffix>.tmp".
func tempName(name string, suffix [tempSuffixSize]byte) string {
	return "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp"
}

// isTempName reports whether n is the name tempName gives a temporary file
// for name: the suffix exactly 2*tempSuffixSize lowercase hex digits.
func isTempName(n, name string) bool {
	rest, ok := strings.CutPrefix(n, "."+name+".")
	if !ok {
		return false
	}
	hexPart, ok := strings.CutSuffix(rest, ".tmp")
	if !ok || len(hexPart) != 2*tempSuffixSize {
		return false
	}
	for i := 0; i < len(hexPart); i++ {
		if c := hexPart[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// syncDir fsyncs root's directory, making a rename or removal in it durable.
// It is a variable so a test can observe and fail each fsync.
var syncDir = fsyncDir

// fsyncDir is syncDir's implementation.
func fsyncDir(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }() // read-only; the Sync is what is checked
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", root.Name(), err)
	}
	return nil
}

// openNoFollow opens name inside root and refuses it (errBadFile) if name is
// a symlink.
//
// O_NOFOLLOW alone does not do that here: os.Root follows a symlink whose
// target stays inside the root, O_NOFOLLOW or not (checked on go1.27.3, where
// os.OpenFile refuses the same link with ELOOP). So the name is Lstat'd after
// the open, and must be no symlink and the very file the descriptor holds. A
// name swapped between the two calls fails the comparison.
//
// The open is O_NONBLOCK: a FIFO planted at name would otherwise block the
// open until a writer appeared, outside every bound the store keeps and while
// holding its lock. The caller refuses anything but a regular file (or a
// directory it asked for), and O_NONBLOCK changes nothing for either.
func openNoFollow(root *os.Root, name string, flag int, perm fs.FileMode) (*os.File, fs.FileInfo, error) {
	f, err := root.OpenFile(name, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
	if err != nil {
		return nil, nil, err
	}
	opened, err := f.Stat()
	if err == nil {
		var named fs.FileInfo
		named, err = root.Lstat(name)
		if err == nil && (named.Mode()&fs.ModeSymlink != 0 || !os.SameFile(opened, named)) {
			err = fmt.Errorf("%w: %s is a symlink or was replaced while it was opened", errBadFile, name)
		}
	}
	if err != nil {
		_ = f.Close() // abandoned; nothing to flush
		return nil, nil, err
	}
	return f, opened, nil
}

// openRegular is openNoFollow refusing (errBadFile) anything but a regular
// file.
func openRegular(root *os.Root, name string, flag int, perm fs.FileMode) (*os.File, fs.FileInfo, error) {
	f, fi, err := openNoFollow(root, name, flag, perm)
	if err == nil && !fi.Mode().IsRegular() {
		_ = f.Close() // abandoned; nothing to flush
		err = fmt.Errorf("%w: %s has mode %s", errBadFile, name, fi.Mode())
	}
	return f, fi, err
}

// readFile reads the regular file name inside root, refused (errBadFile) past
// max bytes. It returns the opened file's info so a caller can judge owner
// and mode on the same descriptor the bytes came from.
func readFile(root *os.Root, name string, max int64) ([]byte, fs.FileInfo, error) {
	f, fi, err := openRegular(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > max {
		return nil, nil, fmt.Errorf("%w: %s is over %d bytes", errBadFile, name, max)
	}
	return b, fi, nil
}

// readDirNames lists the names in root's directory, read dirBatch at a time,
// and fails closed once the directory holds more than max.
func readDirNames(root *os.Root, max int) ([]string, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }() // read-only; nothing to flush
	var names []string
	for {
		batch, err := d.Readdirnames(dirBatch)
		names = append(names, batch...)
		if len(names) > max {
			return nil, fmt.Errorf("%s holds over %d names", root.Name(), max)
		}
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// readDirEntries is readDirNames with each name's type, as the directory
// listing gives it (no Lstat where the volume reports types).
func readDirEntries(root *os.Root, max int) ([]fs.DirEntry, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }() // read-only; nothing to flush
	var des []fs.DirEntry
	for {
		batch, err := d.ReadDir(dirBatch)
		des = append(des, batch...)
		if len(des) > max {
			return nil, fmt.Errorf("%s holds over %d names", root.Name(), max)
		}
		if errors.Is(err, io.EOF) {
			return des, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// openLocked opens the entries' directory, creating it with create set, and
// takes the store lock on it, exclusive or shared. A missing directory is an
// error matching fs.ErrNotExist, for the caller to map. The returned function
// releases the lock and closes the directory.
func (s *FileStore) openLocked(ctx context.Context, create, exclusive bool) (*os.Root, func(), error) {
	root, err := s.openDir(s.dir, create)
	if err != nil {
		return nil, nil, err
	}
	unlock, err := s.lock(ctx, root, exclusive)
	if err != nil {
		_ = root.Close() // abandoned; nothing was written
		return nil, nil, err
	}
	return root, func() { unlock(); _ = root.Close() }, nil
}

// lock takes the store lock, exclusive or shared: first the store's
// in-process writer-preferring lock (storelock.go), then the store-wide
// flock on root's lock file, waiting at most s.lockWait for the two
// together, or until ctx is done. The returned function releases the flock,
// then the in-process lock.
func (s *FileStore) lock(ctx context.Context, root *os.Root, exclusive bool) (func(), error) {
	start := time.Now()
	if err := s.inproc.acquire(ctx, exclusive, s.lockWait); err != nil {
		return nil, err
	}
	unlock, err := s.flock(ctx, root, exclusive, s.lockWait-time.Since(start))
	if err != nil {
		s.inproc.release(exclusive)
		return nil, err
	}
	held := time.Now()
	return func() {
		if s.holdObserver != nil {
			s.holdObserver(exclusive, time.Since(held))
		}
		unlock()
		s.inproc.release(exclusive)
	}, nil
}

// flock takes the store-wide flock on root's lock file, exclusive or shared,
// waiting at most wait, or until ctx is done. The returned function
// releases it.
func (s *FileStore) flock(ctx context.Context, root *os.Root, exclusive bool, wait time.Duration) (func(), error) {
	// The lock file is created exclusively, then opened without O_CREATE.
	// Concurrent O_CREATE opens of one name through an os.Root fail with a
	// spurious ENOENT (seen on go1.27.3 darwin in about 40% of 8-way races),
	// and two processes taking the lock for the first time are such a race.
	// The ownership is applied only to a file this call created.
	if c, err := root.OpenFile(lockName, os.O_RDONLY|os.O_CREATE|os.O_EXCL, fileMode); err == nil {
		err = s.own(c, fileMode)
		if cerr := c.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("create the keystore lock: %w", err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("create the keystore lock: %w", err)
	}
	// flock needs no write access, so the lock is held on a read-only
	// descriptor.
	f, _, err := openRegular(root, lockName, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("open the keystore lock: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := s.flockWaitFor(ctx, f, how, wait); err != nil {
		_ = f.Close() // abandoned; nothing to flush
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // the close below releases it regardless
		_ = f.Close()
	}, nil
}

// flockWait takes flock how on f, waiting at most s.lockWait (then
// errLockTimeout), or until ctx is done (then ctx's error).
func (s *FileStore) flockWait(ctx context.Context, f *os.File, how int) error {
	return s.flockWaitFor(ctx, f, how, s.lockWait)
}

// flockWaitFor is flockWait, waiting at most wait. A ctx already done
// takes nothing, even an uncontended flock.
func (s *FileStore) flockWaitFor(ctx context.Context, f *os.File, how int, wait time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return fmt.Errorf("lock %s: %w", f.Name(), err)
		}
		if time.Now().After(deadline) {
			return errLockTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// readRandom fills b from the store's entropy source.
func (s *FileStore) readRandom(b []byte) error {
	if _, err := io.ReadFull(s.rand, b); err != nil {
		return fmt.Errorf("read %d random bytes: %w", len(b), err)
	}
	return nil
}
