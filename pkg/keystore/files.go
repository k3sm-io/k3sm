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
	"syscall"
	"time"
)

// This file is the store's file access. Every directory the store uses is
// opened as an os.Root, so no name inside it, and no symlink planted under it,
// resolves outside it. That matters because a root-run verb writes into
// directories the service user owns, and a process running as that user could
// otherwise turn a name into a symlink and point root's write elsewhere. The
// two directories opened by path (the entries' directory and cred/) sit in the
// server work dir, whose own entry the service user cannot replace (the data
// root is root:wheel 0755), so only their last component needs the check
// openDir makes.

const (
	// dirMode is the mode of every directory the store creates.
	dirMode fs.FileMode = 0o700
	// fileMode is the mode of every file the store creates.
	fileMode fs.FileMode = 0o600
	// lockName is the store-wide lock file, in the entries' directory.
	lockName = ".lock"
	// lockTimeout bounds every wait for the lock.
	lockTimeout = 10 * time.Second
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

// openSubdir is openDir for the directory name inside parent, created with
// mkdirAt, so the open never leaves parent.
func (s *FileStore) openSubdir(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := s.mkdirAt(parent, name); err != nil && !errors.Is(err, fs.ErrExist) {
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
// user. An existing directory is left as it is for the caller's check.
//
// A crash, or a failed chown, between the Mkdir and the handover leaves the
// directory owned by root, which the caller's check then refuses on every
// retry; the refusal names the owner, and a chown to the service user
// recovers it.
func (s *FileStore) mkdirOwned(path string) error {
	err := os.Mkdir(path, dirMode)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	// Owner and mode go on a descriptor opened with O_NOFOLLOW, never by
	// name, so a symlink swapped in after the Mkdir is not followed.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	return s.own(f, dirMode)
}

// mkdirAt creates the directory name inside root, handed to the service user.
func (s *FileStore) mkdirAt(root *os.Root, name string) error {
	if err := root.Mkdir(name, dirMode); err != nil {
		return err
	}
	f, _, err := openNoFollow(root, name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", name, err)
	}
	defer func() { _ = f.Close() }() // read-only; nothing to flush
	return s.own(f, dirMode)
}

// own applies the service user's ownership and mode to an open file or
// directory. A non-root process giving a file to its own uid and group is a
// no-op chown.
func (s *FileStore) own(f *os.File, mode fs.FileMode) error {
	if err := s.chown(f, int(s.uid), int(s.gid)); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", f.Name(), s.uid, s.gid, err)
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
	var suffix [8]byte
	if err := s.readRandom(suffix[:]); err != nil {
		return fmt.Errorf("name a temporary file: %w", err)
	}
	tmp := "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp"
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
	err = s.own(f, fileMode)
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
	return syncDir(root)
}

// syncDir fsyncs root's directory, making a rename or removal in it durable.
func syncDir(root *os.Root) error {
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

// readDirNames lists the names in root's directory.
func readDirNames(root *os.Root) ([]string, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }() // read-only; nothing to flush
	return d.Readdirnames(-1)
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

// lock takes the store-wide flock on root's lock file, exclusive or shared,
// waiting at most s.lockWait, or until ctx is done. The returned function
// releases it.
func (s *FileStore) lock(ctx context.Context, root *os.Root, exclusive bool) (func(), error) {
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
	deadline := time.Now().Add(s.lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close() // abandoned; nothing to flush
			return nil, fmt.Errorf("lock the keystore: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close() // abandoned; nothing to flush
			return nil, errLockTimeout
		}
		select {
		case <-ctx.Done():
			_ = f.Close() // abandoned; nothing to flush
			return nil, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // the close below releases it regardless
		_ = f.Close()
	}, nil
}

// readRandom fills b from the store's entropy source.
func (s *FileStore) readRandom(b []byte) error {
	if _, err := io.ReadFull(s.rand, b); err != nil {
		return fmt.Errorf("read %d random bytes: %w", len(b), err)
	}
	return nil
}
