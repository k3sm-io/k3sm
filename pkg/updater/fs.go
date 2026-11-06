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

package updater

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ErrSymlink reports a path that is a symlink where a real file or directory
// is required.
var ErrSymlink = errors.New("is a symlink")

// Info is what the updater knows about an open descriptor or a path: fstat(2)
// and lstat(2) results and, for a descriptor, whether an extended ACL is set.
type Info struct {
	// UID is the owning user id.
	UID uint32
	// Mode is the file mode, type and set-id bits included.
	Mode fs.FileMode
	// Size is the size in bytes.
	Size int64
	// Flags are the BSD file flags (st_flags).
	Flags uint32
	// HasACL is true when the file carries an extended ACL.
	HasACL bool
}

// File is an open read-only descriptor.
type File interface {
	io.ReadSeeker
	io.Closer
	// Name returns the path the file was opened by.
	Name() string
	// Info reports the descriptor's own metadata, so a swap of the name after
	// the open changes nothing.
	Info() (Info, error)
}

// WriteFile is a new file being written.
type WriteFile interface {
	io.Writer
	io.Closer
	// Flush makes the written bytes durable with F_FULLFSYNC.
	Flush() error
}

// FS is every filesystem operation of the package. OSFS is the production
// implementation; a test wraps it to inject crashes and owners.
type FS interface {
	// OpenRead opens path read-only without following a final symlink and
	// without blocking on a FIFO. A symlink is an error wrapping ErrSymlink.
	OpenRead(path string) (File, error)
	// Lstat reports path without following a final symlink.
	Lstat(path string) (Info, error)
	// ReadDirNames returns at most max entry names of the directory path.
	ReadDirNames(path string, max int) ([]string, error)
	// Readlink returns a symlink's content.
	Readlink(path string) (string, error)
	// Mkdir creates a directory with exactly mode and flushes its parent.
	Mkdir(path string, mode fs.FileMode) error
	// CreateExcl creates a new file with exactly mode, never through a symlink.
	CreateExcl(path string, mode fs.FileMode) (WriteFile, error)
	// WriteFileAtomic replaces path with data: a temporary name beside it,
	// F_FULLFSYNC, rename, F_FULLFSYNC of the directory.
	WriteFileAtomic(path string, data []byte, mode fs.FileMode) error
	// Symlink creates the symlink path with the content target.
	Symlink(target, path string) error
	// Rename renames oldpath over newpath and flushes the directories.
	Rename(oldpath, newpath string) error
	// Unlink removes a non-directory with unlink(2), never rmdir(2), and
	// flushes its directory.
	Unlink(path string) error
	// RemoveAll removes path and everything under it, following no symlink,
	// and flushes its parent.
	RemoveAll(path string) error
	// Chmod sets the mode of a real file or directory, following no symlink.
	Chmod(path string, mode fs.FileMode) error
	// FlushTree makes every file and directory at or under path durable.
	FlushTree(path string) error
}

// OSFS is FS on the real filesystem.
type OSFS struct {
	// FullSync flushes one open file or directory to stable storage. Nil means
	// F_FULLFSYNC, which is the production value; a failure is never downgraded
	// to fsync(2). The field is the seam a test observes flushes through.
	FullSync func(f *os.File) error
}

var _ FS = (*OSFS)(nil)

func (o *OSFS) sync(f *os.File) error {
	if o.FullSync != nil {
		return o.FullSync(f)
	}
	return fullFsync(f)
}

// flushDir flushes the directory dir.
func (o *OSFS) flushDir(dir string) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s to flush it: %w", dir, err)
	}
	defer func() { _ = d.Close() }()
	if err := o.sync(d); err != nil {
		return fmt.Errorf("flush %s: %w", dir, err)
	}
	return nil
}

type osFile struct{ *os.File }

func (f osFile) Info() (Info, error) {
	fi, err := f.Stat()
	if err != nil {
		return Info{}, err
	}
	info := infoOf(fi)
	if info.HasACL, err = fdHasACL(f.Fd()); err != nil {
		return Info{}, fmt.Errorf("%s: %w", f.Name(), err)
	}
	return info, nil
}

func infoOf(fi fs.FileInfo) Info {
	info := Info{Mode: fi.Mode(), Size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		info.UID = st.Uid
		info.Flags = statFlags(st)
	} else {
		// No owner to read: report one no trust check accepts.
		info.UID = ^uint32(0)
	}
	return info
}

// OpenRead implements FS.
func (o *OSFS) OpenRead(path string) (File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s: %w", path, ErrSymlink)
		}
		return nil, err
	}
	return osFile{f}, nil
}

// Lstat implements FS.
func (o *OSFS) Lstat(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	return infoOf(fi), nil
}

// ReadDirNames implements FS.
func (o *OSFS) ReadDirNames(path string, max int) ([]string, error) {
	d, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	names, err := d.Readdirnames(max)
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	return names, err
}

// Readlink implements FS.
func (o *OSFS) Readlink(path string) (string, error) { return os.Readlink(path) }

// Mkdir implements FS.
func (o *OSFS) Mkdir(path string, mode fs.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil {
		return err
	}
	if err := o.Chmod(path, mode); err != nil {
		return err
	}
	return o.flushDir(filepath.Dir(path))
}

type osWriteFile struct {
	*os.File
	o *OSFS
}

func (w osWriteFile) Flush() error { return w.o.sync(w.File) }

// CreateExcl implements FS.
func (o *OSFS) CreateExcl(path string, mode fs.FileMode) (WriteFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return nil, err
	}
	return osWriteFile{File: f, o: o}, nil
}

// WriteFileAtomic implements FS. The temporary name is fixed so a crash leaves
// at most one, which the next write removes as a non-directory: the state
// directory has one writer.
func (o *OSFS) WriteFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp := path + ".tmp"
	if err := removeStale(o, tmp); err != nil {
		return err
	}
	w, err := o.CreateExcl(tmp, mode)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	if err == nil {
		err = w.Flush()
	}
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = o.Rename(tmp, path)
	}
	if err != nil {
		_ = syscall.Unlink(tmp)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Symlink implements FS.
func (o *OSFS) Symlink(target, path string) error { return os.Symlink(target, path) }

// Rename implements FS.
func (o *OSFS) Rename(oldpath, newpath string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	if err := o.flushDir(filepath.Dir(newpath)); err != nil {
		return err
	}
	if od := filepath.Dir(oldpath); od != filepath.Dir(newpath) {
		return o.flushDir(od)
	}
	return nil
}

// Unlink implements FS.
func (o *OSFS) Unlink(path string) error {
	if err := syscall.Unlink(path); err != nil {
		return &fs.PathError{Op: "unlink", Path: path, Err: err}
	}
	return o.flushDir(filepath.Dir(path))
}

// RemoveAll implements FS.
func (o *OSFS) RemoveAll(path string) error {
	if err := os.RemoveAll(path); err != nil {
		return err
	}
	return o.flushDir(filepath.Dir(path))
}

// Chmod implements FS.
func (o *OSFS) Chmod(path string, mode fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Chmod(mode)
}

// FlushTree implements FS.
func (o *OSFS) FlushTree(path string) error {
	return filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		if err := o.sync(f); err != nil {
			return fmt.Errorf("flush %s: %w", p, err)
		}
		return nil
	})
}
