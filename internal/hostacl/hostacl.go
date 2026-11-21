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

package hostacl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Perm is a set of acl(3) permission bits.
type Perm uint32

// Flag is a set of acl(3) entry flags.
type Flag uint32

// Access is what a grant gives the pods' user.
type Access int

const (
	// ReadWrite lets pods read, create, change and delete under a tree.
	ReadWrite Access = iota
	// ReadOnly lets pods list and read under a tree.
	ReadOnly
)

// The acl(3) permission and flag bits, from <sys/acl.h>. A directory and a
// file read the same bits differently (list or read, add_file or write,
// search or execute, add_subdirectory or append).
const (
	permRead        Perm = 1 << 1
	permWrite       Perm = 1 << 2
	permExecute     Perm = 1 << 3
	permDelete      Perm = 1 << 4
	permAppend      Perm = 1 << 5
	permDeleteChild Perm = 1 << 6
	permReadAttr    Perm = 1 << 7
	permWriteAttr   Perm = 1 << 8
	permReadXattr   Perm = 1 << 9
	permWriteXattr  Perm = 1 << 10
	permReadSec     Perm = 1 << 11

	flagFileInherit Flag = 1 << 5
	flagDirInherit  Flag = 1 << 6
)

// maxDepth bounds the walk; a tree deeper than this is refused, not
// half-granted silently.
const maxDepth = 256

// ErrUnsupported is returned by a build without cgo, which has no acl(3).
var ErrUnsupported = errors.New("hostacl: ACLs need a cgo build of k3sm")

func (a Access) dirPerms() Perm {
	if a == ReadOnly {
		return permRead | permExecute | permReadAttr | permReadXattr | permReadSec
	}
	return permRead | permWrite | permExecute | permDelete | permAppend | permDeleteChild |
		permReadAttr | permWriteAttr | permReadXattr | permWriteXattr | permReadSec
}

func (a Access) filePerms() Perm {
	if a == ReadOnly {
		return permRead | permExecute | permReadAttr | permReadXattr | permReadSec
	}
	return permRead | permWrite | permExecute | permDelete | permAppend |
		permReadAttr | permWriteAttr | permReadXattr | permWriteXattr | permReadSec
}

// DirEntry is the chmod(1) spelling of the entry a grant puts on each
// directory, for the report: "user:<name> allow <perms>".
func (a Access) DirEntry(user string) string {
	return fmt.Sprintf("user:%s allow %s,file_inherit,directory_inherit", user, permWords(a.dirPerms(), true))
}

// FileEntry is the chmod(1) spelling of the entry on each existing file.
func (a Access) FileEntry(user string) string {
	return fmt.Sprintf("user:%s allow %s", user, permWords(a.filePerms(), false))
}

func permWords(p Perm, dir bool) string {
	type w struct {
		bit       Perm
		dir, file string
	}
	words := []w{
		{permRead, "list", "read"}, {permWrite, "add_file", "write"}, {permExecute, "search", "execute"},
		{permDelete, "delete", "delete"}, {permAppend, "add_subdirectory", "append"},
		{permDeleteChild, "delete_child", ""}, {permReadAttr, "readattr", "readattr"},
		{permWriteAttr, "writeattr", "writeattr"}, {permReadXattr, "readextattr", "readextattr"},
		{permWriteXattr, "writeextattr", "writeextattr"}, {permReadSec, "readsecurity", "readsecurity"},
	}
	var out []string
	for _, x := range words {
		name := x.file
		if dir {
			name = x.dir
		}
		if p&x.bit != 0 && name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}

// Report counts what a tree walk did, so the caller can print it exactly.
type Report struct {
	// Dirs and Files had the entry added (or, for a revoke, removed).
	Dirs, Files int
	// Unchanged already had it (or, for a revoke, had none).
	Unchanged int
	// Skipped counts what the walk left alone, by reason: "symlink"
	// (never followed), "hard-linked file" (a grant would reach its other
	// names too), "not owned by <uid>", "unreadable", "special file".
	Skipped map[string]int
}

func (r *Report) skip(why string) {
	if r.Skipped == nil {
		r.Skipped = map[string]int{}
	}
	r.Skipped[why]++
}

// GrantTree adds, on root and on every directory and file under it that
// owner owns, an allow entry for podUID (and, for ReadWrite, the same entry
// for owner, so the owner keeps full access to what pods create). Directory
// entries are inheritable, so what pods create later carries them.
//
// The walk opens every component with O_NOFOLLOW and sets each ACL through
// the open descriptor, so it never follows a symlink, whether it was there
// before or a pod raced one in: chmod -R +a follows symlinks inside the tree
// and would put the entry on their targets. A regular file with more than
// one link is skipped, because an entry on it would also reach its names
// outside the share.
func GrantTree(root string, a Access, podUID, owner uint32) (Report, error) {
	return walkTree(root, owner, func(fd int, dir bool, r *Report) error {
		perms, flags := a.filePerms(), Flag(0)
		if dir {
			perms, flags = a.dirPerms(), flagFileInherit|flagDirInherit
		}
		added, err := addEntry(fd, "", podUID, perms, flags)
		if err != nil {
			return err
		}
		if a == ReadWrite {
			if _, err := addEntry(fd, "", owner, perms, flags); err != nil {
				return err
			}
		}
		count(r, dir, added)
		return nil
	}, true)
}

// RevokeTree removes every allow entry for podUID from root and from every
// directory and file under it that owner owns, inherited entries included.
// Entries for owner, and any deny entry, are left as they are.
func RevokeTree(root string, podUID, owner uint32) (Report, error) {
	return walkTree(root, owner, func(fd int, dir bool, r *Report) error {
		removed, err := removeEntries(fd, "", podUID)
		if err != nil {
			return err
		}
		count(r, dir, removed)
		return nil
	}, false)
}

func count(r *Report, dir, changed bool) {
	switch {
	case !changed:
		r.Unchanged++
	case dir:
		r.Dirs++
	default:
		r.Files++
	}
}

// GrantSocket lets podUID connect to the socket at path (connect(2) needs
// write permission on it). The path's parents were checked by the caller;
// the last component is acted on itself, never followed.
func GrantSocket(path string, podUID uint32) (bool, error) {
	if err := lstatKind(path, unix.S_IFSOCK); err != nil {
		return false, err
	}
	return addEntry(-1, path, podUID, permRead|permWrite, 0)
}

// RevokeSocket removes podUID's allow entries from the socket at path.
func RevokeSocket(path string, podUID uint32) (bool, error) {
	if err := lstatKind(path, unix.S_IFSOCK); err != nil {
		return false, err
	}
	return removeEntries(-1, path, podUID)
}

// GrantSearch lets podUID pass through dir (search only, not inherited).
func GrantSearch(dir string, podUID uint32) (bool, error) {
	fd, err := OpenNoFollow(dir)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	return addEntry(fd, "", podUID, permExecute, 0)
}

// RevokeSearch removes podUID's allow entries from dir.
func RevokeSearch(dir string, podUID uint32) (bool, error) {
	fd, err := OpenNoFollow(dir)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	return removeEntries(fd, "", podUID)
}

// Allowed returns the permissions allow entries on path give uid.
func Allowed(path string, uid uint32) (Perm, error) { return allowed(path, uid) }

// Search is the search (execute) bit of Perm.
const Search = permExecute

// Write is the write (add_file) bit of Perm.
const Write = permWrite

// OpenNoFollow opens the directory at the absolute path one component at a
// time from /, each with O_NOFOLLOW, so the result is that directory and no
// symlink on the way was followed.
func OpenNoFollow(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("hostacl: %q is not an absolute clean path", path)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, c := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if c == "" {
			continue
		}
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open %s: %w", path, err)
		}
		fd = next
	}
	return fd, nil
}

// CanonicalDir returns the directory path spelled the way its volume stores
// each name: `/users/DEV/code` on a case-insensitive volume becomes
// `/Users/dev/Code`. The node compares a pod's hostPath with a share entry
// exactly, so an entry is recorded in this spelling. A result that differs
// from path in more than letter case (a firmlink, say) is not used.
func CanonicalDir(path string) (string, error) {
	fd, err := OpenNoFollow(path)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	got, err := getPath(fd)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, path) {
		return path, nil
	}
	return got, nil
}

func lstatKind(path string, kind uint32) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if uint32(st.Mode)&unix.S_IFMT != kind {
		return fmt.Errorf("hostacl: %s is not the expected kind of file", path)
	}
	return nil
}

// walkTree runs fn on root and every directory and regular file under it
// that owner owns, through O_NOFOLLOW descriptors. hardLinksMatter skips a
// regular file with more than one link (for a grant; a revoke may narrow it).
func walkTree(root string, owner uint32, fn func(fd int, dir bool, r *Report) error, hardLinksMatter bool) (Report, error) {
	var r Report
	fd, err := OpenNoFollow(root)
	if err != nil {
		return r, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return r, err
	}
	w := walker{dev: st.Dev, owner: owner, fn: fn, hl: hardLinksMatter, r: &r}
	err = walkDir(fd, root, 0, w)
	return r, err
}

// walker carries one walk's fixed inputs. dev is the root's device: the
// walk never crosses into another file system mounted inside the tree.
type walker struct {
	dev   int32
	owner uint32
	fn    func(int, bool, *Report) error
	hl    bool
	r     *Report
}

func walkDir(fd int, path string, depth int, w walker) error {
	owner, fn, hl, r := w.owner, w.fn, w.hl, w.r
	defer unix.Close(fd)
	if depth > maxDepth {
		return fmt.Errorf("hostacl: %s is more than %d directories deep", path, maxDepth)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Dev != w.dev {
		r.skip("mount point")
		return nil
	}
	if st.Uid != owner {
		r.skip(fmt.Sprintf("not owned by uid %d", owner))
		// A directory someone else owns is not ours to change, nor is what
		// is under it: a pod-created directory already carries the
		// inherited entry.
		return nil
	}
	if err := fn(fd, true, r); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	d := os.NewFile(uintptr(dup), path)
	ents, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, e := range ents {
		child := filepath.Join(path, e.Name())
		switch t := e.Type(); {
		case t&os.ModeSymlink != 0:
			r.skip("symlink")
		case t.IsDir():
			cfd, err := unix.Openat(fd, e.Name(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				r.skip(unreadable(err))
				continue
			}
			if err := walkDir(cfd, child, depth+1, w); err != nil {
				return err
			}
		case t.IsRegular():
			// O_EVTONLY: an event-only descriptor needs no read
			// permission and does not make a cloud placeholder file
			// download its contents.
			cfd, err := unix.Openat(fd, e.Name(), unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				r.skip(unreadable(err))
				continue
			}
			err = walkFile(cfd, w.dev, owner, fn, hl, r)
			unix.Close(cfd)
			if err != nil {
				return fmt.Errorf("%s: %w", child, err)
			}
		default:
			r.skip("special file")
		}
	}
	return nil
}

func walkFile(fd int, dev int32, owner uint32, fn func(int, bool, *Report) error, hl bool, r *Report) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch {
	case st.Dev != dev:
		r.skip("mount point")
		return nil
	case uint32(st.Mode)&unix.S_IFMT != unix.S_IFREG:
		// Swapped for something else between the read and the open.
		r.skip("special file")
		return nil
	case st.Uid != owner:
		r.skip(fmt.Sprintf("not owned by uid %d", owner))
		return nil
	case hl && st.Nlink > 1:
		r.skip("hard-linked file")
		return nil
	}
	return fn(fd, false, r)
}

func unreadable(err error) string {
	if errors.Is(err, unix.ELOOP) {
		return "symlink"
	}
	return "unreadable"
}
