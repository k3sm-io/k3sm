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
	"path"
	"path/filepath"

	"k3sm.io/k3sm/pkg/updater/layout"
)

var (
	// ErrACL reports a trusted path carrying an extended ACL, which grants what
	// the mode bits do not show.
	ErrACL = errors.New("carries an extended ACL")
	// ErrBSDFlags reports a trusted path with an immutable or append-only flag.
	ErrBSDFlags = errors.New("carries an immutable or append-only flag")
	// ErrTreeMember reports an entry of a version tree that is not a plain
	// root-owned file or directory, or a tree over its bounds.
	ErrTreeMember = errors.New("the version tree holds an unsafe entry")
	// ErrStaleIsDirectory reports a directory where a flip expected a stale
	// temporary link; the flip removes only links and files.
	ErrStaleIsDirectory = errors.New("a directory sits at a temporary link name")
)

// maxTreeDepth bounds the directory depth of a version tree.
const maxTreeDepth = 16

// descriptorLstat is the seam layout.CheckOwnership reads through: it opens the
// path with O_NOFOLLOW and answers from fstat on that descriptor, and it refuses
// an ACL or a denied flag, which the mode bits do not show.
func descriptorLstat(fsys FS) layout.Lstat {
	return func(name string) (layout.Entry, error) {
		f, err := fsys.OpenRead(name)
		if errors.Is(err, ErrSymlink) {
			return layout.Entry{Mode: fs.ModeSymlink}, nil
		}
		if err != nil {
			return layout.Entry{}, err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Info()
		if err != nil {
			return layout.Entry{}, err
		}
		if err := checkExtended(name, info); err != nil {
			return layout.Entry{}, err
		}
		return layout.Entry{UID: info.UID, Mode: info.Mode}, nil
	}
}

func checkExtended(name string, info Info) error {
	if info.HasACL {
		return fmt.Errorf("%s: %w", name, ErrACL)
	}
	if info.Flags&deniedFlags != 0 {
		return fmt.Errorf("%s: %w (flags %#x)", name, ErrBSDFlags, info.Flags)
	}
	return nil
}

// checkTrustedDirs refuses unless every directory and all its ancestors are
// real, root-owned and writable by nobody else.
func checkTrustedDirs(fsys FS, dirs ...string) error {
	for _, d := range dirs {
		if err := layout.CheckOwnership(descriptorLstat(fsys), d); err != nil {
			return err
		}
	}
	return nil
}

// treeEntry is one entry of a version tree.
type treeEntry struct {
	// rel is the slash-separated path relative to the tree.
	rel  string
	info Info
}

// walkTree lists the entries under dir from their own descriptors, refusing a
// symlink, anything but a regular file or directory, a set-id or sticky bit, and
// more than maxEntries entries or maxDepth levels.
func walkTree(fsys FS, dir string, maxEntries int) ([]treeEntry, error) {
	var out []treeEntry
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if depth > maxTreeDepth {
			return fmt.Errorf("%w: deeper than %d levels", ErrTreeMember, maxTreeDepth)
		}
		names, err := fsys.ReadDirNames(filepath.Join(dir, filepath.FromSlash(rel)), maxEntries+1)
		if err != nil {
			return err
		}
		for _, name := range names {
			child := path.Join(rel, name)
			if len(out) == maxEntries {
				return fmt.Errorf("%w: more than %d entries", ErrTreeMember, maxEntries)
			}
			info, err := entryInfo(fsys, filepath.Join(dir, filepath.FromSlash(child)))
			if err != nil {
				return fmt.Errorf("%w: %s: %w", ErrTreeMember, child, err)
			}
			if info.Mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
				return fmt.Errorf("%w: %s has a set-id or sticky bit", ErrTreeMember, child)
			}
			out = append(out, treeEntry{rel: child, info: info})
			switch {
			case info.Mode.IsDir():
				if err := walk(child, depth+1); err != nil {
					return err
				}
			case !info.Mode.IsRegular():
				return fmt.Errorf("%w: %s is %s", ErrTreeMember, child, info.Mode)
			}
		}
		return nil
	}
	if err := walk("", 0); err != nil {
		return nil, err
	}
	return out, nil
}

// entryInfo opens path no-follow and reports its descriptor's metadata.
func entryInfo(fsys FS, p string) (Info, error) {
	f, err := fsys.OpenRead(p)
	if err != nil {
		return Info{}, err
	}
	defer func() { _ = f.Close() }()
	return f.Info()
}

// verifyVersionTree re-verifies a version directory before the node runs from
// it: the directory and ancestors are trusted, and every entry is root-owned,
// writable by nobody else, with no ACL or denied flag.
func verifyVersionTree(fsys FS, dir string, maxEntries int) ([]treeEntry, error) {
	if err := checkTrustedDirs(fsys, dir); err != nil {
		return nil, err
	}
	entries, err := walkTree(fsys, dir, maxEntries)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := filepath.Join(dir, filepath.FromSlash(e.rel))
		switch {
		case e.info.UID != 0:
			return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrTreeMember, e.rel, e.info.UID)
		case e.info.Mode.Perm()&0o022 != 0:
			return nil, fmt.Errorf("%w: %s is writable by group or other (%s)", ErrTreeMember, e.rel, e.info.Mode.Perm())
		}
		if err := checkExtended(name, e.info); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrTreeMember, err)
		}
	}
	return entries, nil
}

// machOMagic reports whether head starts with a Mach-O or universal magic.
func machOMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	switch [4]byte(head[:4]) {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xce, 0xfa, 0xed, 0xfe},
		[4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xcf, 0xfa, 0xed, 0xfe},
		[4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca},
		[4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
		return true
	}
	return false
}

// readHead reads the first four bytes of the file at p.
func readHead(fsys FS, p string) ([]byte, error) {
	f, err := fsys.OpenRead(p)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 4)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return head[:n], nil
}
