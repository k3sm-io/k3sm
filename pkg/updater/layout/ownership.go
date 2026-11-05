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

package layout

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

// Entry is what the ownership check needs to know about one path, as lstat(2)
// reports it: the owner and the mode, with the type bits.
type Entry struct {
	// UID is the owning user id.
	UID uint32
	// Mode is the file mode, type bits included.
	Mode fs.FileMode
}

// Lstat reports a path's Entry without following a final symlink. It is the
// seam CheckOwnership reads the filesystem through.
type Lstat func(name string) (Entry, error)

// CheckOwnership refuses dir unless it and every ancestor up to the
// filesystem root is a real directory (a symlink is refused), owned by root,
// and not writable by its group or by other users. A directory anyone else can
// write is one whose entries, a version directory or a layout symlink among
// them, can be swapped under the updater. dir must be absolute.
func CheckOwnership(lstat Lstat, dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("ownership of %q: %w: not an absolute path", dir, ErrBadName)
	}
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		e, err := lstat(p)
		if err != nil {
			return fmt.Errorf("ownership of %s: %w", p, err)
		}
		switch {
		case e.Mode.Type() != fs.ModeDir:
			return fmt.Errorf("ownership of %s: %s is %w (mode %s)", dir, p, ErrNotDirectory, e.Mode)
		case e.UID != 0:
			return fmt.Errorf("ownership of %s: %s is %w (uid %d)", dir, p, ErrNotRootOwned, e.UID)
		case e.Mode.Perm()&0o022 != 0:
			return fmt.Errorf("ownership of %s: %s is %w (mode %s)", dir, p, ErrWritableByOthers, e.Mode.Perm())
		}
		if parent := filepath.Dir(p); parent == p {
			return nil
		}
	}
}
