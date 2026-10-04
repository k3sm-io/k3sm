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

package atomicfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tempInfix is the one definition of the temp-file naming: a temp for target name is
// "." + name + tempInfix + the digits os.CreateTemp appends.
const tempInfix = ".tmp-"

// tempPrefix returns the temp-file name prefix for the target named name.
func tempPrefix(name string) string { return "." + name + tempInfix }

// WriteNew installs data at path with mode. The bytes go to a temp file in path's
// directory (created 0600, so secret material is never readable mid-write), which is
// chmod'ed to mode, fsync'ed and hard-linked to path; the directory is then fsync'ed so
// the new name is durable. link(2) fails with EEXIST when path exists, so the
// no-overwrite check and the install are one kernel step: an existing path yields an
// error wrapping fs.ErrExist and is left untouched. The temp file is removed on every
// return, success or error.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, tempPrefix(filepath.Base(path)))
	if err != nil {
		return fmt.Errorf("atomicfile: create temp for %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := writeAndSync(tmp, data, mode); err != nil {
		return fmt.Errorf("atomicfile: write temp for %s: %w", path, err)
	}
	if err := os.Link(tmpPath, path); err != nil {
		return fmt.Errorf("atomicfile: install %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("atomicfile: sync directory of %s: %w", path, err)
	}
	return nil
}

// ReapOrphans removes the temp files a killed WriteNew of dir/name may have left: the
// regular files in dir named ".<name>.tmp-<digits>". Nothing else is touched, and an
// absent dir is not an error. It must not run concurrently with a WriteNew of the same
// target, whose temp it would remove.
func ReapOrphans(dir, name string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("atomicfile: read %s: %w", dir, err)
	}
	prefix := tempPrefix(name)
	for _, e := range entries {
		if !isTempOf(e.Name(), prefix) || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("atomicfile: remove orphan temp %s: %w", p, err)
		}
	}
	return nil
}

// isTempOf reports whether entry is prefix followed by one or more digits.
func isTempOf(entry, prefix string) bool {
	rest, ok := strings.CutPrefix(entry, prefix)
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// writeAndSync sets f's mode, writes data, fsyncs and closes f. f is closed on every
// path.
func writeAndSync(f *os.File, data []byte, mode os.FileMode) error {
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// syncDir fsyncs the directory dir so a link made in it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}
