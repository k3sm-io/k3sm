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

package install

import (
	"debug/macho"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// executablePathPrefix is the dyld token a bundled binary's rpaths start with.
const executablePathPrefix = "@executable_path"

// errRelinkSourceDir reports a sourceDir that is not an absolute clean path.
var errRelinkSourceDir = errors.New("relink: source dir is not an absolute clean path")

// executableRpathRewrites lists, for the thin or fat Mach-O at path, each
// LC_RPATH that starts with @executable_path and the absolute path it resolves
// to when the binary sits in sourceDir: [old, new] pairs in load-command order,
// one per distinct old value. A fat binary must carry the same @executable_path
// rpaths in every slice (install_name_tool edits all slices at once).
func executableRpathRewrites(path, sourceDir string) ([][2]string, error) {
	if !filepath.IsAbs(sourceDir) || filepath.Clean(sourceDir) != sourceDir {
		return nil, fmt.Errorf("%w: %q", errRelinkSourceDir, sourceDir)
	}
	// Every rewritten rpath must stay inside the application bundle that
	// holds the source (<bundle>/Contents/Developer/...): the copy may load
	// the bundle's frameworks and nothing else by that route.
	bundle := ""
	if dev, ok := developerDirOf(sourceDir); ok && filepath.Base(filepath.Dir(dev)) == "Contents" {
		bundle = filepath.Dir(filepath.Dir(dev))
	}
	slices, err := machoRpaths(path)
	if err != nil {
		return nil, err
	}
	var want []string
	for i, rp := range slices {
		var exe []string
		for _, r := range rp {
			if strings.HasPrefix(r, executablePathPrefix) {
				exe = append(exe, r)
			}
		}
		if i == 0 {
			want = exe
			continue
		}
		if strings.Join(exe, "\x00") != strings.Join(want, "\x00") {
			return nil, fmt.Errorf("relink %s: the architecture slices disagree on their @executable_path rpaths", path)
		}
	}
	seen := map[string]bool{}
	var out [][2]string
	for _, old := range want {
		if seen[old] {
			continue
		}
		seen[old] = true
		rest := strings.TrimPrefix(old, executablePathPrefix)
		if rest != "" && !strings.HasPrefix(rest, "/") {
			return nil, fmt.Errorf("relink %s: rpath %q is neither @executable_path nor a path under it", path, old)
		}
		abs := filepath.Clean(sourceDir + rest)
		if bundle == "" || (abs != bundle && !strings.HasPrefix(abs, bundle+"/")) {
			return nil, fmt.Errorf("relink %s: rpath %q resolves to %s, outside the bundle %q", path, old, abs, bundle)
		}
		out = append(out, [2]string{old, abs})
	}
	return out, nil
}

// machoRpaths returns the LC_RPATH paths of each architecture slice of path.
func machoRpaths(path string) ([][]string, error) {
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		out := make([][]string, 0, len(ff.Arches))
		for _, a := range ff.Arches {
			out = append(out, rpathsOf(a.File))
		}
		return out, nil
	}
	f, err := macho.Open(path)
	if err != nil {
		return nil, fmt.Errorf("relink: read the Mach-O %s: %w", path, err)
	}
	defer f.Close()
	return [][]string{rpathsOf(f)}, nil
}

func rpathsOf(f *macho.File) []string {
	var out []string
	for _, l := range f.Loads {
		if r, ok := l.(*macho.Rpath); ok {
			out = append(out, r.Path)
		}
	}
	return out
}

// developerDirOf returns the developer dir that holds dir (the nearest
// ancestor named Developer, as in .../Contents/Developer/usr/bin), if any.
func developerDirOf(dir string) (string, bool) {
	for d := dir; d != "/" && d != "."; d = filepath.Dir(d) {
		if filepath.Base(d) == "Developer" {
			return d, true
		}
	}
	return "", false
}

// shadowRelinker is the part of System that makes a Relink shadow copy
// (B1786): the xcodebuild copy cloned out of Xcode.app.
type shadowRelinker interface {
	// RelinkRpaths rewrites every LC_RPATH of path that starts with
	// @executable_path to the absolute, cleaned path it names when the binary
	// sits in sourceDir, so a copy cloned out of an application bundle still
	// finds the bundle's frameworks. Other rpaths are left alone. It runs
	// before AdHocSign, which the edit invalidates. path must still be
	// Apple-signed; the tool it runs is staged and checked first. A trust
	// failure wraps errUntrustedSource.
	RelinkRpaths(path, sourceDir string) error
	// CheckTrustedSource reports whether a shadow source outside the
	// SIP-protected system trees may be copied: path and every ancestor up to
	// / is a real (not symlinked) file or directory owned by root and not
	// world-writable, and group-writable only for the admin group, whose
	// members can already become root. An error wraps errUntrustedSource, or
	// fs.ErrNotExist when the source is absent.
	CheckTrustedSource(path string) error
}

// errUntrustedSource reports a path some non-root identity could replace.
var errUntrustedSource = errors.New("not a root-owned, protected path")

// adminGID is the macOS admin group. Its members can become root, so a tree
// they may write (/Applications is root:admin 0775) is no weaker than root's.
const adminGID = 80

// trustStat is the part of lstat checkTrustedChain reads.
type trustStat struct {
	uid, gid uint32
	mode     uint32
}

// checkTrustedChain applies CheckTrustedSource's rule to path and each
// ancestor, with lstat injected for tests. A missing path wraps
// fs.ErrNotExist so the caller can tell "absent" from "untrusted".
func checkTrustedChain(path string, lstat func(string) (trustStat, error)) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: %q is not an absolute clean path", errUntrustedSource, path)
	}
	for p := path; ; p = filepath.Dir(p) {
		st, err := lstat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("%s: %w", p, fs.ErrNotExist)
			}
			return fmt.Errorf("%w: %s: lstat: %v", errUntrustedSource, p, err)
		}
		switch {
		case st.mode&unix.S_IFMT == unix.S_IFLNK:
			return fmt.Errorf("%w: %s is a symlink", errUntrustedSource, p)
		case st.uid != 0:
			return fmt.Errorf("%w: %s is owned by uid %d, not root", errUntrustedSource, p, st.uid)
		case st.mode&unix.S_IWOTH != 0:
			return fmt.Errorf("%w: %s is world-writable", errUntrustedSource, p)
		case st.mode&unix.S_IWGRP != 0 && st.gid != 0 && st.gid != adminGID:
			return fmt.Errorf("%w: %s is writable by group %d", errUntrustedSource, p, st.gid)
		}
		if p == "/" {
			return nil
		}
	}
}

// rpathImports lists the leaf names of path's @rpath/<name> dylib imports
// (thin or fat; the slices must agree). A name with a directory part is
// refused so a staged copy cannot reach outside its lib/ directory.
func rpathImports(path string) ([]string, error) {
	var sets [][]string
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		for _, a := range ff.Arches {
			l, err := a.ImportedLibraries()
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			sets = append(sets, l)
		}
	} else {
		f, err := macho.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer f.Close()
		l, err := f.ImportedLibraries()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		sets = append(sets, l)
	}
	var out []string
	for i, libs := range sets {
		var names []string
		for _, l := range libs {
			name, ok := strings.CutPrefix(l, "@rpath/")
			if !ok {
				continue
			}
			if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
				return nil, fmt.Errorf("%s imports %q, which is not a plain @rpath dylib name", path, l)
			}
			names = append(names, name)
		}
		if i == 0 {
			out = names
		} else if strings.Join(names, "\x00") != strings.Join(out, "\x00") {
			return nil, fmt.Errorf("%s: slices disagree on @rpath imports", path)
		}
	}
	return out, nil
}
