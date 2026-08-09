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

package oci

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

// Context errors.
var (
	// ErrContextEscape reports a COPY/ADD source that resolves outside the build
	// context root — lexically ("../x"), or after symlink resolution (an
	// in-context symlink, or an in-context directory component that is a
	// symlink, pointing out).
	ErrContextEscape = errors.New("oci: source escapes the build context")

	// ErrSourceNotFound reports a COPY/ADD source with no match in the context.
	ErrSourceNotFound = errors.New("oci: source not found in the build context")

	// ErrUnsupportedFileType reports a context entry that is neither a regular
	// file, a directory, nor a symlink. Devices, FIFOs and sockets are
	// capabilities, not build artifacts, and are refused rather than skipped —
	// a silent skip yields an image missing content the recipe asked for.
	ErrUnsupportedFileType = errors.New("oci: unsupported file type in the build context")

	// ErrContextTooLarge reports a context selection exceeding the byte budget.
	ErrContextTooLarge = errors.New("oci: build context selection is too large")
)

// MaxContextBytes bounds the total bytes one BUILD may read from the context —
// the budget is carried on the Context and spent across every COPY/ADD, not
// reset per instruction (a per-instruction cap bounds nothing, since the
// Dockerfile chooses the instruction count).
//
// On a single-Mac cluster the store shares a volume with the kine datastore, so
// an unbounded `COPY .` at the wrong root is a control-plane availability
// problem, not just a large image.
const MaxContextBytes int64 = 2 << 30 // 2 GiB

// Context is an operator-supplied build-context directory. It is the only
// gateway between a Dockerfile-supplied string and the filesystem.
type Context struct {
	root         string // absolute, as given
	rootResolved string // absolute, symlink-resolved

	// remaining is the build-wide read budget, spent across all instructions.
	remaining int64
}

// NewContext opens dir as a build context. The root is resolved once so every
// later containment check is resolved-vs-resolved (on macOS /var is itself a
// symlink to /private/var, so an unresolved comparison produces false escapes).
func NewContext(dir string) (*Context, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve build context %s: %w", dir, err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("open build context %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("build context %s is not a directory", dir)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve build context %s: %w", dir, err)
	}
	return &Context{root: abs, rootResolved: resolved, remaining: MaxContextBytes}, nil
}

// Root returns the context directory as given (absolute, unresolved).
func (c *Context) Root() string { return c.root }

// isUnder reports whether path is root itself or lies beneath it. Both operands
// must already be cleaned absolute paths.
func isUnder(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(os.PathSeparator))
}

// resolve maps a Dockerfile-supplied source string to a host path inside the
// context, or returns ErrContextEscape.
//
// An ABSOLUTE source is interpreted relative to the context root (Docker
// parity): "COPY /etc/passwd x" reads <context>/etc/passwd, never the host file.
// The forbidden implementation is `if filepath.IsAbs(src) { use src }`.
func (c *Context) resolve(src string) (string, error) {
	rel := src
	if filepath.IsAbs(rel) {
		rel = strings.TrimPrefix(rel, string(os.PathSeparator))
	}
	target := filepath.Join(c.root, rel)
	if !isUnder(target, c.root) {
		return "", fmt.Errorf("%q: %w", src, ErrContextEscape)
	}
	return target, nil
}

// checkResolved re-checks containment after symlink resolution. It is applied to
// every path whose bytes or metadata are about to be read, so an in-context
// symlink — or an intermediate directory component that is one — cannot redirect
// the read outside the root.
func (c *Context) checkResolved(path, src string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%q: %w", src, ErrSourceNotFound)
		}
		return fmt.Errorf("resolve %q: %w", src, err)
	}
	if !isUnder(resolved, c.rootResolved) {
		return fmt.Errorf("%q resolves outside the build context: %w", src, ErrContextEscape)
	}
	return nil
}

// entry is one file selected from the context for inclusion in a layer.
type entry struct {
	name string      // slash-separated path inside the image, no leading "/"
	mode fs.FileMode // the source's mode, normalized at tar-write time
	size int64
	dir  bool
	link string // symlink target, when the entry is a symlink
	host string // the host path to read bytes from (empty for dirs and symlinks)
}

// selectEntries expands one COPY/ADD instruction into the entries it contributes,
// sorted by in-image name so a layer's tar order is a function of content only.
//
// dest semantics follow Docker: a trailing "/" (or more than one source) means
// dest is a directory and each source keeps its base name; otherwise a single
// source is renamed to dest.
func (c *Context) selectEntries(srcs []string, dest, workdir string) ([]entry, error) {
	destPath := dest
	if !strings.HasPrefix(destPath, "/") {
		destPath = filepath.Join(workdir, destPath)
	}
	// A destination is a directory when it ends in "/", when it is "." or ".."
	// (bare or as a final component), or when more than one source targets it.
	// Recognizing only "/" would make `COPY app .` a file RENAME: under
	// `WORKDIR /w` it silently writes the payload as a regular file named "w"
	// where the working directory should be.
	destIsDir := strings.HasSuffix(dest, "/") ||
		dest == "." || dest == ".." ||
		strings.HasSuffix(dest, "/.") || strings.HasSuffix(dest, "/..") ||
		len(srcs) > 1

	var out []entry
	for _, src := range srcs {
		matches, err := c.glob(src)
		if err != nil {
			return nil, err
		}
		for _, host := range matches {
			if err := c.checkResolved(host, src); err != nil {
				return nil, err
			}
			rel, err := filepath.Rel(c.root, host)
			if err != nil {
				return nil, fmt.Errorf("relativize %q: %w", src, err)
			}
			fi, err := os.Lstat(host)
			if err != nil {
				return nil, fmt.Errorf("stat %q: %w", src, err)
			}

			// Docker semantics: a DIRECTORY source contributes its CONTENTS to
			// dest — the directory itself is not recreated there. A file source
			// keeps its base name only when dest is a directory.
			var target string
			switch {
			case fi.IsDir():
				target = destPath
			case destIsDir || len(matches) > 1:
				target = filepath.Join(destPath, filepath.Base(rel))
			default:
				target = destPath
			}
			got, n, err := c.walkInto(host, target, src)
			if err != nil {
				return nil, err
			}
			c.remaining -= n
			if c.remaining < 0 {
				return nil, fmt.Errorf("build exceeds the %d-byte context budget: %w", MaxContextBytes, ErrContextTooLarge)
			}
			out = append(out, got...)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q: %w", strings.Join(srcs, " "), ErrSourceNotFound)
	}

	// STABLE sort: the dedup below keeps the LAST of each equal-name run, so the
	// winner must be the last SOURCE. An unstable sort would let the Go runtime's
	// pivot choice pick the winner, making the emitted bytes — and therefore the
	// layer digest — a function of the toolchain rather than of the recipe.
	sort.SliceStable(out, func(i, j int) bool { return out[i].name < out[j].name })
	// A later source may name the same in-image path as an earlier one; the last
	// wins, as it would with successive writes into a filesystem.
	dedup := out[:0]
	for i, e := range out {
		if i+1 < len(out) && out[i+1].name == e.name {
			continue
		}
		dedup = append(dedup, e)
	}
	return dedup, nil
}

// glob expands a source pattern within the context. Non-pattern sources are
// resolved directly so a literal path containing no metacharacters reports
// ErrSourceNotFound rather than an empty match set.
func (c *Context) glob(src string) ([]string, error) {
	target, err := c.resolve(src)
	if err != nil {
		return nil, err
	}
	if !strings.ContainsAny(src, "*?[") {
		if _, err := os.Lstat(target); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%q: %w", src, ErrSourceNotFound)
			}
			return nil, fmt.Errorf("stat %q: %w", src, err)
		}
		return []string{target}, nil
	}
	matches, err := filepath.Glob(target)
	if err != nil {
		return nil, fmt.Errorf("glob %q: %w", src, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%q: %w", src, ErrSourceNotFound)
	}
	// Every expansion is containment-checked independently: a glob may select an
	// escaping symlink that the pattern itself did not name.
	sort.Strings(matches)
	for _, m := range matches {
		if !isUnder(m, c.root) {
			return nil, fmt.Errorf("%q expands outside the build context: %w", src, ErrContextEscape)
		}
	}
	return matches, nil
}

// walkInto expands one selected host path (file, symlink or directory tree) into
// entries rooted at name, returning the total byte size selected.
func (c *Context) walkInto(host, name, src string) ([]entry, int64, error) {
	fi, err := os.Lstat(host)
	if err != nil {
		return nil, 0, fmt.Errorf("stat %q: %w", src, err)
	}
	// filepath.Clean absorbs a leading "/.." (it is a no-op at the root), so a
	// destination can never carry an upward traversal into an entry name. The
	// checkEntryName backstop in layer.go asserts that rather than assuming it.
	name = strings.TrimPrefix(filepath.ToSlash(filepath.Clean(name)), "/")
	if name == "." {
		name = "" // the image root
	}

	if !fi.IsDir() {
		if name == "" {
			return nil, 0, fmt.Errorf("%q has an empty destination: %w", src, ErrBadInstruction)
		}
		e, n, err := c.leaf(host, name, src, fi)
		if err != nil {
			return nil, 0, err
		}
		return []entry{e}, n, nil
	}

	var (
		out   []entry
		total int64
	)
	// WalkDir does not descend into symlinks, so a symlinked subdirectory is
	// visited as a link and handled by leaf's containment check.
	err = filepath.WalkDir(host, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(host, p)
		if err != nil {
			return err
		}
		inImage := name
		if rel != "." {
			inImage = filepath.ToSlash(rel)
			if name != "" {
				inImage = name + "/" + inImage
			}
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The image root needs no entry of its own.
			if inImage == "" {
				return nil
			}
			out = append(out, entry{name: inImage, mode: fi.Mode(), dir: true})
			return nil
		}
		e, n, err := c.leaf(p, inImage, src, fi)
		if err != nil {
			return err
		}
		total += n
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// leaf builds the entry for a non-directory path, enforcing the type allowlist
// and re-checking containment for symlinks.
func (c *Context) leaf(host, name, src string, fi fs.FileInfo) (entry, int64, error) {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		// The link is preserved as a symlink entry rather than inlined, so the
		// image records what the recipe described. Its target must still resolve
		// inside the context: an escaping link would otherwise let the image
		// reference a host path the operator never offered.
		if err := c.checkResolved(host, src); err != nil {
			return entry{}, 0, err
		}
		dst, err := os.Readlink(host)
		if err != nil {
			return entry{}, 0, fmt.Errorf("readlink %q: %w", src, err)
		}
		return entry{name: name, mode: fi.Mode(), link: dst}, 0, nil
	case fi.Mode().IsRegular():
		return entry{name: name, mode: fi.Mode(), size: fi.Size(), host: host}, fi.Size(), nil
	default:
		return entry{}, 0, fmt.Errorf("%s (%s): %w", name, fi.Mode().Type(), ErrUnsupportedFileType)
	}
}

// openRegular opens a regular file for reading with O_NOFOLLOW and returns it
// with its authoritative size, taken from the descriptor rather than from a
// prior path stat. Sizing from the fd rather than from a prior path stat is what
// lets copyBody refuse a file that changed under it.
//
// Honest limit: O_NOFOLLOW guards the FINAL path component only. An intermediate
// directory swapped for a symlink between selection and the read would still
// redirect it. Closing that needs an openat-from-root-fd walk (or Darwin's
// O_NOFOLLOW_ANY); it is not closed here, and the exposure is a concurrent
// writer inside the operator's own build context.
func openRegular(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, 0, fmt.Errorf("%s (%s): %w", path, fi.Mode().Type(), ErrUnsupportedFileType)
	}
	return f, fi.Size(), nil
}
