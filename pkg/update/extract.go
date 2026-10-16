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

package update

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/darwin-net/pkg/netd/wire"

	"k3sm.io/k3sm/pkg/install"
)

// SetMembers is the build set an archive must carry, as slash-separated paths
// relative to the archive root: k3sm, the files install requires beside it
// (install.RequiredSiblings: the exec shim, the two DYLD shims, the VM-host
// helper and the cp-payload binaries). They are extracted, and nothing else.
func SetMembers() []string {
	out := []string{"k3sm"}
	for _, p := range install.RequiredSiblings("") {
		out = append(out, filepath.ToSlash(p))
	}
	return out
}

// skippedMembers are the release archive members that are not part of the
// build set: the legal files and the k3sm-netd copy of the k3sm binary that
// the archive ships but install never copies. They are read past and never
// written. Every other name outside SetMembers refuses the archive.
var skippedMembers = []string{"LICENSE", "NOTICE", "k3sm-netd"}

// setDirs are the only directories an archive may name.
var setDirs = []string{install.PayloadDirName}

// maxSetBytes bounds the bytes an archive may unpack to, the same bound the
// root helper puts on the set it copies.
const maxSetBytes = wire.MaxUpdateSetBytes

// ExtractSet unpacks the gzip tar at archive into dst, an existing empty
// directory, and returns the manifest of what it wrote: the sha256 of every
// file, by slash-separated relative path. Call it only after the archive's own
// sha256 matched.
//
// It writes regular files only, and only the SetMembers names (each once, all
// of them present); a directory only when setDirs names it. A symlink, a hard
// link, a device or any other entry type refuses, as does an absolute path, a
// ".." component, an unclean path, a name outside the set (skippedMembers
// aside) and an archive that unpacks to more than maxSetBytes. Files are
// created exclusively, never through a symlink, with their permission bits
// less group and other write and any set-id bit.
func ExtractSet(archive, dst string) (map[string]string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, fmt.Errorf("open the archive: %w", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("%w: the archive is not gzip: %w", ErrRefused, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	members := SetMembers()
	manifest := map[string]string{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: read the archive: %w", ErrRefused, err)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := memberName(hdr)
		if err != nil {
			return nil, err
		}
		mode := hdr.FileInfo().Mode()
		switch {
		case mode.IsDir():
			if !slices.Contains(setDirs, name) {
				return nil, fmt.Errorf("%w: the archive names the directory %s, which is not in the build set", ErrRefused, name)
			}
			if err := mkdirOwn(filepath.Join(dst, filepath.FromSlash(name))); err != nil {
				return nil, err
			}
			continue
		case mode&fs.ModeSymlink != 0 || hdr.Typeflag == tar.TypeLink:
			return nil, fmt.Errorf("%w: the archive member %s is a link", ErrRefused, name)
		case !mode.IsRegular():
			return nil, fmt.Errorf("%w: the archive member %s is not a regular file", ErrRefused, name)
		}
		if hdr.Size < 0 || hdr.Size > maxSetBytes-total {
			return nil, fmt.Errorf("%w: the archive unpacks to more than %d bytes", ErrRefused, maxSetBytes)
		}
		total += hdr.Size
		if slices.Contains(skippedMembers, name) {
			if _, err := io.Copy(io.Discard, tr); err != nil {
				return nil, fmt.Errorf("%w: read the archive: %w", ErrRefused, err)
			}
			continue
		}
		if !slices.Contains(members, name) {
			return nil, fmt.Errorf("%w: the archive member %s is not in the build set", ErrRefused, name)
		}
		if _, dup := manifest[name]; dup {
			return nil, fmt.Errorf("%w: the archive names %s twice", ErrRefused, name)
		}
		sum, err := writeMember(tr, dst, name, hdr.Size, mode.Perm())
		if err != nil {
			return nil, err
		}
		manifest[name] = sum
	}
	for _, m := range members {
		if _, ok := manifest[m]; !ok {
			return nil, fmt.Errorf("%w: the archive does not carry %s", ErrRefused, m)
		}
	}
	return manifest, nil
}

// memberName is the member's clean relative path ("./" and a directory's
// trailing "/" dropped), or a refusal.
func memberName(hdr *tar.Header) (string, error) {
	name := strings.TrimPrefix(hdr.Name, "./")
	if hdr.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	bad := name == "" || strings.HasPrefix(name, "/") || strings.ContainsAny(name, "\x00\\") || path.Clean(name) != name
	for _, c := range strings.Split(name, "/") {
		if c == ".." || c == "." {
			bad = true
		}
	}
	if bad {
		return "", fmt.Errorf("%w: the archive member name %q is not a clean relative path", ErrRefused, hdr.Name)
	}
	return name, nil
}

// mkdirOwn creates dir, mode 0700, when it is absent, and otherwise requires
// a real directory.
func mkdirOwn(dir string) error {
	err := os.Mkdir(dir, 0o700)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrRefused, dir)
	}
	return nil
}

// writeMember writes size bytes of r to dst/name, hashing them.
func writeMember(r io.Reader, dst, name string, size int64, perm fs.FileMode) (string, error) {
	p := filepath.Join(dst, filepath.FromSlash(name))
	if dir := filepath.Dir(p); dir != filepath.Clean(dst) {
		if err := mkdirOwn(dir); err != nil {
			return "", err
		}
	}
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", p, err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(r, size))
	if err == nil && n != size {
		err = fmt.Errorf("%w: the archive member %s is truncated", ErrRefused, name)
	}
	if err == nil {
		err = out.Chmod(perm&0o755 | 0o600)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("write %s: %w", p, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
