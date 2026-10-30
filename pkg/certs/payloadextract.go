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

package certs

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// versionMarkerSuffix and maxVersionMarkerBytes give the shape of a version
// marker: a file named <name>.version, under 4 KiB, of printable ASCII and
// newlines.
const (
	versionMarkerSuffix   = ".version"
	maxVersionMarkerBytes = 4 << 10
)

// machOMagics are the first four bytes, read big-endian, of a Mach-O
// (MH_MAGIC, MH_MAGIC_64) or a universal binary (FAT_MAGIC, FAT_MAGIC_64), in
// either byte order.
var machOMagics = []uint32{
	0xfeedface, 0xcefaedfe,
	0xfeedfacf, 0xcffaedfe,
	0xcafebabe, 0xbebafeca,
	0xcafebabf, 0xbfbafeca,
}

// setIDBits are the mode bits no extracted member may carry.
const setIDBits = unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX

// Modes of what extraction creates: directories and Mach-O members are
// 0755, version markers 0644.
const (
	payloadDirMode    fs.FileMode = 0o755
	payloadExecMode   fs.FileMode = 0o755
	payloadMarkerMode fs.FileMode = 0o644
)

// extractPayload unpacks the gzip tar r into dst, an existing empty
// directory. It writes only regular files the manifest lists and directories
// that lie on the path of one, refusing everything VerifySignedPayload names
// in its step 4. Files are created exclusively, never through a symlink.
func extractPayload(ctx context.Context, r io.Reader, dst string, m *PayloadManifest, lim payloadLimits) error {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("%w: the archive is not gzip: %w", ErrPayloadMember, err)
	}
	defer zr.Close()
	declared := make(map[string]PayloadMember, len(m.Members))
	dirs := map[string]bool{}
	for _, mem := range m.Members {
		declared[mem.Path] = mem
		for d := path.Dir(mem.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	tr := tar.NewReader(zr)
	var total int64
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: read the archive: %w", ErrPayloadMember, err)
		}
		if entries >= lim.members {
			return fmt.Errorf("%w: the archive holds more than %d entries", ErrPayloadTooLarge, lim.members)
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		name, err := payloadMemberName(hdr)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeSymlink:
			return fmt.Errorf("%w: the archive member %s is a symlink", ErrPayloadMember, name)
		case tar.TypeLink:
			return fmt.Errorf("%w: the archive member %s is a hard link", ErrPayloadMember, name)
		default:
			return fmt.Errorf("%w: the archive member %s is not a regular file or directory (type %q)", ErrPayloadMember, name, hdr.Typeflag)
		}
		if hdr.Mode&setIDBits != 0 {
			return fmt.Errorf("%w: the archive member %s carries a set-id or sticky bit", ErrPayloadMember, name)
		}
		if hdr.Typeflag == tar.TypeDir {
			if !dirs[name] {
				return fmt.Errorf("%w: the archive carries the directory %s, which holds no manifest member", ErrPayloadManifest, name)
			}
			if err := mkdirPayloadDirs(dst, name); err != nil {
				return err
			}
			continue
		}
		if hdr.Size < 0 || hdr.Size > lim.extractedBytes-total {
			return fmt.Errorf("%w: the archive unpacks to more than %d bytes", ErrPayloadTooLarge, lim.extractedBytes)
		}
		total += hdr.Size
		mem, ok := declared[name]
		if !ok {
			return fmt.Errorf("%w: the archive member %s is not in the manifest", ErrPayloadManifest, name)
		}
		perm := payloadExecMode
		if mem.Kind == PayloadVersionMarker {
			perm = payloadMarkerMode
		}
		if err := writePayloadMember(tr, dst, name, hdr.Size, perm); err != nil {
			return err
		}
	}
}

// payloadMemberName is the member's clean relative path ("./" and a
// directory's trailing "/" dropped), or a refusal.
func payloadMemberName(hdr *tar.Header) (string, error) {
	name := strings.TrimPrefix(hdr.Name, "./")
	if hdr.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	if !cleanMemberPath(name) {
		return "", fmt.Errorf("%w: the archive member name %q is not a clean relative path", ErrPayloadMember, hdr.Name)
	}
	return name, nil
}

// mkdirPayloadDirs creates every component of the relative directory rel
// under dst, requiring each existing component to be a real directory.
func mkdirPayloadDirs(dst, rel string) error {
	cur := dst
	for _, c := range strings.Split(rel, "/") {
		cur = filepath.Join(cur, c)
		err := os.Mkdir(cur, payloadDirMode)
		if err == nil {
			if err := os.Chmod(cur, payloadDirMode); err != nil {
				return fmt.Errorf("chmod %s: %w", cur, err)
			}
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", cur, err)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", cur, err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrPayloadMember, cur)
		}
	}
	return nil
}

// writePayloadMember writes size bytes of r to dst/name with mode perm.
func writePayloadMember(r io.Reader, dst, name string, size int64, perm fs.FileMode) error {
	if dir := path.Dir(name); dir != "." {
		if err := mkdirPayloadDirs(dst, dir); err != nil {
			return err
		}
	}
	p := filepath.Join(dst, filepath.FromSlash(name))
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("%w: create %s: %w", ErrPayloadMember, p, err)
	}
	n, err := io.Copy(out, io.LimitReader(r, size))
	if err == nil && n != size {
		err = fmt.Errorf("%w: the archive member %s is truncated", ErrPayloadMember, name)
	}
	if err == nil {
		err = out.Chmod(perm)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	return nil
}

// checkExtractedSet re-reads every file under dst and requires the set to be
// exactly the manifest's members, each with its digest and its kind.
func checkExtractedSet(ctx context.Context, dst string, m *PayloadManifest) error {
	declared := make(map[string]PayloadMember, len(m.Members))
	for _, mem := range m.Members {
		declared[mem.Path] = mem
	}
	found := make(map[string]bool, len(m.Members))
	err := filepath.WalkDir(dst, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dst, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !d.Type().IsRegular() {
			return fmt.Errorf("%w: the extracted %s is not a regular file", ErrPayloadMember, rel)
		}
		mem, ok := declared[rel]
		if !ok {
			return fmt.Errorf("%w: the extracted %s is not in the manifest", ErrPayloadManifest, rel)
		}
		if err := checkExtractedFile(p, mem); err != nil {
			return err
		}
		found[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	for _, mem := range m.Members {
		if !found[mem.Path] {
			return fmt.Errorf("%w: the archive does not carry the manifest member %s", ErrPayloadManifest, mem.Path)
		}
	}
	return nil
}

// checkExtractedFile hashes the file at p, never through a symlink, and
// checks it against mem: the digest, and the kind its content shows.
func checkExtractedFile(p string, mem PayloadMember) error {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", p, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", p, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return fmt.Errorf("%w: the extracted %s is not a plain regular file", ErrPayloadMember, mem.Path)
	}
	h := sha256.New()
	head := &headWriter{max: maxVersionMarkerBytes}
	if _, err := io.Copy(io.MultiWriter(h, head), f); err != nil {
		return fmt.Errorf("read %s: %w", p, err)
	}
	machO := isMachOHeader(head.buf)
	switch mem.Kind {
	case PayloadMachO:
		if !machO {
			return fmt.Errorf("%w: the manifest declares %s a Mach-O and it is not one", ErrPayloadMember, mem.Path)
		}
	case PayloadVersionMarker:
		if machO || fi.Size() >= maxVersionMarkerBytes || !printableText(head.buf) {
			return fmt.Errorf("%w: the declared version marker %s is not a small text file", ErrPayloadMember, mem.Path)
		}
	default:
		return fmt.Errorf("%w: the manifest member %s has unknown kind %q", ErrPayloadManifest, mem.Path, mem.Kind)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != mem.SHA256 {
		return fmt.Errorf("%w: the extracted %s has sha256 %s, the signed manifest says %s", ErrPayloadDigest, mem.Path, got, mem.SHA256)
	}
	return nil
}

// headWriter keeps the first max bytes written to it and discards the rest.
type headWriter struct {
	buf []byte
	max int
}

// Write implements io.Writer, always reporting the whole write.
func (w *headWriter) Write(b []byte) (int, error) {
	if room := w.max - len(w.buf); room > 0 {
		w.buf = append(w.buf, b[:min(room, len(b))]...)
	}
	return len(b), nil
}

// isMachOHeader reports whether b starts with a Mach-O or universal magic.
func isMachOHeader(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	m := binary.BigEndian.Uint32(b[:4])
	for _, want := range machOMagics {
		if m == want {
			return true
		}
	}
	return false
}

// printableText reports whether b holds only printable ASCII and newlines.
func printableText(b []byte) bool {
	for _, c := range b {
		if c != '\n' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}
