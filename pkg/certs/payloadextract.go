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
	"syscall"

	"golang.org/x/sys/unix"
)

// payloadMarkerDir, versionMarkerSuffix and maxVersionMarkerBytes give the
// shape of a version marker: a file cp-payload/<name>.version, under 4 KiB,
// of printable ASCII and newlines.
const (
	payloadMarkerDir      = "cp-payload"
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
// 0755, version markers and data members 0644.
const (
	payloadDirMode  fs.FileMode = 0o755
	payloadExecMode fs.FileMode = 0o755
	payloadDataMode fs.FileMode = 0o644
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
	stream := &payloadStream{ctx: ctx, r: zr, left: lim.extractedBytes + lim.headerBytes}
	declared := make(map[string]PayloadMember, len(m.Members))
	dirs := map[string]bool{}
	for _, mem := range m.Members {
		declared[mem.Path] = mem
		for d := path.Dir(mem.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	tr := tar.NewReader(stream)
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
			if errors.Is(err, ErrPayloadTooLarge) || ctx.Err() != nil {
				return err
			}
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
			return fmt.Errorf("%w: the archive member %s is a symlink", ErrPayloadMember, untrusted(name))
		case tar.TypeLink:
			return fmt.Errorf("%w: the archive member %s is a hard link", ErrPayloadMember, untrusted(name))
		default:
			return fmt.Errorf("%w: the archive member %s is not a regular file or directory (type %q)", ErrPayloadMember, untrusted(name), hdr.Typeflag)
		}
		if hdr.Mode&setIDBits != 0 {
			return fmt.Errorf("%w: the archive member %s carries a set-id or sticky bit", ErrPayloadMember, untrusted(name))
		}
		if hdr.Typeflag == tar.TypeDir {
			if !dirs[name] {
				return fmt.Errorf("%w: the archive carries the directory %s, which holds no manifest member", ErrPayloadManifest, untrusted(name))
			}
			if err := mkdirPayloadDirs(dst, name); err != nil {
				return err
			}
			continue
		}
		mem, ok := declared[name]
		if !ok {
			return fmt.Errorf("%w: the archive member %s is not in the manifest", ErrPayloadManifest, untrusted(name))
		}
		if hdr.Size < 0 || hdr.Size > lim.extractedBytes-total {
			return fmt.Errorf("%w: the archive unpacks to more than %d bytes", ErrPayloadTooLarge, lim.extractedBytes)
		}
		perm := payloadExecMode
		switch mem.Kind {
		case PayloadData:
			perm = payloadDataMode
			if hdr.Size > MaxPayloadDataBytes {
				return fmt.Errorf("%w: the data member %s is larger than %d bytes", ErrPayloadTooLarge, untrusted(name), MaxPayloadDataBytes)
			}
		case PayloadVersionMarker:
			perm = payloadDataMode
			if hdr.Size >= maxVersionMarkerBytes {
				return fmt.Errorf("%w: the version marker %s is not under %d bytes", ErrPayloadTooLarge, untrusted(name), maxVersionMarkerBytes)
			}
		}
		total += hdr.Size
		if err := writePayloadMember(tr, dst, name, hdr.Size, perm); err != nil {
			return err
		}
	}
}

// payloadStream is the decompressed archive as the tar reader sees it: it
// fails with the context's error once ctx is done, and with
// ErrPayloadTooLarge once more than left bytes would be read, so neither a
// member copy nor a run of headers inside tar.Reader.Next runs unbounded.
type payloadStream struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

// Read implements io.Reader.
func (s *payloadStream) Read(b []byte) (int, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if s.left <= 0 {
		var one [1]byte
		if n, err := s.r.Read(one[:]); n == 0 && errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("%w: the archive decompresses past its bound", ErrPayloadTooLarge)
	}
	if int64(len(b)) > s.left {
		b = b[:s.left]
	}
	n, err := s.r.Read(b)
	s.left -= int64(n)
	return n, err
}

// checkPayloadDestination requires dst to be a directory, not a symlink,
// owned by the effective uid, mode 0700 with no special bits, and empty.
func checkPayloadDestination(dst string) error {
	fi, err := os.Lstat(dst)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPayloadDestination, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.IsDir():
		return fmt.Errorf("%w: %s is not a directory (%v)", ErrPayloadDestination, dst, fi.Mode().Type())
	case fi.Mode() != fs.ModeDir|0o700:
		return fmt.Errorf("%w: %s has mode %v, not drwx------", ErrPayloadDestination, dst, fi.Mode())
	case !ok || int64(st.Uid) != int64(os.Geteuid()):
		return fmt.Errorf("%w: %s is not owned by uid %d", ErrPayloadDestination, dst, os.Geteuid())
	}
	d, err := os.Open(dst)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPayloadDestination, err)
	}
	defer d.Close()
	if names, err := d.Readdirnames(1); len(names) != 0 || !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %s is not empty", ErrPayloadDestination, dst)
	}
	return nil
}

// payloadMemberName is the member's clean relative path ("./" and a
// directory's trailing "/" dropped), or a refusal.
func payloadMemberName(hdr *tar.Header) (string, error) {
	name := strings.TrimPrefix(hdr.Name, "./")
	if hdr.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	if !cleanMemberPath(name) {
		return "", fmt.Errorf("%w: the archive member name %s is not a clean relative path", ErrPayloadMember, untrusted(hdr.Name))
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
				return fmt.Errorf("chmod %s: %w", untrusted(cur), err)
			}
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("create %s: %w", untrusted(cur), err)
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", untrusted(cur), err)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %s is not a directory", ErrPayloadMember, untrusted(cur))
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
		return fmt.Errorf("%w: create %s: %w", ErrPayloadMember, untrusted(p), err)
	}
	n, err := io.Copy(out, io.LimitReader(r, size))
	if err == nil && n != size {
		err = fmt.Errorf("%w: the archive member %s is truncated", ErrPayloadMember, untrusted(name))
	}
	if err == nil {
		err = out.Chmod(perm)
	}
	if cerr := out.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", untrusted(p), err)
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
			return fmt.Errorf("%w: the extracted %s is not a regular file", ErrPayloadMember, untrusted(rel))
		}
		mem, ok := declared[rel]
		if !ok {
			return fmt.Errorf("%w: the extracted %s is not in the manifest", ErrPayloadManifest, untrusted(rel))
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
			return fmt.Errorf("%w: the archive does not carry the manifest member %s", ErrPayloadManifest, untrusted(mem.Path))
		}
	}
	return nil
}

// checkExtractedFile hashes the file at p, never through a symlink, and
// checks it against mem: the digest, and the kind its content shows.
func checkExtractedFile(p string, mem PayloadMember) error {
	f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", untrusted(p), err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", untrusted(p), err)
	}
	if !fi.Mode().IsRegular() || fi.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 {
		return fmt.Errorf("%w: the extracted %s is not a plain regular file", ErrPayloadMember, untrusted(mem.Path))
	}
	if mem.Kind == PayloadData && fi.Size() > MaxPayloadDataBytes {
		return fmt.Errorf("%w: the data member %s is larger than %d bytes", ErrPayloadTooLarge, untrusted(mem.Path), MaxPayloadDataBytes)
	}
	h := sha256.New()
	head := &headWriter{max: maxVersionMarkerBytes}
	if _, err := io.Copy(io.MultiWriter(h, head), f); err != nil {
		return fmt.Errorf("read %s: %w", untrusted(p), err)
	}
	machO := isMachOHeader(head.buf)
	switch mem.Kind {
	case PayloadMachO:
		if !machO {
			return fmt.Errorf("%w: the manifest declares %s a Mach-O and it is not one", ErrPayloadMember, untrusted(mem.Path))
		}
	case PayloadVersionMarker:
		if machO || fi.Size() >= maxVersionMarkerBytes || !printableText(head.buf) {
			return fmt.Errorf("%w: the declared version marker %s is not a small text file", ErrPayloadMember, untrusted(mem.Path))
		}
	case PayloadData:
		if machO {
			return fmt.Errorf("%w: the data member %s is a Mach-O", ErrPayloadMember, untrusted(mem.Path))
		}

	default:
		return fmt.Errorf("%w: the manifest member %s has unknown kind %s", ErrPayloadManifest, untrusted(mem.Path), untrusted(string(mem.Kind)))
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != mem.SHA256 {
		return fmt.Errorf("%w: the extracted %s has sha256 %s, the signed manifest says %s", ErrPayloadDigest, untrusted(mem.Path), got, mem.SHA256)
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
