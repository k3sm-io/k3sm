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

package executor

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/k3sm/internal/binsign"
)

// The shipped source-built children (kine, etcd, etcdutl) on the release path.
//
// A Developer ID-signed k3sm runs the kine and etcd its signed payload carries and
// nothing else: it never builds them, never looks for a Go toolchain, and ignores
// whatever an earlier on-demand build left in the work dir. The payload copy is
// verified against the daemon's own Developer ID requirement first, and only then is
// its build stamp read, from the verified bytes themselves (never by running the
// binary): the version kine's release build stamps into kine's version package, the
// etcd module version Go records in the binary's build info, and the CGO_ENABLED
// setting the build info records. That stamp is rendered as the same (version,
// variant) pair the dev path's version marker records, and must equal the pins.

// ErrPayloadStamp reports a release-path payload binary whose build stamp, read from
// its own verified bytes, is not the build this k3sm pins (another version, another
// patch set, a cgo build, or no readable stamp). The daemon refuses to start rather
// than run it or build a replacement.
var ErrPayloadStamp = errors.New("payload binary is not the build this k3sm pins")

// maxStampLen bounds the stamped version string read out of a binary: a stamp is a
// short tag such as "v0.17.2+p1", and a larger length means the read went wrong.
const maxStampLen = 128

// shippedStamp reads the (version, variant) a child binary at path was built as, from
// its bytes. It is a var so a test drives the release path with fake binaries; the
// production readers are the child's own (stagedChild.readStamp).
var shippedStamp = func(c stagedChild, path string) (version, variant string, err error) {
	if c.readStamp == nil {
		return "", "", fmt.Errorf("%s declares no build-stamp reader", c.name)
	}
	return c.readStamp(path)
}

// cgoVariant renders the CGO_ENABLED build setting as the marker's variant word.
func cgoVariant(bi *debug.BuildInfo) (string, error) {
	for _, s := range bi.Settings {
		if s.Key == "CGO_ENABLED" {
			switch s.Value {
			case "0":
				return "nocgo", nil
			case "1":
				return "cgo", nil
			}
			return "", fmt.Errorf("build info records CGO_ENABLED=%q", s.Value)
		}
	}
	return "", errors.New("build info records no CGO_ENABLED setting")
}

// kineStampOf derives kine's (version, variant) from its build info and the version
// string stamped into kine's version package: "v0.17.2+p1" with CGO_ENABLED=0 is
// ("v0.17.2", "nocgo+p1"), the pair kineChild's marker records. Pure.
func kineStampOf(bi *debug.BuildInfo, stamped string) (version, variant string, err error) {
	if bi.Path != kineModulePath {
		return "", "", fmt.Errorf("main package is %q, want %q", bi.Path, kineModulePath)
	}
	cgo, err := cgoVariant(bi)
	if err != nil {
		return "", "", err
	}
	if stamped == "" {
		return "", "", errors.New("no version is stamped into kine's version package")
	}
	version, patch, _ := strings.Cut(stamped, "+")
	variant = cgo
	if patch != "" {
		variant += "+" + patch
	}
	return version, variant, nil
}

// etcdStampOf derives an etcd wrapper program's (version, variant) from its build
// info: the version of module (the main module or a dependency, never a replaced
// one) and the CGO_ENABLED setting. etcd carries no patch set, so the variant is the
// cgo word alone. pkgPath is the main package the program must be, which keeps etcd
// and etcdutl (both of which depend on the server module) from passing for each
// other. Pure.
func etcdStampOf(bi *debug.BuildInfo, pkgPath, module string) (version, variant string, err error) {
	if bi.Path != pkgPath {
		return "", "", fmt.Errorf("main package is %q, want %q", bi.Path, pkgPath)
	}
	var m *debug.Module
	if bi.Main.Path == module {
		m = &bi.Main
	}
	for _, d := range bi.Deps {
		if m == nil && d.Path == module {
			m = d
		}
	}
	switch {
	case m == nil:
		return "", "", fmt.Errorf("build info does not list module %s", module)
	case m.Replace != nil:
		return "", "", fmt.Errorf("module %s is replaced by %s", module, m.Replace.Path)
	case m.Version == "" || m.Version == "(devel)":
		return "", "", fmt.Errorf("module %s carries no release version (%q)", module, m.Version)
	}
	variant, err = cgoVariant(bi)
	if err != nil {
		return "", "", err
	}
	return m.Version, variant, nil
}

// kineStampFromBinary is kine's production stamp reader.
func kineStampFromBinary(path string) (version, variant string, err error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return "", "", fmt.Errorf("read build info: %w", err)
	}
	stamped, err := machoStringVar(path, kineModulePath+"/pkg/version.Version")
	if err != nil {
		return "", "", err
	}
	return kineStampOf(bi, stamped)
}

// etcdStampReader returns the production stamp reader for the wrapper program whose
// main package is pkgPath, versioned by module.
func etcdStampReader(pkgPath, module string) func(string) (string, string, error) {
	return func(path string) (string, string, error) {
		bi, err := buildinfo.ReadFile(path)
		if err != nil {
			return "", "", fmt.Errorf("read build info: %w", err)
		}
		return etcdStampOf(bi, pkgPath, module)
	}
}

// machoStringVar returns the value of the Go string variable sym in the thin Mach-O
// at path, as the linker initialized it (a -X stamp, or a string literal), without
// running the binary: the variable's two-word header (data pointer, length) is read
// from its symbol's section, and the length bytes from the section the pointer names.
// The binary must keep its symbol table. A universal binary is refused.
func machoStringVar(path, sym string) (string, error) {
	f, err := macho.Open(path)
	if err != nil {
		return "", fmt.Errorf("read Mach-O %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if f.Symtab == nil {
		return "", fmt.Errorf("%s carries no symbol table", path)
	}
	var addr uint64
	found := false
	for _, s := range f.Symtab.Syms {
		if s.Name == sym {
			addr, found = s.Value, true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("%s has no symbol %s", path, sym)
	}
	hdr, err := machoRead(f, addr, 16)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sym, err)
	}
	ptr, n := binary.LittleEndian.Uint64(hdr[:8]), binary.LittleEndian.Uint64(hdr[8:])
	if n == 0 {
		return "", nil
	}
	if n > maxStampLen {
		return "", fmt.Errorf("%s is %d bytes long, more than a stamp", sym, n)
	}
	b, err := machoRead(f, ptr, int(n))
	if err != nil {
		return "", fmt.Errorf("read the bytes of %s: %w", sym, err)
	}
	return string(b), nil
}

// machoRead reads n bytes at virtual address addr from the file-backed section that
// holds them.
func machoRead(f *macho.File, addr uint64, n int) ([]byte, error) {
	for _, s := range f.Sections {
		if addr < s.Addr || addr-s.Addr > s.Size || uint64(n) > s.Size-(addr-s.Addr) {
			continue
		}
		if s.Offset == 0 {
			return nil, fmt.Errorf("address %#x is in zero-fill section %s", addr, s.Name)
		}
		b := make([]byte, n)
		if _, err := s.ReadAt(b, int64(addr-s.Addr)); err != nil {
			return nil, err
		}
		return b, nil
	}
	return nil, fmt.Errorf("no section holds %d bytes at %#x", n, addr)
}

// sameContent reports whether the files at a and b hold the same bytes. A missing b
// is false; any other error is returned.
func sameContent(a, b string) (bool, error) {
	fb, err := os.Open(b)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = fb.Close() }()
	fa, err := os.Open(a)
	if err != nil {
		return false, err
	}
	defer func() { _ = fa.Close() }()
	sa, err := fa.Stat()
	if err != nil {
		return false, err
	}
	sb, err := fb.Stat()
	if err != nil {
		return false, err
	}
	if !sb.Mode().IsRegular() || sa.Size() != sb.Size() {
		return false, nil
	}
	ba, bb := make([]byte, 1<<16), make([]byte, 1<<16)
	for {
		na, ea := io.ReadFull(fa, ba)
		nb, eb := io.ReadFull(fb, bb)
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			return false, nil
		}
		if ea == io.EOF || ea == io.ErrUnexpectedEOF {
			return eb == io.EOF || eb == io.ErrUnexpectedEOF, nil
		}
		if ea != nil {
			return false, ea
		}
		if eb != nil {
			return false, eb
		}
	}
}

// ensureShipped is the release path for a source-built child: the payload's copy is
// the only acceptable binary. It must be a regular file that satisfies the
// daemon's Developer ID requirement, and its stamp, read from those verified bytes,
// must be exactly (c.version, c.variant). The work dir then holds those bytes: an
// identical copy is verified in place and left byte-identical, and anything else
// there (an older on-demand ad-hoc build, a stale copy) is replaced on a new inode
// through atomicfile, the temp re-verified and re-stamped before it takes the name.
// Nothing is signed, nothing is built, and no Go toolchain is looked for; a missing,
// unverified or mismatched payload copy refuses the boot with ErrPayloadSignature or
// ErrPayloadStamp.
func (c stagedChild) ensureShipped(ctx context.Context, p signingPolicy, bd, payloadDir string) error {
	src, err := c.shippedBinary(ctx, p, payloadDir)
	if err != nil {
		return err
	}
	dst := c.binPath(bd)
	same, err := sameContent(src, dst)
	if err != nil {
		return fmt.Errorf("compare the shipped %s with %s: %w", c.name, dst, err)
	}
	if same {
		if err := c.checkShipped(ctx, p, dst); err != nil {
			return err
		}
	} else {
		if err := os.Remove(c.markerPath(bd)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear %s version marker: %w", c.name, err)
		}
		if err := atomicfile.InstallFile(src, dst, 0o755, func(tmp string) error {
			return c.checkShipped(ctx, p, tmp)
		}); err != nil {
			return fmt.Errorf("install the shipped %s: %w", c.name, err)
		}
	}
	stamp := strings.TrimSpace(c.markerContent())
	if err := binsign.RecordHealed(bd, stamp, c.name); err != nil {
		return err
	}
	if c.staged(bd) {
		return nil
	}
	return c.writeMarker(bd)
}

// shippedBinary returns the payload's copy of c after checkShipped accepts it. It is
// the release path's whole lookup: the work dir is never consulted.
func (c stagedChild) shippedBinary(ctx context.Context, p signingPolicy, payloadDir string) (string, error) {
	if payloadDir == "" {
		return "", fmt.Errorf("%w: no staged payload carries %s; reinstall from the signed release", ErrPayloadSignature, c.name)
	}
	src := c.binPath(payloadDir)
	if err := c.checkShipped(ctx, p, src); err != nil {
		return "", err
	}
	return src, nil
}

// checkShipped verifies the binary at path against the release requirement, then
// reads its stamp from the verified bytes and compares it with the pins.
func (c stagedChild) checkShipped(ctx context.Context, p signingPolicy, path string) error {
	if err := verifyReleaseBinary(ctx, p, path); err != nil {
		return err
	}
	v, variant, err := shippedStamp(c, path)
	if err != nil {
		return fmt.Errorf("%w: read the build stamp of %s: %w", ErrPayloadStamp, path, err)
	}
	if v != c.version || variant != c.variant {
		return fmt.Errorf("%w: %s is %s %s, this k3sm pins %s %s; reinstall from the signed release that carries this k3sm",
			ErrPayloadStamp, path, v, variant, c.version, c.variant)
	}
	return nil
}
