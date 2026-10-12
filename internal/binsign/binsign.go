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

package binsign

import (
	"context"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/runtimed/pkg/image"
)

// Signer is the code-signing seam: verify a file's signature, or ad-hoc sign it.
// Codesign is the production implementation; tests fake it.
type Signer interface {
	// Verify reports whether path carries a valid code signature.
	Verify(ctx context.Context, path string) (bool, error)
	// Sign ad-hoc signs the file at path. It is only ever given a temp path that
	// no process can have mapped.
	Sign(ctx context.Context, path string) error
}

// Codesign is the production Signer over runtimed's image package (the
// same codesign invocations runtimed uses for pulled images): Verify is
// `codesign --verify --strict`, Sign is image.AdHocSign (`codesign -s - -f`, no
// hardened runtime, no library validation). The zero value is usable.
type Codesign struct{}

// Verify reports whether path's signature verifies.
func (Codesign) Verify(ctx context.Context, path string) (bool, error) {
	return image.CodesignTool{}.Signed(ctx, path)
}

// Sign ad-hoc signs path.
func (Codesign) Sign(ctx context.Context, path string) error {
	return image.AdHocSign(ctx, path)
}

// EnsureSigned leaves path untouched when its signature already verifies, and
// otherwise re-signs it on a new inode: the bytes are copied to a temp file beside
// it, the temp is signed, and the temp is renamed over path. The copy keeps the
// file's permission bits, and its owner when running as root. It reports whether it
// replaced the file. A signing failure leaves path untouched and is returned.
//
// path must be a regular file; a symlink is refused rather than followed, so the
// copy's source is the very file that was checked.
func EnsureSigned(ctx context.Context, s Signer, path string) (bool, error) {
	if ok, err := s.Verify(ctx, path); err == nil && ok {
		return false, nil
	}
	if err := ResignByReplace(ctx, s, path); err != nil {
		return false, err
	}
	return true, nil
}

// ResignByReplace re-signs path unconditionally on a new inode (see EnsureSigned):
// copy to a temp beside it, sign the temp, rename it over path. It is for bytes that
// must be signed whatever they carry now (a fresh download whose signature is to be
// replaced); a live binary is re-signed through EnsureSigned instead.
func ResignByReplace(ctx context.Context, s Signer, path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s for re-signing: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("re-sign %s: not a regular file (%v)", path, info.Mode().Type())
	}
	return atomicfile.InstallReader(f, path, info.Mode().Perm(), func(tmp string) error {
		if err := s.Sign(ctx, tmp); err != nil {
			return err
		}
		return keepOwner(tmp, info)
	})
}

// Install installs a copy of src at dst with mode on a new inode, ad-hoc
// signing the temp before it is renamed into place, so dst never names unsigned
// bytes. Signing is best-effort, as it has always been for staged binaries: a host
// without codesign still installs the bytes, and a binary that truly cannot run
// fails loudly at exec.
func Install(ctx context.Context, s Signer, src, dst string, mode os.FileMode) error {
	return atomicfile.InstallFile(src, dst, mode, signTemp(ctx, s))
}

// InstallReader is Install over a stream.
func InstallReader(ctx context.Context, s Signer, r io.Reader, dst string, mode os.FileMode) error {
	return atomicfile.InstallReader(r, dst, mode, signTemp(ctx, s))
}

// signTemp is the atomicfile prepare hook that ad-hoc signs the temp. Best-effort:
// a signing failure still installs the bytes (see Install).
func signTemp(ctx context.Context, s Signer) func(string) error {
	return func(tmp string) error {
		_ = s.Sign(ctx, tmp)
		return nil
	}
}

// SignIfInvalid returns the atomicfile prepare hook for bytes that normally arrive signed (a
// payload copy): the temp is signed only when its signature does not verify.
// Best-effort, like signTemp.
func SignIfInvalid(ctx context.Context, s Signer) func(string) error {
	return func(tmp string) error {
		if ok, err := s.Verify(ctx, tmp); err == nil && ok {
			return nil
		}
		_ = s.Sign(ctx, tmp)
		return nil
	}
}

// keepOwner gives tmp the owner of the file it replaces when running as root, so a
// re-sign does not change who owns a binary (an in-place codesign never did). An
// unprivileged process cannot give a file away, so its copy stays its own.
func keepOwner(tmp string, orig os.FileInfo) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, ok := orig.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if err := os.Lchown(tmp, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("keep the owner of %s: %w", tmp, err)
	}
	return nil
}
