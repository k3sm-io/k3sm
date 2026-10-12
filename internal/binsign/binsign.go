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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/atomicfile"
	"k3sm.io/runtimed/pkg/image"
)

// HealMarkerName is the per-bin-dir record of binaries this k3sm has re-signed by
// replace once (see HealOnce). One line per binary: "<name>\t<stamp>".
const HealMarkerName = ".binsign-v1"

// Signer is the code-signing seam: verify a file's signature, or ad-hoc sign it.
// Codesign is the production implementation; tests fake it.
type Signer interface {
	// Verify reports whether path carries a valid AD-HOC signature, the k3sm
	// norm. A valid signature of any other kind reports false, so it is
	// re-signed ad hoc, as every staged binary always was.
	Verify(ctx context.Context, path string) (bool, error)
	// Sign ad-hoc signs the file at path under identifier, which is the
	// binary's final base name: path is only ever a temp no process can have
	// mapped, and its own name must not become the code identifier.
	Sign(ctx context.Context, path, identifier string) error
}

// Codesign is the production Signer. Verify uses runtimed's image.CodesignTool
// (`codesign --verify --strict`, then `codesign -dv` for an ad-hoc signature).
// Sign runs `codesign -s - -f -i <identifier>`: an ad-hoc identity, no hardened
// runtime and no library validation (both would block a DYLD insert), the same
// flags as image.AdHocSign plus the identifier. The zero value is usable.
type Codesign struct{}

// Verify reports whether path's signature verifies and is ad hoc.
func (Codesign) Verify(ctx context.Context, path string) (bool, error) {
	ok, err := image.CodesignTool{}.Signed(ctx, path)
	if err != nil || !ok {
		return false, err
	}
	return image.CodesignTool{}.AdHoc(ctx, path)
}

// Sign ad-hoc signs path under identifier.
func (Codesign) Sign(ctx context.Context, path, identifier string) error {
	if identifier == "" {
		return errors.New("binsign: empty signing identifier")
	}
	cmd := exec.CommandContext(ctx, "codesign", "-s", "-", "-f", "-i", identifier, path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ad-hoc sign %s as %s: %w: %s", path, identifier, err, bytes.TrimSpace(out))
	}
	return nil
}

// EnsureSigned leaves path untouched when its signature verifies and is ad hoc,
// and otherwise re-signs it on a new inode (ResignByReplace). It reports whether it
// replaced the file. A signing failure leaves path untouched and is returned.
func EnsureSigned(ctx context.Context, s Signer, path string) (bool, error) {
	if ok, err := s.Verify(ctx, path); err == nil && ok {
		return false, nil
	}
	if err := ResignByReplace(ctx, s, path); err != nil {
		return false, err
	}
	return true, nil
}

// ResignByReplace re-signs path unconditionally on a new inode: the bytes are
// copied to a temp beside it, the temp is signed under path's base name, and the
// temp is renamed over path (atomicfile.InstallReader, which keeps the owner when
// running as root). The copy keeps the permission bits. path must be a regular
// file; a symlink is refused rather than followed, so the copy's source is the
// very file that was named.
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
	id := filepath.Base(path)
	return atomicfile.InstallReader(f, path, info.Mode().Perm(), func(tmp string) error {
		return s.Sign(ctx, tmp, id)
	})
}

// Install installs a copy of src at dst with mode on a new inode, ad-hoc signing
// the temp under dst's base name before it is renamed into place, so dst never
// names unsigned bytes. Signing is best-effort, as it has always been for staged
// binaries: a host without codesign still installs the bytes, and a binary that
// truly cannot run fails loudly at exec.
func Install(ctx context.Context, s Signer, src, dst string, mode os.FileMode) error {
	return atomicfile.InstallFile(src, dst, mode, signTemp(ctx, s, filepath.Base(dst)))
}

// InstallReader is Install over a stream.
func InstallReader(ctx context.Context, s Signer, r io.Reader, dst string, mode os.FileMode) error {
	return atomicfile.InstallReader(r, dst, mode, signTemp(ctx, s, filepath.Base(dst)))
}

// signTemp is the atomicfile prepare hook that ad-hoc signs the temp under
// identifier. Best-effort: a signing failure still installs the bytes.
func signTemp(ctx context.Context, s Signer, identifier string) func(string) error {
	return func(tmp string) error {
		_ = s.Sign(ctx, tmp, identifier)
		return nil
	}
}

// SignIfInvalid returns the atomicfile prepare hook for bytes that normally arrive
// signed (a payload copy): the temp is signed under identifier only when it does
// not carry a valid ad-hoc signature. Best-effort, like signTemp.
func SignIfInvalid(ctx context.Context, s Signer, identifier string) func(string) error {
	return func(tmp string) error {
		if ok, err := s.Verify(ctx, tmp); err == nil && ok {
			return nil
		}
		_ = s.Sign(ctx, tmp, identifier)
		return nil
	}
}

// HealOnce re-signs by replace, once, each named binary present in dir whose line
// in dir's HealMarkerName does not carry stamp, and then records it. A k3sm older
// than this package re-signed live binaries in place, which can leave a vnode
// whose cached signature no longer matches its bytes, so every process that maps
// it is killed; a check of the file's signature cannot see that state, but a new
// inode clears it. stamp names what is staged (the version marker's content for a
// versioned set), so a re-stage at another version heals again once. A binary
// whose re-sign fails is not recorded and is retried on the next call. Absent
// names are skipped. Not safe to run concurrently for the same dir: a lost update
// only costs one more replace later.
func HealOnce(ctx context.Context, s Signer, dir, stamp string, names ...string) error {
	if strings.ContainsAny(stamp, "\t\n") || stamp == "" {
		return fmt.Errorf("binsign: invalid heal stamp %q", stamp)
	}
	marker := filepath.Join(dir, HealMarkerName)
	healed, err := readHealMarker(marker)
	if err != nil {
		return err
	}
	changed := false
	for _, name := range names {
		if healed[name] == stamp {
			continue
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if err := ResignByReplace(ctx, s, p); err != nil {
			continue
		}
		healed[name] = stamp
		changed = true
	}
	if !changed {
		return nil
	}
	keys := make([]string, 0, len(healed))
	for k := range healed {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\t" + healed[k] + "\n")
	}
	if err := atomicfile.Replace(marker, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("binsign: record healed binaries: %w", err)
	}
	return nil
}

// readHealMarker parses a HealMarkerName file; an absent file is empty.
func readHealMarker(path string) (map[string]string, error) {
	healed := map[string]string{}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return healed, nil
	}
	if err != nil {
		return nil, fmt.Errorf("binsign: read %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if name, stamp, ok := strings.Cut(sc.Text(), "\t"); ok && name != "" {
			healed[name] = stamp
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("binsign: read %s: %w", path, err)
	}
	return healed, nil
}
