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
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/shadow"
	"k3sm.io/runtimed/pkg/image"
)

// shadowSignTimeout bounds one codesign run.
const shadowSignTimeout = time.Minute

// CloneToOwned clones src to dst with cp -c (clonefile on the same APFS
// volume; cp falls back to a byte copy otherwise), then applies owner and mode.
// The parent is created root:wheel 0755 and refused if it is a symlink, and
// dst is replaced (an existing file is removed first, so a clone never writes
// through a planted link).
func (darwinSystem) CloneToOwned(src, dst string, uid, gid int, mode fs.FileMode) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("shadow source %s: %w", src, err)
	}
	dir := filepath.Dir(dst)
	if err := ensureRootOwnedDir(dir, 0o755); err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove the previous %s: %w", dst, err)
	}
	if out, err := exec.Command("cp", "-c", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("cp -c %s %s: %w: %s", src, dst, err, out)
	}
	if err := refuseSymlinkAt(dst); err != nil {
		return fmt.Errorf("shadow copy %s: %w", dst, err)
	}
	if err := os.Chown(dst, uid, gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", dst, uid, gid, err)
	}
	if err := os.Chmod(dst, mode); err != nil {
		return fmt.Errorf("chmod %s %#o: %w", dst, mode, err)
	}
	return nil
}

// AdHocSign re-signs path ad hoc through runtimed's image.AdHocSign, the same
// signer the pull path uses for image binaries.
func (darwinSystem) AdHocSign(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	return image.AdHocSign(ctx, path)
}

// CDHash reads path's cdhash through codesign.
func (darwinSystem) CDHash(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	return shadow.CDHash(ctx, path)
}

// VerifyShadowCopy lstats the copy (so a symlink fails as not regular), reads
// its BSD flags, and checks its signature through codesign.
func (darwinSystem) VerifyShadowCopy(path string) (int64, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return 0, fmt.Errorf("lstat %s: %w", path, err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("lstat %s: %w", path, err)
	}
	if err := shadow.CheckCopyFile(fi.Mode(), st.Flags); err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	if err := shadow.VerifySignature(ctx, path); err != nil {
		return 0, err
	}
	return fi.Size(), nil
}
