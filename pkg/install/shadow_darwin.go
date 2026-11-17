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

// RelinkRpaths reads path's LC_RPATH load commands with debug/macho and
// rewrites each @executable_path one with install_name_tool, resolved against
// sourceDir. The tool comes from the developer dir that holds sourceDir when
// there is one (xcodebuild is the only Relink copy, and it lives in one), so
// the libxcselect trampoline's own developer-dir lookup is not involved.
func (darwinSystem) RelinkRpaths(path, sourceDir string) error {
	rewrites, err := executableRpathRewrites(path, sourceDir)
	if err != nil {
		return err
	}
	tool := installNameTool(sourceDir)
	// The tool runs as root: it must come from a root-owned, protected tree
	// (an Xcode a user owns could otherwise hand root a binary to run).
	if err := (darwinSystem{}).CheckTrustedSource(tool); err != nil {
		return fmt.Errorf("refusing to run %s as root: %w", tool, err)
	}
	if len(rewrites) == 0 {
		return nil
	}
	args := make([]string, 0, 3*len(rewrites)+1)
	for _, r := range rewrites {
		args = append(args, "-rpath", r[0], r[1])
	}
	args = append(args, path)
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	if dev, ok := developerDirOf(sourceDir); ok {
		cmd.Env = append(os.Environ(), "DEVELOPER_DIR="+dev)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install_name_tool %v: %w: %s", args, err, out)
	}
	return nil
}

// CheckTrustedSource walks path and its ancestors with lstat (see the System
// interface for the rule).
func (darwinSystem) CheckTrustedSource(path string) error {
	return checkTrustedChain(path, func(p string) (trustStat, error) {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return trustStat{}, err
		}
		return trustStat{uid: st.Uid, gid: st.Gid, mode: uint32(st.Mode)}, nil
	})
}

// installNameTool is the toolchain's install_name_tool when sourceDir is in a
// developer dir that has one, else /usr/bin/install_name_tool.
func installNameTool(sourceDir string) string {
	if dev, ok := developerDirOf(sourceDir); ok {
		p := filepath.Join(dev, "Toolchains", "XcodeDefault.xctoolchain", "usr", "bin", "install_name_tool")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "/usr/bin/install_name_tool"
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
