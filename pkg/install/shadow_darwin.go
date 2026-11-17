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
// sourceDir. Everything this root process trusts is checked on an object no
// other user can change (B1786 review): path is the root-owned clone and must
// be Apple-signed before it is edited, and install_name_tool and the @rpath
// dylibs it loads are first cloned into a root-only directory, checked as
// Apple-signed there, and run from there with a minimal environment. A swap of
// the source tree during the install therefore cannot hand root other bytes.
func (darwinSystem) RelinkRpaths(path, sourceDir string) error {
	rewrites, err := executableRpathRewrites(path, sourceDir)
	if err != nil {
		return err
	}
	if len(rewrites) == 0 {
		return nil
	}
	if err := verifyAppleSigned(path); err != nil {
		return fmt.Errorf("refusing to relink %s: %w", path, err)
	}
	dev, ok := developerDirOf(sourceDir)
	if !ok {
		return fmt.Errorf("relink %s: %s is not in a developer dir, so there is no toolchain install_name_tool", path, sourceDir)
	}
	tool, cleanup, err := stageInstallNameTool(filepath.Dir(path), dev)
	if err != nil {
		return err
	}
	defer cleanup()
	args := make([]string, 0, 3*len(rewrites)+1)
	for _, r := range rewrites {
		args = append(args, "-rpath", r[0], r[1])
	}
	args = append(args, path)
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, tool, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install_name_tool %v: %w: %s", args, err, out)
	}
	return nil
}

// stageInstallNameTool clones dev's toolchain install_name_tool, and every
// @rpath dylib it imports from the toolchain's usr/lib, into a fresh root-only
// directory under parent (bin/ and lib/, so its @executable_path/../lib rpath
// resolves to the staged copies), and checks each staged file is Apple-signed.
func stageInstallNameTool(parent, dev string) (string, func(), error) {
	usr := filepath.Join(dev, "Toolchains", "XcodeDefault.xctoolchain", "usr")
	tmp, err := os.MkdirTemp(parent, ".relink-")
	if err != nil {
		return "", nil, fmt.Errorf("stage install_name_tool: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	fail := func(err error) (string, func(), error) { cleanup(); return "", nil, err }
	if err := os.Chmod(tmp, 0o700); err != nil {
		return fail(err)
	}
	for _, d := range []string{"bin", "lib"} {
		if err := os.Mkdir(filepath.Join(tmp, d), 0o700); err != nil {
			return fail(err)
		}
	}
	stage := func(src, dst string) error {
		if out, err := exec.Command("cp", "-c", src, dst).CombinedOutput(); err != nil {
			return fmt.Errorf("cp -c %s %s: %w: %s", src, dst, err, out)
		}
		if err := refuseSymlinkAt(dst); err != nil {
			return err
		}
		if err := verifyAppleSigned(dst); err != nil {
			return fmt.Errorf("refusing to run %s as root: %w", src, err)
		}
		return nil
	}
	tool := filepath.Join(tmp, "bin", "install_name_tool")
	if err := stage(filepath.Join(usr, "bin", "install_name_tool"), tool); err != nil {
		return fail(err)
	}
	libs, err := rpathImports(tool)
	if err != nil {
		return fail(err)
	}
	for _, name := range libs {
		if err := stage(filepath.Join(usr, "lib", name), filepath.Join(tmp, "lib", name)); err != nil {
			return fail(err)
		}
	}
	return tool, cleanup, nil
}

// verifyAppleSigned checks path's signature is valid and anchored at Apple.
func verifyAppleSigned(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), shadowSignTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s is not Apple-signed: %s", errUntrustedSource, path, out)
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
