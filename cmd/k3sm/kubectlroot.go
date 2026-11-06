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

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"k3sm.io/k3sm/pkg/executor"
)

// processEuid is this process's effective uid. It is a seam so a test can walk
// the root paths without being root.
var processEuid = os.Geteuid

// rootExecCheck decides whether root may exec a path: the file and every parent
// directory must be root-owned with no group or other write bit.
type rootExecCheck struct {
	// lstat reports the owner and mode of path itself, never of a link's target.
	lstat func(path string) (uid uint32, mode fs.FileMode, err error)
	// evalSymlinks resolves the links in a directory path.
	evalSymlinks func(path string) (string, error)
}

// kubectlExecCheck is the production check. It is a variable so a test can
// describe a root-owned tree without one existing.
var kubectlExecCheck = rootExecCheck{lstat: lstatOwner, evalSymlinks: filepath.EvalSymlinks}

// lstatOwner is rootExecCheck.lstat on the real filesystem.
func lstatOwner(path string) (uint32, fs.FileMode, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("stat %s: no owner", path)
	}
	return st.Uid, fi.Mode(), nil
}

// resolve returns the path root should exec for path, or why path fails.
//
// The directory part is resolved first and the result is what gets checked and
// returned, because macOS's own /var is a root-owned link to /private/var. The
// last component must be a regular file, not a link.
//
// darwin has no fexecve, so the exec is by path. That path has no link left in
// it, and it and each of its parents is root-owned with no group or other write
// bit, so only root can replace any of them between this check and the exec.
func (c rootExecCheck) resolve(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("is not an absolute path")
	}
	dir, err := c.evalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", describeLookupError(err)
	}
	resolved := filepath.Join(dir, filepath.Base(path))
	uid, mode, err := c.lstat(resolved)
	if err != nil {
		return "", describeLookupError(err)
	}
	switch {
	case mode&fs.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a symlink", resolved)
	case !mode.IsRegular():
		return "", fmt.Errorf("%s is not a regular file", resolved)
	case mode.Perm()&0o111 == 0:
		return "", fmt.Errorf("%s is not executable", resolved)
	}
	if err := rootOwnedNotWritable(resolved, uid, mode); err != nil {
		return "", err
	}
	for d := dir; ; d = filepath.Dir(d) {
		uid, mode, err := c.lstat(d)
		if err != nil {
			return "", describeLookupError(err)
		}
		if !mode.IsDir() {
			return "", fmt.Errorf("%s is not a directory", d)
		}
		if err := rootOwnedNotWritable(d, uid, mode); err != nil {
			return "", err
		}
		if d == filepath.Dir(d) {
			return resolved, nil
		}
	}
}

// rootOwnedNotWritable is the owner and mode half of the check.
func rootOwnedNotWritable(path string, uid uint32, mode fs.FileMode) error {
	if uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not root", path, uid)
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (mode %04o)", path, mode.Perm())
	}
	return nil
}

// describeLookupError says "does not exist" plainly for the common case.
func describeLookupError(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return errors.New("does not exist")
	}
	return err
}

// resolveKubectlAsRoot picks the kubectl root runs: the same candidates in the
// same order as resolveKubectlIn, each one checked. A candidate that fails is
// skipped, so a default install lands on the root-owned tree `k3sm install`
// stages (<install dir>/bin/kubectl), whichever account owns the work dir.
// K3SM_WORK_DIR only names a candidate, which is checked like the others.
func resolveKubectlAsRoot(workDir, installDir string, check rootExecCheck, lookPath func(string) (string, error)) (string, error) {
	candidates := []string{executor.KubectlPath(workDir), installedKubectl(installDir)}
	if p, err := lookPath("kubectl"); err == nil {
		candidates = append(candidates, p)
	}
	reasons := make([]string, 0, len(candidates))
	for _, p := range candidates {
		resolved, err := check.resolve(p)
		if err == nil {
			return resolved, nil
		}
		reasons = append(reasons, fmt.Sprintf("%s: %v", p, err))
	}
	return "", fmt.Errorf("no kubectl to run as root: it must be root-owned and not group- or world-writable, with every parent directory the same (%s); run `sudo k3sm install` to restore %s, or run `k3sm kubectl` without sudo",
		strings.Join(reasons, "; "), installedKubectl(installDir))
}
