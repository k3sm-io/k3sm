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
)

// ErrWorkDirLayout reports a --work-dir whose base name is not the one its role
// requires, so the pod sandbox's deny of the role's state directory would not
// cover it.
var ErrWorkDirLayout = errors.New("work dir is outside the pod sandbox's deny")

// resolveWorkDirLayout normalises a --work-dir to one absolute, lexically
// clean path and refuses it unless the pod sandbox's deny covers it. The caller
// stores the returned path and uses only it from then on, so the check and every
// later use (MkdirAll, EnsureWorkDirWritable, RuntimeRoot) see the same path.
//
// The pod sandbox denies <data root>/server and <data root>/agent, where the
// data root is the work dir's parent (executor.RuntimeRoot). Pods, the registry
// and runtimed run as one uid, so that deny is all that keeps a pod out of the
// CA keys, the datastore and the registry store under the work dir. A work dir
// under any other name, /data/k3sm/srv say, would leave the deny guarding
// /data/k3sm/server while the real state sat beside it, readable and writable
// by every pod. So the base name must be subdir (sandbox.ServerSubdir for a
// server, sandbox.AgentSubdir for an agent), and when the directory already
// exists:
//   - it must not itself be a symlink, which would put the state wherever the
//     link points;
//   - it must resolve to <resolved parent>/subdir;
//   - its parent must hold an entry named exactly subdir, because APFS is
//     case-insensitive and a "server" flag would otherwise reach "Server".
//
// Symlinks in parent components are allowed: on macOS /var is a symlink to
// /private/var, and the sandbox resolves the parent itself.
//
// Every layout k3sm creates already passes, so this refuses only a hand-picked
// --work-dir, and it runs before anything is created or written. It is a
// startup guard of the k3sm server and agent commands in cmd/k3sm; other
// callers that build a provider.RuntimedConfig do not get it.
func resolveWorkDirLayout(raw, subdir string) (string, error) {
	workDir, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("--work-dir %s: make it absolute: %w", raw, err)
	}
	if filepath.Base(workDir) != subdir {
		return "", layoutRefusal(workDir, subdir, fmt.Sprintf("must be named %q", subdir))
	}
	fi, err := os.Lstat(workDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Created later, under exactly this name.
		return workDir, nil
	case err != nil:
		return "", fmt.Errorf("%w: --work-dir %s: %w", ErrWorkDirLayout, workDir, err)
	case fi.Mode()&fs.ModeSymlink != 0:
		return "", layoutRefusal(workDir, subdir, "is a symlink")
	}
	parent := filepath.Dir(workDir)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", fmt.Errorf("%w: --work-dir %s: resolve its parent: %w", ErrWorkDirLayout, workDir, err)
	}
	resolved, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		return "", fmt.Errorf("%w: --work-dir %s: resolve it: %w", ErrWorkDirLayout, workDir, err)
	}
	if resolved != filepath.Join(resolvedParent, subdir) {
		return "", layoutRefusal(workDir, subdir, fmt.Sprintf("resolves to %s", resolved))
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return "", fmt.Errorf("%w: --work-dir %s: list its parent: %w", ErrWorkDirLayout, workDir, err)
	}
	for _, e := range entries {
		if e.Name() == subdir {
			return workDir, nil
		}
	}
	return "", layoutRefusal(workDir, subdir, fmt.Sprintf("is not named exactly %q on disk", subdir))
}

// layoutRefusal is the ErrWorkDirLayout refusal for workDir, naming why and the
// layout to use.
func layoutRefusal(workDir, subdir, why string) error {
	return fmt.Errorf("%w: --work-dir %s %s: pods are denied <data root>/%s, and the data root is the work dir's parent, so state anywhere else would be open to them; pass --work-dir <data root>/%s, a real directory, for example --work-dir %s",
		ErrWorkDirLayout, workDir, why, subdir, subdir, filepath.Join(filepath.Dir(workDir), subdir))
}
