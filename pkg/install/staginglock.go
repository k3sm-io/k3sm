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
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// lockMode says which caller is taking the two locks, because the two answer
// a staging lock someone else holds differently.
type lockMode int

const (
	// lockInstallFromStaging is `install --from-staging`. A held staging lock
	// is accepted: see lockStagingThenInstall for what that does and does not
	// prove.
	lockInstallFromStaging lockMode = iota
	// lockUninstall is `uninstall`: a held staging lock is accepted only when
	// this binary itself runs from a staged directory that passes the
	// predicate (the app's own uninstall step); otherwise a copy-out is
	// running and the uninstall is refused.
	lockUninstall
)

// lockStagingThenInstall takes the two locks in the one fixed order: the
// staging lock (outer), then the install lock (inner). Every holder of both
// takes them in this order, so no two of them can each hold one and wait on
// the other. A plain install takes only the inner one, which keeps the order.
// The returned release drops them in reverse.
//
// The held-lock exception, and its accepted limit. The copy-out takes the
// staging lock with lockf(1), which does not hand it to the command it runs,
// so the staged k3sm it starts always finds the lock held. When this binary
// runs from a staged directory that passes the staging predicate (for
// install, preflightFromStaging has already proved that; for uninstall,
// runsFromStaging proves it here), a held lock is accepted. That proves the
// staged directory is well formed and root-only. It does NOT prove that the
// process holding the lock is the copy-out that created the directory: some
// other root process could hold it. That limit is accepted because only root
// can create that state, a root-only directory directly inside a root-only
// staging root, and root can already do anything this lock guards against.
func lockStagingThenInstall(sys System, cfg Config, mode lockMode) (func(), error) {
	var releases []func()
	release := func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}
	stagingLock := StagingLockPath(cfg.stagingRoot())
	unlockStaging, err := sys.LockStaging(stagingLock)
	switch {
	case errors.Is(err, ErrStagingBusy):
		if mode == lockUninstall && !runsFromStaging(cfg) {
			return nil, err
		}
		cfg.Logger.Info("the staging lock is held, and this command runs from a trusted k3sm.app staging directory", "path", stagingLock)
	case err != nil:
		return nil, err
	default:
		releases = append(releases, func() {
			if err := unlockStaging(); err != nil {
				cfg.Logger.Warn("could not release the staging lock", "path", stagingLock, "err", err)
			}
		})
	}
	unlockInstall, err := sys.LockInstall(cfg.installLockPath())
	if err != nil {
		release()
		return nil, err
	}
	releases = append(releases, func() {
		if err := unlockInstall(); err != nil {
			cfg.Logger.Warn("could not release the install lock", "path", cfg.installLockPath(), "err", err)
		}
	})
	return release, nil
}

// lockForInstall takes the locks an install holds from its first write to its
// return: the install lock, and before it the staging lock when the install is
// from a k3sm.app staging directory.
func lockForInstall(sys System, cfg Config) (func(), error) {
	if cfg.FromStagingDir != "" {
		return lockStagingThenInstall(sys, cfg, lockInstallFromStaging)
	}
	unlock, err := sys.LockInstall(cfg.installLockPath())
	if err != nil {
		return nil, err
	}
	return func() {
		if err := unlock(); err != nil {
			cfg.Logger.Warn("could not release the install lock", "path", cfg.installLockPath(), "err", err)
		}
	}, nil
}

// runsFromStaging reports whether cfg.Executable lies inside a direct child of
// the staging root that passes the staging predicate: the k3sm.app root step's
// own staged CLI.
func runsFromStaging(cfg Config) bool {
	if cfg.StagingFS == nil || cfg.Executable == "" {
		return false
	}
	root := cfg.stagingRoot()
	if !pathInside(root, cfg.Executable) {
		return false
	}
	rel, err := filepath.Rel(root, filepath.Clean(cfg.Executable))
	if err != nil {
		return false
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	child := filepath.Join(root, first)
	if child == filepath.Clean(cfg.Executable) {
		return false
	}
	return checkStagingDir(cfg.StagingFS, root, child) == nil
}

// uninstallLocked is Uninstall with its defaults applied: an unconfirmed purge
// refuses before anything is touched; otherwise both locks are taken (staging
// first), the teardown or purge runs, and a teardown that succeeded ends with
// the staging sweep. A failed one leaves the staging trees for the re-run, so
// a purge that reports "nothing was removed" removed nothing.
func uninstallLocked(ctx context.Context, sys System, cfg Config) error {
	if cfg.Purge && !cfg.PurgeConfirmed {
		return ErrPurgeNotConfirmed
	}
	release, err := lockStagingThenInstall(sys, cfg, lockUninstall)
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	defer release()
	if cfg.Purge {
		err = purge(ctx, sys, cfg)
	} else {
		_, err = uninstall(ctx, sys, cfg, nil)
	}
	if err != nil {
		return err
	}
	if err := sweepStaging(sys, cfg); err != nil {
		return fmt.Errorf("uninstall: staging sweep: %w", err)
	}
	return nil
}

// legacySwapSuffix is the install swap dir's name before it was renamed to
// installSwapSuffix.
const legacySwapSuffix = ".staging"

// sweepStaging removes the k3sm.app staging root, any install swap tree left
// by an interrupted install, and a swap tree an older build left under the old
// name. It runs under both locks, judges each path
// with an lstat first (a symlink, a non-directory, a non-root owner or a
// group- or other-writable directory is refused, never followed), and removes
// a trusted tree without following any symlink inside it. A tree an older
// build left at the staging root under the old swap name is removed here, and
// only here.
func sweepStaging(sys System, cfg Config) error {
	var firstErr error
	paths := []string{cfg.stagingRoot(), cfg.swapDir()}
	// The old swap name is the staging root itself in the default layout; it
	// is listed on its own for an install root somewhere else.
	if legacy := filepath.Clean(cfg.InstallDir) + legacySwapSuffix; legacy != cfg.stagingRoot() {
		paths = append(paths, legacy)
	}
	for _, path := range paths {
		present, err := trustedStagingPath(sys, path)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if !present {
			continue
		}
		if err := sys.RemoveTree(path); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("remove %s: %w", path, err)
			}
			continue
		}
		cfg.Logger.Info("removed a k3sm staging directory", "path", path)
	}
	return firstErr
}
