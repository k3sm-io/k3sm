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

package dev

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
)

// invokingUser returns the human who invoked a sudo'd `k3sm dev` (the SUDO_USER
// env var launchctl/sudo set) and their uid/gid, so a datapath run's
// artifacts (workdir, kubeconfig, registry) are owned by the human, NOT root —
// else the NEXT rootless run EACCES-es against a root-owned tree. It returns
// ok=false when not under sudo (SUDO_USER unset) or the user can't be resolved,
// in which case the caller skips chown (the artifacts are already the right
// owner). Mirrors the hack/acceptance/m2.sh SUDO_USER pattern.
func invokingUser() (name string, uid, gid int, ok bool) {
	name = os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return "", 0, 0, false
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", 0, 0, false
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return "", 0, 0, false
	}
	gid, err = strconv.Atoi(u.Gid)
	if err != nil {
		return "", 0, 0, false
	}
	return name, uid, gid, true
}

// chownTree recursively chowns path to uid:gid — used under sudo to hand a
// datapath instance's workdir/kubeconfig back to the invoking human. Best-effort
// per entry (a chown failure is wrapped once at the root call), and a no-op when
// uid < 0 (the not-under-sudo case). A missing path is not an error (the tree may
// not exist yet).
func chownTree(path string, uid, gid int) error {
	if uid < 0 {
		return nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(path, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return nil // skip an unreadable entry, never abort the walk
		}
		if cerr := os.Lchown(p, uid, gid); cerr != nil {
			return fmt.Errorf("chown %s to %d:%d: %w", p, uid, gid, cerr)
		}
		return nil
	})
}

// userHomeFor resolves the home directory of the given username (for the
// SUDO_USER-scoped ~/.kube/config target), falling back to os.UserHomeDir when
// the name is empty or unresolvable.
func userHomeFor(name string) (string, error) {
	if name != "" {
		if u, err := user.Lookup(name); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}
