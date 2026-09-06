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
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"

	"k3sm.io/k3sm/pkg/dataroot"
)

// ownership is the privileged filesystem seam listenNetd runs its data-root
// decisions through. It is defined here at the consumer so a unit test can
// describe postures it could never create for real (a declared-but-unmounted
// volume, a root-owned data root) and can observe that netd creates and chowns
// exactly nothing when it refuses.
type ownership interface {
	dataroot.FS
	// Lookup resolves a user name to its uid and primary gid. It fails when the
	// user does not exist — the pre-install posture, in which netd must leave
	// ownership alone rather than guess.
	Lookup(name string) (uid, gid int, err error)
	MkdirAll(path string, perm fs.FileMode) error
	Chown(path string, uid, gid int) error
	Chmod(path string, mode fs.FileMode) error
	Remove(path string) error
}

// osOwnership is the production ownership: the real filesystem and the real
// user database. Its zero value is usable.
type osOwnership struct{ dataroot.OSFS }

// Lookup implements ownership.
func (osOwnership) Lookup(name string) (int, int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("look up %s: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q of %s: %w", u.Uid, name, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q of %s: %w", u.Gid, name, err)
	}
	return uid, gid, nil
}

// MkdirAll implements ownership.
func (osOwnership) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }

// Chown implements ownership.
func (osOwnership) Chown(path string, uid, gid int) error { return os.Chown(path, uid, gid) }

// Chmod implements ownership.
func (osOwnership) Chmod(path string, mode fs.FileMode) error { return os.Chmod(path, mode) }

// Remove implements ownership.
func (osOwnership) Remove(path string) error { return os.Remove(path) }
