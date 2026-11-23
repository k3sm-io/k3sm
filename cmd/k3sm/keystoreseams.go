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
	"os"
	"os/user"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// The keystore paths' named seams in cmd/k3sm (docs/design/keystore.md §
// "Package layout and seams"). Each replaces one real primitive, and the
// package's TestMain sets each to a stub that panics, so a unit test that
// forgets to inject a fake never reaches the host. The exec seam is
// kubectlExec (kubectl.go). The clock, the client-side peer-credential
// source and the server code identity come with the code that first uses
// them.
var (
	// euidSeam is the effective uid behind the keys verbs' root check and
	// the delivery reconciler's identity check: os.Geteuid.
	euidSeam = os.Geteuid
	// uidResolverSeam resolves the service user's name to its account:
	// getpwnam, through os/user.
	uidResolverSeam = user.Lookup
	// fileAttrSeam writes a file's owner, mode and flags on a held
	// descriptor for the maintenance verbs (floor --rebuild): fchown,
	// fchmod and fchflags.
	fileAttrSeam keystore.FileAttrWriter = realFileAttrWriter{}
)

// realFileAttrWriter is the file-attribute writer over the syscalls.
type realFileAttrWriter struct{}

func (realFileAttrWriter) Fchown(fd, uid, gid int) error    { return unix.Fchown(fd, uid, gid) }
func (realFileAttrWriter) Fchmod(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }
func (realFileAttrWriter) Fchflags(fd, flags int) error     { return unix.Fchflags(fd, flags) }
