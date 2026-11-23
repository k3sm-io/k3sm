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
	"os"

	"golang.org/x/sys/unix"
)

// The package's named seams (docs/design/keystore.md § "Package layout and
// seams": pkg/install carries the euid source and the file-attribute
// writer). Each replaces one real primitive; the package's TestMain sets
// each to a stub that panics, so a unit test that forgets to inject a fake
// never reaches the host.
var (
	// euidSeam is the effective uid behind the keystore step's root check:
	// os.Geteuid.
	euidSeam = os.Geteuid
	// fileAttrSeam writes a file's owner, mode and flags on a held
	// descriptor: fchown, fchmod and fchflags.
	fileAttrSeam fileAttrWriter = realFileAttrWriter{}
)

// fileAttrWriter is the file-attribute writer: each call acts on an open
// descriptor, never a path.
type fileAttrWriter interface {
	Fchown(fd, uid, gid int) error
	Fchmod(fd int, mode uint32) error
	Fchflags(fd, flags int) error
}

// swapStepper is the optional step seam of the file-attribute writer: when
// fileAttrSeam also implements it, the keystore step calls BeforeSwapStep
// with the step's name before each step of a log's creation that makes no
// attribute call of its own ("create": the build of the log's directory in
// keystore-staging/, "rename": its RENAME_EXCL into keystore-logs/,
// "fsync"), so a root-run
// test can probe, or stop install at, every step. An error fails the step
// as a crash there would leave it.
type swapStepper interface {
	BeforeSwapStep(step string) error
}

// beforeLogStep calls the step seam, when fileAttrSeam has one.
func beforeLogStep(step string) error {
	h, ok := fileAttrSeam.(swapStepper)
	if !ok {
		return nil
	}
	return h.BeforeSwapStep(step)
}

// realFileAttrWriter is the file-attribute writer over the syscalls.
type realFileAttrWriter struct{}

func (realFileAttrWriter) Fchown(fd, uid, gid int) error    { return unix.Fchown(fd, uid, gid) }
func (realFileAttrWriter) Fchmod(fd int, mode uint32) error { return unix.Fchmod(fd, mode) }
func (realFileAttrWriter) Fchflags(fd, flags int) error     { return unix.Fchflags(fd, flags) }
