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

package socket

import (
	"fmt"
	"os"
)

// The real primitives behind ProcessEUID and DataRootIgnoresOwnership. They
// are variables so that the package's TestMain can replace each with a
// stub that panics, which keeps every unit test off the host; the
// Supervisor never reads them, since it takes its checks from its config.
var (
	geteuidSeam          = os.Geteuid
	ignoresOwnershipSeam = fstatfsIgnoresOwnership
)

// ProcessEUID returns the process's effective uid: the production
// SupervisorConfig.EUID.
func ProcessEUID() int { return geteuidSeam() }

// DataRootIgnoresOwnership reports whether the file system holding dir, the
// data root opened as a directory, is mounted with MNT_IGNORE_OWNERSHIP,
// read with fstatfs on dir's descriptor (f_flags). Off darwin it fails, so
// the listener stays off.
func DataRootIgnoresOwnership(dir *os.File) (bool, error) {
	rc, err := dir.SyscallConn()
	if err != nil {
		return false, fmt.Errorf("data root descriptor: %w", err)
	}
	var ignores bool
	var serr error
	if err := rc.Control(func(fd uintptr) { ignores, serr = ignoresOwnershipSeam(fd) }); err != nil {
		return false, fmt.Errorf("data root descriptor: %w", err)
	}
	if serr != nil {
		return false, fmt.Errorf("fstatfs the data root: %w", serr)
	}
	return ignores, nil
}
