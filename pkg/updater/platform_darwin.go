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

package updater

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// deniedFlags are the BSD flags the updater refuses on anything it trusts: an
// immutable or append-only entry cannot be replaced by a flip, and only someone
// outside the updater's own path sets one.
const deniedFlags = unix.UF_IMMUTABLE | unix.UF_APPEND | unix.SF_IMMUTABLE | unix.SF_APPEND

// fullFsync asks the drive to flush with F_FULLFSYNC; fsync(2) on macOS stops at
// the drive's volatile cache. A volume that cannot do it is an error, not a
// quiet fsync.
func fullFsync(f *os.File) error {
	_, err := unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	return err
}

func statFlags(st *syscall.Stat_t) uint32 { return st.Flags }

// sysctlBootID reads the kernel's boot session uuid.
func sysctlBootID() (string, error) { return unix.Sysctl("kern.bootsessionuuid") }
