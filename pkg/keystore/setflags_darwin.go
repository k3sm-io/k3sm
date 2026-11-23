//go:build darwin

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

package keystore

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// setFlagsAt sets the st_flags of name in the directory dirfd to flags
// with setattrlistat(2) for ATTR_CMN_FLAGS and FSOPT_NOFOLLOW: by
// directory descriptor and name, never following a symlink at name, and
// without opening the file, so a FIFO, socket or device has its flags
// changed with none of an open's side effects. It is a variable so a test
// can record the calls.
var setFlagsAt = func(dirfd int, name string, flags uint32) error {
	p, err := unix.BytePtrFromString(name)
	if err != nil {
		return err
	}
	al := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_FLAGS,
	}
	buf := flags
	// x/sys/unix wraps no setattrlistat; Syscall6 reaches it through libc's
	// syscall(2) entry, as fdHasACL reaches fgetattrlist.
	//lint:ignore SA1019 x/sys/unix has no setattrlistat wrapper.
	_, _, errno := unix.Syscall6(unix.SYS_SETATTRLISTAT, uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&al)), uintptr(unsafe.Pointer(&buf)), unsafe.Sizeof(buf), unix.FSOPT_NOFOLLOW)
	if errno != 0 {
		return errno
	}
	return nil
}
