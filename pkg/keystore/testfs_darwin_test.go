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
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// setFlags sets path's file flags (chflags) without following it.
func setFlags(path string, flags int) error {
	return syscall.Chflags(path, flags)
}

// fcntlGetPath fills buf with the path of the file open at fd (fcntl
// F_GETPATH).
func fcntlGetPath(fd int, buf []byte) error {
	if _, _, errno := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), unix.F_GETPATH, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return errno
	}
	return nil
}
