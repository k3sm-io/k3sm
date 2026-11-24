//go:build darwin && cgo

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

// launch_activate_socket is public API (<launch.h>, macOS 10.10+); the rest
// of launch.h is deprecated, this function is not. It returns the
// descriptors launchd created for one Sockets entry of the calling job, in
// a malloc'd array the caller frees; for any process that is not the job it
// fails with ESRCH (measured 2026-11-23: a login user, the service user, a
// child of the job and a Pod process each got ESRCH).

//
// proc_pidfdinfo is public API (<libproc.h>). It reads this process's own
// descriptor's socket options, because getsockopt(SO_ACCEPTCONN) is not
// supported on darwin (ENOPROTOOPT).

/*
#include <errno.h>
#include <launch.h>
#include <libproc.h>
#include <stdlib.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>

// k3sm_accepting is 1 when fd is a socket in the listening state, 0 when it
// is not, and -1 with errno set when its socket info cannot be read: errno
// is cleared before the call, so a failure reports proc_pidfdinfo's own
// errno, and a short or size-mismatched return, which sets none, is EINVAL.
static int k3sm_accepting(int fd) {
	struct socket_fdinfo si;
	errno = 0;
	int n = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
	if (n <= 0 && errno != 0) {
		return -1;
	}
	if (n != (int)sizeof(si)) {
		errno = EINVAL;
		return -1;
	}
	return (si.psi.soi_options & SO_ACCEPTCONN) ? 1 : 0;
}

static int k3sm_activate(const char *name, int **fds, size_t *cnt) {
	return launch_activate_socket(name, fds, cnt);
}

static int k3sm_fd_at(int *fds, size_t i) { return fds[i]; }
*/
import "C"

import (
	"syscall"
	"unsafe"
)

// LaunchdActivator is the Activator over launch_activate_socket.
type LaunchdActivator struct{}

// Activate calls launch_activate_socket for name.
func (LaunchdActivator) Activate(name string) ([]int, error) {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var fds *C.int
	var cnt C.size_t
	rc := C.k3sm_activate(cname, &fds, &cnt)
	var out []int
	if fds != nil {
		for i := C.size_t(0); i < cnt; i++ {
			out = append(out, int(C.k3sm_fd_at(fds, i)))
		}
		C.free(unsafe.Pointer(fds))
	}
	if rc != 0 {
		return out, syscall.Errno(rc)
	}
	return out, nil
}

// socketAccepting reports whether fd is a socket in the listening state
// (SO_ACCEPTCONN in its socket options).
func socketAccepting(fd int) (bool, error) {
	rc, err := C.k3sm_accepting(C.int(fd))
	if rc < 0 {
		if err == nil {
			err = syscall.EINVAL
		}
		return false, err
	}
	return rc == 1, nil
}
