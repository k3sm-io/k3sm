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

package keystore

/*
#include <sys/types.h>
#include <sys/acl.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>

// k3sm_has_acl is 1 when the file fd holds has an extended ACL with at
// least one entry, 0 when it has none, and -1 (errno set) when it cannot
// tell. fd was opened with O_NOFOLLOW, so the answer is about that file.
static int k3sm_has_acl(int fd) {
	acl_t a = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (a == NULL) return errno == ENOENT ? 0 : -1;
	acl_entry_t e;
	int r = acl_get_entry(a, ACL_FIRST_ENTRY, &e) == 0 ? 1 : 0;
	acl_free(a);
	return r;
}

// k3sm_link_has_acl is k3sm_has_acl for the file at path, read by the path
// without following a final symlink and without opening it
// (acl_get_link_np), so it reads a directory whose mode or ACL denies its
// open. It is for a diagnosis only, never a judgement: a name can be swapped
// between it and any later open.
static int k3sm_link_has_acl(const char *path) {
	acl_t a = acl_get_link_np(path, ACL_TYPE_EXTENDED);
	if (a == NULL) return errno == ENOENT ? 0 : -1;
	acl_entry_t e;
	int r = acl_get_entry(a, ACL_FIRST_ENTRY, &e) == 0 ? 1 : 0;
	acl_free(a);
	return r;
}

// k3sm_remove_acl removes the extended ACL of the file fd holds, as
// chmod -N does: fchmodx_np with a filesec whose ACL is
// _FILESEC_REMOVE_ACL, leaving owner, group and mode unchanged. It is 0,
// or -1 with errno set.
static int k3sm_remove_acl(int fd) {
	filesec_t f = filesec_init();
	if (f == NULL) return -1;
	int r = filesec_set_property(f, FILESEC_ACL, _FILESEC_REMOVE_ACL);
	if (r == 0) r = fchmodx_np(fd, f);
	int e = errno;
	filesec_free(f);
	errno = e;
	return r;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// hasExtendedACL reports whether the file fd holds carries an extended
// ACL entry: acl_get_fd_np, on the descriptor, so a name swapped after the
// open changes nothing.
func hasExtendedACL(fd int) (bool, error) {
	r, err := C.k3sm_has_acl(C.int(fd))
	switch {
	case r == 1:
		return true, nil
	case r == 0:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read the ACL: %w", err)
	}
	return false, fmt.Errorf("read the ACL: acl_get_fd_np failed")
}

// linkHasExtendedACL reports whether the file at path carries an extended
// ACL entry, read by the path without opening it (acl_get_link_np), so it
// answers for a directory the caller cannot open. It names a repair; it never
// judges a file the store goes on to use.
func linkHasExtendedACL(path string) (bool, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	r, err := C.k3sm_link_has_acl(cp)
	switch {
	case r == 1:
		return true, nil
	case r == 0:
		return false, nil
	case err != nil:
		return false, fmt.Errorf("read the ACL of %s: %w", path, err)
	}
	return false, fmt.Errorf("read the ACL of %s: acl_get_link_np failed", path)
}

// removeExtendedACL removes the extended ACL of the file fd holds, on the
// descriptor (fchmodx_np, _FILESEC_REMOVE_ACL); a file with none is left
// as it is.
func removeExtendedACL(fd int) error {
	if r, err := C.k3sm_remove_acl(C.int(fd)); r != 0 {
		if err != nil {
			return fmt.Errorf("remove the ACL: %w", err)
		}
		return fmt.Errorf("remove the ACL: fchmodx_np failed")
	}
	return nil
}
