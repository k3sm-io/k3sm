//go:build cgo

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

/*
#include <errno.h>
#include <sys/types.h>
#include <sys/acl.h>

// k3sm_fd_has_acl returns 1 when fd carries an extended ACL with at least one
// entry, 0 when it carries none, and -1 with errno set when the probe failed.
static int k3sm_fd_has_acl(int fd) {
	errno = 0;
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	if (acl == NULL) {
		return errno == ENOENT ? 0 : -1;
	}
	acl_entry_t entry;
	int has = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == 0 ? 1 : 0;
	acl_free(acl);
	return has;
}
*/
import "C"

import "fmt"

// fdHasACL reports whether the open descriptor carries an extended ACL, through
// acl_get_fd_np(3), which has no Go binding.
func fdHasACL(fd uintptr) (bool, error) {
	r, errno := C.k3sm_fd_has_acl(C.int(fd))
	switch r {
	case 0:
		return false, nil
	case 1:
		return true, nil
	}
	return false, fmt.Errorf("read the ACL: %v", errno)
}
