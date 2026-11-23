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
#include <errno.h>

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
*/
import "C"

import "fmt"

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
