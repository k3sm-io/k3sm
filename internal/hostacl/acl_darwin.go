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

package hostacl

/*
#include <sys/types.h>
#include <sys/acl.h>
#include <membership.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/param.h>

static const acl_perm_t k3sm_perms[] = {
	ACL_READ_DATA, ACL_WRITE_DATA, ACL_EXECUTE, ACL_DELETE, ACL_APPEND_DATA,
	ACL_DELETE_CHILD, ACL_READ_ATTRIBUTES, ACL_WRITE_ATTRIBUTES,
	ACL_READ_EXTATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_READ_SECURITY,
};
static const acl_flag_t k3sm_flags[] = { ACL_ENTRY_FILE_INHERIT, ACL_ENTRY_DIRECTORY_INHERIT };

// The fd forms never follow a symlink because the caller opened the fd with
// O_NOFOLLOW; the _link_np forms act on a path's last component itself.
static acl_t k3sm_get(int fd, const char *path) {
	acl_t a = fd >= 0 ? acl_get_fd_np(fd, ACL_TYPE_EXTENDED) : acl_get_link_np(path, ACL_TYPE_EXTENDED);
	if (a == NULL && errno == ENOENT) a = acl_init(1);
	return a;
}

static int k3sm_set(int fd, const char *path, acl_t a) {
	return fd >= 0 ? acl_set_fd_np(fd, a, ACL_TYPE_EXTENDED) : acl_set_link_np(path, ACL_TYPE_EXTENDED, a);
}

static int k3sm_is_allow_for(acl_entry_t e, const unsigned char *u) {
	acl_tag_t tag;
	if (acl_get_tag_type(e, &tag) != 0 || tag != ACL_EXTENDED_ALLOW) return 0;
	void *q = acl_get_qualifier(e);
	if (q == NULL) return 0;
	int m = memcmp(q, u, sizeof(uuid_t)) == 0;
	acl_free(q);
	return m;
}

// k3sm_covers reports whether e already gives perms and flags to the object
// it is on. An only_inherit entry applies to children alone, so it never
// covers the object itself.
static int k3sm_covers(acl_entry_t e, unsigned int perms, unsigned int flags) {
	acl_permset_t ps;
	acl_flagset_t fs;
	if (acl_get_permset(e, &ps) != 0 || acl_get_flagset_np(e, &fs) != 0) return 0;
	if (acl_get_flag_np(fs, ACL_ENTRY_ONLY_INHERIT) == 1) return 0;
	for (size_t i = 0; i < sizeof(k3sm_perms) / sizeof(k3sm_perms[0]); i++)
		if ((perms & k3sm_perms[i]) && acl_get_perm_np(ps, k3sm_perms[i]) != 1) return 0;
	for (size_t i = 0; i < sizeof(k3sm_flags) / sizeof(k3sm_flags[0]); i++)
		if ((flags & k3sm_flags[i]) && acl_get_flag_np(fs, k3sm_flags[i]) != 1) return 0;
	return 1;
}

// k3sm_acl_add adds an allow entry for uid with perms and flags, before the
// first inherited entry (the canonical place for an explicit one), unless an
// allow entry for uid already covers them. 1 added, 0 already there, -1 error.
static int k3sm_acl_add(int fd, const char *path, uid_t uid, unsigned int perms, unsigned int flags) {
	uuid_t u;
	if (mbr_uid_to_uuid(uid, u) != 0) { errno = EINVAL; return -1; }
	acl_t a = k3sm_get(fd, path);
	if (a == NULL) return -1;
	acl_entry_t e;
	int id = ACL_FIRST_ENTRY, idx = 0, first_inherited = -1;
	while (acl_get_entry(a, id, &e) == 0) {
		id = ACL_NEXT_ENTRY;
		if (k3sm_is_allow_for(e, u) && k3sm_covers(e, perms, flags)) { acl_free(a); return 0; }
		acl_flagset_t fs;
		if (first_inherited < 0 && acl_get_flagset_np(e, &fs) == 0 && acl_get_flag_np(fs, ACL_ENTRY_INHERITED) == 1)
			first_inherited = idx;
		idx++;
	}
	acl_entry_t ne;
	if (acl_create_entry_np(&a, &ne, first_inherited >= 0 ? first_inherited : ACL_LAST_ENTRY) != 0) { acl_free(a); return -1; }
	acl_permset_t ps;
	acl_flagset_t fs;
	if (acl_set_tag_type(ne, ACL_EXTENDED_ALLOW) != 0 || acl_set_qualifier(ne, u) != 0 ||
	    acl_get_permset(ne, &ps) != 0 || acl_clear_perms(ps) != 0 ||
	    acl_get_flagset_np(ne, &fs) != 0 || acl_clear_flags_np(fs) != 0) { acl_free(a); return -1; }
	for (size_t i = 0; i < sizeof(k3sm_perms) / sizeof(k3sm_perms[0]); i++)
		if (perms & k3sm_perms[i]) acl_add_perm(ps, k3sm_perms[i]);
	for (size_t i = 0; i < sizeof(k3sm_flags) / sizeof(k3sm_flags[0]); i++)
		if (flags & k3sm_flags[i]) acl_add_flag_np(fs, k3sm_flags[i]);
	if (acl_set_permset(ne, ps) != 0 || acl_set_flagset_np(ne, fs) != 0) { acl_free(a); return -1; }
	int r = k3sm_set(fd, path, a);
	acl_free(a);
	return r == 0 ? 1 : -1;
}

// k3sm_acl_remove deletes every allow entry for uid, inherited ones included,
// and only allow entries (a deny the owner set stays). 1 removed, 0 none.
static int k3sm_acl_remove(int fd, const char *path, uid_t uid) {
	uuid_t u;
	if (mbr_uid_to_uuid(uid, u) != 0) { errno = EINVAL; return -1; }
	acl_t a = fd >= 0 ? acl_get_fd_np(fd, ACL_TYPE_EXTENDED) : acl_get_link_np(path, ACL_TYPE_EXTENDED);
	if (a == NULL) return errno == ENOENT ? 0 : -1;
	int removed = 0, again = 1;
	while (again) {
		again = 0;
		acl_entry_t e;
		int id = ACL_FIRST_ENTRY;
		while (acl_get_entry(a, id, &e) == 0) {
			id = ACL_NEXT_ENTRY;
			if (k3sm_is_allow_for(e, u)) {
				if (acl_delete_entry(a, e) != 0) { acl_free(a); return -1; }
				removed++;
				again = 1;
				break;
			}
		}
	}
	int r = removed ? k3sm_set(fd, path, a) : 0;
	acl_free(a);
	if (r != 0) return -1;
	return removed ? 1 : 0;
}

// k3sm_acl_perms returns the union of the perms of every allow entry for uid,
// or -1 on error: a test and report seam.
static long long k3sm_acl_perms(int fd, const char *path, uid_t uid) {
	uuid_t u;
	if (mbr_uid_to_uuid(uid, u) != 0) { errno = EINVAL; return -1; }
	acl_t a = fd >= 0 ? acl_get_fd_np(fd, ACL_TYPE_EXTENDED) : acl_get_link_np(path, ACL_TYPE_EXTENDED);
	if (a == NULL) return errno == ENOENT ? 0 : -1;
	long long out = 0;
	acl_entry_t e;
	int id = ACL_FIRST_ENTRY;
	while (acl_get_entry(a, id, &e) == 0) {
		id = ACL_NEXT_ENTRY;
		if (!k3sm_is_allow_for(e, u)) continue;
		acl_permset_t ps;
		if (acl_get_permset(e, &ps) != 0) continue;
		for (size_t i = 0; i < sizeof(k3sm_perms) / sizeof(k3sm_perms[0]); i++)
			if (acl_get_perm_np(ps, k3sm_perms[i]) == 1) out |= k3sm_perms[i];
	}
	acl_free(a);
	return out;
}

// k3sm_getpath writes the path the kernel holds for fd (F_GETPATH), which
// spells every component the way the volume stores it.
static int k3sm_getpath(int fd, char *buf) { return fcntl(fd, F_GETPATH, buf); }
*/
import "C"

import (
	"syscall"
	"unsafe"
)

func cpath(fd int, path string) (*C.char, func()) {
	if fd >= 0 {
		return nil, func() {}
	}
	p := C.CString(path)
	return p, func() { C.free(unsafe.Pointer(p)) }
}

// addEntry adds an allow entry for uid on the open fd (or, with fd -1, on
// path's last component, not following it).
func addEntry(fd int, path string, uid uint32, perms Perm, flags Flag) (bool, error) {
	p, free := cpath(fd, path)
	defer free()
	r, err := C.k3sm_acl_add(C.int(fd), p, C.uid_t(uid), C.uint(perms), C.uint(flags))
	if r < 0 {
		return false, errnoOr(err)
	}
	return r == 1, nil
}

// removeEntries deletes every allow entry for uid.
func removeEntries(fd int, path string, uid uint32) (bool, error) {
	p, free := cpath(fd, path)
	defer free()
	r, err := C.k3sm_acl_remove(C.int(fd), p, C.uid_t(uid))
	if r < 0 {
		return false, errnoOr(err)
	}
	return r == 1, nil
}

// allowed returns the permissions allow entries give uid on path's last
// component.
func allowed(path string, uid uint32) (Perm, error) {
	p, free := cpath(-1, path)
	defer free()
	r, err := C.k3sm_acl_perms(-1, p, C.uid_t(uid))
	if r < 0 {
		return 0, errnoOr(err)
	}
	return Perm(r), nil
}

// getPath returns the kernel's path for fd.
func getPath(fd int) (string, error) {
	buf := (*C.char)(C.malloc(C.MAXPATHLEN))
	defer C.free(unsafe.Pointer(buf))
	if r, err := C.k3sm_getpath(C.int(fd), buf); r < 0 {
		return "", errnoOr(err)
	}
	return C.GoString(buf), nil
}

func errnoOr(err error) error {
	if err == nil {
		return syscall.EIO
	}
	return err
}
