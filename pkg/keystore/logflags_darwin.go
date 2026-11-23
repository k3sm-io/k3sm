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
	"encoding/binary"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fileFlags is the chflags flag source: f's st_flags, read with fstat on
// its descriptor.
func fileFlags(f *os.File) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	return st.Flags, nil
}

// fdFlags is the st_flags of the open descriptor fd, read with fstat.
func fdFlags(fd int) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return st.Flags, nil
}

// The fgetattrlist layout fdHasACL reads (<sys/attr.h>, <sys/kauth.h>).
const (
	// fsoptPackInvalAttrs is FSOPT_PACK_INVAL_ATTRS: every requested
	// attribute keeps its slot, so the reply's layout is fixed.
	fsoptPackInvalAttrs = 0x8
	// aclReplyRef is the offset of the attrreference_t of
	// ATTR_CMN_EXTENDED_SECURITY: after the reply's length and its
	// attribute_set_t of returned attributes.
	aclReplyRef = 4 + 5*4
	// filesecMagic is KAUTH_FILESEC_MAGIC, and filesecEntryCount the offset
	// of fsec_entrycount in a kauth_filesec: after the magic and the owner
	// and group GUIDs.
	filesecMagic      = 0x012cc16d
	filesecEntryCount = 4 + 16 + 16
	// filesecNoACL is KAUTH_FILESEC_NOACL, an entry count meaning no ACL.
	filesecNoACL = 0xffffffff
	// aclReplySize holds the reply's fixed part and a kauth_filesec header;
	// a longer ACL is truncated, which keeps the entry count.
	aclReplySize = 512
)

// fdHasACL reports whether the open descriptor fd carries a non-empty
// extended ACL, read with fgetattrlist(2) for ATTR_CMN_EXTENDED_SECURITY,
// which any caller that can stat the file may ask, root or not. x/sys/unix
// wraps no acl_get_fd, and fgetxattr of com.apple.system.Security is EPERM
// for every caller but root, so the service user could not use it.
func fdHasACL(fd int) (bool, error) {
	al := unix.Attrlist{
		Bitmapcount: unix.ATTR_BIT_MAP_COUNT,
		Commonattr:  unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY,
	}
	buf := make([]byte, aclReplySize)
	// x/sys/unix wraps no fgetattrlist; Syscall6 reaches it through libc's
	// syscall(2) entry, which is the path the deprecation names.
	//lint:ignore SA1019 x/sys/unix has no fgetattrlist wrapper, and this package uses no cgo.
	_, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, uintptr(fd), uintptr(unsafe.Pointer(&al)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), fsoptPackInvalAttrs, 0)
	if errno != 0 {
		return false, errno
	}
	le := binary.LittleEndian
	if le.Uint32(buf) < aclReplyRef+8 {
		return false, unix.EINVAL
	}
	// The returned common attributes follow the length.
	if le.Uint32(buf[4:])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return false, nil
	}
	off := int64(aclReplyRef) + int64(int32(le.Uint32(buf[aclReplyRef:])))
	size := int64(le.Uint32(buf[aclReplyRef+4:]))
	if size == 0 {
		return false, nil
	}
	if size < filesecEntryCount+4 || off < 0 || off+filesecEntryCount+4 > int64(len(buf)) {
		// A security attribute this reader cannot see into is refused.
		return true, nil
	}
	sec := buf[off:]
	if le.Uint32(sec) != filesecMagic {
		return true, nil
	}
	count := le.Uint32(sec[filesecEntryCount:])
	return count != 0 && count != filesecNoACL, nil
}

// statFlags is st's st_flags.
func statFlags(st *unix.Stat_t) uint32 { return st.Flags }

// clearFdFlags sets the flags of the file held at fd to 0.
func clearFdFlags(fd int) error { return unix.Fchflags(fd, 0) }
