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
#include <membership.h>
#include <string.h>

// The Go side reads a GeneratedUID into a 16-byte array (generationSize).
_Static_assert(sizeof(uuid_t) == 16, "uuid_t is not 16 bytes");

// k3sm_uid_to_uuid writes uid's GeneratedUID to out and returns
// mbr_uid_to_uuid's status.
static int k3sm_uid_to_uuid(unsigned int uid, unsigned char *out) {
	uuid_t u;
	int rc = mbr_uid_to_uuid((uid_t)uid, u);
	if (rc == 0) memcpy(out, u, sizeof(uuid_t));
	return rc;
}
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

// A GeneratedUID is exactly a generation: these fail to compile unless
// generationSize equals sizeof(uuid_t).
var (
	_ [generationSize - C.sizeof_uuid_t]byte
	_ [C.sizeof_uuid_t - generationSize]byte
)

// generatedUIDIsReal reports that this build reads the real GeneratedUID.
const generatedUIDIsReal = true

// realGeneratedUID is mbr_uid_to_uuid. It may answer a synthesized UUID with
// status 0 for a uid with no record; lookupGeneratedUID refuses that.
func realGeneratedUID(uid uint32) ([generationSize]byte, error) {
	var g [generationSize]byte
	if rc := C.k3sm_uid_to_uuid(C.uint(uid), (*C.uchar)(unsafe.Pointer(&g[0]))); rc != 0 {
		return g, fmt.Errorf("mbr_uid_to_uuid(%d): %w", uid, syscall.Errno(rc))
	}
	return g, nil
}
