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

package oslog

/*
#include <os/log.h>
#include <stdlib.h>

static void k3sm_oslog(const char *subsystem, const char *category, int level, const char *msg) {
	os_log_t log = os_log_create(subsystem, category);
	os_log_with_type(log, (os_log_type_t)level, "%{public}s", msg);
	os_release(log);
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

// Write logs msg under Subsystem and category at level. A message holding a
// NUL byte is dropped, because C would silently cut it there.
func Write(category string, level Level, msg string) {
	if strings.ContainsRune(msg, 0) || strings.ContainsRune(category, 0) {
		return
	}
	cs := C.CString(Subsystem)
	defer C.free(unsafe.Pointer(cs))
	cc := C.CString(category)
	defer C.free(unsafe.Pointer(cc))
	cm := C.CString(msg)
	defer C.free(unsafe.Pointer(cm))
	C.k3sm_oslog(cs, cc, C.int(level), cm)
}
