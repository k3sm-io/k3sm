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
#include <dlfcn.h>
#include <stdlib.h>

// k3sm_dlsym_resolves reports whether name resolves in the process's global
// symbol scope.
static int k3sm_dlsym_resolves(const char *name) {
	return dlsym(RTLD_DEFAULT, name) != NULL;
}
*/
import "C"

import "unsafe"

// symbolResolves reports whether the named symbol resolves at run time
// through dlsym(RTLD_DEFAULT): the per-name half of k3sm's symbol canary,
// so a test is red for exactly the symbol a macOS update removed.
func symbolResolves(name string) bool {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	return C.k3sm_dlsym_resolves(c) != 0
}
