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

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

// cfstr copies a CFString into a malloc'd C string, or returns NULL.
static char *cfstr(CFStringRef s) {
	if (s == NULL || CFGetTypeID(s) != CFStringGetTypeID()) return NULL;
	CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
	char *buf = malloc(n);
	if (buf == NULL) return NULL;
	if (!CFStringGetCString(s, buf, n, kCFStringEncodingUTF8)) { free(buf); return NULL; }
	return buf;
}

static CFStringRef mkstr(const char *c) {
	return CFStringCreateWithCString(NULL, c, kCFStringEncodingUTF8);
}

static SecStaticCodeRef mkcode(const char *path, OSStatus *st) {
	CFStringRef p = mkstr(path);
	CFURLRef url = CFURLCreateWithFileSystemPath(NULL, p, kCFURLPOSIXPathStyle, false);
	CFRelease(p);
	SecStaticCodeRef code = NULL;
	*st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	return code;
}

// probe_check runs SecStaticCodeCheckValidityWithErrors with the flags the
// updater plan names. *err receives a malloc'd description on failure.
static OSStatus probe_check(const char *path, const char *req, char **err) {
	*err = NULL;
	OSStatus st;
	SecStaticCodeRef code = mkcode(path, &st);
	if (st != errSecSuccess) return st;
	CFStringRef rs = mkstr(req);
	SecRequirementRef r = NULL;
	st = SecRequirementCreateWithString(rs, kSecCSDefaultFlags, &r);
	CFRelease(rs);
	if (st != errSecSuccess) { CFRelease(code); return st; }
	CFErrorRef cfe = NULL;
	st = SecStaticCodeCheckValidityWithErrors(code,
		kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, r, &cfe);
	if (cfe != NULL) {
		CFStringRef d = CFErrorCopyDescription(cfe);
		*err = cfstr(d);
		if (d) CFRelease(d);
		CFRelease(cfe);
	}
	CFRelease(r);
	CFRelease(code);
	return st;
}

typedef struct {
	char *identifier;
	char *team;
	uint32_t flags;
	int has_plist;
	char *bundle_id;
	char *short_version;
	char **ent_keys;
	int ent_count;
} probe_info_t;

static void probe_info_free(probe_info_t *pi) {
	free(pi->identifier); free(pi->team); free(pi->bundle_id); free(pi->short_version);
	for (int i = 0; i < pi->ent_count; i++) free(pi->ent_keys[i]);
	free(pi->ent_keys);
}

static char *ent_key(probe_info_t *pi, int i) { return pi->ent_keys[i]; }

static OSStatus probe_info(const char *path, probe_info_t *pi) {
	memset(pi, 0, sizeof(*pi));
	OSStatus st;
	SecStaticCodeRef code = mkcode(path, &st);
	if (st != errSecSuccess) return st;
	CFDictionaryRef d = NULL;
	st = SecCodeCopySigningInformation(code,
		kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSInternalInformation, &d);
	CFRelease(code);
	if (st != errSecSuccess) return st;
	pi->identifier = cfstr(CFDictionaryGetValue(d, kSecCodeInfoIdentifier));
	pi->team = cfstr(CFDictionaryGetValue(d, kSecCodeInfoTeamIdentifier));
	CFNumberRef f = CFDictionaryGetValue(d, kSecCodeInfoFlags);
	if (f != NULL && CFGetTypeID(f) == CFNumberGetTypeID()) {
		int64_t v = 0;
		CFNumberGetValue(f, kCFNumberSInt64Type, &v);
		pi->flags = (uint32_t)v;
	}
	CFDictionaryRef pl = CFDictionaryGetValue(d, kSecCodeInfoPList);
	if (pl != NULL && CFGetTypeID(pl) == CFDictionaryGetTypeID()) {
		pi->has_plist = 1;
		pi->bundle_id = cfstr(CFDictionaryGetValue(pl, CFSTR("CFBundleIdentifier")));
		pi->short_version = cfstr(CFDictionaryGetValue(pl, CFSTR("CFBundleShortVersionString")));
	}
	CFDictionaryRef ent = CFDictionaryGetValue(d, kSecCodeInfoEntitlementsDict);
	if (ent != NULL && CFGetTypeID(ent) == CFDictionaryGetTypeID()) {
		CFIndex n = CFDictionaryGetCount(ent);
		if (n > 0) {
			const void **keys = malloc(sizeof(void *) * n);
			pi->ent_keys = calloc(n, sizeof(char *));
			if (keys != NULL && pi->ent_keys != NULL) {
				CFDictionaryGetKeysAndValues(ent, keys, NULL);
				for (CFIndex i = 0; i < n; i++) pi->ent_keys[i] = cfstr(keys[i]);
				pi->ent_count = (int)n;
			}
			free(keys);
		}
	}
	CFRelease(d);
	return errSecSuccess;
}
*/
import "C"

import (
	"fmt"
	"sort"
	"time"
	"unsafe"
)

// kSecCodeSignatureRuntime is the hardened-runtime bit of kSecCodeInfoFlags.
const kSecCodeSignatureRuntime = 0x10000

// gostr converts a C string; the caller frees it.
func gostr(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// check reports whether path satisfies the requirement string req.
func check(path, req string) (CheckResult, error) {
	cp, cr := C.CString(path), C.CString(req)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cr))
	var cerr *C.char
	start := time.Now()
	st := C.probe_check(cp, cr, &cerr)
	wall := time.Since(start)
	msg := gostr(cerr)
	C.free(unsafe.Pointer(cerr))
	return CheckResult{
		Path:        path,
		Requirement: req,
		Satisfied:   st == 0,
		Status:      int(st),
		Error:       msg,
		WallMillis:  float64(wall.Microseconds()) / 1000,
	}, nil
}

// info reads the signing information of path.
func info(path string) (InfoResult, error) {
	cp := C.CString(path)
	defer C.free(unsafe.Pointer(cp))
	var pi C.probe_info_t
	if st := C.probe_info(cp, &pi); st != 0 {
		return InfoResult{}, fmt.Errorf("signing information for %s: OSStatus %d", path, int(st))
	}
	defer C.probe_info_free(&pi)
	ents := []string{}
	for i := 0; i < int(pi.ent_count); i++ {
		ents = append(ents, gostr(C.ent_key(&pi, C.int(i))))
	}
	sort.Strings(ents)
	return InfoResult{
		Path:            path,
		Identifier:      gostr(pi.identifier),
		Team:            gostr(pi.team),
		Flags:           uint32(pi.flags),
		HardenedRuntime: pi.flags&kSecCodeSignatureRuntime != 0,
		Entitlements:    ents,
		InfoPlist:       pi.has_plist != 0,
		BundleID:        gostr(pi.bundle_id),
		ShortVersion:    gostr(pi.short_version),
	}, nil
}
