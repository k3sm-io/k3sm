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

package netdsvc

/*
#cgo LDFLAGS: -framework SystemConfiguration -framework CoreFoundation
#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

static SCDynamicStoreRef k3sm_store_create(void) {
	return SCDynamicStoreCreate(NULL, CFSTR("io.k3sm.netd"), NULL, NULL);
}

static void k3sm_release(CFTypeRef ref) {
	if (ref != NULL) {
		CFRelease(ref);
	}
}

static CFMutableArrayRef k3sm_array_new(void) {
	return CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
}

static void k3sm_array_append(CFMutableArrayRef arr, const char *s) {
	CFStringRef str = CFStringCreateWithCString(NULL, s, kCFStringEncodingUTF8);
	if (str != NULL) {
		CFArrayAppendValue(arr, str);
		CFRelease(str);
	}
}

// k3sm_store_set_dns writes the supplemental DNS dictionary at key. Returns 0 or
// the SCError() status.
static int k3sm_store_set_dns(SCDynamicStoreRef store, const char *key, CFArrayRef servers,
                              CFArrayRef domains, int nosearch, int order) {
	CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
	CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
	                                                     &kCFTypeDictionaryValueCallBacks);
	CFNumberRef ns = CFNumberCreate(NULL, kCFNumberIntType, &nosearch);
	CFNumberRef ord = CFNumberCreate(NULL, kCFNumberIntType, &order);
	CFDictionarySetValue(d, CFSTR("ServerAddresses"), servers);
	CFDictionarySetValue(d, CFSTR("SupplementalMatchDomains"), domains);
	CFDictionarySetValue(d, CFSTR("SupplementalMatchDomainsNoSearch"), ns);
	CFDictionarySetValue(d, CFSTR("SupplementalMatchOrder"), ord);
	Boolean ok = SCDynamicStoreSetValue(store, k, d);
	int status = ok ? 0 : SCError();
	CFRelease(ns);
	CFRelease(ord);
	CFRelease(d);
	CFRelease(k);
	return status;
}

// k3sm_store_remove removes key. Returns 0 (also for an absent key) or the
// SCError() status.
static int k3sm_store_remove(SCDynamicStoreRef store, const char *key) {
	CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
	Boolean ok = SCDynamicStoreRemoveValue(store, k);
	int status = ok ? 0 : SCError();
	CFRelease(k);
	if (status == kSCStatusNoKey) {
		return 0;
	}
	return status;
}

// k3sm_store_has reports 1 when key holds a value, 0 when it does not.
static int k3sm_store_has(SCDynamicStoreRef store, const char *key) {
	CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
	CFPropertyListRef v = SCDynamicStoreCopyValue(store, k);
	CFRelease(k);
	if (v == NULL) {
		return 0;
	}
	CFRelease(v);
	return 1;
}

static const char *k3sm_sc_error_string(int status) {
	return SCErrorString(status);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// SystemStore is the production resolverPublisher: one SCDynamicStore session
// held for the daemon's life (the key it writes with SCDynamicStoreSetValue
// persists in configd after the session ends, which is why netd rewrites the
// full entry on every start and removes it explicitly on stop and uninstall).
// Writing a State: key needs root; reading does not.
//
// Concurrency: mu serializes every call on the store ref.
type SystemStore struct {
	mu    sync.Mutex
	store C.SCDynamicStoreRef
}

// OpenSystemStore opens the dynamic-store session.
func OpenSystemStore() (*SystemStore, error) {
	s := C.k3sm_store_create()
	if s == 0 {
		return nil, fmt.Errorf("SCDynamicStoreCreate: %s", scError(int(C.SCError())))
	}
	return &SystemStore{store: s}, nil
}

// Publish writes entry at key, replacing any previous value.
func (s *SystemStore) Publish(key string, entry ResolverEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == 0 {
		return fmt.Errorf("dynamic store is closed")
	}
	servers := cfStringArray(entry.ServerAddresses)
	defer C.k3sm_release(C.CFTypeRef(servers))
	domains := cfStringArray(entry.SupplementalMatchDomains)
	defer C.k3sm_release(C.CFTypeRef(domains))
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	noSearch := 0
	if entry.SupplementalMatchDomainsNoSearch {
		noSearch = 1
	}
	if st := C.k3sm_store_set_dns(s.store, ck, C.CFArrayRef(servers), C.CFArrayRef(domains),
		C.int(noSearch), C.int(entry.SupplementalMatchOrder)); st != 0 {
		return fmt.Errorf("SCDynamicStoreSetValue %s: %s", key, scError(int(st)))
	}
	return nil
}

// Remove deletes key; an absent key is not an error.
func (s *SystemStore) Remove(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == 0 {
		return fmt.Errorf("dynamic store is closed")
	}
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	if st := C.k3sm_store_remove(s.store, ck); st != 0 {
		return fmt.Errorf("SCDynamicStoreRemoveValue %s: %s", key, scError(int(st)))
	}
	return nil
}

// Present reports whether key holds a value.
func (s *SystemStore) Present(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == 0 {
		return false, fmt.Errorf("dynamic store is closed")
	}
	ck := C.CString(key)
	defer C.free(unsafe.Pointer(ck))
	return C.k3sm_store_has(s.store, ck) == 1, nil
}

// Close releases the session. It does NOT remove what was published.
func (s *SystemStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	C.k3sm_release(C.CFTypeRef(s.store))
	s.store = 0
	return nil
}

// cfStringArray builds a CFArray of CFStrings; the caller releases it.
func cfStringArray(values []string) C.CFMutableArrayRef {
	arr := C.k3sm_array_new()
	for _, v := range values {
		cv := C.CString(v)
		C.k3sm_array_append(arr, cv)
		C.free(unsafe.Pointer(cv))
	}
	return arr
}

// scError renders an SCError status.
func scError(status int) string {
	return fmt.Sprintf("%s (status %d)", C.GoString(C.k3sm_sc_error_string(C.int(status))), status)
}
