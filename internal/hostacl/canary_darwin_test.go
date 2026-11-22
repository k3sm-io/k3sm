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

import "testing"

// TestMbrUIDToUUIDSymbolCanary is the symbol canary for mbr_uid_to_uuid,
// which this package's ACL entries and the keystore's GeneratedUID binding
// (pkg/keystore, docs/design/keystore.md § "Key hierarchy") call. Both link
// it, so a macOS without it fails the build; this names it at run time, an
// integration test of the real primitive.
func TestMbrUIDToUUIDSymbolCanary(t *testing.T) {
	if !symbolResolves("mbr_uid_to_uuid") {
		t.Fatal("mbr_uid_to_uuid does not resolve: the GeneratedUID lookup and the ACL entries both need it")
	}
	if symbolResolves("k3sm_no_such_symbol_canary") {
		t.Fatal("the canary resolves a symbol that does not exist, so it proves nothing")
	}
}
