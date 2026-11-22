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

import "testing"

// The real GeneratedUID lookup needs cgo on darwin; a cgo-free darwin build
// would ship the stub, under which every user scope fails closed. This test
// fails such a build.
func TestGeneratedUIDLookupIsRealOnDarwin(t *testing.T) {
	if !generatedUIDIsReal {
		t.Fatal("built without cgo: the GeneratedUID lookup is the stub, so every user scope fails closed; build with CGO_ENABLED=1")
	}
}
