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

package socket

import (
	"strings"
	"testing"
)

// Each class's remedy names only a repair that exists. No doctor check
// judges a scope's shape, so an incomplete scope's remedy names the
// design's recovery instead: a whole-scope restore, or rm-scope then
// floor --rebuild.
func TestDamageRemediesNameRealRepairs(t *testing.T) {
	r := damageRemedies[DamageScopeIncomplete]
	if strings.Contains(r, "doctor") {
		t.Errorf("the scope-incomplete remedy %q names doctor, which has no check for it", r)
	}
	for _, want := range []string{"from one backup", "sudo k3sm keys rm-scope user/<uid> --yes", "sudo k3sm keys floor --rebuild"} {
		if !strings.Contains(r, want) {
			t.Errorf("the scope-incomplete remedy %q does not name %q", r, want)
		}
	}
}
