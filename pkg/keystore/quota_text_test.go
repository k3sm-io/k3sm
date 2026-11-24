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
	"errors"
	"strings"
	"testing"
)

// No quota text recommends rm then put as a remedy: rm is a deletion that
// cannot be undone, and the put after it may itself be refused.
func TestQuotaTextsNameNoRmThenPut(t *testing.T) {
	budget := judgeScopeQuota(map[string]int64{}, "token", []byte("v"), maxScopeBytes)
	if !errors.Is(budget, ErrQuota) {
		t.Fatalf("a put past the byte budget: %v, want ErrQuota", budget)
	}
	for _, err := range []error{ErrQuota, budget} {
		msg := strings.ToLower(err.Error())
		for _, bad := range []string{"then put", "put it again", "and put"} {
			if strings.Contains(msg, bad) {
				t.Errorf("quota text %q recommends rm then put (%q)", err, bad)
			}
		}
	}
}
