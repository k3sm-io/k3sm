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

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// keysRmScopeStub answers RemoveScope with a fixed result.
type keysRmScopeStub struct {
	keysStore
	recorded bool
	err      error
}

func (s keysRmScopeStub) RemoveScope(context.Context, uint32) (bool, error) {
	return s.recorded, s.err
}

// rm-scope exits 4, audited committed, both when the record is full (its
// own text) and when it removed a keyless scope it could not list (that
// text, never the full record's).
func TestKeysRmScopeUnlistedExitsCommitted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		want     string
		mustNot  string
		recorded bool
	}{
		{"full record", nil, "the removed-scopes record is full", "", false},
		{"keyless scope", fmt.Errorf("%w: removed user/1001 without listing it in keystore-removed-scopes.json, because its scope.key was absent", keystore.ErrCommitted), "without listing it", "is full", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newKeysHarness(t)
			var lines []string
			h.wrap = func(s keysStore) keysStore {
				return keysAuditRecorder{keysStore: keysRmScopeStub{keysStore: s, recorded: tc.recorded, err: tc.err}, lines: &lines}
			}
			h.euid = 0
			h.mustRun(keysCommitted, "rm-scope", "user/1001", "--yes")
			out := h.stdout.String() + h.stderr.String()
			if !strings.Contains(out, tc.want) || (tc.mustNot != "" && strings.Contains(out, tc.mustNot)) {
				t.Errorf("rm-scope printed %q, want %q and not %q", out, tc.want, tc.mustNot)
			}
			if !slices.Equal(lines, []string{"rm-scope  committed"}) {
				t.Errorf("rm-scope audit lines %q, want committed", lines)
			}
		})
	}
}
