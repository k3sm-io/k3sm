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
	"os"
	"path/filepath"
	"testing"
)

// The service user can keep its scope directory, or .user, at a mode other
// than 0700; that does not let the principal being revoked veto its
// revocation: rm-scope's judge opens either directory whatever its mode
// (the owner rule is unchanged), so the scope is judged, listed and
// removed, exit 0. The serving path still refuses the mode.
func TestRmScopeDirectoryModeCannotVeto(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  func(server string) string
		mode os.FileMode
	}{
		{"scope directory 0750", func(server string) string { return scopeDir(server, "1001") }, 0o750},
		{"scope directory 0777", func(server string) string { return scopeDir(server, "1001") }, 0o777},
		{".user 0755", func(server string) string { return filepath.Dir(scopeDir(server, "1001")) }, 0o755},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			if err := os.Chmod(tc.dir(server), tc.mode); err != nil {
				t.Fatal(err)
			}
			root, err := s.openDir(s.dir, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rmScopeOf(s, 1001).openScopeDir(root, false); !errors.Is(err, ErrCorrupt) {
				t.Errorf("the serving path's opener at mode %#o: %v, want ErrCorrupt", tc.mode, err)
			}
			_ = root.Close()
			res, err := s.RemoveScope(t.Context(), 1001)
			if err != nil || !res.Recorded {
				t.Fatalf("rm-scope with %s: %v, recorded %v; want removed and listed", tc.name, err, res.Recorded)
			}
			if _, err := os.Lstat(scopeDir(server, "1001")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the scope directory is still there: %v", err)
			}
			if !readRecord(t, s).listed(1001) {
				t.Fatal("the scope is not listed")
			}
		})
	}
}
