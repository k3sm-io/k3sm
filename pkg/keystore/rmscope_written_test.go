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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writtenThenSecondList sets up a judged run whose check meets a second
// key to list after the run wrote the record: uid 1001's first scope (K1)
// is kept aside, a fresh scope (K2) is minted at a 0750 mode (which the
// judge accepts and which, through the service-uid seam, is not a taken
// leftover by path), and after the judge listed K2 the seam puts K1's
// directory, every level at 0700 and so root's through the seam, at the
// name, then runs fail, so check's list of K1 fails.
func writtenThenSecondList(t *testing.T, fail func(s *FileStore)) (*FileStore, string) {
	t.Helper()
	s, server, u := fileLogScope(t)
	dir := scopeDir(server, "1001")
	spare := filepath.Join(server, "spare")
	if err := os.Rename(dir, spare); err != nil {
		t.Fatal(err)
	}
	takeLeftover(t, spare)
	userPut(t, u, "user/1001/y", "y")
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	setSeam(t, &rmServiceUID, func(*FileStore) uint32 { return s.uid + 1 })
	setSeam(t, &rmBeforeTree, func() {
		if err := os.Rename(dir, dir+".away"); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(spare, dir); err != nil {
			t.Fatal(err)
		}
		fail(s)
	})
	return s, dir
}

// When this run already wrote the record and a later list fails (check's
// read of the floor's size, or a failure before the rename of the second
// write), the result is committed, never "nothing was changed".
func TestRmScopeFailureAfterWriteIsCommitted(t *testing.T) {
	if asRoot() {
		t.Skip("the seam's other service uid makes the store's own directories foreign as root")
	}
	for name, fail := range map[string]func(s *FileStore){
		"floor size": func(s *FileStore) {
			if err := os.Chmod(filepath.Join(s.dataRoot, logsDirName), 0o777); err != nil {
				t.Fatal(err)
			}
		},
		"second write before its rename": func(s *FileStore) {
			if err := os.Mkdir(filepath.Join(s.dataRoot, removedScopesTemp), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.dataRoot, removedScopesTemp, "x"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, dir := writtenThenSecondList(t, fail)
			res, err := s.RemoveScope(t.Context(), 1001)
			if err == nil || !Committed(err) {
				t.Fatalf("rm-scope whose second list failed after a write: %v (recorded %v), want committed", err, res.Recorded)
			}
			if strings.Contains(err.Error(), "nothing was changed") {
				t.Errorf("the error %q says nothing was changed after the record was written", err)
			}
			if !strings.Contains(err.Error(), "earlier in this run") {
				t.Errorf("the error %q does not say the record was written earlier in this run", err)
			}
			if _, err := os.Lstat(dir); err != nil {
				t.Fatalf("the directory at the name: %v, want it untouched", err)
			}
		})
	}
}
