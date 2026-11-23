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
	"slices"
	"testing"
)

// On the no-key and untrusted paths there is no key identity to bind the
// held directory to, so it must be the directory the judge opened: another
// directory holding the same kind of thing, swapped in at the name after
// the judge (the seam), is refused with nothing taken, and both
// directories are untouched.
func TestRmScopePinsJudgedDirectory(t *testing.T) {
	for name, damage := range map[string]func(t *testing.T, dir string){
		"no key": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		},
		"untrusted": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, scopeKeyName), []byte("not a key record"), fileMode); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			damage(t, dir)
			other := filepath.Join(server, "other")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(other, "kept"), []byte("x"), fileMode); err != nil {
				t.Fatal(err)
			}
			damage(t, other)
			away := filepath.Join(server, "away")
			var before, judged []string
			setSeam(t, &rmBeforeTree, func() {
				mustRename(t, dir, away)
				mustRename(t, other, dir)
				before, judged = treeNames(t, dir), treeNames(t, away)
			})
			takes := countTakes(t)
			_, err := s.RemoveScope(t.Context(), 1001)
			if !errors.Is(err, errNotJudgedScope) || Committed(err) {
				t.Fatalf("rm-scope over a directory swapped in after the judge: %v, want a refusal, errNotJudgedScope", err)
			}
			if *takes != 0 {
				t.Errorf("rmTakeDir ran %d times, want none", *takes)
			}
			if after := treeNames(t, dir); !slices.Equal(before, after) {
				t.Fatalf("the swapped-in directory holds %v, want %v untouched", after, before)
			}
			if after := treeNames(t, away); !slices.Equal(judged, after) {
				t.Fatalf("the judged directory holds %v, want %v untouched", after, judged)
			}
		})
	}
}
