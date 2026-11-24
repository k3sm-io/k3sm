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
	"os"
	"path/filepath"
	"testing"
)

// Two spellings of one keystore directory, through a symlink (on macOS
// t.TempDir is under /var, itself a link to /private/var), get one
// TreeState, so their stores share one lock and one set of usage figures.
// A directory not there yet is keyed by its cleaned path.
func TestKeystoreTreeKeyedOnResolvedDir(t *testing.T) {
	real := filepath.Join(t.TempDir(), "keystore")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if a, b, c := keystoreTree(real), keystoreTree(link), keystoreTree(resolved); a != b || a != c {
		t.Fatalf("one tree by three spellings got TreeStates %p, %p, %p, want one", a, b, c)
	}
	missing := filepath.Join(t.TempDir(), "none")
	if keystoreTree(missing+"/") != keystoreTree(missing) {
		t.Fatal("a directory not there yet, spelled with a trailing slash, got its own TreeState")
	}
}
