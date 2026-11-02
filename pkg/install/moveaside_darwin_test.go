//go:build darwin

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

package install

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestMoveInstallRootAsideOnDisk pins the one-way move: an absent aside
// receives the tree, and an existing aside (an empty directory too, which a
// plain rename would replace) is refused with fs.ErrExist and both paths are
// left as they were.
func TestMoveInstallRootAsideOnDisk(t *testing.T) {
	sys := darwinSystem{}
	for _, tc := range []struct {
		name  string
		aside map[string]string // nil: absent; empty: an empty directory
	}{
		{name: "an absent aside receives the tree"},
		{name: "an empty directory at the aside is refused", aside: map[string]string{}},
		{name: "a tree at the aside is refused", aside: map[string]string{"planted": "planted"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			live, aside := filepath.Join(root, "k3sm"), filepath.Join(root, "k3sm.swap")
			mustTree(t, live, map[string]string{"k3sm": "new binary"})
			if tc.aside != nil {
				if err := os.Mkdir(aside, 0o700); err != nil {
					t.Fatal(err)
				}
				mustTree(t, aside, tc.aside)
			}
			err := sys.MoveInstallRootAside(live, aside)
			if tc.aside == nil {
				if err != nil {
					t.Fatalf("MoveInstallRootAside: %v", err)
				}
				if got := mustRead(t, filepath.Join(aside, "k3sm")); got != "new binary" {
					t.Errorf("the aside holds %q, want the moved tree", got)
				}
				if _, err := os.Lstat(live); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("the install root is still there after the move: %v", err)
				}
				return
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("MoveInstallRootAside = %v, want fs.ErrExist", err)
			}
			if got := mustRead(t, filepath.Join(live, "k3sm")); got != "new binary" {
				t.Errorf("the install root holds %q after a refusal, want the new tree", got)
			}
			if _, err := os.Lstat(filepath.Join(live, "planted")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("what was at the aside reached the install root: %v", err)
			}
		})
	}
}
