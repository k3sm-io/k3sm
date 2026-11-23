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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Every stop of RemoveScope that a rerun would meet the same way returns
// text, at the layer the operator reads, that names what it left for
// reading and offers no command: no sudo line, no rm, no "remove it as
// root", no rerun. Each case drives RemoveScope into one stop through its
// seams: the emptied scope directory moved away before its rmdir, a
// symlink planted at the scope's name, another user's flag on .user (the
// seam stands for its owner), another scope's directory at the name, a
// directory on another device in the tree, and a tree nested too deep.
func TestRmScopeErrorTextsOfferNoCommand(t *testing.T) {
	if asRoot() {
		t.Skip("the cases set the test user's own flags and own its tree; the root cases are in the root-run tests")
	}
	for _, tc := range []struct {
		name  string
		want  error
		setup func(t *testing.T, s *FileStore, server, dir string)
	}{
		{"moved before its rmdir", errScopeDirMoved, func(t *testing.T, _ *FileStore, _, dir string) {
			done := false
			setSeam(t, &rmBeforeScopeRmdir, func(step rmdirStep) {
				if done || step != rmdirBeforeStat {
					return
				}
				done = true
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"planted at the scope's name", errPlanted, func(t *testing.T, _ *FileStore, _, dir string) {
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".away", dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"another user's flag on .user", errSharedDirFlag, func(t *testing.T, s *FileStore, _, dir string) {
			shared := filepath.Dir(dir)
			t.Cleanup(func() { _ = unix.Chflags(shared, 0) })
			setScopeFlags(t, shared, unix.UF_IMMUTABLE, false)
			setSeam(t, &rmSharedOwner, func(*unix.Stat_t) uint32 { return s.uid + 1 })
		}},
		{"another scope at the name", errNotJudgedScope, func(t *testing.T, s *FileStore, server, dir string) {
			userPut(t, userScope(t, s, 1002), "user/1002/x", "x")
			setSeam(t, &rmBeforeTree, func() {
				if err := os.Rename(dir, dir+".away"); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(scopeDir(server, "1002"), dir); err != nil {
					t.Fatal(err)
				}
			})
		}},
		{"a directory on another device", errScopeForeignDir, func(t *testing.T, _ *FileStore, _, dir string) {
			mount := filepath.Join(dir, scopeEntriesName, "mounted")
			if err := os.Mkdir(mount, 0o700); err != nil {
				t.Fatal(err)
			}
			ino, _ := inoOf(t, mount)
			otherDeviceFor(t, ino)
		}},
		{"nested too deep", errScopeTreeDeep, func(t *testing.T, _ *FileStore, _, dir string) {
			p := filepath.Join(dir, scopeEntriesName)
			for i := 0; i <= maxScopeTreeDepth; i++ {
				p = filepath.Join(p, fmt.Sprintf("c%d", i))
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, server, _ := fileLogScope(t)
			dir := scopeDir(server, "1001")
			tc.setup(t, s, server, dir)
			_, err := s.RemoveScope(t.Context(), 1001)
			if !errors.Is(err, tc.want) {
				t.Fatalf("rm-scope: %v, want %v", err, tc.want)
			}
			msg := err.Error()
			for _, bad := range []string{"sudo", "rm -", "remove it as root", "rerun"} {
				if strings.Contains(msg, bad) {
					t.Errorf("the error %q offers %q, and a rerun cannot help", msg, bad)
				}
			}
		})
	}
	// A scope directory that is gone when the walk comes to open it was not
	// removed by this run, and nothing was written: a refusal saying it was
	// found absent, never that it was removed.
	t.Run("absent at the open", func(t *testing.T) {
		s, server, _ := fileLogScope(t)
		dir := scopeDir(server, "1001")
		if err := os.Remove(filepath.Join(dir, scopeKeyName)); err != nil {
			t.Fatal(err)
		}
		setSeam(t, &rmBeforeTree, func() {
			if err := os.Rename(dir, dir+".away"); err != nil {
				t.Fatal(err)
			}
		})
		_, err := s.RemoveScope(t.Context(), 1001)
		if err == nil || Committed(err) {
			t.Fatalf("rm-scope of a keyless scope found absent: %v, want a refusal", err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "absent at its name") || strings.Contains(msg, "removed user/1001") || strings.Contains(msg, "removed the directory") {
			t.Errorf("the report %q does not say the scope was found absent, or says it was removed", msg)
		}
	})
}
