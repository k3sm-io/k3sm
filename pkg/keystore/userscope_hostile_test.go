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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The user tree is walked by descriptor and judged on what was opened: a
// symlinked scope directory, a scope.key that is a FIFO, a second link, too
// wide a mode or too large, and an entries/ that is a file each refuse the
// scope with ErrCorrupt. None reads as an absent scope or entry, none blocks,
// and a Put mints nothing over it.
func TestUserTreeRefusesHostileFiles(t *testing.T) {
	for _, tt := range []struct {
		name  string
		plant func(t *testing.T, scope string)
	}{
		{"symlinked scope directory", func(t *testing.T, scope string) {
			moved := scope + ".real"
			if err := os.Rename(scope, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(moved), scope); err != nil {
				t.Fatal(err)
			}
		}},
		{"scope.key a FIFO", func(t *testing.T, scope string) {
			remove(t, filepath.Join(scope, scopeKeyName))
			if err := syscall.Mkfifo(filepath.Join(scope, scopeKeyName), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"scope.key hard-linked", func(t *testing.T, scope string) {
			if err := os.Link(filepath.Join(scope, scopeKeyName), filepath.Join(scope, "kept-copy")); err != nil {
				t.Fatal(err)
			}
		}},
		{"scope.key mode 0644", func(t *testing.T, scope string) {
			chmod(t, filepath.Join(scope, scopeKeyName), 0o644)
		}},
		{"scope.key oversized", func(t *testing.T, scope string) {
			p := filepath.Join(scope, scopeKeyName)
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, make([]byte, 4096)...), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"entries/ a file", func(t *testing.T, scope string) {
			e := filepath.Join(scope, scopeEntriesName)
			if err := os.RemoveAll(e); err != nil {
				t.Fatal(err)
			}
			writeFile(t, e, "not a directory")
			chmod(t, e, 0o600)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			s, server := newMasteredStore(t)
			fakeGUIDs(t, map[uint32][generationSize]byte{1001: guid(0xA1)})
			u := userScope(t, s, 1001)
			userPut(t, u, "user/1001/token", "v")
			scope := scopeDir(server, "1001")
			key, err := os.ReadFile(filepath.Join(scope, scopeKeyName))
			if err != nil {
				t.Fatal(err)
			}
			tt.plant(t, scope)
			for op, err := range map[string]error{
				"Current": func() error { _, _, err := u.Current(ctx, "user/1001/token"); return err }(),
				"List":    func() error { _, err := u.List(ctx); return err }(),
				"Put":     func() error { _, err := u.Put(ctx, "user/1001/other", KindOpaque, []byte("v")); return err }(),
			} {
				if !errors.Is(err, ErrCorrupt) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrScopeAbsent) {
					t.Errorf("%s: %v, want ErrCorrupt, not an absence", op, err)
				}
			}
			// A refused Put leaves scope.key as it was planted: whatever is at
			// the name is not a fresh regular file holding another key.
			if fi, err := os.Lstat(filepath.Join(scope, scopeKeyName)); err == nil && fi.Mode().IsRegular() {
				if after, err := os.ReadFile(filepath.Join(scope, scopeKeyName)); err != nil || (!bytes.HasPrefix(after, key) && len(after) == len(key)) {
					t.Errorf("a refused Put replaced scope.key: %v", err)
				}
			}
		})
	}
}
