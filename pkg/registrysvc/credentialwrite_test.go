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

package registrysvc

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteCredentialRefusesStaleWideTemp checks that the push credential and
// the htpasswd file are written through a fresh temp file: a leftover 0666
// temp file does not pass its mode on, a temp name that is a symlink is never
// written through, and the final file is a 0600 regular file holding the new
// content. It also checks that provision narrows a wider registry dir and
// refuses a symlinked one.
func TestWriteCredentialRefusesStaleWideTemp(t *testing.T) {
	secretFiles := map[string]func(string) string{
		"push-credential.json": CredentialPath,
		"htpasswd":             HTPasswdPath,
	}
	assertFinal := func(t *testing.T, path string) {
		t.Helper()
		fi, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.Mode().IsRegular() {
			t.Fatalf("%s is %v, want a regular file", path, fi.Mode())
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %#o, want 0600", path, fi.Mode().Perm())
		}
		if _, err := os.Lstat(path + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("the temp file %s.tmp survived: %v", path, err)
		}
	}
	mint := func(t *testing.T) Credential {
		t.Helper()
		c, err := generateCredential("127.0.0.1:6450")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for name, pathOf := range secretFiles {
		t.Run(name+": a stale 0666 temp file does not set the mode", func(t *testing.T) {
			work := t.TempDir()
			if err := os.Mkdir(StateDir(work), 0o700); err != nil {
				t.Fatal(err)
			}
			tmp := pathOf(work) + ".tmp"
			if err := os.WriteFile(tmp, []byte("stale"), 0o666); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tmp, 0o666); err != nil {
				t.Fatal(err)
			}
			cred := mint(t)
			if err := WriteCredential(work, cred); err != nil {
				t.Fatal(err)
			}
			assertFinal(t, pathOf(work))
			got, err := ReadCredential(work)
			if err != nil {
				t.Fatal(err)
			}
			if got != cred {
				t.Errorf("the credential file holds %+v, want the new credential", got)
			}
		})
		t.Run(name+": a symlinked temp file is never written through", func(t *testing.T) {
			work := t.TempDir()
			if err := os.Mkdir(StateDir(work), 0o700); err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(victim, pathOf(work)+".tmp"); err != nil {
				t.Fatal(err)
			}
			cred := mint(t)
			if err := WriteCredential(work, cred); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(victim)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != "untouched" {
				t.Errorf("the write followed the temp symlink: the target now holds %q", b)
			}
			assertFinal(t, pathOf(work))
			got, err := ReadCredential(work)
			if err != nil {
				t.Fatal(err)
			}
			if got != cred {
				t.Errorf("the credential file holds %+v, want the new credential", got)
			}
		})
	}
	t.Run("a directory swapped for a symlink after the check is not followed", func(t *testing.T) {
		work := t.TempDir()
		dir := StateDir(work)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		d, err := openStateDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		// After the check: the checked directory moves aside and a symlink to
		// a directory of the attacker's choosing takes its name.
		moved := filepath.Join(work, "registry.checked")
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		target := t.TempDir()
		// A stale temp name in the symlink target: a removal that went by path
		// instead of through the checked descriptor would delete it.
		sentinel := filepath.Join(target, "push-credential.json.tmp")
		if err := os.WriteFile(sentinel, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, dir); err != nil {
			t.Fatal(err)
		}
		// The write is bound to the checked descriptor, so it succeeds into the
		// directory that was checked, wherever its name now points.
		if err := writeFileInDir(d, CredentialPath(work), []byte("secret\n")); err != nil {
			t.Fatalf("the write through the checked directory failed: %v", err)
		}
		b, err := os.ReadFile(sentinel)
		if err != nil {
			t.Fatalf("the stale temp name in the symlink target was removed: %v", err)
		}
		if string(b) != "sentinel" {
			t.Errorf("the stale temp name in the symlink target now holds %q", b)
		}
		if _, err := os.Lstat(filepath.Join(target, "push-credential.json")); !os.IsNotExist(err) {
			t.Errorf("push-credential.json landed in the symlink target: %v", err)
		}
		b, err = os.ReadFile(filepath.Join(moved, "push-credential.json"))
		if err != nil {
			t.Fatalf("the write did not land in the checked directory: %v", err)
		}
		if string(b) != "secret\n" {
			t.Errorf("the checked directory holds %q, want the new content", b)
		}
		if _, err := os.Lstat(filepath.Join(moved, "push-credential.json.tmp")); !os.IsNotExist(err) {
			t.Errorf("the temp file survived in the checked directory: %v", err)
		}
	})
	t.Run("a path outside the open directory is refused", func(t *testing.T) {
		work := t.TempDir()
		d, err := openStateDir(StateDir(work))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		if err := os.Mkdir(ServeStateDir(work), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeFileInDir(d, ServeConfigPath(work), []byte("x")); err == nil {
			t.Fatal("writeFileInDir wrote a path outside the directory it holds")
		}
		if _, err := os.Lstat(ServeConfigPath(work)); !os.IsNotExist(err) {
			t.Errorf("a file landed outside the open directory: %v", err)
		}
	})
	t.Run("provision narrows a wider registry dir", func(t *testing.T) {
		work := t.TempDir()
		if err := os.Mkdir(StateDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(StateDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{WorkDir: work, Port: 6450})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.provision(); err != nil {
			t.Fatal(err)
		}
		fi, err := os.Lstat(StateDir(work))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o700 {
			t.Errorf("registry dir mode %#o, want 0700", fi.Mode().Perm())
		}
	})
	t.Run("provision refuses a symlinked registry dir", func(t *testing.T) {
		work := t.TempDir()
		target := t.TempDir()
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, StateDir(work)); err != nil {
			t.Fatal(err)
		}
		s, err := New(Config{WorkDir: work, Port: 6450})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.provision(); err == nil {
			t.Fatal("provision wrote through a symlinked registry dir")
		}
		for name := range secretFiles {
			if _, err := os.Lstat(filepath.Join(target, name)); !os.IsNotExist(err) {
				t.Errorf("%s landed in the symlink target: %v", name, err)
			}
		}
	})
}
