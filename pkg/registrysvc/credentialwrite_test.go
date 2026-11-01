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
