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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// An existing store directory that carries an extended ACL is refused,
// as pre-restore.d is, since an entry can grant past the mode: EnsureDir
// marks it StoreDirRefused (the persistent refusal the server names the
// repair for), CheckDir refuses it the same way, and neither removes it.
// A directory EnsureDir makes under an inheritable ACL carries none and
// passes. The entry is the test user's own, set with chmod +a, so no root is
// needed.
func TestEnsureDirRefusesExtendedACL(t *testing.T) {
	t.Run("an existing directory with an ACL is a refusal", func(t *testing.T) {
		s, server := newTestStore(t)
		dir := filepath.Join(server, "keystore")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		giveToService(t, dir)
		if out, err := exec.Command("/bin/chmod", "+a", "everyone allow list,search", dir).CombinedOutput(); err != nil {
			t.Fatalf("chmod +a: %v: %s", err, out)
		}
		err := s.EnsureDir()
		if !StoreDirRefused(err) || StoreDirRace(err) || !strings.Contains(err.Error(), "extended ACL") || !strings.Contains(err.Error(), "chmod -h -N") {
			t.Fatalf("EnsureDir = %v: refused %v race %v, want a refusal naming the ACL", err, StoreDirRefused(err), StoreDirRace(err))
		}
		if err := s.CheckDir(); err == nil || !strings.Contains(err.Error(), "extended ACL") {
			t.Fatalf("CheckDir = %v, want the ACL refused", err)
		}
		if !pathHasACL(t, dir) {
			t.Fatal("the refusal removed the ACL; an existing directory is never repaired")
		}
	})
	t.Run("a directory it makes under an inheritable ACL passes", func(t *testing.T) {
		s, server := newTestStore(t)
		addInheritableACL(t, server)
		if err := s.EnsureDir(); err != nil {
			t.Fatalf("EnsureDir: %v", err)
		}
		if pathHasACL(t, filepath.Join(server, "keystore")) {
			t.Fatal("the new directory kept the inherited ACL")
		}
	})
}
