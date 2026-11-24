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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// U104 (install's half): the keystore step creates keystore-sock/ at 0755,
// the data root owner's and in the data root's group (root:wheel in
// production), keeps one that is already right, and refuses one at another
// mode, changing nothing; the server's uninstall removes it, and an agent's
// manifest does not name it.
func TestKeystoreSockDirAtInstall(t *testing.T) {
	me := os.Getuid()
	setup := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		rec := &attrRecorder{}
		setSeam(t, &euidSeam, func() int { return 0 })
		setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
		setSeam(t, &keystoreFstatSeam, rec.fakeStat(271))
		return root
	}
	sock := func(root string) string { return filepath.Join(root, keystorepaths.SockDir) }
	t.Run("fresh, then kept", func(t *testing.T) {
		root := setup(t)
		for range 2 {
			if err := ensureKeystoreFiles(root, 271, 20, me); err != nil {
				t.Fatal(err)
			}
			var rst, st unix.Stat_t
			if err := unix.Lstat(root, &rst); err != nil {
				t.Fatal(err)
			}
			if err := unix.Lstat(sock(root), &st); err != nil {
				t.Fatal(err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o755 || int(st.Uid) != me || st.Gid != rst.Gid {
				t.Fatalf("keystore-sock/: mode %#o uid %d gid %d; want a 0755 directory of uid %d, gid %d", st.Mode, st.Uid, st.Gid, me, rst.Gid)
			}
		}
	})
	t.Run("wrong mode refused", func(t *testing.T) {
		root := setup(t)
		if err := os.Mkdir(sock(root), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, 271, 20, me); !errors.Is(err, errKeystoreFileUntrusted) {
			t.Fatalf("got %v, want errKeystoreFileUntrusted", err)
		}
		if fi, err := os.Lstat(sock(root)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("keystore-sock/ changed: %v, %v", fi, err)
		}
	})
	t.Run("uninstall", func(t *testing.T) {
		names := func(cfg Config) bool {
			for _, a := range artifactManifest(cfg) {
				if a.path == filepath.Join(cfg.withDefaults().DataRoot, keystorepaths.SockDir) {
					return a.kind == kindDir && a.disp == dispRemove
				}
			}
			return false
		}
		if !names(Config{Role: RoleServer}) {
			t.Fatal("the server manifest does not remove keystore-sock/")
		}
		if names(Config{Role: RoleAgent}) {
			t.Fatal("the agent manifest names keystore-sock/")
		}
	})
}
