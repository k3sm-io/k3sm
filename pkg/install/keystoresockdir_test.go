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
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/runtimed/pkg/keystorepaths"
)

// U104 (install's half): the keystore step creates keystore-sock/ at 0755,
// the data root owner's and in the socket group (root:wheel in production,
// the test user's own group here: keystoreSockGID), whatever the data
// root's group; keeps one that is already right; and refuses one at another
// mode or in another group, with the server's start check's text, changing
// nothing; the server's uninstall removes it, and an agent's manifest does
// not name it.
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
	// other is a group the test user is in that is not its own: BSD mkdir
	// gives a new directory its parent's group, so a data root in other
	// would hand it to keystore-sock/.
	other := func(t *testing.T) int {
		t.Helper()
		gs, err := os.Getgroups()
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range gs {
			if g != os.Getgid() {
				return g
			}
		}
		t.Skip("the test user is in no group beside its own")
		return -1
	}
	t.Run("fresh, then kept", func(t *testing.T) {
		root := setup(t)
		for range 2 {
			if err := ensureKeystoreFiles(root, 271, 20, me); err != nil {
				t.Fatal(err)
			}
			var st unix.Stat_t
			if err := unix.Lstat(sock(root), &st); err != nil {
				t.Fatal(err)
			}
			if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o755 || int(st.Uid) != me || int(st.Gid) != os.Getgid() {
				t.Fatalf("keystore-sock/: mode %#o uid %d gid %d; want a 0755 directory of uid %d, gid %d", st.Mode, st.Uid, st.Gid, me, os.Getgid())
			}
		}
	})
	t.Run("a data root in another group still gets the socket group", func(t *testing.T) {
		root := setup(t)
		g := other(t)
		if err := os.Chown(root, -1, g); err != nil {
			t.Fatal(err)
		}
		if err := ensureKeystoreFiles(root, 271, 20, me); err != nil {
			t.Fatal(err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(sock(root), &st); err != nil {
			t.Fatal(err)
		}
		if int(st.Gid) != os.Getgid() {
			t.Fatalf("keystore-sock/ in a data root of group %d: gid %d, want the socket group %d", g, st.Gid, os.Getgid())
		}
	})
	t.Run("an existing directory in another group refused", func(t *testing.T) {
		root := setup(t)
		g := other(t)
		// The data root and the directory share the group, as BSD mkdir
		// leaves them: install's old judge took the data root's group.
		if err := os.Chown(root, -1, g); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(sock(root), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(sock(root), -1, g); err != nil {
			t.Fatal(err)
		}
		err := ensureKeystoreFiles(root, 271, 20, me)
		if !errors.Is(err, errKeystoreFileUntrusted) || !strings.Contains(err.Error(), "the socket directory "+keystorepaths.SockDir+" is not owned by root:wheel") {
			t.Fatalf("got %v, want errKeystoreFileUntrusted with the start check's text", err)
		}
		var st unix.Stat_t
		if err := unix.Lstat(sock(root), &st); err != nil || int(st.Gid) != g {
			t.Fatalf("keystore-sock/ changed: gid %d, %v; want %d", st.Gid, err, g)
		}
	})
	t.Run("a 077 umask still makes it 0755", func(t *testing.T) {
		root := setup(t)
		dfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }() // a directory, read-only
		old := unix.Umask(0o077)
		err = ensureKeystoreSockDir(dfd, me)
		unix.Umask(old)
		if err != nil {
			t.Fatalf("under a 077 umask: %v", err)
		}
		if fi, err := os.Lstat(sock(root)); err != nil || fi.Mode().Perm() != 0o755 {
			t.Fatalf("keystore-sock/ under a 077 umask: %v, %v; want 0755", fi, err)
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
