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
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// TestKeystoreRunDirUserFlagAsRoot, root-run: the service user sets uchg
// on keystore-run/, which it owns, so root's fchmod and fchown on it fail
// EPERM; install clears the user flag on its judged descriptor first and
// finishes, leaving the directory the service user's 0700 with no flag.
func TestKeystoreRunDirUserFlagAsRoot(t *testing.T) {
	r := newInstRoot(t, false)
	setSeam[fileAttrWriter](t, &fileAttrSeam, &instProbeAttrs{})
	if err := ensureKeystoreFiles(r.root, r.svcUID, r.svcGID, 0); err != nil {
		t.Fatalf("the first install: %v", err)
	}
	run := filepath.Join(r.root, keystore.RunDirName)
	// The service user cannot search the test's temp parents, so it sets
	// the flag through a descriptor root opened: fchflags is judged on
	// ownership, which is the service user's.
	fd, err := unix.Open(run, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := r.asService(func() error { return unix.Fchflags(fd, unix.UF_IMMUTABLE) }); err != nil {
		t.Fatalf("the service user's fchflags uchg of keystore-run/: %v", err)
	}
	if err := unix.Chmod(run, 0o755); err == nil {
		t.Fatal("root's chmod of a uchg directory succeeded; the case this test pins does not arise")
	}
	if err := ensureKeystoreFiles(r.root, r.svcUID, r.svcGID, 0); err != nil {
		t.Fatalf("install over a uchg keystore-run/: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Lstat(run, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.UF_SETTABLE != 0 || st.Mode&0o7777 != keystoreRunDirMode || int(st.Uid) != r.svcUID {
		t.Fatalf("keystore-run/ is flags %#x mode %04o uid %d, want no user flag, %04o, the service user's", st.Flags, st.Mode&0o7777, st.Uid, keystoreRunDirMode)
	}
}
