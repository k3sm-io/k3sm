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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/pkg/keystore"
)

// The service user owns keystore-run/ and can set a user flag on it,
// which would make root's fchmod and fchown fail: install clears the
// user-settable flags on the judged descriptor first, and makes the chmod
// and chown only when the mode or owner is not already right.
func TestKeystoreRunDirClearsUserFlag(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, keystore.RunDirName)
	if err := os.Mkdir(run, keystoreRunDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, keystoreRunDirMode); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(run, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(run, 0) })
	dfd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(dfd) }()
	rec := &attrRecorder{}
	setSeam[fileAttrWriter](t, &fileAttrSeam, rec)
	me, gid := os.Getuid(), os.Getgid()
	if err := ensureKeystoreRunDir(dfd, me, gid, 0); err != nil {
		t.Fatalf("ensureKeystoreRunDir over a uchg directory: %v", err)
	}
	want := []string{fmt.Sprintf("chflags:%s:%#x", keystore.RunDirName, 0)}
	if !slices.Equal(rec.calls, want) {
		t.Fatalf("calls %q, want the user flag cleared and no chmod or chown (mode and owner already right): %q", rec.calls, want)
	}
	// Owner and mode wrong, no flag: chmod and chown, no chflags.
	if err := unix.Chflags(run, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(run, 0o755); err != nil {
		t.Fatal(err)
	}
	rec.calls = nil
	if err := ensureKeystoreRunDir(dfd, 271, 20, me); err != nil {
		t.Fatal(err)
	}
	want = []string{fmt.Sprintf("chmod:%s:%#o", keystore.RunDirName, keystoreRunDirMode), fmt.Sprintf("chown:%s:271:20", keystore.RunDirName)}
	if !slices.Equal(rec.calls, want) {
		t.Fatalf("calls %q, want %q", rec.calls, want)
	}
}
