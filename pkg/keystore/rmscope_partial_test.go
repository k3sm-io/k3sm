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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// An rm-scope that stops after it changed something is committed (exit 4,
// audited committed), never a refusal: a first run that wrote the
// removed-scopes record and then stopped at the take, and a rerun whose
// walk removed entries and then met a directory on another device
// (through the seam), both return the committed class, saying what remains
// and that a rerun continues. A third run, which changes nothing in the
// tree before that directory stops it again, still rewrote the record that
// lists the scope to make it durable again, so it is committed too.
func TestRmScopePartialRemovalIsCommitted(t *testing.T) {
	s, server, _ := fileLogScope(t)
	dir := scopeDir(server, "1001")
	mount := filepath.Join(dir, scopeEntriesName, "mounted")
	if err := os.Mkdir(mount, 0o700); err != nil {
		t.Fatal(err)
	}
	kept := filepath.Join(mount, "theirs")
	if err := os.WriteFile(kept, []byte("another volume's"), 0o600); err != nil {
		t.Fatal(err)
	}
	giveToService(t, mount, kept)
	ino, _ := inoOf(t, mount)
	otherDeviceFor(t, ino)
	ctx := t.Context()

	// Run 1: the record is written, then the scope directory's take fails
	// before the walk changes anything.
	saved := rmTakeDir
	setSeam(t, &rmTakeDir, func(int) error { return unix.EIO })
	_, err := s.RemoveScope(ctx, 1001)
	if !Committed(err) || !errors.Is(err, unix.EIO) {
		t.Fatalf("rm-scope stopped after writing the record: %v, want committed wrapping EIO", err)
	}
	for _, want := range []string{"is listed as removed", "partly or wholly present", "rerun sudo k3sm keys rm-scope user/1001 --yes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the committed stop %q does not say %q", err, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, scopeKeyName)); err != nil {
		t.Fatalf("scope.key after a stop at the take: %v, want it present", err)
	}

	// Run 2: the record already lists the scope; the walk removes the
	// entries beside the other device's directory, then stops at it.
	rmTakeDir = saved
	_, err = s.RemoveScope(ctx, 1001)
	if !Committed(err) || !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("rm-scope that removed entries, then met a foreign directory: %v, want committed wrapping errScopeForeignDir", err)
	}
	if strings.Contains(err.Error(), "sudo") {
		t.Errorf("the stop at a foreign directory %q offers a rerun, which cannot help", err)
	}
	if names, rerr := os.ReadDir(filepath.Join(dir, scopeEntriesName)); rerr != nil || len(names) != 1 || names[0].Name() != "mounted" {
		t.Fatalf("entries/ holds %v (%v), want only the other device's directory", names, rerr)
	}
	if b, rerr := os.ReadFile(kept); rerr != nil || string(b) != "another volume's" {
		t.Fatalf("the file on the other device: %q, %v; want it untouched", b, rerr)
	}

	// Run 3: nothing is left in the tree that the walk can change before
	// it stops, but the run rewrote the record.
	_, err = s.RemoveScope(ctx, 1001)
	if !errors.Is(err, errScopeForeignDir) {
		t.Fatalf("the rerun over only the foreign directory: %v, want errScopeForeignDir", err)
	}
	if !Committed(err) {
		t.Fatalf("a run that rewrote the record is not committed: %v", err)
	}
	if strings.Contains(err.Error(), "sudo") {
		t.Errorf("the refusal at a foreign directory %q offers a rerun, which cannot help", err)
	}
}
