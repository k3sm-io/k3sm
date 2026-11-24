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

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/keystore"
)

// TestStoreDirDenialNamesItsCause: a store directory the server cannot
// open names the repair for what denies it, read without opening it. A
// service-user-owned 0700 directory with a deny ACE is the race on the
// first pass only and then names chmod -N; a parent that denies the walk is
// never the race and names the parent; a third uid's directory is never the
// race and is to be inspected and removed, never chowned.
func TestStoreDirDenialNamesItsCause(t *testing.T) {
	t.Run("a deny ACE names chmod -N", func(t *testing.T) {
		f, _ := installedWiringFixture(t, false)
		storeCfg := f.deps.layout(f.deps.workDir)
		storeCfg.UID, storeCfg.GID = uint32(os.Getuid()), uint32(os.Getgid())
		if err := os.Mkdir(storeCfg.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		me, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command("/bin/chmod", "+a", me.Username+" deny list,search,read", storeCfg.Dir).CombinedOutput(); err != nil {
			t.Fatalf("chmod +a: %v: %s", err, out)
		}
		t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", storeCfg.Dir).Run() })
		step := serverStoreDir(keystore.New(storeCfg), storeCfg.UID, storeCfg.GID)
		if err := step(t.Context()); err == nil || !strings.Contains(err.Error(), storeDirRaceText) {
			t.Fatalf("the first pass: %v, want the race text", err)
		}
		err = step(t.Context())
		if err == nil || !strings.Contains(err.Error(), "chmod -h -N "+storeCfg.Dir) || strings.Contains(err.Error(), storeDirRaceText) {
			t.Fatalf("the second pass: %v, want chmod -N %s and not the race", err, storeCfg.Dir)
		}
		if strings.Contains(err.Error(), "chown") || strings.Contains(err.Error(), "chflags") {
			t.Fatalf("the second pass: %v names a repair the directory does not need", err)
		}
	})
	t.Run("an unsearchable parent is never the race", func(t *testing.T) {
		f, _ := installedWiringFixture(t, false)
		storeCfg := f.deps.layout(f.deps.workDir)
		storeCfg.UID, storeCfg.GID = uint32(os.Getuid()), uint32(os.Getgid())
		parent := filepath.Dir(storeCfg.Dir)
		if err := os.Chmod(parent, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		step := serverStoreDir(keystore.New(storeCfg), storeCfg.UID, storeCfg.GID)
		for pass := 1; pass <= 2; pass++ {
			err := step(t.Context())
			if err == nil || strings.Contains(err.Error(), storeDirRaceText) || !strings.Contains(err.Error(), parent+" denies the service user") || !strings.Contains(err.Error(), "chmod -h 700 "+parent) {
				t.Fatalf("pass %d: %v, want the parent %s named and not the race", pass, err, parent)
			}
		}
	})
	t.Run("a third uid's directory is inspected, never chowned", func(t *testing.T) {
		f, _ := installedWiringFixture(t, false)
		storeCfg := f.deps.layout(f.deps.workDir)
		// The store's service uid is another uid than the test user, which
		// owns the directory: to the store, a third uid.
		storeCfg.UID, storeCfg.GID = uint32(os.Getuid())+1, uint32(os.Getgid())
		if err := os.Mkdir(storeCfg.Dir, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(storeCfg.Dir, 0o700) })
		step := serverStoreDir(keystore.New(storeCfg), storeCfg.UID, storeCfg.GID)
		want := fmt.Sprintf("owned by uid %d, neither root nor the service user, so nothing in it has been checked: as root, inspect it, then remove it", os.Getuid())
		for pass := 1; pass <= 2; pass++ {
			err := step(t.Context())
			if err == nil || strings.Contains(err.Error(), storeDirRaceText) || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "chown") || strings.Contains(err.Error(), "chmod") {
				t.Fatalf("pass %d: %v, want %q, no chown or chmod, and not the race", pass, err, want)
			}
		}
	})
}
