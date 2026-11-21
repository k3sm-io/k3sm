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

package hf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// age sets the modification time of every path to before.
func age(t *testing.T, before time.Time, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.Chtimes(p, before, before); err != nil {
			t.Fatal(err)
		}
	}
}

// TestImportSweepsLeftoverScratch: an import removes, from its scratch
// root, the ScratchPrefix directories this user owns that have been quiet
// for StaleScratchAge, and leaves everything else: a recent one, an old one
// with a recent file in it (a live import), an unprefixed one, a prefixed
// symbolic link and its target, and a prefixed file.
func TestImportSweepsLeftoverScratch(t *testing.T) {
	parent := t.TempDir()
	outside := t.TempDir()
	old := time.Now().Add(-StaleScratchAge - time.Hour)
	mk := func(name string) string {
		p := filepath.Join(parent, name)
		if err := os.MkdirAll(filepath.Join(p, "sub"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "sub", "model.safetensors"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := mk(ScratchPrefix + "stale")
	age(t, old, filepath.Join(stale, "sub", "model.safetensors"), filepath.Join(stale, "sub"), stale)
	recent := mk(ScratchPrefix + "recent")
	live := mk(ScratchPrefix + "live")
	age(t, old, filepath.Join(live, "sub"), live) // the file inside is still being written
	other := mk("someone-elses")
	age(t, old, filepath.Join(other, "sub", "model.safetensors"), filepath.Join(other, "sub"), other)
	target := filepath.Join(outside, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	age(t, old, target)
	if err := os.Symlink(target, filepath.Join(parent, ScratchPrefix+"link")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(parent, ScratchPrefix+"file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, old, file)

	t.Run("another user's leftovers are not swept", func(t *testing.T) {
		if removed, errs := sweepScratch(parent, time.Now(), os.Getuid()+1); len(removed) != 0 || len(errs) != 0 {
			t.Fatalf("sweep as another uid removed %v (%v)", removed, errs)
		}
	})

	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	var notes []string
	if _, err := hub.client(t).Import(testContext(t), mustRef(t, "hf://acme/tiny-model"), ImportOptions{
		ScratchDir: parent,
		Note:       func(m string) { notes = append(notes, m) },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale scratch directory still there (%v)", err)
	}
	for _, keep := range []string{recent, live, other, target, filepath.Join(parent, ScratchPrefix+"link"), file} {
		if _, err := os.Lstat(keep); err != nil {
			t.Errorf("%s was removed: %v", keep, err)
		}
	}
	if !slices.ContainsFunc(notes, func(n string) bool { return strings.Contains(n, "removed leftover") && strings.Contains(n, stale) }) {
		t.Errorf("notes %q do not name the swept directory", notes)
	}
	if !slices.ContainsFunc(notes, func(n string) bool {
		return strings.HasPrefix(n, "downloading into "+filepath.Join(parent, ScratchPrefix))
	}) {
		t.Errorf("notes %q do not say where the import downloads", notes)
	}
}

// TestImportRemovesScratchWhenCancelled: a cancelled import (Ctrl-C cancels
// the CLI's context) returns the cancellation and leaves no scratch
// directory behind.
func TestImportRemovesScratchWhenCancelled(t *testing.T) {
	hub := newFakeHub(t)
	hub.addCommit("main", commitA, tinyModel("a")...)
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	hub.onCDN = cancel // cancel in the middle of the first LFS download
	scratch := t.TempDir()
	_, err := hub.client(t).Import(ctx, mustRef(t, "hf://acme/tiny-model"), ImportOptions{ScratchDir: scratch})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Import = %v, want context.Canceled", err)
	}
	left, err := os.ReadDir(scratch)
	if err != nil || len(left) != 0 {
		t.Errorf("scratch holds %v (%v) after a cancelled import, want nothing", left, err)
	}
}
