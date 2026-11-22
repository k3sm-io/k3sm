//go:build darwin

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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestDeleteClearsUserFlags (G23): a uchg the service user set on a file in
// the entry, or on the entry directory, makes unlink fail even for root. rm
// buries first, then, after the removal answers EPERM, clears the locking
// flags and removes the entry; the copy put back is refused as deleted.
func TestDeleteClearsUserFlags(t *testing.T) {
	ctx := context.Background()
	for _, at := range []string{"v1", currentName, "."} {
		t.Run(at, func(t *testing.T) {
			s, server := newTestStore(t)
			mustPut(t, s, "k", KindOpaque, []byte("one"))
			old := saveEntry(t, server, "k", generationName, "v1", currentName)
			p := filepath.Join(server, "keystore", "k", at)
			if err := unix.Chflags(p, unix.UF_IMMUTABLE); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Chflags(p, 0) })
			if err := s.Delete(ctx, "k"); err != nil {
				t.Fatalf("Delete with uchg on %s: %v, want the flag cleared and the entry removed", at, err)
			}
			if _, err := os.Lstat(filepath.Join(server, "keystore", "k")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("entry after Delete with uchg on %s: %v, want it removed", at, err)
			}
			putBack(t, server, old, "k")
			_, _, err := s.Current(ctx, "k")
			refusedAsDeleted(t, "Current of the copy put back", err)
		})
	}
}

// TestDeleteKeepsHardLinkedFlags (G23): a flagged file hard-linked into the
// entry from outside it shares its flags with that other name, so Delete
// never clears them: the file outside keeps its uchg, and the error reports
// the entry left behind, naming the hard link.
func TestDeleteKeepsHardLinkedFlags(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	outside := filepath.Join(server, "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The service user plants the link, so the file is its own: under root the
	// owner check would otherwise refuse it before the link count is read.
	giveToService(t, outside)
	if err := os.Link(outside, filepath.Join(server, "keystore", "k", "planted")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(outside, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(outside, 0) })
	err := s.Delete(ctx, "k")
	if err == nil || !strings.Contains(err.Error(), "left behind") || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("Delete with a flagged hard link: %v, want the entry left behind and the hard link named", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(outside, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.UF_IMMUTABLE == 0 {
		t.Fatalf("the file outside the entry lost its uchg (flags %#x)", st.Flags)
	}
}

// TestDeleteClearsKeystoreDirFlag (G23): a uchg on keystore/ itself makes
// the entry's unlink from it fail; Delete clears it, as it clears the
// entry's, and removes the entry.
func TestDeleteClearsKeystoreDirFlag(t *testing.T) {
	ctx := context.Background()
	s, server := newTestStore(t)
	mustPut(t, s, "k", KindOpaque, []byte("one"))
	ks := filepath.Join(server, "keystore")
	if err := unix.Chflags(ks, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(ks, 0) })
	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete with uchg on keystore/: %v, want the flag cleared and the entry removed", err)
	}
	if _, err := os.Lstat(filepath.Join(ks, "k")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("entry after Delete with uchg on keystore/: %v, want it removed", err)
	}
}
