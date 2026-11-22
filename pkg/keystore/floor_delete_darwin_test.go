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
// buries first, then clears the user flags and removes the entry; and if the
// removal still fails, it reports the directory left behind. Either way the
// copy put back is refused as deleted.
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
			err := s.Delete(ctx, "k")
			_, lerr := os.Lstat(filepath.Join(server, "keystore", "k"))
			switch {
			case err == nil && errors.Is(lerr, os.ErrNotExist):
				// The flag was cleared and the entry removed.
			case err != nil && strings.Contains(err.Error(), "left behind") && lerr == nil:
				// The leftover is reported.
				_ = unix.Chflags(p, 0)
				if err := os.RemoveAll(filepath.Join(server, "keystore", "k")); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("Delete with uchg on %s: %v (entry: %v), want it removed or the leftover reported", at, err, lerr)
			}
			putBack(t, server, old, "k")
			_, _, err = s.Current(ctx, "k")
			refusedAsDeleted(t, "Current of the copy put back", err)
		})
	}
}
