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
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadNodePasswordRefusesAnUnreadableFile proves loadOrCreateNodePassword
// only mints a fresh node-password for the genuinely-absent case, and never for
// an unreadable one. A re-mint on any other read error would silently rotate this
// node's identity: the server's node-password store binds a name to the FIRST
// password it was shown, so the new value would be refused as a mismatch on the
// next join, and only then would the damage surface.
func TestLoadNodePasswordRefusesAnUnreadableFile(t *testing.T) {
	t.Run("present readable file is loaded unchanged", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "node-password")
		want := "existing-node-password"
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatalf("seed node-password: %v", err)
		}

		got, err := loadOrCreateNodePassword(dir)
		if err != nil {
			t.Fatalf("loadOrCreateNodePassword: %v", err)
		}
		if got != want {
			t.Fatalf("password = %q, want %q (unchanged)", got, want)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back node-password: %v", err)
		}
		if string(b) != want {
			t.Fatalf("stored bytes = %q, want %q — nothing should have been written", string(b), want)
		}
	})

	t.Run("absent file is minted and persisted at 0600", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "node-password")

		got, err := loadOrCreateNodePassword(dir)
		if err != nil {
			t.Fatalf("loadOrCreateNodePassword: %v", err)
		}
		if got == "" {
			t.Fatal("minted password is empty")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat minted node-password: %v", err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("minted node-password mode = %o, want 0600", mode)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back minted node-password: %v", err)
		}
		if string(b) != got {
			t.Fatalf("stored bytes = %q, want the returned password %q", string(b), got)
		}
	})

	t.Run("unreadable file errors and leaves the file untouched", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file mode bits — the file would still be readable")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "node-password")
		original := []byte("undamaged-node-password")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatalf("seed node-password: %v", err)
		}
		// write-only (no read bit): denies ReadFile while leaving the inode itself
		// writable, so this is the reproduction that actually distinguishes the two
		// behaviors under test. chmod 0000 denies BOTH read and write at the OS
		// level, which means the pre-fix code's own persist-the-mint step would ALSO
		// fail (for the wrong reason — permission, not the fix's guard) and the file
		// would come out untouched by coincidence, masking the bug: verified this
		// file's own gate goes green even on the pre-fix code under 0000. 0200 is the
		// mode where read fails and write silently succeeds, which is exactly the
		// silent-overwrite this test exists to catch.
		if err := os.Chmod(path, 0o200); err != nil {
			t.Fatalf("chmod 0200 node-password: %v", err)
		}

		_, loadErr := loadOrCreateNodePassword(dir)

		// restore the mode before asserting on content — t.TempDir's own cleanup
		// needs it too — but restoring never un-happens the loadErr assertion above.
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("restore node-password mode: %v", err)
		}
		if loadErr == nil {
			t.Fatal("loadOrCreateNodePassword: got nil error for an unreadable file, want an error")
		}

		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read back node-password: %v", err)
		}
		if !bytes.Equal(b, original) {
			t.Fatalf("stored bytes changed to %q, want the untouched original %q — a read error must never re-mint", string(b), string(original))
		}
	})
}
