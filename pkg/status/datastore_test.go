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

package status

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestDatastorePosture exercises the REAL read-only probe against a temp file to
// prove it (a) reports an absent path with no file creation and (b) parses the
// SQLite header without a driver. It never opens a real control-plane db.
func TestDatastorePosture(t *testing.T) {
	t.Parallel()

	t.Run("absent-path-creates-nothing", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.db")
		present, uv, jm, err := DatastorePosture(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if present {
			t.Fatal("absent path reported present=true")
		}
		if uv != 0 || jm != "" {
			t.Fatalf("absent path returned uv=%d jm=%q, want 0/\"\"", uv, jm)
		}
		// The probe must NOT have created the file (forbidden side effect).
		if _, statErr := os.Stat(path); statErr == nil {
			t.Fatal("probe created the state.db file — it must be strictly read-only")
		}
	})

	t.Run("parses-wal-header", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.db")
		writeFakeSQLiteHeader(t, path, 2 /*WAL*/, 42 /*user_version*/)
		present, uv, jm, err := DatastorePosture(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !present || uv != 42 || jm != "wal" {
			t.Fatalf("got present=%v uv=%d jm=%q, want true/42/wal", present, uv, jm)
		}
	})

	t.Run("parses-rollback-header", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.db")
		writeFakeSQLiteHeader(t, path, 1 /*rollback*/, 7)
		present, uv, jm, err := DatastorePosture(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !present || uv != 7 || jm != "rollback" {
			t.Fatalf("got present=%v uv=%d jm=%q, want true/7/rollback", present, uv, jm)
		}
	})

	t.Run("bad-magic-is-an-error-not-a-posture", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "state.db")
		if err := os.WriteFile(path, make([]byte, 100), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, _, err := DatastorePosture(path); err == nil {
			t.Fatal("a file that is not a sqlite database reported no error")
		}
	})
}

// writeFakeSQLiteHeader writes a minimal 100-byte SQLite database header with the
// given write-version byte (offset 18: 1=rollback, 2=WAL) and user_version (offset
// 60, big-endian uint32) — enough for DatastorePosture's header parse. It is NOT a
// real database; the probe only reads the header.
func writeFakeSQLiteHeader(t *testing.T, path string, writeVersion byte, userVersion uint32) {
	t.Helper()
	var hdr [100]byte
	copy(hdr[0:16], "SQLite format 3\x00")
	hdr[18] = writeVersion
	hdr[19] = writeVersion
	binary.BigEndian.PutUint32(hdr[60:64], userVersion)
	if err := os.WriteFile(path, hdr[:], 0o600); err != nil {
		t.Fatalf("write fake header: %v", err)
	}
}
