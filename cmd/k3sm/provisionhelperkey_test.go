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
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// levelRecorder is a slog handler that keeps every record's level and message,
// so a test can assert on the level a path logs at rather than on text.
type levelRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

func (r *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (r *levelRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec.Clone())
	return nil
}

func (r *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r *levelRecorder) WithGroup(string) slog.Handler      { return r }

// atOrAbove returns the messages of every record at level or higher.
func (r *levelRecorder) atOrAbove(level slog.Level) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.records {
		if rec.Level >= level {
			out = append(out, rec.Message)
		}
	}
	return out
}

// TestProvisionHelperKeyIsSilentWhenServiceUserCannotWrite pins the installed
// posture: a node running as the _k3sm service user cannot write the root-only
// key directory, `k3sm install` already provisioned the copy there, so the
// write is not attempted and nothing is logged at WARN. As root the best-effort
// write still lands the key 0600, and a root write that fails still warns.
func TestProvisionHelperKeyIsSilentWhenServiceUserCannotWrite(t *testing.T) {
	const keyRef = "mesh.key"
	const keyB64 = "c2VjcmV0LWtleS1ieXRlcy1mb3ItdGhlLW1lc2gtMDAwMA=="

	tests := []struct {
		name string
		euid int
		// unwritable points the key dir at a directory that does not exist, so
		// the write fails for root and non-root alike.
		unwritable bool
		wantFile   bool
		wantWarn   bool
	}{
		{name: "service user with a writable dir attempts no write", euid: 501},
		{name: "service user with the root-only dir does not warn", euid: 501, unwritable: true},
		{name: "root writes the key 0600", euid: 0, wantFile: true},
		{name: "root write failure warns", euid: 0, unwritable: true, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.unwritable {
				dir = filepath.Join(dir, "absent")
			}
			oldEUID, oldDir := helperKeyEUID, helperKeyDir
			t.Cleanup(func() { helperKeyEUID, helperKeyDir = oldEUID, oldDir })
			helperKeyEUID = func() int { return tt.euid }
			helperKeyDir = dir

			rec := &levelRecorder{}
			in := meshBringUp{keyRef: keyRef, privateKeyB64: keyB64}
			in.provisionHelperKey(slog.New(rec))

			warns := rec.atOrAbove(slog.LevelWarn)
			if tt.wantWarn && len(warns) == 0 {
				t.Errorf("want a WARN record, got none")
			}
			if !tt.wantWarn && len(warns) != 0 {
				t.Errorf("want no WARN-level record, got %q", warns)
			}

			path := filepath.Join(dir, keyRef)
			info, err := os.Stat(path)
			if !tt.wantFile {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("want no key file at %s (no write attempted), stat err = %v", path, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want the key at %s: %v", path, err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Errorf("key mode = %o, want 600", got)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read key: %v", err)
			}
			if string(got) != keyB64 {
				t.Errorf("key bytes = %q, want %q", got, keyB64)
			}
		})
	}
}
