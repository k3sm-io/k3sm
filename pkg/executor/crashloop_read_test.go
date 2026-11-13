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

package executor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadCrashRecordRefusesSymlinkAndBoundsSize pins the record reader's
// refusals: the record lives in a work dir its writer's uid shares with every
// pod, so the reader must not follow a planted symlink, block on a planted
// FIFO, or read an unbounded file — while a missing record stays the ordinary
// empty one and a symlinked parent directory (which O_NOFOLLOW does not guard)
// still reads.
func TestReadCrashRecordRefusesSymlinkAndBoundsSize(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	valid := CrashRecord{Crashes: []Crash{{At: at, Component: "kine", Origin: CrashOriginBringUp}}}
	writeValid := func(t *testing.T, path string) {
		t.Helper()
		if err := WriteCrashRecord(path, valid); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		// setup prepares dir and returns the path to read.
		setup       func(t *testing.T, dir string) string
		wantRefused bool
		wantRecord  bool // the valid record, rather than an empty one
	}{
		{
			name: "a regular record reads",
			setup: func(t *testing.T, dir string) string {
				p := CrashLoopPath(dir)
				writeValid(t, p)
				return p
			},
			wantRecord: true,
		},
		{
			name: "a symlink to a valid record is refused",
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "elsewhere.json")
				writeValid(t, target)
				p := CrashLoopPath(dir)
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantRefused: true,
		},
		{
			name: "a FIFO is refused without blocking",
			setup: func(t *testing.T, dir string) string {
				p := CrashLoopPath(dir)
				if err := unix.Mkfifo(p, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantRefused: true,
		},
		{
			name: "an oversized file is refused",
			setup: func(t *testing.T, dir string) string {
				p := CrashLoopPath(dir)
				// Valid JSON padded past the bound, so only the size can refuse it.
				b := append([]byte(`{"crashes":[]}`), bytes.Repeat([]byte(" "), CrashRecordMaxBytes)...)
				if err := os.WriteFile(p, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantRefused: true,
		},
		{
			name: "a missing file is an empty record with no error",
			setup: func(t *testing.T, dir string) string {
				return CrashLoopPath(dir)
			},
		},
		{
			name: "a record behind a symlinked parent directory still reads",
			setup: func(t *testing.T, dir string) string {
				real := filepath.Join(dir, "real")
				if err := os.Mkdir(real, 0o700); err != nil {
					t.Fatal(err)
				}
				writeValid(t, CrashLoopPath(real))
				link := filepath.Join(dir, "link")
				if err := os.Symlink(real, link); err != nil {
					t.Fatal(err)
				}
				return CrashLoopPath(link)
			},
			wantRecord: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t, t.TempDir())
			type result struct {
				r   CrashRecord
				err error
			}
			done := make(chan result, 1)
			go func() {
				r, err := ReadCrashRecord(path)
				done <- result{r, err}
			}()
			var got result
			select {
			case got = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("ReadCrashRecord blocked")
			}
			if tc.wantRefused {
				if !errors.Is(got.err, errCrashRecordRefused) {
					t.Fatalf("ReadCrashRecord = %+v, %v; want an error wrapping errCrashRecordRefused", got.r, got.err)
				}
				if len(got.r.Crashes) != 0 || got.r.TrippedAt != nil {
					t.Errorf("a refused read returned a non-empty record %+v", got.r)
				}
				return
			}
			if got.err != nil {
				t.Fatalf("ReadCrashRecord: %v", got.err)
			}
			if tc.wantRecord {
				if len(got.r.Crashes) != 1 || !got.r.Crashes[0].At.Equal(at) || got.r.Crashes[0].Component != "kine" {
					t.Errorf("ReadCrashRecord = %+v, want %+v", got.r, valid)
				}
			} else if len(got.r.Crashes) != 0 || got.r.TrippedAt != nil {
				t.Errorf("ReadCrashRecord = %+v, want an empty record", got.r)
			}
		})
	}
}
