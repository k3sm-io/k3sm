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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"k3sm.io/k3sm/internal/boundedread"
)

// TestStatusFSRefusesAFIFOALinkAndAnOversizedFile pins that `k3sm status`,
// which may run as root, reads the files it finds in service-user-writable
// trees through the bounded reader: a FIFO planted there must not hang it, a
// symlink must not redirect it, and a huge file must not make it allocate
// without limit. Each is refused with boundedread.ErrRefused, within a bound.
func TestStatusFSRefusesAFIFOALinkAndAnOversizedFile(t *testing.T) {
	cases := []struct {
		name string
		make func(t *testing.T, dir string) string
	}{
		{"a FIFO", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "fifo")
			if err := unix.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"a link", func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "link")
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"an oversized file", func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "big")
			if err := os.WriteFile(p, make([]byte, statusFSReadMax+1), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.make(t, t.TempDir())
			done := make(chan error, 1)
			go func() {
				_, err := osStatusFS{}.ReadFile(path)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, boundedread.ErrRefused) {
					t.Fatalf("osStatusFS.ReadFile(%s) err = %v, want boundedread.ErrRefused", path, err)
				}
			case <-time.After(10 * time.Second):
				// The blocked goroutine is left behind on purpose; the
				// test binary exits with it.
				t.Fatalf("osStatusFS.ReadFile(%s) did not return: it blocked", path)
			}
		})
	}
}
