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

// makeSparseOversized creates a file one byte over the status read cap as a
// sparse file: the reader refuses on the fstat size, so no bytes need exist.
func makeSparseOversized(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(statusFSReadMax + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

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
			makeSparseOversized(t, p)
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

// TestStatusFSReadFileFollowingLink pins the admin-kubeconfig reader: a link to
// a regular file is read, a link to a FIFO is refused without blocking, and an
// oversized target is refused.
func TestStatusFSReadFileFollowingLink(t *testing.T) {
	link := func(t *testing.T, dir string, target string) string {
		p := filepath.Join(dir, "link")
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name string
		make func(t *testing.T, dir string) string
		want []byte // nil means refused
	}{
		{"a link to a regular file", func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			return link(t, dir, target)
		}, []byte("{}")},
		{"a link to a FIFO", func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "fifo")
			if err := unix.Mkfifo(target, 0o600); err != nil {
				t.Fatal(err)
			}
			return link(t, dir, target)
		}, nil},
		{"a link to an oversized file", func(t *testing.T, dir string) string {
			target := filepath.Join(dir, "big")
			makeSparseOversized(t, target)
			return link(t, dir, target)
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.make(t, t.TempDir())
			type res struct {
				b   []byte
				err error
			}
			done := make(chan res, 1)
			go func() {
				b, err := osStatusFS{}.ReadFileFollowingLink(path)
				done <- res{b, err}
			}()
			select {
			case r := <-done:
				if tc.want == nil {
					if !errors.Is(r.err, boundedread.ErrRefused) {
						t.Fatalf("ReadFileFollowingLink(%s) err = %v, want boundedread.ErrRefused", path, r.err)
					}
					return
				}
				if r.err != nil || string(r.b) != string(tc.want) {
					t.Fatalf("ReadFileFollowingLink(%s) = %q, %v; want %q", path, r.b, r.err, tc.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("ReadFileFollowingLink(%s) did not return: it blocked", path)
			}
		})
	}
}

// TestStatusCollectorFSFollowsTheAdminKubeconfigLink pins the wiring: the FS
// the status commands hand the collector exposes ReadFileFollowingLink, which
// pkg/status/servingcert.go finds by an optional-interface assertion. A wrapper
// that hid the method would silently turn a linked admin kubeconfig into a
// "not readable" mismatch.
func TestStatusCollectorFSFollowsTheAdminKubeconfigLink(t *testing.T) {
	type linkFollower interface {
		ReadFileFollowingLink(path string) ([]byte, error)
	}
	// Construction dials nothing; it only resolves paths and reads local files.
	// Point HOME and KUBECONFIG at a temp dir so clientcmd's default loading
	// rules never see the host's ~/.kube/config or $KUBECONFIG.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "no-such-kubeconfig"))
	for name, fs := range map[string]any{
		"newStatusCollector":  newStatusCollector().FS,
		"newDaemonsCollector": newDaemonsCollector().FS,
	} {
		if _, ok := fs.(linkFollower); !ok {
			t.Errorf("%s FS is %T, which does not implement ReadFileFollowingLink", name, fs)
		}
	}
}
