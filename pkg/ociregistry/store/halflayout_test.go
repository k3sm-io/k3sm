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

package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/ociregistry/ref"
	"k3sm.io/k3sm/pkg/ociregistry/store"
)

// TestSweepReapsAHalfRemovedLayout covers the directory a stopped
// RemoveLayout leaves: oci-layout, an empty blobs/ and .uploads/, no
// index.json.
func TestSweepReapsAHalfRemovedLayout(t *testing.T) {
	ctx := context.Background()
	n, err := ref.ParseName("app")
	if err != nil {
		t.Fatal(err)
	}
	// half builds the leftover, then lets mutate change it.
	half := func(t *testing.T, mutate func(dir string)) (*store.Store, string) {
		t.Helper()
		dir := t.TempDir()
		s, err := store.Open(filepath.Join(dir, "registry"), filepath.Join(dir, "registry-state"))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Init(ctx, n); err != nil {
			t.Fatal(err)
		}
		repo, err := n.Dir(s.Root())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(repo, "index.json")); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(repo)
		}
		return s, repo
	}
	write := func(t *testing.T, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(p string) bool { _, err := os.Lstat(p); return err == nil }

	cases := []struct {
		name   string
		mutate func(t *testing.T, repo string)
		reaped bool
	}{
		{"reaped", nil, true},
		{"blob", func(t *testing.T, repo string) {
			write(t, filepath.Join(repo, "blobs", "sha256", "aa"))
		}, false},
		{"upload", func(t *testing.T, repo string) {
			write(t, filepath.Join(repo, ".uploads", "11111111-1111-4111-8111-111111111111"))
		}, false},
		{"unknown file", func(t *testing.T, repo string) {
			write(t, filepath.Join(repo, "notes.txt"))
		}, false},
		{"empty temps", func(t *testing.T, repo string) {
			if err := os.Mkdir(filepath.Join(repo, ".temps"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, true},
		{"a temp", func(t *testing.T, repo string) {
			write(t, filepath.Join(repo, ".temps", ".tmp-11111111-1111-4111-8111-111111111111"))
		}, false},
		{"temps is a file", func(t *testing.T, repo string) {
			write(t, filepath.Join(repo, ".temps"))
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, repo := half(t, func(dir string) {
				if tc.mutate != nil {
					tc.mutate(t, dir)
				}
			})
			got, err := s.ReapHalfRemovedLayouts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1) != tc.reaped {
				t.Fatalf("reaped %v, want reaped=%v", got, tc.reaped)
			}
			if gone := !exists(filepath.Join(repo, "oci-layout")); gone != tc.reaped {
				t.Fatalf("oci-layout gone=%v, want %v", gone, tc.reaped)
			}
			if tc.reaped && (exists(filepath.Join(repo, "blobs")) || exists(filepath.Join(repo, ".uploads")) || exists(filepath.Join(repo, ".temps"))) {
				t.Fatal("blobs/, .uploads/ or .temps/ left behind")
			}
		})
	}

	t.Run("a layout being created concurrently", func(t *testing.T) {
		s, repo := half(t, nil)
		// The push finishes between the sweep finding oci-layout without an
		// index.json and taking the lock.
		store.SetHalfFound(s, func(ref.Name) {
			if err := s.Init(ctx, n); err != nil {
				t.Error(err)
			}
		})
		got, err := s.ReapHalfRemovedLayouts(ctx)
		if err != nil || len(got) != 0 {
			t.Fatalf("reaped %v, %v; want nothing", got, err)
		}
		for _, f := range []string{"oci-layout", "index.json", "blobs"} {
			if !exists(filepath.Join(repo, f)) {
				t.Errorf("%s was removed from a layout a push created", f)
			}
		}
		if repos, err := s.Repositories(); err != nil || len(repos) != 1 {
			t.Fatalf("repositories %v, %v", repos, err)
		}
	})
}
