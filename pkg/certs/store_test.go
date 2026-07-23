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

package certs_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/certs"
)

// TestLoadCAPins pins the read-only pin accessor's three contracts: the pins it
// returns are the CAs' own PinHash values, an absent or half-present hierarchy is a
// typed failure (never a freshly minted CA), and nothing is created on disk.
func TestLoadCAPins(t *testing.T) {
	t.Parallel()

	// damage names a file the case removes after the hierarchy is seeded; mutate is
	// an arbitrary post-seed mutation (the symlink plants).
	cases := []struct {
		name      string
		seed      bool
		damage    func(dir string) string
		mutate    func(t *testing.T, dir string)
		wantErrIs error
	}{
		{name: "intact hierarchy", seed: true},
		{
			name:      "no hierarchy at all",
			wantErrIs: certs.ErrNoHierarchy,
		},
		{
			name:      "cluster CA certificate removed",
			seed:      true,
			damage:    certs.ClusterCACertPath,
			wantErrIs: certs.ErrNoHierarchy,
		},
		{
			name:      "signing CA certificate removed",
			seed:      true,
			damage:    certs.SigningCACertPath,
			wantErrIs: certs.ErrNoHierarchy,
		},
		{
			name:      "cluster CA key removed",
			seed:      true,
			damage:    certs.ClusterCAKeyPath,
			wantErrIs: certs.ErrIncompleteHierarchy,
		},
		{
			name:      "signing CA key removed",
			seed:      true,
			damage:    certs.SigningCAKeyPath,
			wantErrIs: certs.ErrIncompleteHierarchy,
		},
		{
			// A CA certificate replaced by a SYMLINK is refused, not followed. Under
			// os.Stat the link would be followed and the pin computed from whatever it
			// points at — a planted link redirecting a root read at an arbitrary file.
			name: "cluster CA certificate replaced by a symlink",
			seed: true,
			mutate: func(t *testing.T, dir string) {
				plantSymlink(t, certs.ClusterCACertPath(dir), certs.SigningCACertPath(dir))
			},
			wantErrIs: certs.ErrIncompleteHierarchy,
		},
		{
			// Same for a CA KEY: a link to any existing file would satisfy a plain
			// stat and make ErrIncompleteHierarchy unreachable for a hierarchy that is
			// in fact half-present.
			name: "signing CA key replaced by a symlink",
			seed: true,
			mutate: func(t *testing.T, dir string) {
				plantSymlink(t, certs.SigningCAKeyPath(dir), certs.SigningCACertPath(dir))
			},
			wantErrIs: certs.ErrIncompleteHierarchy,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			var want *certs.Hierarchy
			if tc.seed {
				h, err := certs.EnsureHierarchy(dir)
				if err != nil {
					t.Fatalf("EnsureHierarchy: %v", err)
				}
				want = h
			}
			if tc.damage != nil {
				if err := os.Remove(tc.damage(dir)); err != nil {
					t.Fatalf("damage: %v", err)
				}
			}
			if tc.mutate != nil {
				tc.mutate(t, dir)
			}
			before := listTree(t, dir)

			cluster, signing, err := certs.LoadCAPins(dir)

			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("LoadCAPins error = %v, want errors.Is %v", err, tc.wantErrIs)
				}
			} else {
				if err != nil {
					t.Fatalf("LoadCAPins: %v", err)
				}
				if cluster != want.Cluster.PinHash() {
					t.Errorf("cluster pin = %s, want %s", cluster, want.Cluster.PinHash())
				}
				if signing != want.Signing.PinHash() {
					t.Errorf("signing pin = %s, want %s", signing, want.Signing.PinHash())
				}
			}

			// LoadCAPins must CREATE NOTHING — never a stray CA against a wrong work dir.
			if after := listTree(t, dir); !equalStrings(before, after) {
				t.Errorf("LoadCAPins changed the tree: %v -> %v", before, after)
			}
		})
	}
}

// TestLoadCAPinsNeverOpensCAKeys proves pin verification works against CA private
// keys the caller cannot read: the keys are Stat'ed, never opened.
func TestLoadCAPinsNeverOpensCAKeys(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file mode bits — the 0000 keys would be readable")
	}
	dir := t.TempDir()
	h, err := certs.EnsureHierarchy(dir)
	if err != nil {
		t.Fatalf("EnsureHierarchy: %v", err)
	}
	for _, p := range []string{certs.ClusterCAKeyPath(dir), certs.SigningCAKeyPath(dir)} {
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatalf("chmod 0000 %s: %v", p, err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	}
	cluster, signing, err := certs.LoadCAPins(dir)
	if err != nil {
		t.Fatalf("LoadCAPins with unreadable CA keys: %v", err)
	}
	if cluster != h.Cluster.PinHash() || signing != h.Signing.PinHash() {
		t.Errorf("pins = %s/%s, want %s/%s", cluster, signing, h.Cluster.PinHash(), h.Signing.PinHash())
	}
}

// plantSymlink replaces path with a symlink to target — the planted link a
// stat-and-follow implementation would obey.
func plantSymlink(t *testing.T, path, target string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("symlink %s -> %s: %v", path, target, err)
	}
}

// listTree returns every path under root, sorted (WalkDir yields lexical order).
func listTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
