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

package install

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLockRemediesQuoteTheirPaths is TestRemediesQuoteTheirPaths for the
// darwin-only lock file remedies, with the expected commands as literals.
func TestLockRemediesQuoteTheirPaths(t *testing.T) {
	const q = remedyQuoted
	root := t.TempDir()
	cases := []struct {
		name   string
		remedy func(t *testing.T) string
		want   []string
	}{
		{"directory at the lock path", func(t *testing.T) string {
			return lockRemedy(fs.ModeDir, remedyPath)
		}, []string{"`sudo rmdir -- " + q + "`", "`sudo rm -rf -- " + q + "`"}},
		{"socket at the lock path", func(t *testing.T) string {
			return lockRemedy(fs.ModeSocket, remedyPath)
		}, []string{"`sudo rm -- " + q + "`"}},
		{"hard link at the lock path", func(t *testing.T) string {
			other := filepath.Join(root, "elsewhere")
			if err := os.WriteFile(other, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "it's here.lock")
			if err := os.Link(other, path); err != nil {
				t.Fatal(err)
			}
			err := ensureFileOwnedBy(path, os.Getuid(), os.Getgid(), 0o600)
			if err == nil {
				t.Fatal("ensureFileOwnedBy accepted a hard link")
			}
			return err.Error()
		}, []string{"`sudo rm -- '" + root + `/it'\''s here.lock'` + "`"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.remedy(t)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("remedy %q does not carry %q", got, w)
				}
			}
		})
	}
}
