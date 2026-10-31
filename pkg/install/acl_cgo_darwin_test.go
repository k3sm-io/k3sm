//go:build cgo

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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestPathHasACL runs the ACL probe against the real filesystem: a plain file
// has none, a file given one with `chmod +a` has one, and a symlink to that
// file is judged as the link itself, which carries none.
func TestPathHasACL(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	withACL := filepath.Join(dir, "acl")
	link := filepath.Join(dir, "link")
	for _, p := range []string{plain, withACL} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", withACL).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v: %s", err, out)
	}
	if err := os.Symlink(withACL, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{{plain, false}, {withACL, true}, {link, false}} {
		got, err := pathHasACL(tc.path)
		if err != nil {
			t.Fatalf("pathHasACL(%s): %v", tc.path, err)
		}
		if got != tc.want {
			t.Errorf("pathHasACL(%s) = %v, want %v", filepath.Base(tc.path), got, tc.want)
		}
	}
}
