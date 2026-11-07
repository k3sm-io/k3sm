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
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// TestRemoveLeftoverZotFollowsNoSymlink runs the removal on a real filesystem. It
// removes the two files from a plain <DataRoot>/server/bin. A symlink at the data
// root, at server or at bin stops it with a warning, and the two files the link
// reaches stay: root would otherwise unlink them wherever it pointed.
func TestRemoveLeftoverZotFollowsNoSymlink(t *testing.T) {
	names := []string{registrysvc.ZotBinaryName, registrysvc.ZotMarkerName}
	plant := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := func(t *testing.T, dataRoot string) string {
		t.Helper()
		var log bytes.Buffer
		cfg := Config{DataRoot: dataRoot, Logger: slog.New(slog.NewTextHandler(&log, nil))}
		removeLeftoverZot(darwinSystem{}, cfg)
		return log.String()
	}
	t.Run("a plain work dir", func(t *testing.T) {
		root := t.TempDir()
		bin := filepath.Join(root, "server", "bin")
		plant(t, bin)
		if log := run(t, root); log != "" {
			t.Errorf("logged %s", log)
		}
		for _, n := range names {
			if _, err := os.Lstat(filepath.Join(bin, n)); !os.IsNotExist(err) {
				t.Errorf("%s survived: %v", n, err)
			}
		}
	})
	t.Run("nothing there is not worth a warning", func(t *testing.T) {
		for _, sub := range []string{"", "server", "server/bin"} {
			root := t.TempDir()
			if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
				t.Fatal(err)
			}
			if log := run(t, root); log != "" {
				t.Errorf("%q: logged %s", sub, log)
			}
		}
		if log := run(t, filepath.Join(t.TempDir(), "absent")); log != "" {
			t.Errorf("an absent data root: logged %s", log)
		}
	})
	for _, tc := range []struct{ name, link string }{
		{"a symlink at the data root", ""},
		{"a symlink at server", "server"},
		{"a symlink at bin", "server/bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			root := filepath.Join(base, "root")
			// The directory the link names is laid out so the path would resolve
			// to a zot in it.
			elsewhere := filepath.Join(base, "elsewhere")
			rel, err := filepath.Rel(filepath.Join("/", tc.link), "/server/bin")
			if err != nil {
				t.Fatal(err)
			}
			victim := filepath.Join(elsewhere, rel)
			plant(t, victim)
			link := filepath.Join(root, tc.link)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, link); err != nil {
				t.Fatal(err)
			}
			log := run(t, root)
			for _, n := range names {
				if _, err := os.Lstat(filepath.Join(victim, n)); err != nil {
					t.Errorf("root unlinked %s through the link: %v", n, err)
				}
			}
			if !strings.Contains(log, "could not remove the zot") {
				t.Errorf("no warning for a refused removal: %q", log)
			}
		})
	}
}
