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
	"os"
	"path/filepath"
	"testing"
)

// TestSeedBinDir proves the payload seed: staged binaries are copied 0755 into
// the workdir bin, existing workdir binaries are never overwritten, missing
// payload entries are tolerated (the ensure* fallbacks own that error), and an
// empty payloadDir is a no-op — so a dev shell with no payload keeps the gh/go
// acquisition path while a packaged install never needs it.
func TestSeedBinDir(t *testing.T) {
	t.Run("copies staged binaries 0755, skips missing", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(payload, "kube-apiserver"), []byte("apiserver"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payload, "kine"), []byte("kine"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(binDir(work), "kube-apiserver"))
		if err != nil || string(got) != "apiserver" {
			t.Errorf("kube-apiserver not seeded: %v %q", err, got)
		}
		fi, err := os.Stat(filepath.Join(binDir(work), "kine"))
		if err != nil || fi.Mode().Perm() != 0o755 {
			t.Errorf("kine mode = %v, want 0755 (must be executable)", fi.Mode())
		}
		// kube-scheduler was not staged — tolerated, no file, no error.
		if _, err := os.Stat(filepath.Join(binDir(work), "kube-scheduler")); !os.IsNotExist(err) {
			t.Errorf("unstaged kube-scheduler unexpectedly present/errored: %v", err)
		}
	})

	t.Run("never overwrites an existing workdir binary", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(binDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir(work), "kine"), []byte("existing"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payload, "kine"), []byte("payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(binDir(work), "kine"))
		if string(got) != "existing" {
			t.Error("seed overwrote an existing workdir binary")
		}
	})

	t.Run("empty payloadDir is a no-op", func(t *testing.T) {
		work := t.TempDir()
		if err := seedBinDir(work, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(binDir(work)); !os.IsNotExist(err) {
			t.Error("no-op seed must not create the bin dir")
		}
	})
}
