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
		if err := seedBinDir(work, payload, DefaultKineVersion); err != nil {
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
		if err := os.WriteFile(filepath.Join(binDir(work), "kube-apiserver"), []byte("existing"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payload, "kube-apiserver"), []byte("payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(filepath.Join(binDir(work), "kube-apiserver"))
		if string(got) != "existing" {
			t.Error("seed overwrote an existing workdir binary")
		}
	})

	// kine is the ONE binary the seed will replace, because ensureKineInto's fallback
	// for a stale kine is a Go toolchain a launchd daemon does not have. A packaged
	// upgrade whose pin moved must therefore get the payload's kine, not a build.
	t.Run("re-seeds a kine whose marker does not vouch for the target pin", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(binDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		// A previously-booted node: a kine binary from an older release, no marker.
		if err := os.WriteFile(filepath.Join(binDir(work), "kine"), []byte("old-pin"), 0o755); err != nil {
			t.Fatal(err)
		}
		// The payload is verifiably THIS release's: binary + a marker vouching for the
		// target. That is the only condition under which the seed replaces a kine.
		if err := os.WriteFile(filepath.Join(payload, "kine"), []byte("new-pin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kineMarkerPath(payload), []byte(kineMarkerContent(DefaultKineVersion)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(filepath.Join(binDir(work), "kine")); string(got) != "new-pin" {
			t.Errorf("stale kine not re-seeded: got %q, want the payload's bytes", got)
		}
		if !kineStaged(binDir(work), DefaultKineVersion) {
			v, variant := readKineMarker(binDir(work))
			t.Errorf("re-seed left marker %q %q, want it to vouch for %s/%s", v, variant, DefaultKineVersion, kineBuildVariant)
		}
	})

	t.Run("leaves a kine whose marker already vouches for the target pin", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(binDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir(work), "kine"), []byte("current"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kineMarkerPath(binDir(work)), []byte(kineMarkerContent(DefaultKineVersion)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payload, "kine"), []byte("payload"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(filepath.Join(binDir(work), "kine")); string(got) != "current" {
			t.Errorf("an up-to-date kine was re-seeded anyway: got %q", got)
		}
	})

	// The converse, and the reason the predicate is not simply "the payload has a kine":
	// a node upgraded by replacing only the binary still has the PREVIOUS release's
	// payload staged. Seeding from it and stamping the target version onto it would
	// leave the node running the old datastore engine while claiming the new one.
	t.Run("does NOT seed from an unmarked payload", func(t *testing.T) {
		payload, work := t.TempDir(), t.TempDir()
		if err := os.MkdirAll(binDir(work), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir(work), "kine"), []byte("old-pin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(payload, "kine"), []byte("unverified"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := seedBinDir(work, payload, DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if got, _ := os.ReadFile(filepath.Join(binDir(work), "kine")); string(got) != "old-pin" {
			t.Errorf("seeded from an unmarked payload: got %q", got)
		}
		if _, err := os.Stat(kineMarkerPath(binDir(work))); !os.IsNotExist(err) {
			t.Error("stamped a marker for bytes nothing vouched for")
		}
	})

	t.Run("empty payloadDir is a no-op", func(t *testing.T) {
		work := t.TempDir()
		if err := seedBinDir(work, "", DefaultKineVersion); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(binDir(work)); !os.IsNotExist(err) {
			t.Error("no-op seed must not create the bin dir")
		}
	})
}
