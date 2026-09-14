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

package datavol_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

// plainDataRoot builds a data root that looks like a live one: a kine
// datastore, an image blob, a nested directory.
func plainDataRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "k3sm")
	files := map[string]string{
		"server/db/state.db":       "the kine datastore, which cannot be rebuilt",
		"server/tls/server-ca.crt": "a certificate",
		"agent/images/blob":        "layer bytes",
	}
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// mutatingSys copies for real and then lets the test damage the destination,
// which is how a verification failure is produced without a privileged seam.
type mutatingSys struct {
	*datavoltest.Fake
	after func(t *testing.T, dst string)
	t     *testing.T
}

func (m mutatingSys) CopyTree(src, dst string) error {
	if err := m.Fake.CopyTree(src, dst); err != nil {
		return err
	}
	m.after(m.t, dst)
	return nil
}

// markingIndexing is a Fake whose SpotlightOff really writes the opt-out
// marker, the way the production Darwin implementation does. It exists to pin
// that the verification walk does not count k3sm's own markers: they land on
// the staging mount BEFORE the copy, so counting them would fail every
// migration.
type markingIndexing struct{ *datavoltest.Fake }

func (m markingIndexing) SpotlightOff(ctx context.Context, mountpoint string) error {
	if err := m.Fake.SpotlightOff(ctx, mountpoint); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(mountpoint, ".metadata_never_index"), nil, 0o644)
}

// stagedVolume registers an unmounted volume and returns its record.
func stagedVolume(f *datavoltest.Fake, mountpoint string) dataroot.Record {
	f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true, Quota: 100 << 30})
	return dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mountpoint, QuotaBytes: 100 << 30}
}

// TestMigrateFailsSafe pins the property the whole migration exists for:
// every failure before the rename leaves the data root exactly as it was and
// takes the half-filled volume with it, so "nothing changed" is true.
func TestMigrateFailsSafe(t *testing.T) {
	ctx := context.Background()

	t.Run("a verified copy moves the old root aside", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		staging := t.TempDir()
		rec := stagedVolume(f, root)

		stats, err := datavol.Migrate(ctx, f.Deps(), f.FS(), f, rec, root, staging, datavol.MigrateOptions{})
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if stats.Files != 3 {
			t.Fatalf("Files = %d, want 3", stats.Files)
		}
		if stats.Bytes == 0 || stats.CopyDuration == 0 || stats.VerifyDuration == 0 {
			t.Fatalf("Stats = %+v, want real counts and timings", stats)
		}
		if _, err := os.Stat(root + datavol.PreVolumeSuffix); err != nil {
			t.Fatalf("the old data root was not moved aside: %v", err)
		}
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the old data root is still in place: %v", err)
		}
		// The exclusions run before a byte is copied.
		want := []string{"mount " + rigUUID + " " + staging, "spotlight " + staging, "timemachine " + staging, "copytree " + root + " " + staging}
		for i, w := range want {
			if f.Calls[i] != w {
				t.Fatalf("calls %v, want %v first", f.Calls, want)
			}
		}
	})

	t.Run("the markers k3sm writes on the staging mount are not counted", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		staging := t.TempDir()
		rec := stagedVolume(f, root)
		deps := f.Deps()
		deps.Indexing = markingIndexing{Fake: f}

		stats, err := datavol.Migrate(ctx, deps, f.FS(), f, rec, root, staging, datavol.MigrateOptions{})
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if stats.Files != 3 {
			t.Fatalf("Files = %d, want 3 (the Spotlight marker is k3sm's, not the operator's data)", stats.Files)
		}
		if _, err := os.Stat(filepath.Join(staging, ".metadata_never_index")); err != nil {
			t.Fatalf("the Spotlight marker was not written before the copy: %v", err)
		}
	})

	t.Run("the metadata macOS puts on a mounted volume is not content", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		staging := t.TempDir()
		rec := stagedVolume(f, root)
		sys := mutatingSys{Fake: f, t: t, after: func(t *testing.T, dst string) {
			// What a real mounted APFS volume carries at its root. .Trashes
			// is mode 0000 even for root, which is how the lab run failed:
			// the walk could not open it at all.
			trashes := filepath.Join(dst, ".Trashes")
			if err := os.Mkdir(trashes, 0o755); err != nil {
				t.Fatalf("mkdir .Trashes: %v", err)
			}
			if err := os.WriteFile(filepath.Join(trashes, "501"), []byte("x"), 0o600); err != nil {
				t.Fatalf("write into .Trashes: %v", err)
			}
			if err := os.Chmod(trashes, 0o000); err != nil {
				t.Fatalf("chmod .Trashes: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(trashes, 0o755) })
			if err := os.Mkdir(filepath.Join(dst, ".fseventsd"), 0o755); err != nil {
				t.Fatalf("mkdir .fseventsd: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dst, ".fseventsd", "fseventsd-uuid"), []byte("u"), 0o644); err != nil {
				t.Fatalf("write into .fseventsd: %v", err)
			}
			for _, name := range []string{".DS_Store", ".metadata_never_index", datavol.MarkerName} {
				if err := os.WriteFile(filepath.Join(dst, name), nil, 0o644); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}
		}}

		stats, err := datavol.Migrate(ctx, f.Deps(), f.FS(), sys, rec, root, staging, datavol.MigrateOptions{})
		if err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if stats.Files != 3 {
			t.Fatalf("Files = %d, want 3 (volume metadata is not the operator's data)", stats.Files)
		}
		if _, err := os.Stat(root + datavol.PreVolumeSuffix); err != nil {
			t.Fatalf("the migration did not complete: %v", err)
		}
	})

	t.Run("remove-old deletes the copy after verification", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)

		if _, err := datavol.Migrate(ctx, f.Deps(), f.FS(), f, rec, root, t.TempDir(), datavol.MigrateOptions{RemoveOld: true}); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if _, err := os.Stat(root + datavol.PreVolumeSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the old data root survived --remove-old-data-root: %v", err)
		}
	})

	t.Run("an encrypted volume refuses to leave a plaintext copy", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)
		rec.Encrypted = true

		_, err := datavol.Migrate(ctx, f.Deps(), f.FS(), f, rec, root, t.TempDir(), datavol.MigrateOptions{})
		if !errors.Is(err, datavol.ErrEncryptedNeedsRemoveOld) {
			t.Fatalf("Migrate = %v, want ErrEncryptedNeedsRemoveOld", err)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("Migrate acted before refusing: %v", f.Calls)
		}
	})

	t.Run("a leftover copy from a previous migration is not overwritten", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)
		if err := os.MkdirAll(root+datavol.PreVolumeSuffix, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		_, err := datavol.Migrate(ctx, f.Deps(), f.FS(), f, rec, root, t.TempDir(), datavol.MigrateOptions{})
		if !errors.Is(err, datavol.ErrPreVolumeExists) {
			t.Fatalf("Migrate = %v, want ErrPreVolumeExists", err)
		}
	})

	t.Run("a copy that lost a file destroys the volume and changes nothing", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)
		sys := mutatingSys{Fake: f, t: t, after: func(t *testing.T, dst string) {
			if err := os.Remove(filepath.Join(dst, "agent/images/blob")); err != nil {
				t.Fatalf("damage the copy: %v", err)
			}
		}}

		_, err := datavol.Migrate(ctx, f.Deps(), f.FS(), sys, rec, root, t.TempDir(), datavol.MigrateOptions{})
		if !errors.Is(err, datavol.ErrCopyMismatch) {
			t.Fatalf("Migrate = %v, want ErrCopyMismatch", err)
		}
		if _, ok := f.Vols[rigUUID]; ok {
			t.Fatal("the half-filled volume was left behind")
		}
		if _, err := os.Stat(filepath.Join(root, "server/db/state.db")); err != nil {
			t.Fatalf("the data root was disturbed by a failed migration: %v", err)
		}
		if _, err := os.Stat(root + datavol.PreVolumeSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a failed migration moved the data root aside")
		}
	})

	t.Run("a datastore whose bytes differ destroys the volume", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)
		sys := mutatingSys{Fake: f, t: t, after: func(t *testing.T, dst string) {
			// Same size, different bytes: only the hash can catch this.
			path := filepath.Join(dst, "server/db/state.db")
			fi, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			corrupt := make([]byte, fi.Size())
			for i := range corrupt {
				corrupt[i] = 'x'
			}
			if err := os.WriteFile(path, corrupt, 0o640); err != nil {
				t.Fatalf("corrupt the copy: %v", err)
			}
		}}

		_, err := datavol.Migrate(ctx, f.Deps(), f.FS(), sys, rec, root, t.TempDir(), datavol.MigrateOptions{})
		if !errors.Is(err, datavol.ErrCopyMismatch) {
			t.Fatalf("Migrate = %v, want ErrCopyMismatch", err)
		}
		if _, ok := f.Vols[rigUUID]; ok {
			t.Fatal("the volume holding a corrupt datastore was left behind")
		}
	})

	t.Run("a copy that failed outright destroys the volume", func(t *testing.T) {
		f := datavoltest.New()
		root := plainDataRoot(t)
		rec := stagedVolume(f, root)
		f.SetErr("copytree", errors.New("ditto: no space left on device"))

		_, err := datavol.Migrate(ctx, f.Deps(), f.FS(), f, rec, root, t.TempDir(), datavol.MigrateOptions{})
		if err == nil {
			t.Fatal("Migrate reported success after a failed copy")
		}
		if _, ok := f.Vols[rigUUID]; ok {
			t.Fatal("the volume was left behind after a failed copy")
		}
		if _, err := os.Stat(filepath.Join(root, "server/db/state.db")); err != nil {
			t.Fatalf("the data root was disturbed: %v", err)
		}
	})
}
