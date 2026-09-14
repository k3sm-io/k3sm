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
	"strings"
	"testing"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

const (
	netdLabel   = "io.k3sm.netd"
	serverLabel = "io.k3sm.server"
)

// deleteRig sets up a mounted data volume with both of its declarations on
// disk, and returns the record, the record path, the fstab path and the Fake.
func deleteRig(t *testing.T, encrypted bool) (dataroot.Record, string, string, *datavoltest.Fake) {
	t.Helper()
	dir := t.TempDir()
	mp := filepath.Join(dir, "k3sm")
	if err := os.MkdirAll(mp, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	fstabPath := filepath.Join(dir, "fstab")
	fstab := "LABEL=Backup /Volumes/Backup hfs rw\nUUID=" + rigUUID + " " + mp + " apfs rw,nobrowse,nosuid,nodev\n"
	if err := os.WriteFile(fstabPath, []byte(fstab), 0o644); err != nil {
		t.Fatalf("write fstab: %v", err)
	}
	rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp, QuotaBytes: 100 << 30, Encrypted: encrypted}
	recPath := filepath.Join(dir, "io.k3sm.datavol.json")
	if err := dataroot.WriteRecord(recPath, rec); err != nil {
		t.Fatalf("WriteRecord: %v", err)
	}

	f := datavoltest.New()
	f.Files[fstabPath] = fstab
	f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", Mountpoint: mp, CaseSensitive: true, Encrypted: encrypted})
	if encrypted {
		f.Keys[rigUUID] = "deadbeef"
	}
	return rec, recPath, fstabPath, f
}

// TestDeleteRefuses pins every gate in front of the one destructive operation
// in the package.
func TestDeleteRefuses(t *testing.T) {
	ctx := context.Background()

	t.Run("without an explicit confirmation nothing happens", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{FstabPath: fstabPath})
		if !errors.Is(err, datavol.ErrConfirmRequired) {
			t.Fatalf("Delete = %v, want ErrConfirmRequired", err)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("Delete acted without confirmation: %v", f.Calls)
		}
	})

	t.Run("a loaded daemon stops it before the unmount, on the live data root", func(t *testing.T) {
		for _, label := range []string{netdLabel, serverLabel} {
			rec, recPath, fstabPath, f := deleteRig(t, false)
			f.LoadedLabels[label] = true
			err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{
				Yes: true, FstabPath: fstabPath, NetdLabel: netdLabel, ServerLabel: serverLabel,
				ProtectedMountpoint: rec.Mountpoint,
			})
			if !errors.Is(err, datavol.ErrDaemonsLoaded) {
				t.Fatalf("Delete with %s loaded = %v, want ErrDaemonsLoaded", label, err)
			}
			if !strings.Contains(err.Error(), label) {
				t.Fatalf("the message does not name %s: %v", label, err)
			}
			if len(f.Calls) != 0 {
				t.Fatalf("Delete acted with %s loaded: %v", label, f.Calls)
			}
		}
	})

	t.Run("the live data root is recognised through the /private symlink", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		f.LoadedLabels[netdLabel] = true
		// The mount point reached through a symlinked parent is the same
		// directory, the way /var/lib/k3sm and /private/var/lib/k3sm are.
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(filepath.Dir(rec.Mountpoint), link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{
			Yes: true, FstabPath: fstabPath, NetdLabel: netdLabel, ServerLabel: serverLabel,
			ProtectedMountpoint: filepath.Join(link, filepath.Base(rec.Mountpoint)),
		})
		if !errors.Is(err, datavol.ErrDaemonsLoaded) {
			t.Fatalf("Delete = %v, want ErrDaemonsLoaded through the symlinked spelling", err)
		}
	})

	t.Run("an implausible mount point is refused", func(t *testing.T) {
		for _, mp := range []string{
			"", "relative/path", "/", "/var", "/System", "/System/Volumes/Data",
			"/Library/k3sm", "/Library/k3sm/data", "/Users", "/Users/someone",
			"/private/var", "/Volumes",
		} {
			_, recPath, fstabPath, f := deleteRig(t, false)
			rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}
			err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath})
			if !errors.Is(err, datavol.ErrImplausibleMountpoint) {
				t.Fatalf("Delete(%q) = %v, want ErrImplausibleMountpoint", mp, err)
			}
			if len(f.Calls) != 0 {
				t.Fatalf("Delete(%q) acted: %v", mp, f.Calls)
			}
		}
		// The paths a data root really is at stay reachable.
		for _, mp := range []string{"/var/lib/k3sm", "/private/var/lib/k3sm", "/Users/someone/k3sm-data", "/Volumes/scratch/k3sm"} {
			_, recPath, fstabPath, f := deleteRig(t, false)
			rec := dataroot.Record{UUID: "GONE", Name: "k3sm", Mountpoint: mp}
			err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath})
			if errors.Is(err, datavol.ErrImplausibleMountpoint) {
				t.Fatalf("Delete(%q) refused a plausible data root", mp)
			}
		}
	})

	t.Run("a busy volume names the known cause and keeps the record", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		f.SetErr("unmount", errors.New("Resource busy -- try again"))

		err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath})
		if err == nil {
			t.Fatal("Delete reported success with a busy volume")
		}
		if !strings.Contains(err.Error(), "k3sm-vmhost") {
			t.Fatalf("the message does not name the known busy cause: %v", err)
		}
		if _, ok := f.Vols[rigUUID]; !ok {
			t.Fatal("the volume was destroyed after a failed unmount")
		}
		if _, err := os.Stat(recPath); err != nil {
			t.Fatalf("the record was removed after a failed unmount: %v", err)
		}
	})
}

// TestDeleteSequence pins what a confirmed delete actually does, in order.
func TestDeleteSequence(t *testing.T) {
	ctx := context.Background()

	t.Run("mount, volume, fstab line, record and mount point all go", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{
			Yes: true, FstabPath: fstabPath, NetdLabel: netdLabel, ServerLabel: serverLabel,
			ProtectedMountpoint: rec.Mountpoint,
		}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		want := []string{"unmount " + rec.Mountpoint, "deletevolume " + rigUUID}
		if len(f.Calls) != len(want) {
			t.Fatalf("calls %v, want %v", f.Calls, want)
		}
		for i, w := range want {
			if f.Calls[i] != w {
				t.Fatalf("calls %v, want %v", f.Calls, want)
			}
		}
		if _, ok := f.Vols[rigUUID]; ok {
			t.Fatal("the volume survived")
		}
		fstab, err := os.ReadFile(fstabPath)
		if err != nil {
			t.Fatalf("read fstab: %v", err)
		}
		if strings.Contains(string(fstab), rec.Mountpoint) {
			t.Fatalf("the fstab declaration survived: %q", fstab)
		}
		if !strings.Contains(string(fstab), "LABEL=Backup") {
			t.Fatalf("the operator's own fstab lines were lost: %q", fstab)
		}
		if _, err := os.Stat(recPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the record survived: %v", err)
		}
		if _, err := os.Stat(rec.Mountpoint); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the empty mount point survived: %v", err)
		}
	})

	t.Run("a scratch volume elsewhere is deletable while the daemons run", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		f.LoadedLabels[netdLabel] = true
		f.LoadedLabels[serverLabel] = true

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{
			Yes: true, FstabPath: fstabPath, NetdLabel: netdLabel, ServerLabel: serverLabel,
			ProtectedMountpoint: "/var/lib/k3sm",
		}); err != nil {
			t.Fatalf("Delete of a scratch volume: %v", err)
		}
		if _, ok := f.Vols[rigUUID]; ok {
			t.Fatal("the scratch volume survived")
		}
	})

	t.Run("an encrypted volume's passphrase is removed too", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, true)

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if !contains(f.Calls, "delete "+rigUUID) {
			t.Fatalf("the keychain item was not removed: %v", f.Calls)
		}
		if _, ok := f.Keys[rigUUID]; ok {
			t.Fatal("the passphrase survived the volume")
		}
	})

	t.Run("an unencrypted volume does not touch the keychain", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		for _, c := range f.Calls {
			if strings.HasPrefix(c, "delete ") || strings.HasPrefix(c, "lookup ") {
				t.Fatalf("an unencrypted delete consulted the keychain: %v", f.Calls)
			}
		}
	})

	t.Run("a migrated copy of the data root is never touched", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		preVolume := rec.Mountpoint + datavol.PreVolumeSuffix
		if err := os.MkdirAll(preVolume, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := os.Stat(preVolume); err != nil {
			t.Fatalf("the operator's rollback copy was removed: %v", err)
		}
	})

	t.Run("a mount point that is not empty is left in place", func(t *testing.T) {
		rec, recPath, fstabPath, f := deleteRig(t, false)
		if err := os.WriteFile(filepath.Join(rec.Mountpoint, "stray"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}

		if err := datavol.Delete(ctx, f.Deps(), f.FS(), f, recPath, rec, datavol.DeleteOptions{Yes: true, FstabPath: fstabPath}); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := os.Stat(rec.Mountpoint); err != nil {
			t.Fatalf("a non-empty mount point was removed: %v", err)
		}
	})
}
