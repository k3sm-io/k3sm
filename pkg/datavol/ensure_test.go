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
	"encoding/json"
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
	testRoot   = "/var/lib/k3sm"
	recordPath = "/Library/Preferences/io.k3sm.datavol.json"
	rigUUID    = "6DEAE471-6CDE-4A4E-88A1-6A7B4DEF2DDD"
)

// recordText renders a record the way dataroot.WriteRecord would, for the
// Fake's in-memory file map.
func recordText(t *testing.T, r dataroot.Record) string {
	t.Helper()
	r.Version = dataroot.RecordVersion
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	return string(b)
}

// k3smVolume is the rig's data volume as the Fake describes it.
func k3smVolume(mountpoint string) datavoltest.Volume {
	return datavoltest.Volume{
		UUID: rigUUID, Name: "k3sm", Container: "disk3", Device: "disk3s7",
		Mountpoint: mountpoint, InUse: 34811297792, CaseSensitive: true,
		FilesystemType: "apfs",
	}
}

// markedDir returns a directory carrying the k3sm provenance marker.
func markedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, datavol.MarkerName), []byte("k3sm\n"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	return dir
}

// TestEnsureCreatesOrAdopts walks every path Ensure can take, and pins the two
// properties that make it safe to run unattended from `k3sm install`: it never
// takes over a volume that is not k3sm's, and it never leaves a volume behind
// that it decided not to keep.
func TestEnsureCreatesOrAdopts(t *testing.T) {
	ctx := context.Background()
	base := datavol.Options{Name: "k3sm", Mountpoint: testRoot, QuotaBytes: datavol.DefaultQuotaBytes, CreatedBy: "k3sm test"}

	t.Run("an existing record is returned untouched", func(t *testing.T) {
		f := datavoltest.New()
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: testRoot, QuotaBytes: 100 << 30, Adopted: true}
		f.Files[recordPath] = recordText(t, rec)

		got, plan, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if !plan.Existing || plan.Created || plan.Adopted {
			t.Fatalf("Plan = %+v, want Existing", plan)
		}
		if got.UUID != rigUUID || got.QuotaBytes != 100<<30 {
			t.Fatalf("record = %+v, want the recorded one", got)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("Ensure touched the disk on a no-op re-run: %v", f.Calls)
		}
	})

	t.Run("encryption over an existing unencrypted volume is refused", func(t *testing.T) {
		f := datavoltest.New()
		f.Files[recordPath] = recordText(t, dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: testRoot})

		o := base
		o.Encrypt = true
		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, o)
		if !errors.Is(err, datavol.ErrEncryptRequiresFresh) {
			t.Fatalf("Ensure = %v, want ErrEncryptRequiresFresh", err)
		}
	})

	t.Run("an fstab line adopts the volume it names", func(t *testing.T) {
		f := datavoltest.New()
		f.Fstab = "#\nLABEL=Backup /Volumes/Backup hfs rw\nUUID=" + rigUUID + " " + testRoot + " apfs rw,nobrowse\n"
		v := k3smVolume(testRoot)
		v.Quota = 100 << 30
		f.Add(v)

		got, plan, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if !plan.Adopted || !plan.FromFstab {
			t.Fatalf("Plan = %+v, want Adopted+FromFstab", plan)
		}
		if got.UUID != rigUUID || !got.Adopted || got.QuotaBytes != 100<<30 || got.Name != "k3sm" {
			t.Fatalf("record = %+v", got)
		}
		if got.CreatedAt == "" || got.CreatedBy != "k3sm test" {
			t.Fatalf("record provenance = %+v", got)
		}
		if !strings.HasPrefix(f.Calls[0], "info "+rigUUID) {
			t.Fatalf("Ensure did not inspect the fstab volume first: %v", f.Calls)
		}
	})

	t.Run("a same-named volume carrying the marker is adopted", func(t *testing.T) {
		f := datavoltest.New()
		v := k3smVolume(markedDir(t))
		f.Add(v)

		got, plan, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if !plan.Adopted || plan.FromFstab {
			t.Fatalf("Plan = %+v, want Adopted by name", plan)
		}
		if got.UUID != rigUUID || !got.Adopted {
			t.Fatalf("record = %+v", got)
		}
	})

	t.Run("a same-named volume with foreign data is refused, not taken over", func(t *testing.T) {
		f := datavoltest.New()
		f.Add(k3smVolume(t.TempDir()))

		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if !errors.Is(err, datavol.ErrForeignVolume) {
			t.Fatalf("Ensure = %v, want ErrForeignVolume", err)
		}
		for _, call := range f.Calls {
			if strings.HasPrefix(call, "addvolume") || strings.HasPrefix(call, "deletevolume") {
				t.Fatalf("Ensure mutated the disk while refusing: %v", f.Calls)
			}
		}
	})

	t.Run("encryption over an adopted unencrypted volume is refused", func(t *testing.T) {
		f := datavoltest.New()
		f.Fstab = "UUID=" + rigUUID + " " + testRoot + " apfs rw\n"
		f.Add(k3smVolume(testRoot))

		o := base
		o.Encrypt = true
		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, o)
		if !errors.Is(err, datavol.ErrEncryptRequiresFresh) {
			t.Fatalf("Ensure = %v, want ErrEncryptRequiresFresh", err)
		}
	})

	t.Run("a case-insensitive volume is not a data root", func(t *testing.T) {
		f := datavoltest.New()
		v := k3smVolume(testRoot)
		v.CaseSensitive = false
		f.Fstab = "UUID=" + rigUUID + " " + testRoot + " apfs rw\n"
		f.Add(v)

		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if !errors.Is(err, datavol.ErrForeignVolume) {
			t.Fatalf("Ensure = %v, want ErrForeignVolume", err)
		}
	})

	t.Run("nothing to adopt creates a quota'd volume", func(t *testing.T) {
		f := datavoltest.New()
		f.NextUUID = "NEW-0000-0000-0000-000000000001"

		got, plan, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if !plan.Created || plan.Adopted {
			t.Fatalf("Plan = %+v, want Created", plan)
		}
		if got.UUID != f.NextUUID || got.QuotaBytes != datavol.DefaultQuotaBytes || got.Adopted {
			t.Fatalf("record = %+v", got)
		}
		if got.Encrypted {
			t.Fatal("an unencrypted request produced an encrypted record")
		}
		if f.Mounted(got.UUID) {
			t.Fatal("Ensure mounted the volume; mounting is MountRecorded's job")
		}
		want := "addvolume disk3 k3sm quota=107374182400 encrypted=false"
		if !contains(f.Calls, want) {
			t.Fatalf("calls %v do not contain %q", f.Calls, want)
		}
	})

	t.Run("encryption stores the passphrase before the record exists", func(t *testing.T) {
		f := datavoltest.New()
		f.NextUUID = "ENC-0000-0000-0000-000000000001"

		o := base
		o.Encrypt = true
		got, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, o)
		if err != nil {
			t.Fatalf("Ensure: %v", err)
		}
		if !got.Encrypted {
			t.Fatalf("record = %+v, want Encrypted", got)
		}
		pw, err := f.Lookup(ctx, got.UUID)
		if err != nil {
			t.Fatalf("the passphrase was not stored: %v", err)
		}
		if len(pw) != 64 {
			t.Fatalf("passphrase is %d hex characters, want 64 (256 bits)", len(pw))
		}
		if !contains(f.Calls, "addvolume disk3 k3sm quota=107374182400 encrypted=true") {
			t.Fatalf("the volume was not created encrypted: %v", f.Calls)
		}
	})

	t.Run("a quota that did not land deletes the volume", func(t *testing.T) {
		f := datavoltest.New()
		f.NextUUID = "NOQUOTA-0000-0000-0000-00000001"
		f.DropQuota = true

		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base)
		if !errors.Is(err, datavol.ErrQuotaNotApplied) {
			t.Fatalf("Ensure = %v, want ErrQuotaNotApplied", err)
		}
		if _, ok := f.Vols[f.NextUUID]; ok {
			t.Fatal("the unbounded volume was left behind")
		}
		if !contains(f.Calls, "deletevolume "+f.NextUUID) {
			t.Fatalf("calls %v do not delete the volume", f.Calls)
		}
	})

	t.Run("a keychain failure deletes the volume", func(t *testing.T) {
		f := datavoltest.New()
		f.NextUUID = "NOKEY-0000-0000-0000-000000001"
		f.SetErr("store", errors.New("the System keychain is locked"))

		o := base
		o.Encrypt = true
		_, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, o)
		if err == nil {
			t.Fatal("Ensure accepted an unstorable passphrase")
		}
		if _, ok := f.Vols[f.NextUUID]; ok {
			t.Fatal("an encrypted volume whose passphrase was lost was left behind")
		}
	})

	t.Run("a quota below the floor is refused unless the gate waives it", func(t *testing.T) {
		f := datavoltest.New()
		o := base
		o.QuotaBytes = 2 << 30

		if _, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, o); !errors.Is(err, datavol.ErrQuotaTooSmall) {
			t.Fatalf("Ensure = %v, want ErrQuotaTooSmall", err)
		}
		if len(f.Vols) != 0 {
			t.Fatal("a refused request still created a volume")
		}

		waived := datavoltest.New()
		waived.NextUUID = "SMALL-0000-0000-0000-000000001"
		o.AllowSmallQuota = true
		got, plan, err := datavol.Ensure(ctx, waived.Deps(), waived.FS(), recordPath, o)
		if err != nil {
			t.Fatalf("Ensure with AllowSmallQuota: %v", err)
		}
		if !plan.Created || got.QuotaBytes != 2<<30 {
			t.Fatalf("Plan = %+v, record = %+v", plan, got)
		}
	})

	t.Run("an unreadable record is fatal, unlike in dataroot.Read", func(t *testing.T) {
		f := datavoltest.New()
		f.Files[recordPath] = "{ not json"

		if _, _, err := datavol.Ensure(ctx, f.Deps(), f.FS(), recordPath, base); err == nil {
			t.Fatal("Ensure overwrote a declaration it could not read")
		}
	})
}

// contains reports whether calls holds want.
func contains(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}
