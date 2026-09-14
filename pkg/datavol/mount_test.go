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
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
	"k3sm.io/k3sm/pkg/datavol/datavoltest"
)

// shrinkRetry makes the bounded mount retry finish inside a unit test, and
// restores the production policy afterwards.
func shrinkRetry(t *testing.T) {
	t.Helper()
	saved := datavol.RetryPolicy
	datavol.RetryPolicy = datavol.Retry{Poll: time.Millisecond, Budget: 50 * time.Millisecond}
	t.Cleanup(func() { datavol.RetryPolicy = saved })
}

// flakyVolumes fails the first failures Mount calls and then delegates, the
// way disk arbitration is transiently unready at boot.
type flakyVolumes struct {
	*datavoltest.Fake
	mu       sync.Mutex
	failures int
	attempts int
}

func (v *flakyVolumes) Mount(ctx context.Context, uuid, mountpoint string) error {
	v.mu.Lock()
	v.attempts++
	if v.failures > 0 {
		v.failures--
		v.mu.Unlock()
		return errors.New("could not mount: disk arbitration is not ready")
	}
	v.mu.Unlock()
	return v.Fake.Mount(ctx, uuid, mountpoint)
}

// TestMountRecordedIsIdempotent pins the one mount routine the installer, the
// boot daemon and the gate all share: running it twice is a no-op, a transient
// early-boot failure is retried rather than fatal, and the mount point ends up
// marked and owned.
func TestMountRecordedIsIdempotent(t *testing.T) {
	ctx := context.Background()

	t.Run("a volume already mounted there is left alone", func(t *testing.T) {
		f := datavoltest.New()
		mp := t.TempDir()
		f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", Mountpoint: mp, CaseSensitive: true})
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil); err != nil {
			t.Fatalf("MountRecorded: %v", err)
		}
		if len(f.Calls) != 0 {
			t.Fatalf("MountRecorded acted on an already-mounted volume: %v", f.Calls)
		}
	})

	t.Run("an unmounted volume is mounted, excluded and marked", func(t *testing.T) {
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true})
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil); err != nil {
			t.Fatalf("MountRecorded: %v", err)
		}
		if !f.Mounted(rigUUID) {
			t.Fatal("the volume is not mounted")
		}
		want := []string{
			"info " + rigUUID,
			"mount " + rigUUID + " " + mp,
			"spotlight " + mp,
			"timemachine " + mp,
		}
		for i, w := range want {
			if i >= len(f.Calls) || f.Calls[i] != w {
				t.Fatalf("calls %v, want %v", f.Calls, want)
			}
		}
		if _, err := os.Stat(filepath.Join(mp, datavol.MarkerName)); err != nil {
			t.Fatalf("the provenance marker was not written: %v", err)
		}
		// A second run is a no-op, including the marker write.
		before := len(f.Calls)
		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil); err != nil {
			t.Fatalf("MountRecorded (second): %v", err)
		}
		if len(f.Calls) != before {
			t.Fatalf("the second run acted: %v", f.Calls[before:])
		}
	})

	t.Run("a transient diskutil failure is retried, not fatal", func(t *testing.T) {
		shrinkRetry(t)
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true})
		// The first mount fails the way early-boot disk arbitration does; the
		// second succeeds. Deterministic, so the test is not a stopwatch.
		vols := &flakyVolumes{Fake: f, failures: 1}
		deps := f.Deps()
		deps.Volumes = vols
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

		if err := datavol.MountRecorded(ctx, deps, f.FS(), rec, datavol.Owner{}, nil); err != nil {
			t.Fatalf("MountRecorded: %v", err)
		}
		if !f.Mounted(rigUUID) {
			t.Fatal("the volume is not mounted after the retry")
		}
		if vols.attempts < 2 {
			t.Fatalf("mount was attempted %d time(s), want a retry", vols.attempts)
		}
	})

	t.Run("a permanent failure is reported once the budget is spent", func(t *testing.T) {
		shrinkRetry(t)
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		rec := dataroot.Record{UUID: "GONE", Name: "k3sm", Mountpoint: mp}

		err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil)
		if err == nil {
			t.Fatal("MountRecorded reported success with no volume to mount")
		}
	})

	t.Run("a locked encrypted volume is unlocked from the keychain", func(t *testing.T) {
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		f.Add(datavoltest.Volume{
			UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true,
			Encrypted: true, Locked: true, Passphrase: "deadbeef",
		})
		f.Keys[rigUUID] = "deadbeef"
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp, Encrypted: true}

		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil); err != nil {
			t.Fatalf("MountRecorded: %v", err)
		}
		for i, want := range []string{"info " + rigUUID, "lookup " + rigUUID, "unlock " + rigUUID} {
			if f.Calls[i] != want {
				t.Fatalf("calls %v, want the unlock sequence", f.Calls)
			}
		}
	})

	t.Run("a passphrase the keychain will not give up is not retried", func(t *testing.T) {
		shrinkRetry(t)
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		f.Add(datavoltest.Volume{
			UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true,
			Encrypted: true, Locked: true,
		})
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp, Encrypted: true}

		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil); err == nil {
			t.Fatal("MountRecorded reported success with no passphrase")
		}
		lookups := 0
		for _, c := range f.Calls {
			if c == "lookup "+rigUUID {
				lookups++
			}
		}
		if lookups != 1 {
			t.Fatalf("the keychain was consulted %d times; it does not race with boot: %v", lookups, f.Calls)
		}
	})

	t.Run("ownership is applied only when the caller knows a service user", func(t *testing.T) {
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true})
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

		// UID 0 means "leave it to root", the install-time posture: no chown
		// is attempted, which is why this succeeds unprivileged.
		if err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{UID: 0, GID: 0, Mode: 0o750}, nil); err != nil {
			t.Fatalf("MountRecorded: %v", err)
		}
		fi, err := os.Stat(mp)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if fi.Mode().Perm() != 0o755 {
			t.Fatalf("mode = %v, want the mkdir default 0755 (Owner{UID:0} changes nothing)", fi.Mode().Perm())
		}

		// A non-zero UID does attempt the chown; unprivileged that fails, and
		// the failure must be reported rather than swallowed.
		f2 := datavoltest.New()
		mp2 := filepath.Join(t.TempDir(), "k3sm")
		f2.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true})
		rec2 := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp2}
		err = datavol.MountRecorded(ctx, f2.Deps(), f2.FS(), rec2, datavol.Owner{UID: 1, GID: 1}, nil)
		if os.Geteuid() == 0 {
			if err != nil {
				t.Fatalf("MountRecorded as root: %v", err)
			}
			return
		}
		if err == nil {
			t.Fatal("an unprivileged chown of the data root reported success")
		}
	})
}

// TestMountRecordedRefuses pins the two postures MountRecorded will not act
// on, both of which arise from the record being a file that can be wrong. Both
// refusals happen before anything is created, mounted or chowned.
func TestMountRecordedRefuses(t *testing.T) {
	ctx := context.Background()

	t.Run("a mount point no data root could be at", func(t *testing.T) {
		for _, mp := range []string{"", "relative/path", "/", "/System/Volumes/Data", "/Users/someone", "/private/var"} {
			f := datavoltest.New()
			f.Add(datavoltest.Volume{UUID: rigUUID, Name: "k3sm", Container: "disk3", CaseSensitive: true})
			rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

			err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil)
			if !errors.Is(err, datavol.ErrImplausibleMountpoint) {
				t.Fatalf("MountRecorded(%q) = %v, want ErrImplausibleMountpoint", mp, err)
			}
			if len(f.Calls) != 0 {
				t.Fatalf("MountRecorded(%q) acted: %v", mp, f.Calls)
			}
		}
	})

	t.Run("a record naming a volume that is not the one there", func(t *testing.T) {
		shrinkRetry(t)
		f := datavoltest.New()
		mp := filepath.Join(t.TempDir(), "k3sm")
		// The UUID answers, but it is somebody else's volume now.
		f.Add(datavoltest.Volume{UUID: rigUUID, Name: "someone-elses", Container: "disk3", CaseSensitive: true})
		rec := dataroot.Record{UUID: rigUUID, Name: "k3sm", Mountpoint: mp}

		err := datavol.MountRecorded(ctx, f.Deps(), f.FS(), rec, datavol.Owner{}, nil)
		if !errors.Is(err, datavol.ErrRecordMismatch) {
			t.Fatalf("MountRecorded = %v, want ErrRecordMismatch", err)
		}
		if f.Mounted(rigUUID) {
			t.Fatal("a volume the record does not describe was mounted at the data root")
		}
		// A record that names the wrong volume will name the wrong volume in
		// ninety seconds too, so it is not retried.
		attempts := 0
		for _, c := range f.Calls {
			if c == "info "+rigUUID {
				attempts++
			}
		}
		if attempts != 1 {
			t.Fatalf("the mismatch was retried %d times: %v", attempts, f.Calls)
		}
		if _, err := os.Stat(mp); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the mount point was created before the record was verified: %v", err)
		}
	})
}
