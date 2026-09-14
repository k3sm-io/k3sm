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

package datavol

import (
	"context"
	"errors"
	"fmt"
	"os"

	"k3sm.io/k3sm/pkg/dataroot"
)

// Launchd reports whether a LaunchDaemon is loaded. Delete needs it and
// nothing else, so it is one method, defined here at the consumer.
type Launchd interface {
	Loaded(label string) bool
}

// DeleteOptions govern the one destructive operation in this package.
type DeleteOptions struct {
	// Yes is the operator's confirmation. Without it nothing happens.
	Yes bool
	// FstabPath is the fstab to remove the k3sm line from; empty means
	// dataroot.FstabPath.
	FstabPath string
	// NetdLabel and ServerLabel are the LaunchDaemons that must not be
	// running. An empty label is not checked.
	NetdLabel   string
	ServerLabel string
	// ProtectedMountpoint is the LIVE data root, /var/lib/k3sm. The
	// daemons-loaded refusal applies only to a record for THAT mount point:
	// the daemons hold the live data root open and nothing else, so a scratch
	// volume mounted elsewhere is deletable while the cluster runs. Empty
	// disables the check entirely.
	ProtectedMountpoint string
}

var (
	// ErrConfirmRequired is returned when Delete was called without Yes.
	ErrConfirmRequired = errors.New("deleting the data volume destroys every cluster object, image and volume on it and needs an explicit confirmation")
	// ErrDaemonsLoaded is returned while netd or the server is still loaded
	// and the volume being deleted is the live data root. Unmounting THAT one
	// under a running control plane is how a datastore gets truncated; a
	// scratch volume elsewhere is nobody's business but the operator's.
	ErrDaemonsLoaded = errors.New("the k3sm daemons are still loaded")
)

// Delete destroys the data volume rec describes and every declaration of it.
//
// It is deliberately hard to reach: it refuses without an explicit
// confirmation, it refuses while either daemon is loaded AND the record names
// the live data root (o.ProtectedMountpoint), it refuses a mount point that
// could not be a k3sm data root, and it refuses a record that does not match
// the volume actually there. What it removes, in order,
// is the mount, the volume, the keychain item, the fstab line, the record and
// an empty mount point. It never touches the .pre-volume copy of a migrated
// data root -- that is the operator's rollback and only the operator deletes
// it.
func Delete(ctx context.Context, deps Deps, fsys dataroot.FS, ld Launchd, recordPath string, rec dataroot.Record, o DeleteOptions) error {
	if err := deps.validate(); err != nil {
		return err
	}
	if !o.Yes {
		return fmt.Errorf("data volume %s (%s) at %s: %w", rec.Name, rec.UUID, rec.Mountpoint, ErrConfirmRequired)
	}
	if ld != nil && o.ProtectedMountpoint != "" && samePath(rec.Mountpoint, o.ProtectedMountpoint) {
		for _, label := range []string{o.NetdLabel, o.ServerLabel} {
			if label != "" && ld.Loaded(label) {
				return fmt.Errorf("%s is loaded and %s is the live data root: %w — run `sudo k3sm uninstall` first", label, rec.Mountpoint, ErrDaemonsLoaded)
			}
		}
	}
	if implausibleMountpoint(rec.Mountpoint) {
		return fmt.Errorf("%s: %w", rec.Mountpoint, ErrImplausibleMountpoint)
	}

	// Cross-check the record against the disk before anything destructive.
	// The record is a file; the volume is the thing that gets destroyed, and
	// the two are only assumed to correspond. An APFS UUID freed by a delete
	// can be handed to a new volume, and a hand-run diskutil can move a
	// volume out from under a record, so a stale record must not be able to
	// aim deleteVolume at whatever now answers to that UUID.
	info, err := deps.Volumes.Info(ctx, rec.UUID)
	if err != nil {
		return fmt.Errorf("inspect the data volume %s: %w", rec.UUID, err)
	}
	if err := verifyRecord(info, rec); err != nil {
		return err
	}
	if info.MountPoint != "" && !samePath(info.MountPoint, rec.Mountpoint) {
		return fmt.Errorf("the record puts volume %s (%s) at %s but it is mounted at %s: %w",
			rec.Name, rec.UUID, rec.Mountpoint, info.MountPoint, ErrRecordMismatch)
	}

	st, err := dataroot.Read(fsys, rec.Mountpoint)
	if err != nil {
		return fmt.Errorf("inspect the data root %s: %w", rec.Mountpoint, err)
	}
	if st.Mounted {
		if err := deps.Volumes.Unmount(ctx, rec.Mountpoint); err != nil {
			return fmt.Errorf("unmount the data volume at %s: %w — a process still holding it open keeps it busy; the known one is an orphaned k3sm-vmhost, which `sudo pkill -f k3sm-vmhost` clears", rec.Mountpoint, err)
		}
	}
	if err := deps.Volumes.DeleteVolume(ctx, rec.UUID); err != nil {
		return err
	}
	if rec.Encrypted {
		if err := deps.Keychain.Delete(ctx, rec.UUID); err != nil {
			return err
		}
	}

	fstabPath := o.FstabPath
	if fstabPath == "" {
		fstabPath = dataroot.FstabPath
	}
	if _, err := RemoveFstabLine(fsys, fstabPath, rec.Mountpoint); err != nil {
		return err
	}
	if err := dataroot.RemoveRecord(recordPath); err != nil {
		return err
	}
	removeIfEmpty(rec.Mountpoint)
	return nil
}

// removeIfEmpty deletes the now-unmounted mount point when nothing is left in
// it. A failure is deliberately silent: an empty directory at /var/lib/k3sm is
// the ordinary posture of a Mac that never had a data volume, so it is not
// worth failing a completed delete over.
func removeIfEmpty(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 0 {
		return
	}
	_ = os.Remove(dir)
}
