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
	"path/filepath"
	"strings"

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
}

var (
	// ErrConfirmRequired is returned when Delete was called without Yes.
	ErrConfirmRequired = errors.New("deleting the data volume destroys every cluster object, image and volume on it and needs an explicit confirmation")
	// ErrDaemonsLoaded is returned while netd or the server is still loaded.
	// Unmounting under a running control plane is how a datastore gets
	// truncated.
	ErrDaemonsLoaded = errors.New("the k3sm daemons are still loaded")
	// ErrImplausibleMountpoint is returned for a mount point no k3sm data
	// volume could be at. It is the guard against a corrupted or
	// hand-edited record turning `datavol delete` into a system-wide unmount.
	ErrImplausibleMountpoint = errors.New("that mount point is not a plausible k3sm data root")
)

// Delete destroys the data volume rec describes and every declaration of it.
//
// It is deliberately hard to reach: it refuses without an explicit
// confirmation, it refuses while either daemon is loaded, and it refuses a
// mount point that could not be a k3sm data root. What it removes, in order,
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
	if ld != nil {
		for _, label := range []string{o.NetdLabel, o.ServerLabel} {
			if label != "" && ld.Loaded(label) {
				return fmt.Errorf("%s is loaded: %w — run `sudo k3sm uninstall` first", label, ErrDaemonsLoaded)
			}
		}
	}
	if implausibleMountpoint(rec.Mountpoint) {
		return fmt.Errorf("%s: %w", rec.Mountpoint, ErrImplausibleMountpoint)
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

// implausibleMountpoint reports a mount point no k3sm data volume could be at.
//
// The guard exists because everything after it is destructive and the mount
// point comes from a file on disk: a truncated, hand-edited or corrupted
// record must not be able to aim `diskutil unmount` at the boot volume or a
// home directory. The rule is deliberately coarse -- at least two path
// segments, and not inside the places a data root is never allowed to be.
func implausibleMountpoint(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return true
	}
	clean := filepath.Clean(p)
	segments := strings.Split(strings.Trim(clean, "/"), "/")
	// "/" and every single-segment path: /var, /System, /Library, /Users.
	if clean == "/" || len(segments) < 2 {
		return true
	}
	// A home directory itself, though a directory inside one is fine.
	if segments[0] == "Users" && len(segments) == 2 {
		return true
	}
	// These and everything inside them.
	for _, forbidden := range []string{"/System", "/Library/k3sm"} {
		if clean == forbidden || strings.HasPrefix(clean, forbidden+"/") {
			return true
		}
	}
	// These exactly: they are roots other filesystems hang off, not data
	// roots. A directory inside them is allowed.
	for _, forbidden := range []string{"/private", "/private/var", "/private/etc", "/Volumes"} {
		if clean == forbidden {
			return true
		}
	}
	return false
}
