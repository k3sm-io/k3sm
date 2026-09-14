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
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"k3sm.io/k3sm/pkg/dataroot"
)

var (
	// ErrImplausibleMountpoint is returned for a mount point no k3sm data
	// volume could be at. It is the guard against a corrupted or hand-edited
	// record turning a mount or a delete into a system-wide operation.
	ErrImplausibleMountpoint = errors.New("that mount point is not a plausible k3sm data root")
	// ErrRecordMismatch is returned when the volume a record names is not the
	// volume that is actually there. The record is a file on disk: an APFS
	// UUID can be reused after a delete-and-recreate, a stale record can
	// survive a hand-run diskutil, and a destructive operation must act on
	// the volume it verified, never on the one it was told about.
	ErrRecordMismatch = errors.New("the data volume record does not match the volume that is there")
)

// implausibleMountpoint reports a mount point no k3sm data volume could be at.
//
// The guard exists because the mount point comes from a file on disk and the
// operations behind it are destructive: a truncated, hand-edited or corrupted
// record must not be able to aim `diskutil unmount` at the boot volume, or a
// chown at a home directory. The rule is deliberately coarse -- at least two
// path segments, and not inside the places a data root is never allowed to be.
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

// verifyRecord checks that the volume diskutil reports is the volume the
// record describes, before anything is done to it.
//
// The UUID compare is not redundant with having looked the volume up BY uuid:
// a stale record can name a UUID that a later delete-and-recreate cycle handed
// to a different volume, and the volume label is the operator-visible identity
// that would have changed with it.
func verifyRecord(info Info, rec dataroot.Record) error {
	if !strings.EqualFold(info.VolumeUUID, rec.UUID) {
		return fmt.Errorf("the record names volume %s but diskutil reports %s: %w", rec.UUID, info.VolumeUUID, ErrRecordMismatch)
	}
	if info.VolumeName != rec.Name {
		return fmt.Errorf("the record names volume %q (%s) but it is called %q: %w", rec.Name, rec.UUID, info.VolumeName, ErrRecordMismatch)
	}
	return nil
}

// samePath reports whether two paths name the same directory, resolving
// symlinks on both sides when both resolve. It is the same rule
// pkg/dataroot applies to a record's mountpoint, and it exists for the same
// reason: macOS reports /private/var where k3sm writes /var.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		return false
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		return false
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}
