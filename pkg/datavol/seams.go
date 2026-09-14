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
)

// MountOptions are the mount options every k3sm data volume is mounted with,
// in both the diskutil command line and the /etc/fstab line, as one literal so
// the two cannot drift.
//
// nobrowse keeps the volume out of Finder and the sidebar; nosuid and nodev
// mean a setuid binary or a device node written into a PersistentVolume
// directory by a workload is inert. noexec is deliberately absent: native pods
// execute from the data root.
const MountOptions = "nobrowse,nosuid,nodev"

// Info is the subset of "diskutil info -plist <target>" k3sm decides on.
type Info struct {
	// DeviceIdentifier is the device node's short name, e.g. "disk3s7". It
	// renumbers across boots; VolumeUUID does not.
	DeviceIdentifier string
	// VolumeUUID is the APFS volume UUID, the stable handle every other verb
	// in this package takes.
	VolumeUUID string
	// VolumeName is the APFS volume label, e.g. "k3sm".
	VolumeName string
	// MountPoint is where the volume is mounted, empty when it is not. macOS
	// reports the resolved path, so it may read /private/var/lib/k3sm.
	MountPoint string
	// ContainerReference is the APFS container the volume belongs to, e.g.
	// "disk3" -- the container a new volume is added to.
	ContainerReference string
	// FilesystemType is the mount type, "apfs" for every volume k3sm accepts.
	FilesystemType string
	// FilesystemName is the human name diskutil prints, e.g.
	// "Case-sensitive APFS". CaseSensitive is derived from it.
	FilesystemName string
	// CaseSensitive reports a case-sensitive volume. k3sm requires one: image
	// layers and Linux root trees routinely carry names that differ only in
	// case, and a case-insensitive volume silently collapses them.
	CaseSensitive bool
	// Encrypted reports APFS encryption of any kind, including the hardware
	// encryption an Apple Silicon Mac applies with no passphrase.
	Encrypted bool
	// FileVault reports that the encryption is FileVault, i.e. gated on a
	// user or recovery key rather than the SEP alone.
	FileVault bool
	// Locked reports that the volume cannot be mounted until it is unlocked
	// with its passphrase.
	Locked bool
}

// Capacity is the subset of "diskutil apfs list -plist <container>" k3sm
// decides on, for one volume. It is a separate call from Info because diskutil
// reports a volume's quota only in the container listing.
type Capacity struct {
	// Quota is the APFS quota in bytes, 0 when the volume carries none and
	// can therefore grow to fill its container.
	Quota uint64
	// Reserve is the reserved capacity in bytes, 0 unless someone set one.
	// k3sm never sets a reserve; it reports what it finds.
	Reserve uint64
	// InUse is the volume's current usage in bytes.
	InUse uint64
}

// Volumes is the diskutil seam: everything k3sm asks of the disk. It is
// defined here at the consumer, and Darwin is the production implementation.
type Volumes interface {
	// Info reports on target, which may be a device node, a mount point, a
	// volume name or a volume UUID -- whatever diskutil info accepts.
	Info(ctx context.Context, target string) (Info, error)
	// Capacity reports the quota, reserve and usage of the volume with the
	// given UUID inside container.
	Capacity(ctx context.Context, container, uuid string) (Capacity, error)
	// AddVolume creates a case-sensitive APFS volume named name in container,
	// quota-capped and left unmounted. A non-empty passphrase encrypts it and
	// is transported on stdin, never in the argv.
	AddVolume(ctx context.Context, container, name string, quotaBytes uint64, passphrase string) error
	// Mount mounts the volume with the given UUID at mountpoint, with
	// MountOptions.
	Mount(ctx context.Context, uuid, mountpoint string) error
	// Unmount unmounts target, which may be a mount point or a volume UUID.
	Unmount(ctx context.Context, target string) error
	// DeleteVolume destroys the volume with the given UUID and everything on
	// it.
	DeleteVolume(ctx context.Context, uuid string) error
	// Unlock unlocks an encrypted volume without mounting it. The passphrase
	// is transported on stdin.
	Unlock(ctx context.Context, uuid, passphrase string) error
}

// Keychain is the System-keychain seam for an encrypted volume's passphrase.
//
// Honesty about what this protects: the item is created by /usr/bin/security
// in the System keychain and is readable by any root process through the same
// tool. It keeps the passphrase off the disk in cleartext and out of every
// argv; it does not defend against a root attacker, and the user docs say so.
type Keychain interface {
	// Store saves passphrase under the volume's UUID.
	Store(ctx context.Context, uuid, passphrase string) error
	// Lookup returns the passphrase stored for the volume's UUID.
	Lookup(ctx context.Context, uuid string) (string, error)
	// Delete removes the item. An item that is not there is not an error.
	Delete(ctx context.Context, uuid string) error
}

// Indexing is the seam for keeping the data root out of the two macOS services
// that would otherwise walk it: Spotlight and Time Machine. Both are
// best-effort -- a failure is logged, never fatal, because an indexed data
// root still works.
type Indexing interface {
	// SpotlightOff disables Spotlight indexing on mountpoint.
	SpotlightOff(ctx context.Context, mountpoint string) error
	// TimeMachineExclude excludes mountpoint from Time Machine backups.
	TimeMachineExclude(ctx context.Context, mountpoint string) error
}

// Deps bundles the three seams every operation in this package takes. Callers
// build it with NewDarwin in production and with datavoltest.Fake.Deps in
// tests.
type Deps struct {
	Volumes  Volumes
	Keychain Keychain
	Indexing Indexing
}

// errMissingSeam reports a Deps that was not filled in. Calling through a nil
// interface would panic, and a library does not panic.
var errMissingSeam = errors.New("datavol: dependencies are incomplete")

// validate reports whether every seam an operation may reach is present.
func (d Deps) validate() error {
	switch {
	case d.Volumes == nil:
		return fmt.Errorf("%w: no Volumes", errMissingSeam)
	case d.Keychain == nil:
		return fmt.Errorf("%w: no Keychain", errMissingSeam)
	case d.Indexing == nil:
		return fmt.Errorf("%w: no Indexing", errMissingSeam)
	}
	return nil
}
