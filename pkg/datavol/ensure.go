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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// Options describe the data volume k3sm should end up with.
type Options struct {
	// Name is the APFS volume label to create or adopt, e.g. "k3sm".
	Name string
	// Mountpoint is the data root the volume belongs at, /var/lib/k3sm.
	Mountpoint string
	// QuotaBytes is the requested quota. APFS fixes it at creation, so this
	// is the one chance to bound the volume.
	QuotaBytes uint64
	// Encrypt asks for a volume encrypted with a random passphrase kept in
	// the System keychain. It can only be honoured on a volume k3sm creates:
	// APFS cannot encrypt a volume in place, so asking for it over an
	// existing unencrypted one is refused.
	Encrypt bool
	// CreatedBy names the k3sm version, recorded for the operator.
	CreatedBy string
	// AllowSmallQuota waives the MinQuotaBytes floor.
	//
	// It exists ONLY for the acceptance gate, whose scratch volumes are a
	// couple of gigabytes so a lab run does not need 32 GiB of free container
	// to prove the create, quota and delete paths. `k3sm install` never sets
	// it, and no CLI flag reaches it.
	AllowSmallQuota bool
}

// Plan reports which of Ensure's four paths was taken, so the caller can
// decide what still has to happen: a migration, an fstab line, a record write.
type Plan struct {
	// Existing reports that a record already described the volume; nothing
	// was inspected or changed.
	Existing bool
	// Adopted reports that k3sm took over a volume it did not create.
	Adopted bool
	// FromFstab reports that the adopted volume was found through an
	// /etc/fstab line rather than by name.
	FromFstab bool
	// Created reports that the volume was created by this call.
	Created bool
}

var (
	// ErrEncryptRequiresFresh is returned when encryption is asked for over a
	// volume that already exists unencrypted. APFS cannot encrypt in place
	// from here, and pretending otherwise would leave an unencrypted volume
	// behind a flag that says encrypted.
	ErrEncryptRequiresFresh = errors.New("an existing data volume cannot be encrypted in place")
	// ErrForeignVolume is returned when a volume with the requested name
	// exists but carries no proof of being k3sm's. k3sm refuses it by name
	// rather than taking ownership of an operator's data -- including when it
	// happens to be empty, because emptiness is not provenance.
	ErrForeignVolume = errors.New("a volume with that name exists and is not k3sm's")
	// ErrQuotaNotApplied is returned when a freshly created volume does not
	// report the quota that was asked for. The volume is deleted first: a
	// record claiming a bound the volume does not have is the failure this
	// whole feature exists to end.
	ErrQuotaNotApplied = errors.New("the data volume was created without the requested quota")
	// ErrQuotaTooSmall is returned for a requested quota below MinQuotaBytes.
	ErrQuotaTooSmall = errors.New("the requested data volume quota is below the supported minimum")
)

// quotaTolerance is how far the observed quota may sit from the requested one
// before Ensure calls it a failure, as a divisor: 100 means one percent. APFS
// rounds a quota up to a block boundary, so an exact compare would reject every
// volume it just made.
const quotaTolerance = 100

// Ensure returns the record for the data volume o describes, creating or
// adopting one as needed. It takes exactly one of four paths, in this order:
//
//  1. a record already exists -- return it untouched, so a re-run of
//     `k3sm install --data-volume` is a no-op;
//  2. /etc/fstab declares the mount point -- adopt the volume that line names,
//     which is how the hand-made pre-feature setup is taken over;
//  3. a volume named o.Name exists and looks like k3sm's -- adopt it;
//  4. otherwise create one.
//
// Ensure never mounts anything and never writes the record. Both are the
// caller's, in that order: the record is the declaration that the volume is
// k3sm's, and it must not exist until a mount has actually succeeded.
func Ensure(ctx context.Context, deps Deps, fsys dataroot.FS, recordPath string, o Options) (dataroot.Record, Plan, error) {
	if err := deps.validate(); err != nil {
		return dataroot.Record{}, Plan{}, err
	}

	// 1. An existing record is the whole answer. A record that does not parse
	// is fatal here, unlike in dataroot.Read: this is the authoring path, and
	// overwriting a declaration it could not read is how a second volume gets
	// created over a live one.
	rec, err := dataroot.ReadRecord(fsys, recordPath)
	if err != nil {
		return dataroot.Record{}, Plan{}, err
	}
	if rec != nil {
		if o.Encrypt && !rec.Encrypted {
			return dataroot.Record{}, Plan{}, fmt.Errorf("data volume %s (%s): %w", rec.Name, rec.UUID, ErrEncryptRequiresFresh)
		}
		return *rec, Plan{Existing: true}, nil
	}

	// 2. An fstab line declaring the mount point names a volume to adopt.
	if spec, ok := fstabSpecFor(fsys, dataroot.FstabPath, o.Mountpoint); ok {
		info, err := deps.Volumes.Info(ctx, fstabTarget(spec))
		if err != nil {
			return dataroot.Record{}, Plan{}, fmt.Errorf("inspect the volume /etc/fstab mounts at %s: %w", o.Mountpoint, err)
		}
		record, err := adopt(ctx, deps, info, o)
		if err != nil {
			return dataroot.Record{}, Plan{}, err
		}
		return record, Plan{Adopted: true, FromFstab: true}, nil
	}

	// 3. A volume of the right name, if it carries k3sm's provenance.
	if info, err := deps.Volumes.Info(ctx, o.Name); err == nil {
		if !apfsCaseSensitive(info) {
			return dataroot.Record{}, Plan{}, fmt.Errorf("volume %q is %s: %w", o.Name, describeFilesystem(info), ErrForeignVolume)
		}
		ours, capacity, err := isOurs(ctx, deps, fsys, info, o)
		if err != nil {
			return dataroot.Record{}, Plan{}, err
		}
		if !ours {
			return dataroot.Record{}, Plan{}, fmt.Errorf("volume %q (%s) holds %s of data, is not mounted at %s and carries no %s marker: %w — pick another name with --data-volume-name, or remove that volume yourself with `diskutil apfs deleteVolume %s`",
				o.Name, info.VolumeUUID, FormatSize(capacity.InUse), o.Mountpoint, MarkerName, ErrForeignVolume, info.VolumeUUID)
		}
		record, err := adopt(ctx, deps, info, o)
		if err != nil {
			return dataroot.Record{}, Plan{}, err
		}
		return record, Plan{Adopted: true}, nil
	}

	// 4. Create one.
	record, err := create(ctx, deps, o)
	if err != nil {
		return dataroot.Record{}, Plan{}, err
	}
	return record, Plan{Created: true}, nil
}

// adopt builds the record for a volume k3sm did not create, after checking it
// is one k3sm can actually use.
func adopt(ctx context.Context, deps Deps, info Info, o Options) (dataroot.Record, error) {
	if !apfsCaseSensitive(info) {
		return dataroot.Record{}, fmt.Errorf("the volume at %s is %s, and k3sm's data root must be a case-sensitive APFS volume: %w",
			o.Mountpoint, describeFilesystem(info), ErrForeignVolume)
	}
	if o.Encrypt && !info.Encrypted {
		return dataroot.Record{}, fmt.Errorf("data volume %s (%s): %w", info.VolumeName, info.VolumeUUID, ErrEncryptRequiresFresh)
	}
	capacity, err := deps.Volumes.Capacity(ctx, info.ContainerReference, info.VolumeUUID)
	if err != nil {
		return dataroot.Record{}, fmt.Errorf("read the quota of volume %s: %w", info.VolumeUUID, err)
	}
	return dataroot.Record{
		Version:    dataroot.RecordVersion,
		UUID:       info.VolumeUUID,
		Name:       info.VolumeName,
		Mountpoint: o.Mountpoint,
		QuotaBytes: capacity.Quota,
		Encrypted:  info.Encrypted,
		CreatedBy:  o.CreatedBy,
		CreatedAt:  now(),
		Adopted:    true,
	}, nil
}

// create makes the volume, then verifies the one thing that cannot be fixed
// afterwards: that the quota landed. A volume that failed any check is deleted
// before the error returns, so a failed install leaves nothing behind.
func create(ctx context.Context, deps Deps, o Options) (dataroot.Record, error) {
	if o.QuotaBytes < MinQuotaBytes && !o.AllowSmallQuota {
		return dataroot.Record{}, fmt.Errorf("%s requested, minimum is %s: %w", FormatSize(o.QuotaBytes), FormatSize(MinQuotaBytes), ErrQuotaTooSmall)
	}
	root, err := deps.Volumes.Info(ctx, "/")
	if err != nil {
		return dataroot.Record{}, fmt.Errorf("find the boot APFS container: %w", err)
	}
	container := root.ContainerReference
	if container == "" {
		return dataroot.Record{}, fmt.Errorf("find the boot APFS container: / reports no APFS container")
	}

	passphrase := ""
	if o.Encrypt {
		passphrase, err = newPassphrase()
		if err != nil {
			return dataroot.Record{}, err
		}
	}
	if err := deps.Volumes.AddVolume(ctx, container, o.Name, o.QuotaBytes, passphrase); err != nil {
		return dataroot.Record{}, err
	}

	info, err := deps.Volumes.Info(ctx, o.Name)
	if err != nil {
		return dataroot.Record{}, fmt.Errorf("inspect the new volume %q: %w", o.Name, err)
	}
	capacity, err := deps.Volumes.Capacity(ctx, container, info.VolumeUUID)
	if err != nil {
		return dataroot.Record{}, destroy(ctx, deps, info.VolumeUUID, fmt.Errorf("read the quota of the new volume %s: %w", info.VolumeUUID, err))
	}
	if !quotaApplied(capacity.Quota, o.QuotaBytes) {
		return dataroot.Record{}, destroy(ctx, deps, info.VolumeUUID,
			fmt.Errorf("asked for %s, the volume reports %s: %w", FormatSize(o.QuotaBytes), FormatSize(capacity.Quota), ErrQuotaNotApplied))
	}
	if o.Encrypt {
		if err := deps.Keychain.Store(ctx, info.VolumeUUID, passphrase); err != nil {
			return dataroot.Record{}, destroy(ctx, deps, info.VolumeUUID, err)
		}
	}
	return dataroot.Record{
		Version:    dataroot.RecordVersion,
		UUID:       info.VolumeUUID,
		Name:       info.VolumeName,
		Mountpoint: o.Mountpoint,
		QuotaBytes: capacity.Quota,
		Encrypted:  o.Encrypt,
		CreatedBy:  o.CreatedBy,
		CreatedAt:  now(),
	}, nil
}

// destroy deletes a volume create has decided not to keep and folds any
// deletion failure into the error that caused it, so the operator reads both.
func destroy(ctx context.Context, deps Deps, uuid string, cause error) error {
	if err := deps.Volumes.DeleteVolume(ctx, uuid); err != nil {
		return fmt.Errorf("%w (and the volume could not be removed: %v)", cause, err)
	}
	return cause
}

// isOurs decides whether a same-named volume may be adopted. It is ours when
// it is already mounted at the requested data root, or when it carries the
// provenance marker MountRecorded writes -- read where it is mounted, or
// through a temporary mount when it is not mounted at all.
//
// There is deliberately no "it looks empty, so take it" rule. Emptiness is not
// provenance: a volume someone else made moments ago, or emptied, is
// indistinguishable from one k3sm made, and adopting it makes k3sm the thing
// that destroyed it at the next `datavol delete`. The marker is cheap to
// produce for a volume that really is k3sm's (mount it and re-run), and a
// wrong adoption is not recoverable.
func isOurs(ctx context.Context, deps Deps, fsys dataroot.FS, info Info, o Options) (bool, Capacity, error) {
	capacity, err := deps.Volumes.Capacity(ctx, info.ContainerReference, info.VolumeUUID)
	if err != nil {
		return false, Capacity{}, fmt.Errorf("read the usage of volume %s: %w", info.VolumeUUID, err)
	}
	if info.MountPoint != "" {
		if samePath(info.MountPoint, o.Mountpoint) {
			return true, capacity, nil
		}
		marked, err := hasMarker(fsys, info.MountPoint)
		if err != nil {
			return false, capacity, fmt.Errorf("look for the %s marker on volume %s: %w", MarkerName, info.VolumeUUID, err)
		}
		return marked, capacity, nil
	}
	marked, err := markedViaTempMount(ctx, deps, fsys, info.VolumeUUID)
	if err != nil {
		return false, capacity, err
	}
	return marked, capacity, nil
}

// markedViaTempMount mounts an unmounted volume somewhere private, looks for
// the provenance marker, and unmounts it again. It is the only way to read a
// volume's contents without first committing it to the data root, which is
// exactly the commitment the answer is supposed to license.
//
// The staging directory is a fresh 0700 directory under the system temp dir,
// so the volume's contents are never browsable while the probe runs.
func markedViaTempMount(ctx context.Context, deps Deps, fsys dataroot.FS, uuid string) (bool, error) {
	staging, err := os.MkdirTemp(os.TempDir(), "k3sm-datavol-probe-")
	if err != nil {
		return false, fmt.Errorf("create a staging directory to inspect volume %s: %w", uuid, err)
	}
	defer func() { _ = os.Remove(staging) }()

	if err := deps.Volumes.Mount(ctx, uuid, staging); err != nil {
		return false, fmt.Errorf("inspect volume %s before adopting it: %w", uuid, err)
	}
	defer func() { _ = deps.Volumes.Unmount(ctx, staging) }()

	marked, err := hasMarker(fsys, staging)
	if err != nil {
		return false, fmt.Errorf("look for the %s marker on volume %s: %w", MarkerName, uuid, err)
	}
	return marked, nil
}

// hasMarker reports whether the provenance marker is at the root of the tree
// mounted at mountpoint.
func hasMarker(fsys dataroot.FS, mountpoint string) (bool, error) {
	if _, err := fsys.Stat(filepath.Join(mountpoint, MarkerName)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// quotaApplied reports whether an observed quota is the requested one within
// quotaTolerance.
func quotaApplied(got, want uint64) bool {
	if want == 0 {
		return true
	}
	slack := want / quotaTolerance
	return got+slack >= want && got <= want+slack
}

// apfsCaseSensitive reports the one filesystem k3sm's data root may be: a
// case-sensitive APFS volume. Case matters because image layers and Linux root
// trees carry names that differ only in case, which a case-insensitive volume
// silently collapses.
func apfsCaseSensitive(info Info) bool {
	return strings.EqualFold(info.FilesystemType, "apfs") && info.CaseSensitive
}

// describeFilesystem names what a rejected volume actually is, for the error.
func describeFilesystem(info Info) string {
	if info.FilesystemName != "" {
		return info.FilesystemName
	}
	if info.FilesystemType != "" {
		return info.FilesystemType
	}
	return "of an unknown filesystem"
}

// newPassphrase returns a fresh 256-bit passphrase, hex-encoded so it survives
// every transport (stdin to diskutil, a security(1) command line) with no
// quoting question.
func newPassphrase() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate a data volume passphrase: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// now is the record timestamp, RFC 3339 in UTC. It is a var so a test can pin
// it.
var now = func() string { return time.Now().UTC().Format(time.RFC3339) }
