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
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
)

// MarkerName is the provenance marker k3sm writes at the root of a volume it
// owns. It is what lets Ensure adopt a same-named volume on a later run
// without taking over an operator's unrelated data.
const MarkerName = ".k3sm-datavol"

// markerContent is written into the marker. It is for a human reading the
// volume, not for k3sm: nothing parses it.
const markerContent = "This APFS volume holds k3sm's data root. See docs/user/storage.md.\n"

// Owner is the ownership MountRecorded applies to the mount point once the
// volume is mounted. A zero UID means "leave it to root", which is the right
// answer during install, where the service user may not exist yet and
// EnsureServiceUser chowns the data root immediately afterwards.
type Owner struct {
	UID  int
	GID  int
	Mode fs.FileMode
}

// Retry bounds how long MountRecorded keeps trying.
type Retry struct {
	// Poll is the wait between attempts.
	Poll time.Duration
	// Budget is the total time allowed before the mount is called failed.
	Budget time.Duration
}

// RetryPolicy bounds the mount retry.
//
// It exists because the io.k3sm.datavol daemon runs at boot, where disk
// arbitration has been observed to be transiently unready: launchd offers no
// ordering, so one unretried diskutil failure would leave netd and the server
// refusing the shadowed data root until an operator intervened. Ninety seconds
// of two-second polls is long enough for arbitration to settle and short
// enough that a genuinely absent volume is reported the same boot.
//
// It is a var so tests can shrink it; production never changes it.
var RetryPolicy = Retry{Poll: 2 * time.Second, Budget: 90 * time.Second}

// MountRecorded mounts the volume rec describes at rec.Mountpoint, and is the
// ONE mount routine: `k3sm install`, the io.k3sm.datavol daemon and the
// acceptance gate all call it, so there is one definition of a correctly
// mounted k3sm data volume.
//
// It is idempotent. The RECORD'S volume already mounted there -- by this
// daemon, by diskarbitrationd from the fstab line, or by hand -- returns
// immediately, and a partial previous run is completed rather than redone.
// Some OTHER filesystem mounted there is not the same thing and is refused:
// "a filesystem is mounted" is not the question the caller is asking.
//
// It refuses two postures outright, both of which come from the record being a
// file that can be wrong: a mount point no data root could be at
// (ErrImplausibleMountpoint), and a UUID whose volume is not the one the
// record names (ErrRecordMismatch).
//
// logger may be nil, in which case slog.Default is used. It records only the
// two best-effort steps (Spotlight, Time Machine), whose failure leaves a
// working data root and must not fail the mount.
func MountRecorded(ctx context.Context, deps Deps, fsys dataroot.FS, rec dataroot.Record, own Owner, logger *slog.Logger) error {
	if err := deps.validate(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	// Before anything is created, mounted or chowned: the mount point comes
	// from a record on disk, and every step below acts on it as root.
	if implausibleMountpoint(rec.Mountpoint) {
		return fmt.Errorf("%s: %w", rec.Mountpoint, ErrImplausibleMountpoint)
	}

	st, err := dataroot.Read(fsys, rec.Mountpoint)
	if err != nil {
		return fmt.Errorf("inspect the data root %s: %w", rec.Mountpoint, err)
	}
	if st.Mounted {
		// Something is mounted there, but "something" is not the question.
		// The fast path is the one every boot and every re-run takes, so it
		// is also the one place a wrong volume would be accepted silently and
		// then written to as the data root.
		info, err := deps.Volumes.Info(ctx, rec.UUID)
		if err != nil {
			return fmt.Errorf("inspect the data volume %s: %w", rec.UUID, err)
		}
		if err := verifyRecord(info, rec); err != nil {
			return err
		}
		if !samePath(info.MountPoint, rec.Mountpoint) {
			return fmt.Errorf("%s has a filesystem mounted on it, but volume %s (%s) is mounted at %q: %w",
				rec.Mountpoint, rec.Name, rec.UUID, info.MountPoint, ErrRecordMismatch)
		}
		return nil
	}

	if err := mountWithRetry(ctx, deps, fsys, rec); err != nil {
		return err
	}

	if err := deps.Indexing.SpotlightOff(ctx, rec.Mountpoint); err != nil {
		logger.Warn("could not disable Spotlight on the data volume", "mountpoint", rec.Mountpoint, "err", err)
	}
	if err := deps.Indexing.TimeMachineExclude(ctx, rec.Mountpoint); err != nil {
		logger.Warn("could not exclude the data volume from Time Machine", "mountpoint", rec.Mountpoint, "err", err)
	}

	if err := writeMarker(fsys, rec.Mountpoint); err != nil {
		return err
	}

	// Ownership is applied only when the caller knows a service user. During
	// install the data root is chowned by EnsureServiceUser right afterwards;
	// at boot the daemon looks _k3sm up and passes it here.
	if own.UID > 0 {
		if err := os.Chown(rec.Mountpoint, own.UID, own.GID); err != nil {
			return fmt.Errorf("chown the data root %s to %d:%d: %w", rec.Mountpoint, own.UID, own.GID, err)
		}
		if own.Mode != 0 {
			if err := os.Chmod(rec.Mountpoint, own.Mode); err != nil {
				return fmt.Errorf("chmod the data root %s to %v: %w", rec.Mountpoint, own.Mode, err)
			}
		}
	}
	return nil
}

// mountWithRetry unlocks (when needed) and mounts the volume, retrying the
// steps that race with early-boot disk arbitration until RetryPolicy.Budget is
// spent. A mount that reports success but leaves nothing mounted counts as a
// failure and is retried too -- the caller's whole question is whether the
// data root is safe to write.
func mountWithRetry(ctx context.Context, deps Deps, fsys dataroot.FS, rec dataroot.Record) error {
	deadline := time.Now().Add(RetryPolicy.Budget)
	var last error
	for attempt := 1; ; attempt++ {
		last = mountOnce(ctx, deps, fsys, rec)
		if last == nil {
			return nil
		}
		if errors.Is(last, errPassphraseUnavailable) || errors.Is(last, ErrRecordMismatch) || !time.Now().Add(RetryPolicy.Poll).Before(deadline) {
			return fmt.Errorf("mount the data volume %s at %s (attempt %d): %w", rec.UUID, rec.Mountpoint, attempt, last)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mount the data volume %s at %s: %w", rec.UUID, rec.Mountpoint, ctx.Err())
		case <-time.After(RetryPolicy.Poll):
		}
	}
}

// errPassphraseUnavailable marks a failure mountWithRetry must not retry: the
// keychain does not race with boot, so a missing or unreadable passphrase will
// not become readable in ninety seconds. ErrRecordMismatch is the other:
// a record that names the wrong volume will still name the wrong volume in
// ninety seconds.
var errPassphraseUnavailable = errors.New("the data volume passphrase is unavailable")

// mountOnce is a single attempt: inspect, unlock if locked, mount, confirm.
func mountOnce(ctx context.Context, deps Deps, fsys dataroot.FS, rec dataroot.Record) error {
	info, err := deps.Volumes.Info(ctx, rec.UUID)
	if err != nil {
		return err
	}
	// A record naming a volume that is not the one there must not be mounted
	// at the data root: the daemons would then write a cluster's state onto
	// somebody else's volume.
	if err := verifyRecord(info, rec); err != nil {
		return err
	}
	// The mount point is created only once the record has been shown to
	// describe the volume, so a refusal leaves no empty directory behind.
	// MkdirAll is idempotent, so a retry costs nothing.
	if err := os.MkdirAll(rec.Mountpoint, 0o755); err != nil {
		return fmt.Errorf("create the mount point %s: %w", rec.Mountpoint, err)
	}
	if info.Locked && rec.Encrypted {
		passphrase, err := deps.Keychain.Lookup(ctx, rec.UUID)
		if err != nil {
			return fmt.Errorf("%w: %v", errPassphraseUnavailable, err)
		}
		if err := deps.Volumes.Unlock(ctx, rec.UUID, passphrase); err != nil {
			return err
		}
	}
	if err := deps.Volumes.Mount(ctx, rec.UUID, rec.Mountpoint); err != nil {
		return err
	}
	st, err := dataroot.Read(fsys, rec.Mountpoint)
	if err != nil {
		return fmt.Errorf("inspect the data root %s: %w", rec.Mountpoint, err)
	}
	if !st.Mounted {
		return fmt.Errorf("diskutil reported success but nothing is mounted at %s", rec.Mountpoint)
	}
	return nil
}

// writeMarker writes the provenance marker if it is not already there.
func writeMarker(fsys dataroot.FS, mountpoint string) error {
	path := filepath.Join(mountpoint, MarkerName)
	if _, err := fsys.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("look for %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(markerContent), 0o644); err != nil {
		return fmt.Errorf("write the data volume marker %s: %w", path, err)
	}
	return nil
}
