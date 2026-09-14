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

package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/datavol"
)

// ensureDataVolume is `k3sm install --data-volume`: it makes the data root sit
// on an APFS volume k3sm owns, and it runs FIRST, before EnsureServiceUser.
//
// The ordering is the load-bearing part, not an optimisation. EnsureServiceUser
// carries the unconditional refuse-shadow check (install_darwin.go), which fires
// on a data root that is DECLARED a mount point and is not mounted -- which is
// precisely the posture this block exists to resolve, and precisely the posture
// a Mac is in after a reboot where the volume did not come up. Running the block
// later would mean `sudo k3sm install --data-volume` could never repair the one
// state it was written for; running it first means the guard sees a mounted
// volume and does its ordinary job.
//
// The steps, in order, and what each leaves behind if it fails:
//
//  1. Ensure -- create, adopt or recognise the volume. A creation that fails
//     any check deletes the volume it made, so nothing is left behind.
//  2. Migrate (only for a plain, non-empty data root onto a volume k3sm just
//     created) -- the daemons are booted out first, the copy is verified before
//     anything moves, and the old root is RENAMED aside, never deleted in place.
//  3. MountRecorded -- the one mount routine, idempotent and retried.
//  4. The record, written ONLY after the mount succeeded, and the /etc/fstab
//     line on a freshly created volume: two declarations, so a k3sm too old to
//     read the record still perceives the volume, and diskarbitrationd mounts
//     it at boot even with no daemon.
func ensureDataVolume(ctx context.Context, sys System, cfg Config, m []artifact, st dataroot.State) error {
	logger := cfg.Logger
	fsys := cfg.DataRootFS
	deps := cfg.DataVolumeDeps

	rec, plan, err := datavol.Ensure(ctx, deps, fsys, dataroot.DefaultRecordPath, *cfg.DataVolume)
	if err != nil {
		return fmt.Errorf("install: data volume: %w", err)
	}
	logger.Info("data volume resolved", "volume", rec.Name, "uuid", rec.UUID,
		"quota", datavol.FormatSize(rec.QuotaBytes), "encrypted", rec.Encrypted,
		"created", plan.Created, "adopted", plan.Adopted, "existing", plan.Existing)

	// A migration is the one case where there is data in the way: the data root
	// is a plain directory with contents, and the volume that must take its
	// place was made by the call above. An adopted or already-recorded volume is
	// either already the data root or already k3sm's, and copying into it would
	// duplicate what is there.
	if plan.Created && st.Exists && !st.Mounted {
		nonEmpty, err := dataRootHasContent(fsys, cfg.DataRoot)
		if err != nil {
			return fmt.Errorf("install: data volume: %w", err)
		}
		if nonEmpty {
			if err := migrateDataRoot(ctx, sys, cfg, m, rec); err != nil {
				return err
			}
		}
	}

	// The service user may not exist yet on a first install, in which case the
	// mount point stays root's and EnsureServiceUser chowns it moments later.
	own := datavol.Owner{GID: DataRootGID, Mode: DataRootMode}
	if uid, ok := sys.LookupServiceUID(cfg.ServiceUser); ok {
		own.UID = uid
	}
	if err := datavol.MountRecorded(ctx, deps, fsys, rec, own, logger); err != nil {
		return fmt.Errorf("install: mount the data volume %s at %s: %w (re-run `sudo k3sm install --data-volume`: adoption is by marker, so nothing is copied twice and the mount is simply retried)", rec.UUID, rec.Mountpoint, err)
	}

	// Only now. The record is k3sm's declaration that this directory is a mount
	// point, and every daemon refuses a declared root that is not mounted -- so
	// a record written before a verified mount would turn a failed install into
	// a cluster that will not start.
	if err := sys.WriteDataVolumeRecord(dataroot.DefaultRecordPath, rec); err != nil {
		return fmt.Errorf("install: write the data volume record %s: %w", dataroot.DefaultRecordPath, err)
	}
	if plan.Created {
		added, err := datavol.EnsureFstabLine(fsys, dataroot.FstabPath, rec.UUID, rec.Mountpoint)
		if err != nil {
			return fmt.Errorf("install: declare the data volume in %s: %w", dataroot.FstabPath, err)
		}
		logger.Info("data volume declared", "record", dataroot.DefaultRecordPath, "fstab", dataroot.FstabPath, "added", added)
	}
	return nil
}

// migrateDataRoot moves an existing plain data root onto the freshly created
// volume, with the daemons stopped for the duration.
//
// Every error it returns names what is on disk, because that is the only
// question an operator has at that moment. Nothing here deletes the data root:
// a failed copy takes the new volume with it and leaves the root untouched, and
// a successful one renames the root aside to <dir>.pre-volume.
func migrateDataRoot(ctx context.Context, sys System, cfg Config, m []artifact, rec dataroot.Record) error {
	// Checked BEFORE the daemons go down, not inside Migrate, so a refusal costs
	// no downtime: an encrypted volume beside a plaintext copy of the same
	// secrets is not encryption, and the operator has to decide, not be told
	// after their cluster stopped.
	if rec.Encrypted && !cfg.RemoveOldDataRoot {
		return fmt.Errorf("install: data volume %s: %w (pass --remove-old-data-root)", rec.Name, datavol.ErrEncryptedNeedsRemoveOld)
	}

	staging := cfg.datavolStaging()
	if err := bootoutDaemons(ctx, sys, m, cfg.Logger); err != nil {
		return fmt.Errorf("install: stop the daemons before migrating the data root: %w", err)
	}
	if err := sys.EnsureRootDir(staging, datavolStagingMode); err != nil {
		return fmt.Errorf("install: create the migration staging mount point %s: %w", staging, err)
	}

	stats, err := datavol.Migrate(ctx, cfg.DataVolumeDeps, cfg.DataRootFS, sys, rec, cfg.DataRoot, staging, datavol.MigrateOptions{RemoveOld: cfg.RemoveOldDataRoot})
	if err != nil {
		if errors.Is(err, datavol.ErrPreVolumeExists) {
			return fmt.Errorf("install: migrate the data root %s: %w (move %s aside and re-run `sudo k3sm install --data-volume`)", cfg.DataRoot, err, cfg.DataRoot+datavol.PreVolumeSuffix)
		}
		return fmt.Errorf("install: migrate the data root %s: %w (nothing changed; the daemons are down, run 'sudo k3sm install' to restart them)", cfg.DataRoot, err)
	}
	// The staging mount point is an empty directory now that the volume has been
	// unmounted from it; leaving it would look like a half-finished migration.
	if err := sys.RemoveTree(staging); err != nil {
		return fmt.Errorf("install: remove the migration staging mount point %s: %w", staging, err)
	}
	cfg.Logger.Info("migrated data root", "from", cfg.DataRoot, "volume", rec.Name,
		"files", stats.Files, "bytes", datavol.FormatSize(stats.Bytes),
		"copy", stats.CopyDuration.Round(timeRounding), "verify", stats.VerifyDuration.Round(timeRounding),
		"kept", preVolumeClause(cfg))
	return nil
}

// datavolStagingMode is the staging mount point's mode: root-owned, root-only.
// The data being copied through it is the whole datastore, and it is nobody
// else's business for the minutes it takes.
const datavolStagingMode fs.FileMode = 0o700

// preVolumeClause names what the migration left beside the data root, so the
// log line an operator reads says whether they still have a rollback.
func preVolumeClause(cfg Config) string {
	if cfg.RemoveOldDataRoot {
		return "nothing (--remove-old-data-root)"
	}
	return cfg.DataRoot + datavol.PreVolumeSuffix
}

// dataRootHasContent reports whether the data root holds anything a migration
// would have to carry across. k3sm's own provenance marker does not count: a
// volume k3sm previously mounted here and then lost carries one, and treating
// that as content would copy a marker onto itself.
func dataRootHasContent(fsys dataroot.FS, dir string) (bool, error) {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("read the data root %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.Name() != datavol.MarkerName {
			return true, nil
		}
	}
	return false, nil
}

// DatavolPlist renders the io.k3sm.datavol LaunchDaemon plist: root (no
// UserName), execing `k3sm datavol mount`.
//
// It is a ONESHOT, and the two keys that say so are the whole design. RunAtLoad
// runs it at boot; KeepAliveOnFailure ({SuccessfulExit: false}) means launchd
// relaunches it only if it exits non-zero, so a successful mount ends the job
// instead of respawning it forever. ThrottleInterval bounds how fast a failing
// mount is retried, on top of the in-process retry MountRecorded already does
// for early-boot disk arbitration.
//
// The boot contract it implements, stated plainly: launchd offers NO ordering
// between jobs, so netd and the server may well start before the volume is
// mounted. They refuse a declared-but-unmounted data root and are relaunched at
// launchd's throttle until the mount lands, which costs an expected zero or one
// refusal per boot. A mount that never lands shows up as a failed datavol row
// and a not-mounted data root in `k3sm status`.
func DatavolPlist(cfg Config) []byte {
	cfg = cfg.withDefaults()
	return renderPlist(launchdPlist{
		Label:              DatavolLabel,
		ProgramArguments:   []string{cfg.installedBinary(), "datavol", "mount"},
		RunAtLoad:          true,
		KeepAliveOnFailure: true,
		ThrottleInterval:   datavolThrottleSeconds,
		StdoutPath:         DatavolLogPath(),
		StderrPath:         DatavolLogPath(),
		// No UserName: mounting a volume is root's.
	})
}

// datavolThrottleSeconds is launchd's minimum interval between spawns of the
// mount oneshot. Ten seconds is launchd's own default, stated explicitly
// because this job's relaunch cadence is part of the boot contract above rather
// than an inherited default nobody chose.
const datavolThrottleSeconds = 10

// timeRounding is the precision the migration's durations are logged at. A
// migration takes minutes; microseconds in the log are noise.
const timeRounding = 10 * time.Millisecond
