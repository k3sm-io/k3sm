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

package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Operator-driven datastore snapshots — the library behind `k3sm snapshot save` and
// `k3sm snapshot restore`.
//
// This is the on-demand sibling of the automatic pre-migration backup in
// kinemigrate.go, and it reuses that file's machinery: the sqlite3 seam, the free-space
// floor, integrityCheck, and the build-at-a-tmp-name → verify → atomic-rename discipline
// that makes "the file exists" mean "the file is complete and was proven readable".
//
// It differs from the pre-migration backup in ONE way that decides the mechanism.
// snapshotBeforeKineUpgrade runs inside provision(), BEFORE kine is started, so it has
// the whole database to itself and a plain file copy of a WAL-drained state.db is exact.
// An operator runs `k3sm snapshot save` against a LIVE cluster, where kine is writing
// throughout: a TRUNCATE checkpoint followed by a copy is then not consistent, because
// every commit landing between the checkpoint and the last byte of the copy lands in a
// file the copy has already passed. So the copy itself is delegated to SQLite —
// `VACUUM INTO`, which runs inside a read transaction and therefore writes out one
// self-consistent point-in-time image of the database whether or not a writer is active,
// and whose output is a single file with no WAL to leave behind. The TRUNCATE checkpoint
// is still run first, best-effort, because on a quiescent datastore it leaves the source
// in the canonical drained state the pre-migration path guarantees; but a busy checkpoint
// is NOT a failure here, because `VACUUM INTO` reads the write-ahead log too and does not
// depend on the drain.
//
// Scope: the single-node kine→SQLite datastore only. On the HA/Postgres posture the state
// of record is the operator's Postgres, which this command cannot see, let alone restore;
// it refuses (ErrSnapshotExternalDatastore) and names pg_dump.

// Snapshot failures. Each is a typed sentinel (errors.Is-comparable) so the CLI can turn
// it into an actionable message and a non-zero exit without string matching.
var (
	// ErrSnapshotExternalDatastore reports a save/restore attempted on a node whose
	// state of record is an external (Postgres) datastore. Refusing is the feature:
	// k3sm has no read of that database, and a "snapshot" of a local SQLite file on
	// such a node would be either empty or a stale pre-HA remnant presented as the
	// cluster's state.
	ErrSnapshotExternalDatastore = errors.New("executor: snapshot save/restore covers only the single-node kine→SQLite datastore, not an external (Postgres) one")
	// ErrNoDatastore reports that the work dir holds no state.db to snapshot.
	ErrNoDatastore = errors.New("executor: no kine SQLite datastore to snapshot")
	// ErrSnapshotIntegrity reports a snapshot that failed PRAGMA integrity_check. On
	// restore it is checked BEFORE anything on disk is touched, so a corrupt snapshot
	// costs an error and nothing else.
	ErrSnapshotIntegrity = errors.New("executor: snapshot failed PRAGMA integrity_check")
	// ErrControlPlaneRunning reports a restore attempted against a live control plane.
	// Swapping the datastore file under a running kine is corruption, not a restore:
	// kine holds the old file open by inode and keeps writing to it, so the restored
	// database is overwritten by the state the restore existed to discard — and the
	// unlinked original cannot be recovered.
	ErrControlPlaneRunning = errors.New("executor: a control plane is running against this datastore")
	// ErrNoRunningProbe reports a restore with no way to tell whether a control plane
	// is live. It is fail-closed for the same reason ErrNoHealthProbe is: performing
	// the destructive step blind is worse than refusing.
	ErrNoRunningProbe = errors.New("executor: restoring requires a live-control-plane probe (refusing to replace the datastore with no way to tell whether a server is running)")
	// ErrSnapshotNotFound reports a restore naming a snapshot that is not a regular file.
	ErrSnapshotNotFound = errors.New("executor: snapshot file not found")
)

// snapshotNameLayout is the timestamp in a generated snapshot's basename: UTC, sortable,
// and filesystem-safe on a case-insensitive volume.
const snapshotNameLayout = "20060102T150405Z"

// SnapshotDir is where `k3sm snapshot save` writes when no --out is given: a snapshots/
// directory beside the datastore, mirroring k3s's db/snapshots. It is deliberately on the
// same volume as the cluster it protects — which is why the CLI tells the operator to copy
// it off the node, and why an --out onto external storage is the better habit.
func SnapshotDir(workDir string) string { return filepath.Join(dbDir(workDir), "snapshots") }

// LiveControlPlaneProbe reports the control plane currently running against this node's
// datastore. It returns a human-readable description of the holder ("" when nothing is
// running) so a refusal can name what the operator has to stop. An error means the
// question could not be answered, which a restore treats as a refusal — never as "no".
type LiveControlPlaneProbe func(ctx context.Context) (holder string, err error)

// SnapshotSaveOptions parametrizes SaveSnapshot.
type SnapshotSaveOptions struct {
	// WorkDir is the control-plane state root holding db/state.db. Required.
	WorkDir string
	// DatastoreEndpoint is the server's --datastore-endpoint, when it has one. A
	// non-empty value means the state of record is external and the save refuses.
	DatastoreEndpoint string
	// Out is the destination. Empty writes a generated name into SnapshotDir; a path
	// naming an existing DIRECTORY writes a generated name inside it; anything else is
	// taken as the exact file to write.
	Out string
}

// SnapshotSaveResult is what a save produced.
type SnapshotSaveResult struct {
	// Path is the snapshot that now exists, Bytes its size.
	Path  string
	Bytes int64
	// SourceDB is the datastore it was taken from, TakenAt when.
	SourceDB string
	TakenAt  time.Time
	// Checkpointed reports whether the pre-copy TRUNCATE checkpoint drained the
	// source's write-ahead log. False is normal on a live cluster (a writer held the
	// log) and does NOT weaken the snapshot: VACUUM INTO reads the WAL. CheckpointNote
	// carries why, for the report.
	Checkpointed   bool
	CheckpointNote string
}

// SnapshotRestoreOptions parametrizes RestoreSnapshot.
type SnapshotRestoreOptions struct {
	// WorkDir is the control-plane state root whose db/state.db is replaced. Required.
	WorkDir string
	// DatastoreEndpoint is the server's --datastore-endpoint, when it has one.
	DatastoreEndpoint string
	// Snapshot is the file to restore. Required.
	Snapshot string
	// Running is the live-control-plane probe. Required: nil is ErrNoRunningProbe.
	Running LiveControlPlaneProbe
}

// SnapshotRestoreResult is what a restore did, in the order it did it.
type SnapshotRestoreResult struct {
	// Snapshot is the file restored, Bytes its size, RestoredDB where it now lives.
	Snapshot   string
	Bytes      int64
	RestoredDB string
	// PreviousDB is the superseded datastore, preserved (never deleted) — empty when
	// the work dir had no datastore to preserve. MovedAside lists everything else that
	// was relocated with it: the -wal/-shm sidecars, whose survival beside a restored
	// database is exactly how a "successful" restore comes back with the old state,
	// and the kine pin stamp, which describes a database that is no longer there.
	PreviousDB string
	MovedAside []string
}

// SaveSnapshot writes a consistent, integrity-verified copy of this node's kine SQLite
// datastore, and returns where it put it.
//
// The order is fail-closed throughout: refuse an external datastore, refuse an absent
// datastore, refuse a volume without room, and only then write anything. The snapshot is
// built at a .tmp name, integrity-checked there, and renamed into place, so a snapshot
// that exists under its final name is one that has been proven readable as a database —
// never a truncated file left by a full volume or an interrupted command.
func SaveSnapshot(ctx context.Context, opts SnapshotSaveOptions) (*SnapshotSaveResult, error) {
	if opts.WorkDir == "" {
		return nil, errors.New("executor: snapshot save requires a work dir")
	}
	if err := requireLocalDatastore(opts.WorkDir, opts.DatastoreEndpoint); err != nil {
		return nil, err
	}
	db := StateDBPath(opts.WorkDir)
	fi, err := os.Stat(db)
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not exist (a node that has never run a control plane has no state to snapshot)", ErrNoDatastore, db)
	}

	takenAt := time.Now().UTC()
	out, err := resolveSnapshotOut(opts.WorkDir, opts.Out, takenAt)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	// The floor is measured on the DESTINATION volume, which is the one the write can
	// fill — an --out onto external storage moves the constraint with it.
	if err := requireFreeSpace(filepath.Dir(out), uint64(fi.Size())*snapshotFreeSpaceFactor); err != nil {
		return nil, err
	}

	res := &SnapshotSaveResult{Path: out, SourceDB: db, TakenAt: takenAt}
	// Best-effort drain: exact on a stopped control plane, declined by a live writer.
	// Either way VACUUM INTO below reads the WAL, so this decides the source's tidiness,
	// never the snapshot's completeness.
	if err := checkpointTruncate(ctx, db); err != nil {
		res.CheckpointNote = err.Error()
	} else if err := requireWALDrained(db); err != nil {
		res.CheckpointNote = err.Error()
	} else {
		res.Checkpointed = true
	}

	tmp := out + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clear stale partial snapshot %s: %w", tmp, err)
	}
	if err := vacuumInto(ctx, db, tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := setWALMode(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	if err := integrityCheck(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("%w: the snapshot just taken from %s is not readable as a database: %w", ErrSnapshotIntegrity, db, err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("tighten snapshot permissions: %w", err)
	}
	if err := os.Rename(tmp, out); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("install snapshot %s: %w", out, err)
	}
	if sfi, err := os.Stat(out); err == nil {
		res.Bytes = sfi.Size()
	}
	return res, nil
}

// RestoreSnapshot replaces this node's datastore with a snapshot, preserving the
// superseded one.
//
// Everything that can refuse, refuses before anything on disk moves: an external
// datastore, a running control plane, a snapshot that fails integrity_check, a volume
// without room, and a copy whose ownership cannot be made to match the datastore it
// replaces. The destructive window is then two renames wide — the old datastore aside,
// the verified copy into place — and the old datastore is MOVED, never deleted, so the
// state a mistaken restore discarded is still on disk under its .bak name.
func RestoreSnapshot(ctx context.Context, opts SnapshotRestoreOptions) (*SnapshotRestoreResult, error) {
	if opts.WorkDir == "" {
		return nil, errors.New("executor: snapshot restore requires a work dir")
	}
	if opts.Snapshot == "" {
		return nil, errors.New("executor: snapshot restore requires a snapshot to restore")
	}
	if err := requireLocalDatastore(opts.WorkDir, opts.DatastoreEndpoint); err != nil {
		return nil, err
	}
	if opts.Running == nil {
		return nil, ErrNoRunningProbe
	}
	holder, err := opts.Running(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: could not determine whether a control plane is running (refusing to replace the datastore blind): %w", ErrControlPlaneRunning, err)
	}
	if holder != "" {
		return nil, fmt.Errorf("%w: %s — stop the control plane and re-run; swapping the datastore under a running kine corrupts it (kine keeps writing to the file it already holds open)", ErrControlPlaneRunning, holder)
	}

	fi, err := os.Stat(opts.Snapshot)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrSnapshotNotFound, opts.Snapshot, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrSnapshotNotFound, opts.Snapshot)
	}
	// VERIFY FIRST — before the datastore is touched. A restore that discovers the
	// snapshot is corrupt only after moving the live database aside has destroyed the
	// one copy of the state that was still good.
	if err := integrityCheck(ctx, opts.Snapshot); err != nil {
		return nil, fmt.Errorf("%w: %s — nothing was changed: %w", ErrSnapshotIntegrity, opts.Snapshot, err)
	}

	dbd := dbDir(opts.WorkDir)
	if err := os.MkdirAll(dbd, 0o755); err != nil {
		return nil, fmt.Errorf("create datastore dir: %w", err)
	}
	if err := requireFreeSpace(dbd, uint64(fi.Size())*snapshotFreeSpaceFactor); err != nil {
		return nil, err
	}

	db := StateDBPath(opts.WorkDir)
	res := &SnapshotRestoreResult{Snapshot: opts.Snapshot, Bytes: fi.Size(), RestoredDB: db}

	// Stage the replacement first: copy, verify the COPY (the same rule the snapshot
	// itself was written under — the bytes that take the final name are the bytes that
	// were checked), and give it the datastore's ownership. A failure here aborts with
	// the live datastore untouched.
	tmp := db + ".restoring.tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("clear stale partial restore %s: %w", tmp, err)
	}
	if err := copyFile(opts.Snapshot, tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("copy snapshot into the datastore dir: %w", err)
	}
	if err := integrityCheck(ctx, tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("%w: the copy of %s did not verify — nothing was changed: %w", ErrSnapshotIntegrity, opts.Snapshot, err)
	}
	if err := inheritDatastoreOwner(db, tmp); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}

	// Move the superseded datastore aside, sidecars and pin stamp with it.
	stamp := time.Now().UTC().Format(snapshotNameLayout)
	bak := db + ".restore-" + stamp + ".bak"
	if fileExists(db) {
		if err := os.Rename(db, bak); err != nil {
			_ = os.Remove(tmp)
			return nil, fmt.Errorf("preserve the superseded datastore as %s: %w", bak, err)
		}
		res.PreviousDB = bak
	}
	// A -wal/-shm left beside the restored file belongs to the database that was just
	// moved away; SQLite would replay it over the restored state. The kine pin stamp
	// describes that same superseded file, and leaving it would tell the next boot that
	// the current pin has already opened THIS database — suppressing the automatic
	// pre-migration backup for a database it never saw.
	for _, side := range []struct{ from, to string }{
		{db + "-wal", bak + "-wal"},
		{db + "-shm", bak + "-shm"},
		{kinePinStampPath(opts.WorkDir), bak + "-kine-pin"},
	} {
		if !fileExists(side.from) {
			continue
		}
		if err := os.Rename(side.from, side.to); err != nil {
			return res, fmt.Errorf("move %s aside (it would be replayed over the restored datastore): %w", side.from, err)
		}
		res.MovedAside = append(res.MovedAside, side.to)
	}

	if err := os.Rename(tmp, db); err != nil {
		installErr := fmt.Errorf("install the restored datastore at %s: %w", db, err)
		if res.PreviousDB != "" {
			if back := os.Rename(res.PreviousDB, db); back != nil {
				return res, fmt.Errorf("%w — AND the superseded datastore could not be put back (it is at %s): %w", installErr, res.PreviousDB, back)
			}
			res.PreviousDB = ""
		}
		return res, installErr
	}
	return res, nil
}

// ControlPlanePortProbe reports a live control plane by its loopback listeners: the kine
// datastore port and the apiserver's secure port.
//
// Ports are the probe that works for EVERY posture — the launchd daemon, a foreground
// `k3sm server`, and a `k3sm dev` cluster — because all three must hold them. It is the
// same bind test preflightDatastorePort uses and it fails the same way: any bind error
// at all reads as held, because a port this process cannot take is a port that something
// is doing something with, and a restore is not the place to guess. lsof names the holder
// when it can; the refusal never depends on it.
func ControlPlanePortProbe(kinePort, apiServerPort int) LiveControlPlaneProbe {
	return func(ctx context.Context) (string, error) {
		for _, p := range []struct {
			what string
			port int
		}{
			{"the kine datastore port", kinePort},
			{"the apiserver port", apiServerPort},
		} {
			if p.port <= 0 {
				continue
			}
			if holder, held := portHeld(ctx, p.port); held {
				return fmt.Sprintf("%s 127.0.0.1:%d is held by %s", p.what, p.port, holder), nil
			}
		}
		return "", nil
	}
}

// portHeld reports whether something holds port on loopback, and names it if lsof can.
func portHeld(ctx context.Context, port int) (string, bool) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err == nil {
		_ = ln.Close()
		return "", false
	}
	holder := portHolder(ctx, port)
	if holder == "" {
		holder = "an unidentified process"
	}
	return holder, true
}

// requireLocalDatastore refuses when this node's state of record is not the local kine
// SQLite file.
//
// Two signals, both fail-closed. The endpoint (the server's --datastore-endpoint /
// $K3SM_DATASTORE_ENDPOINT) is the direct one. The .pgpass file is the on-disk residue of
// a Postgres posture — the executor writes it so the DSN password never reaches kine's
// argv — and it is treated as decisive even when a state.db is present, because a node
// that moved from single-node to HA keeps its now-abandoned SQLite file, and snapshotting
// THAT would hand the operator a stale database labelled as the cluster's state. The
// error names the way out for the false positive (a leftover .pgpass on a node that no
// longer uses Postgres).
func requireLocalDatastore(workDir, endpoint string) error {
	if endpoint != "" {
		return fmt.Errorf("%w: this server's datastore is %s — back it up with pg_dump (and restore with pg_restore/psql) on your Postgres schedule; see docs/user/ha.md",
			ErrSnapshotExternalDatastore, redactDatastoreEndpoint(endpoint))
	}
	if pg := pgPassPath(workDir); fileExists(pg) {
		return fmt.Errorf("%w: %s holds a Postgres password file, so this node serves an external datastore — back it up with pg_dump on your Postgres schedule (if this node no longer uses Postgres, remove %s and re-run)",
			ErrSnapshotExternalDatastore, workDir, pg)
	}
	return nil
}

// redactDatastoreEndpoint renders a datastore DSN for an error message with the password
// removed. A CLI error is echoed into terminals, logs, and issue reports; the credential
// in it is the operator's Postgres password.
func redactDatastoreEndpoint(dsn string) string {
	sanitized, _, err := splitDatastorePassword(dsn)
	if err != nil {
		// Unparseable: say so rather than echo an unredacted string that may carry a
		// password in a shape this function does not understand.
		return "an external datastore (endpoint withheld: it did not parse as a DSN)"
	}
	return sanitized
}

// resolveSnapshotOut decides where a save writes: the default snapshots dir, inside a
// directory the operator named, or the exact file they named.
func resolveSnapshotOut(workDir, out string, at time.Time) (string, error) {
	name := "k3sm-snapshot-" + at.Format(snapshotNameLayout) + ".db"
	if out == "" {
		return filepath.Join(SnapshotDir(workDir), name), nil
	}
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		return filepath.Join(out, name), nil
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("resolve --out %s: %w", out, err)
	}
	return abs, nil
}

// vacuumInto writes a consistent point-in-time image of db to dst.
//
// `VACUUM INTO` is SQLite's own online-backup statement: it runs inside a read
// transaction, so under WAL it neither blocks a writer nor is torn by one, and the file
// it produces is a complete single-file database — no WAL, no -shm, nothing to replay.
// That is the property a live snapshot needs and that checkpoint-then-copy does not have
// while kine is writing. dst must not exist (SQLite refuses to overwrite), which is why
// the caller builds at a .tmp name it has just cleared.
func vacuumInto(ctx context.Context, db, dst string) error {
	if _, err := sqlite3(ctx, db, "VACUUM INTO '"+strings.ReplaceAll(dst, "'", "''")+"';"); err != nil {
		return fmt.Errorf("take a consistent snapshot of %s: %w", db, err)
	}
	return nil
}

// setWALMode puts a freshly written snapshot into WAL journal mode.
//
// VACUUM INTO emits a database in the default ROLLBACK-JOURNAL mode regardless of the
// source's mode, and the restored file becomes the live datastore. kine's DSN would
// convert it back to WAL on the next boot, so this is not a correctness fix — it is a
// truthfulness one: `k3sm doctor` reports the datastore's journal mode, backup-restore.md
// tells the operator that a restored datastore reporting a non-WAL journal is a reason to
// STOP, and a snapshot that trips that check by construction would burn exactly the signal
// the restore drill depends on.
//
// The mode is a header flag, so it survives the close; the -wal the switch creates is
// checkpointed and removed when the CLI's connection closes cleanly, leaving the
// single-file database integrityCheck then verifies as immutable.
func setWALMode(ctx context.Context, db string) error {
	out, err := sqlite3(ctx, db, "PRAGMA journal_mode=WAL;")
	if err != nil {
		return fmt.Errorf("set the snapshot's journal mode: %w", err)
	}
	if got := strings.ToLower(strings.TrimSpace(out)); got != "wal" {
		return fmt.Errorf("snapshot %s did not take WAL journal mode (PRAGMA reported %q)", db, got)
	}
	return nil
}

// inheritDatastoreOwner gives the staged replacement the ownership of the datastore it
// replaces, so a restore run under sudo does not hand the unprivileged control-plane user
// a root-owned state.db it cannot write — a cluster that comes back read-only-broken with
// no error at restore time. A work dir with no current datastore has no owner to inherit
// and is left as this process created it.
func inheritDatastoreOwner(db, staged string) error {
	fi, err := os.Stat(db)
	if err != nil {
		return nil // nothing to inherit from
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	sfi, err := os.Stat(staged)
	if err != nil {
		return fmt.Errorf("stat the staged datastore: %w", err)
	}
	if sst, ok := sfi.Sys().(*syscall.Stat_t); ok && sst.Uid == st.Uid && sst.Gid == st.Gid {
		return nil
	}
	if err := os.Chown(staged, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("give the restored datastore the ownership of %s (uid %d gid %d) — the control plane runs as that user and could not write a datastore owned by anyone else; re-run with sudo: %w",
			db, st.Uid, st.Gid, err)
	}
	return nil
}
