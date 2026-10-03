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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// snapshotUsage is the `k3sm snapshot` help text. It states the single-node scope up
// front: an operator on the etcd HA posture must be told what this command does not
// cover before they run it, not after.
const snapshotUsage = `Usage: k3sm snapshot save    [--out <path>] [--work-dir <dir>]
       k3sm snapshot restore <snapshot> [--work-dir <dir>]

Back up and restore this node's datastore — the control plane's state of record:
the kine SQLite datastore on a single server, the embedded etcd member on an HA
server.

  save     write a consistent, integrity-verified copy of the datastore. Safe to run
           while the control plane is serving (the copy is taken by SQLite inside a
           read transaction, so a concurrent write cannot tear it).
  restore  replace the datastore with a snapshot. REFUSES while a control plane is
           running, and verifies the snapshot BEFORE touching anything; the datastore
           it supersedes is preserved beside it as a .bak, never deleted.

Flags:
  --work-dir <dir>  control-plane state root (default: this posture's work dir)
  --out <path>      save: the snapshot file, or a directory to name one in
                    (default: %s under the work dir)

On an embedded etcd HA server, save streams an online snapshot of this server's
etcd member (no member is stopped and no quorum is spent), verifies it, and writes
it 0600: it holds every Secret in plaintext. Restoring an etcd member is not
supported in this release; restore refuses there.

PersistentVolume data is NOT in a snapshot: it lives in local-path directories on each
node and is backed up separately. See docs/user/backup-restore.md.
`

// runSnapshot dispatches the `k3sm snapshot` subcommands.
func runSnapshot(args []string) error {
	if len(args) == 0 {
		return errors.New(snapshotHelp())
	}
	switch args[0] {
	case "save":
		return runSnapshotSave(args[1:])
	case "restore":
		return runSnapshotRestore(args[1:])
	case "-h", "--help", "help":
		fmt.Print(snapshotHelp())
		return nil
	default:
		return fmt.Errorf("unknown snapshot subcommand %q (want: save, restore)", args[0])
	}
}

// snapshotHelp renders the usage with the default snapshot location filled in.
func snapshotHelp() string {
	return fmt.Sprintf(snapshotUsage, filepath.Join("db", "snapshots"))
}

// snapshotWorkDirFlag registers the posture-aware --work-dir on fs. A resolve failure
// falls back to the root-posture const, which the operator can override — the same
// treatment `k3sm certificate rotate` and `k3sm doctor` give it.
func snapshotWorkDirFlag(fs *flag.FlagSet) *string {
	def, err := executor.ResolveWorkDir()
	if err != nil {
		def = executor.DefaultWorkDir
	}
	return fs.String("work-dir", def, "control-plane state root (the kine state.db or the etcd member lives here)")
}

// runSnapshotSave parses the flags and writes the snapshot.
func runSnapshotSave(args []string) error {
	fs := flag.NewFlagSet("snapshot save", flag.ExitOnError)
	workDir := snapshotWorkDirFlag(fs)
	out := fs.String("out", "", "snapshot destination: a file, or a directory to name one in (default: db/snapshots under the work dir)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("snapshot save takes no positional arguments (got %q); the destination is --out", fs.Arg(0))
	}

	return saveSnapshot(context.Background(), os.Stdout, *workDir, *out, defaultSnapshotSavers())
}

// snapshotSavers are the two save paths and the posture test that picks one; seams so
// the dispatch is testable without a datastore.
type snapshotSavers struct {
	etcdMember func(workDir string) bool
	etcd       func(ctx context.Context, workDir, dst string) error
	sqlite     func(ctx context.Context, opts executor.SnapshotSaveOptions) (*executor.SnapshotSaveResult, error)
	now        func() time.Time
}

func defaultSnapshotSavers() snapshotSavers {
	return snapshotSavers{
		etcdMember: executor.EtcdMemberExists,
		etcd:       executor.SnapshotEtcd,
		sqlite:     executor.SaveSnapshot,
		now:        time.Now,
	}
}

// saveSnapshot takes the snapshot the work dir's posture calls for: an online,
// verified etcd snapshot when the work dir holds an etcd member, the kine SQLite
// snapshot otherwise.
func saveSnapshot(ctx context.Context, w io.Writer, workDir, out string, s snapshotSavers) error {
	if s.etcdMember(workDir) {
		dst, err := etcdSnapshotDest(workDir, out, s.now().UTC())
		if err != nil {
			return err
		}
		if err := s.etcd(ctx, workDir, dst); err != nil {
			return annotateSnapshotError(err, workDir)
		}
		renderEtcdSnapshotSave(w, dst)
		return nil
	}
	res, err := s.sqlite(ctx, executor.SnapshotSaveOptions{WorkDir: workDir, Out: out})
	if err != nil {
		return annotateSnapshotError(err, workDir)
	}
	renderSnapshotSave(w, res)
	return nil
}

// etcdSnapshotLayout stamps an etcd snapshot's default name, matching the kine one.
const etcdSnapshotLayout = "20060102T150405Z"

// etcdSnapshotDest decides where an etcd save writes: the default snapshots dir
// (created 0700), inside a directory the operator named, or the exact file named.
func etcdSnapshotDest(workDir, out string, at time.Time) (string, error) {
	name := "k3sm-etcd-snapshot-" + at.Format(etcdSnapshotLayout) + ".db"
	if out == "" {
		dir := executor.SnapshotDir(workDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create %s: %w", dir, err)
		}
		return filepath.Join(dir, name), nil
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

// renderEtcdSnapshotSave prints what an etcd save produced.
func renderEtcdSnapshotSave(w io.Writer, path string) {
	fmt.Fprintf(w, "k3sm snapshot save — embedded etcd member\n\n")
	fmt.Fprintf(w, "  snapshot   %s\n", path)
	if fi, err := os.Stat(path); err == nil {
		fmt.Fprintf(w, "  size       %d bytes\n", fi.Size())
	}
	fmt.Fprint(w, `
Taken online from this server's etcd member and verified. It holds every Secret in
plaintext: keep it 0600 and copy it OFF this node. Restoring an etcd member is not
supported in this release.

PersistentVolume data is NOT in this snapshot — see docs/user/storage.md.
`)
}

// runSnapshotRestore parses the flags, wires the live-control-plane probe, and restores.
func runSnapshotRestore(args []string) error {
	fs := flag.NewFlagSet("snapshot restore", flag.ExitOnError)
	workDir := snapshotWorkDirFlag(fs)
	apiPort := fs.Int("apiserver-port", executor.DefaultAPIServerPort, "apiserver secure port the running-server check probes")
	kinePort := fs.Int("datastore-port", executor.DefaultKinePort, "kine listen port the running-server check probes")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("snapshot restore takes exactly one argument, the snapshot to restore (got %d)\n\n%s", fs.NArg(), snapshotHelp())
	}

	res, err := executor.RestoreSnapshot(context.Background(), executor.SnapshotRestoreOptions{
		WorkDir:  *workDir,
		Snapshot: fs.Arg(0),
		Running:  liveControlPlaneProbe(install.NewDarwinSystem(), install.ServerLabel, *kinePort, *apiPort),
	})
	if err != nil {
		return annotateSnapshotError(err, *workDir)
	}
	renderSnapshotRestore(os.Stdout, res)
	return nil
}

// servicePIDReader reads the pid launchd has for a label. It is the read-only half of
// install.System, declared here at the consumer so the probe is testable with a fake.
type servicePIDReader interface {
	LaunchctlServicePID(label string) (int, error)
}

// liveControlPlaneProbe reports a running control plane, from two independent signals.
//
// launchd first: it names the daemon and its pid, which is the answer an operator can
// act on ("bootout that job"). Ports second, because launchd knows nothing about a
// foreground `k3sm server` or a `k3sm dev` cluster — both of which hold the datastore
// just as firmly. Either signal alone is a refusal; only both silent is a "no".
//
// A launchd error (the usual one being "the job is not loaded") is NOT a refusal: on a
// node that never ran `k3sm install` it is the normal answer, and treating it as
// "running" would make restore impossible there. The port probe is what stays honest in
// that case, and IT fails closed.
func liveControlPlaneProbe(sys servicePIDReader, label string, kinePort, apiPort int) executor.LiveControlPlaneProbe {
	ports := executor.ControlPlanePortProbe(kinePort, apiPort)
	return func(ctx context.Context) (string, error) {
		if sys != nil {
			if pid, err := sys.LaunchctlServicePID(label); err == nil && pid > 0 {
				return fmt.Sprintf("the %s launchd job is running (pid %d)", label, pid), nil
			}
		}
		return ports(ctx)
	}
}

// annotateSnapshotError turns a typed snapshot failure into an actionable one, binding
// the launchd label and the log path this command's callers need. The wrapped error is
// preserved with %w so errors.Is still works.
func annotateSnapshotError(err error, workDir string) error {
	switch {
	case errors.Is(err, executor.ErrControlPlaneRunning):
		return fmt.Errorf("%w\n\nStop it first:\n  sudo launchctl bootout system/%s\nand start it again after the restore:\n  sudo launchctl bootstrap system %s",
			err, install.ServerLabel, filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist"))
	case errors.Is(err, executor.ErrNoDatastore):
		return fmt.Errorf("%w — if the control plane keeps its state somewhere else, point --work-dir at it; that state root is owned by the %s service user, so `sudo k3sm snapshot save` may be what you want",
			err, install.DefaultServiceUser)
	case errors.Is(err, executor.ErrNoEtcdClient):
		return fmt.Errorf("%w — the etcd snapshot is taken from the running server's member, whose loopback address that server records under %s; start the server, and run the command under sudo (the work dir is the %s service user's)",
			err, workDir, install.DefaultServiceUser)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%w — the datastore under %s is not accessible as this user; it is owned by the %s service user, so run the command under sudo",
			err, workDir, install.DefaultServiceUser)
	}
	return err
}

// renderSnapshotSave prints what the save produced. The off-node reminder is not
// decoration: the default location is the same volume as the cluster it protects, so a
// snapshot that stays there does not survive the failure most likely to need it.
func renderSnapshotSave(w io.Writer, res *executor.SnapshotSaveResult) {
	fmt.Fprintf(w, "k3sm snapshot save — %s\n\n", res.SourceDB)
	fmt.Fprintf(w, "  snapshot   %s\n", res.Path)
	fmt.Fprintf(w, "  size       %d bytes\n", res.Bytes)
	fmt.Fprintf(w, "  taken at   %s\n", res.TakenAt.Format("2006-01-02 15:04:05 UTC"))
	if res.Checkpointed {
		fmt.Fprint(w, "  source     write-ahead log checkpointed and drained\n")
	} else {
		fmt.Fprintf(w, "  source     write-ahead log not drained (%s)\n", res.CheckpointNote)
		fmt.Fprint(w, "             — expected while the control plane is serving; the snapshot is a\n")
		fmt.Fprint(w, "               consistent point-in-time image either way, and its integrity was verified\n")
	}
	fmt.Fprintf(w, `
Copy it OFF this node — another disk or another host. It is written on the same
volume as the cluster it protects, which does not survive losing that volume.

Restore it with (control plane stopped):
  k3sm snapshot restore %s

PersistentVolume data is NOT in this snapshot — see docs/user/storage.md.
`, res.Path)
}

// renderSnapshotRestore prints what the restore did AND the verification step. The
// verification is part of the output on purpose: a restore that starts the daemon is not
// a restore that worked, and the operator running this at 3 AM should not have to go find
// the doc that says so.
func renderSnapshotRestore(w io.Writer, res *executor.SnapshotRestoreResult) {
	fmt.Fprintf(w, "k3sm snapshot restore — %s\n\n", res.Snapshot)
	fmt.Fprintf(w, "  restored   %s (%d bytes)\n", res.RestoredDB, res.Bytes)
	if res.PreviousDB != "" {
		fmt.Fprintf(w, "  preserved  %s (the datastore you replaced — NOT deleted)\n", res.PreviousDB)
	} else {
		fmt.Fprint(w, "  preserved  nothing — the work dir held no datastore to replace\n")
	}
	for _, m := range res.MovedAside {
		fmt.Fprintf(w, "  moved      %s\n", m)
	}
	kept := "the .bak beside it"
	if res.PreviousDB != "" {
		kept = res.PreviousDB
	}
	fmt.Fprintf(w, `
Next:

1. Start the control plane:
     sudo launchctl bootstrap system %s

2. VERIFY the restore — do not skip this. A restore that starts the daemon is not a
   restore that worked; check that the API server serves AND that the objects you
   expected came back:
     k3sm kubectl get --raw='/readyz?verbose'    # every check ok
     k3sm kubectl get nodes                      # your node(s), Ready
     k3sm kubectl get pods -A                    # the workloads the snapshot should hold
     k3sm doctor                                 # datastore: journal_mode=wal, kine pin

3. If objects are missing or the datastore check reports a non-WAL journal, stop and
   keep %s — it is the state you replaced, and the only copy of it.
`, filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist"), kept)
}
