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
	"strconv"
	"time"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// snapshotUsage is the `k3sm snapshot` help text. It states the single-node scope up
// front: an operator on the etcd HA posture must be told what this command does not
// cover before they run it, not after.
const snapshotUsage = `Usage: k3sm snapshot save    [--out <path>] [--work-dir <dir>]
       k3sm snapshot restore <snapshot> [--work-dir <dir>]
                             [--node-name <name>] [--etcd-peer-ip <ip>] [--etcd-peer-port <port>]

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
  --work-dir <dir>        control-plane state root (default: this posture's work dir)
  --out <path>            save: the snapshot file, or a directory to name one in
                          (default: %s under the work dir)
  --node-name <name>      restore, etcd: this server's member name
  --etcd-peer-ip <ip>     restore, etcd: this server's etcd peer address
  --etcd-peer-port <port> restore, etcd: this server's etcd peer port
                          (all three default to the installed server's own flags)

On an embedded etcd HA server, save streams an online snapshot of this server's
etcd member (no member is stopped and no quorum is spent), verifies it, and writes
it 0600: it holds every Secret in plaintext. Restore, with the server stopped,
rebuilds this server as the ONLY member of a new etcd cluster holding the
snapshot's data, and moves the old etcd data dir aside; every other server then
re-joins as a fresh member with its etcd data dir wiped.

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
plaintext: keep it 0600 and copy it OFF this node. Restore it with (server stopped):
  k3sm snapshot restore <the file>

PersistentVolume data is NOT in this snapshot — see docs/user/storage.md.
`)
}

// runSnapshotRestore parses the flags, decides the posture, and restores.
func runSnapshotRestore(args []string) error {
	fs := flag.NewFlagSet("snapshot restore", flag.ExitOnError)
	workDir := snapshotWorkDirFlag(fs)
	apiPort := fs.Int("apiserver-port", executor.DefaultAPIServerPort, "apiserver secure port the running-server check probes")
	kinePort := fs.Int("datastore-port", executor.DefaultKinePort, "kine listen port (the etcd client port on an etcd server) the running-server check probes")
	nodeName := fs.String("node-name", "", "etcd: this server's member name (default: the installed server's --node-name, else this host's node name)")
	peerIP := fs.String("etcd-peer-ip", "", "etcd: this server's etcd peer address (default: the installed server's --etcd-peer-ip)")
	peerPort := fs.Int("etcd-peer-port", 0, "etcd: this server's etcd peer port (default: the installed server's --etcd-peer-port, else 2380)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("snapshot restore takes exactly one argument, the snapshot to restore (got %d)\n\n%s", fs.NArg(), snapshotHelp())
	}
	installed, err := install.InstalledServerArgs(os.ReadFile, installedPlistPath(install.ServerLabel), dataroot.DefaultServerArgsRecordPath)
	if err != nil {
		return fmt.Errorf("read the installed server's flags (the restore needs its etcd posture): %w", err)
	}
	target := resolveRestoreTarget(installed, restoreFlags{nodeName: *nodeName, peerIP: *peerIP, peerPort: *peerPort})
	sys := install.NewDarwinSystem()
	return restoreSnapshot(context.Background(), os.Stdout, restoreRequest{
		workDir: *workDir, snapshot: fs.Arg(0), target: target, kinePort: *kinePort, apiPort: *apiPort,
		payloadBinDir: installedPayloadBinDir(),
		kineProbe:     liveControlPlaneProbe(sys, install.ServerLabel, *kinePort, *apiPort),
		launchd:       launchdProbe(sys, install.ServerLabel),
	}, defaultSnapshotRestorers())
}

// restoreFlags are the etcd identity flags given on the command line ("" / 0: not
// given).
type restoreFlags struct {
	nodeName, peerIP string
	peerPort         int
}

// restoreTarget is the posture a restore runs in and, for etcd, the member identity.
type restoreTarget struct {
	// etcd is set when the server is configured as an embedded etcd member: the
	// installed server carries --cluster-init or --server-join, or --etcd-peer-ip was
	// given here.
	etcd           bool
	name, peerIP   string
	peerPort       int
	identitySource string
}

// resolveRestoreTarget decides the posture from configuration, never from whether an
// etcd member exists on disk: a rebuilt server has none and still restores. A flag
// given here wins over the installed server's.
func resolveRestoreTarget(installed []string, f restoreFlags) restoreTarget {
	t := restoreTarget{
		etcd: f.peerIP != "" || install.ServerArgBool(installed, "cluster-init") || install.ServerArgBool(installed, "server-join"),
		name: f.nodeName, peerIP: f.peerIP, peerPort: f.peerPort, identitySource: "flags",
	}
	if !t.etcd {
		return t
	}
	if t.name == "" {
		t.name = install.ServerArgValue(installed, "node-name")
	}
	if t.name == "" {
		t.name = defaultNodeName()
	}
	if t.peerIP == "" {
		t.peerIP = install.ServerArgValue(installed, "etcd-peer-ip")
		t.identitySource = "the installed server's flags"
	}
	if t.peerPort == 0 {
		if p, err := strconv.Atoi(install.ServerArgValue(installed, "etcd-peer-port")); err == nil && p > 0 {
			t.peerPort = p
		} else {
			t.peerPort = executor.DefaultEtcdPeerPort
		}
	}
	return t
}

// restoreRequest is one restore's inputs.
type restoreRequest struct {
	workDir, snapshot string
	target            restoreTarget
	kinePort, apiPort int
	payloadBinDir     string
	kineProbe         executor.LiveControlPlaneProbe
	launchd           executor.LiveControlPlaneProbe
}

// snapshotRestorers are the two restore paths; seams so the dispatch is testable.
type snapshotRestorers struct {
	etcdMember func(workDir string) bool
	etcd       func(ctx context.Context, opts executor.EtcdRestoreOptions) (*executor.EtcdRestoreResult, error)
	kine       func(ctx context.Context, opts executor.SnapshotRestoreOptions) (*executor.SnapshotRestoreResult, error)
}

func defaultSnapshotRestorers() snapshotRestorers {
	return snapshotRestorers{etcdMember: executor.EtcdMemberExists, etcd: executor.RestoreEtcdSnapshot, kine: executor.RestoreSnapshot}
}

// restoreSnapshot runs the restore the posture calls for.
func restoreSnapshot(ctx context.Context, w io.Writer, req restoreRequest, r snapshotRestorers) error {
	if req.target.etcd {
		res, err := r.etcd(ctx, executor.EtcdRestoreOptions{
			WorkDir: req.workDir, Snapshot: req.snapshot,
			Name: req.target.name, PeerIP: req.target.peerIP, PeerPort: req.target.peerPort,
			ClientPort: req.kinePort, APIServerPort: req.apiPort,
			PayloadBinDir: req.payloadBinDir, Running: req.launchd,
		})
		if err != nil {
			return annotateSnapshotError(err, req.workDir)
		}
		renderEtcdSnapshotRestore(w, res)
		return nil
	}
	if r.etcdMember(req.workDir) {
		return fmt.Errorf("%w: %s holds an etcd member, but neither the installed server nor this command names its etcd posture; pass --etcd-peer-ip <this server's LAN address> (and --node-name if it is not this host's node name)",
			executor.ErrEtcdRestoreNeedsEtcd, executor.EtcdDataDir(req.workDir))
	}
	res, err := r.kine(ctx, executor.SnapshotRestoreOptions{WorkDir: req.workDir, Snapshot: req.snapshot, Running: req.kineProbe})
	if err != nil {
		return annotateSnapshotError(err, req.workDir)
	}
	renderSnapshotRestore(w, res)
	return nil
}

// installedPayloadBinDir is the bin/ beside the running k3sm binary, where a packaged
// install staged its payload (etcdutl among it), or "" on a dev shell.
func installedPayloadBinDir() string {
	dir, err := install.ExecutableDir()
	if err != nil {
		return ""
	}
	if fi, err := os.Stat(filepath.Join(dir, "bin")); err == nil && fi.IsDir() {
		return filepath.Join(dir, "bin")
	}
	return ""
}

// renderEtcdSnapshotRestore prints what an etcd restore did and the steps that make
// it a working cluster again.
func renderEtcdSnapshotRestore(w io.Writer, res *executor.EtcdRestoreResult) {
	fmt.Fprintf(w, "k3sm snapshot restore (embedded etcd) %s\n\n", res.Snapshot)
	for _, warn := range res.Warnings {
		fmt.Fprintf(w, "  WARNING    %s\n", warn)
	}
	fmt.Fprintf(w, "  restored   %s (%d bytes of snapshot)\n", res.DataDir, res.Bytes)
	fmt.Fprintf(w, "  member     %s at %s, the only member of a NEW cluster\n", res.MemberName, res.PeerURL)
	fmt.Fprintf(w, "  revision   raised by %d and marked compacted, so every watcher relists\n", res.RevisionBump)
	if res.PreviousDataDir != "" {
		fmt.Fprintf(w, "  preserved  %s (the etcd data dir you replaced, NOT deleted)\n", res.PreviousDataDir)
	} else {
		fmt.Fprint(w, "  preserved  nothing: the work dir held no etcd data dir to replace\n")
	}
	for _, m := range res.MovedAside {
		fmt.Fprintf(w, "  moved      %s\n", m)
	}
	fmt.Fprintf(w, `
Next:

1. Start this server:
     sudo launchctl bootstrap system %s

2. VERIFY the restore before anything else joins:
     k3sm kubectl get --raw='/readyz?verbose'    # every check ok
     k3sm kubectl get nodes                      # the nodes the snapshot held
     k3sm kubectl get pods -A                    # the workloads the snapshot should hold
     k3sm status                                 # etcd: 1 voting member, leader present

3. Re-join every OTHER server as a fresh member. Their etcd data belongs to the
   cluster this restore replaced, and they refuse to start on it. On each one:
     sudo launchctl bootout system/%s
     sudo mv <its work dir>/etcd <its work dir>/etcd.pre-restore
     then start it with --server-join, --server <this server's LAN address> and the
     server token, as when it first joined.
`, filepath.Join(install.DefaultLaunchDaemonDir, install.ServerLabel+".plist"), install.ServerLabel)
}

// servicePIDReader reads the pid launchd has for a label. It is the read-only half of
// install.System, declared here at the consumer so the probe is testable with a fake.
type servicePIDReader interface {
	LaunchctlServicePID(label string) (int, error)
}

// launchdProbe reports the server's launchd job when it is running. A launchd error
// (usually "not loaded") is not a refusal: the etcd restore's own lock, port and pid
// probes stay honest in that case.
func launchdProbe(sys servicePIDReader, label string) executor.LiveControlPlaneProbe {
	return func(context.Context) (string, error) {
		if sys != nil {
			if pid, err := sys.LaunchctlServicePID(label); err == nil && pid > 0 {
				return fmt.Sprintf("the %s launchd job is running (pid %d)", label, pid), nil
			}
		}
		return "", nil
	}
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
	launchd := launchdProbe(sys, label)
	return func(ctx context.Context) (string, error) {
		if holder, _ := launchd(ctx); holder != "" {
			return holder, nil
		}
		return ports(ctx)
	}
}

// annotateSnapshotError turns a typed snapshot failure into an actionable one, binding
// the launchd label and the log path this command's callers need. The wrapped error is
// preserved with %w so errors.Is still works.
func annotateSnapshotError(err error, workDir string) error {
	switch {
	case errors.Is(err, executor.ErrControlPlaneRunning), errors.Is(err, executor.ErrWorkDirLocked):
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
