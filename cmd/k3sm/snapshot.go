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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf8"

	"k3sm.io/k3sm/pkg/dataroot"
	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/install"
)

// snapshotUsage is the `k3sm snapshot` help text. It states the single-node scope up
// front: an operator on the etcd HA posture must be told what this command does not
// cover before they run it, not after.
const snapshotUsage = `Usage: k3sm snapshot save    [--out <path>] [--compress] [--work-dir <dir>]
       k3sm snapshot restore <snapshot> [--work-dir <dir>]
                             [--node-name <name>] [--etcd-peer-ip <ip>] [--etcd-peer-port <port>]
       k3sm snapshot ls      [-o text|json] [--node-name <name>] [--work-dir <dir>]
       k3sm snapshot delete  <name>... [--work-dir <dir>]
       k3sm snapshot prune   [--snapshot-retention <n>] [--dry-run] [--node-name <name>] [--work-dir <dir>]

Back up and restore this node's datastore — the control plane's state of record:
the kine SQLite datastore on a single server, the embedded etcd member on an HA
server.

  save     write a consistent, integrity-verified copy of the datastore. Safe to run
           while the control plane is serving (the copy is taken by SQLite inside a
           read transaction, so a concurrent write cannot tear it).
  restore  replace the datastore with a snapshot. REFUSES while a control plane is
           running, and verifies the snapshot BEFORE touching anything; the datastore
           it supersedes is preserved beside it as a .bak, never deleted.
  ls       list the snapshots in the snapshots directory: name, size, created, kind
           (scheduled for this node, manual, or other) and whether compressed. Reads
           file metadata only; a missing directory is an empty list.
  delete   remove the named snapshots from the snapshots directory, by the bare names
           ls prints. IRREVERSIBLE: a deleted snapshot cannot be recovered. Only
           regular files are removed, never a symlink, directory or partial .tmp file.
  prune    remove this node's scheduled snapshots past the newest --snapshot-retention,
           the selection the schedule's own retention makes. Manual saves and other
           nodes' snapshots are never pruned (remove those with delete). IRREVERSIBLE.

Flags:
  --work-dir <dir>        control-plane state root (default: this posture's work dir)
  --out <path>            save: the snapshot file, or a directory to name one in
                          (default: %s under the work dir)
  --compress              save: write the snapshot as a zip archive (one member,
                          deflated); a generated name then ends in .zip. Restore
                          recognizes a compressed snapshot by its content, whatever
                          the file is called
  --node-name <name>      restore, etcd: this server's member name
  --etcd-peer-ip <ip>     restore, etcd: this server's etcd peer address
  --etcd-peer-port <port> restore, etcd: this server's etcd peer port
                          (all three default to the installed server's own flags)
  -o text|json            ls: output format (default text)
  --snapshot-retention <n> prune: how many scheduled snapshots to keep (default %d)
  --dry-run               prune: print what would be removed and remove nothing

delete and prune refuse a snapshots directory that is group- or world-writable or
owned by anyone but root, the %s service user or you, and run under sudo on
an installed server.

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
	case "ls":
		return runSnapshotLs(args[1:], os.Stdout)
	case "delete":
		return runSnapshotDelete(args[1:], os.Stdout)
	case "prune":
		return runSnapshotPrune(args[1:], os.Stdout)
	case "-h", "--help", "help":
		fmt.Print(snapshotHelp())
		return nil
	default:
		return fmt.Errorf("unknown snapshot subcommand %q (want: save, restore, ls, delete, prune)", args[0])
	}
}

// snapshotHelp renders the usage with the default snapshot location filled in.
func snapshotHelp() string {
	return fmt.Sprintf(snapshotUsage, filepath.Join("db", "snapshots"), executor.DefaultEtcdSnapshotRetention, install.DefaultServiceUser)
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
	compress := fs.Bool("compress", false, "write the snapshot as a zip archive; restore detects it by content")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		return fmt.Errorf("snapshot save takes no positional arguments (got %q); the destination is --out", fs.Arg(0))
	}

	return saveSnapshot(context.Background(), os.Stdout, *workDir, *out, *compress, defaultSnapshotSavers())
}

// snapshotSavers are the two save paths and the posture test that picks one; seams so
// the dispatch is testable without a datastore.
type snapshotSavers struct {
	etcdMember func(workDir string) bool
	etcd       func(ctx context.Context, workDir, dst string, compress bool) error
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
// snapshot otherwise. compress writes either one as a zip archive.
func saveSnapshot(ctx context.Context, w io.Writer, workDir, out string, compress bool, s snapshotSavers) error {
	if s.etcdMember(workDir) {
		dst, err := etcdSnapshotDest(workDir, out, s.now().UTC(), compress)
		if err != nil {
			return err
		}
		if err := s.etcd(ctx, workDir, dst, compress); err != nil {
			return annotateSnapshotError(err, workDir)
		}
		renderEtcdSnapshotSave(w, dst, compress)
		return nil
	}
	res, err := s.sqlite(ctx, executor.SnapshotSaveOptions{WorkDir: workDir, Out: out, Compress: compress})
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
// A compressed snapshot's generated name ends in .zip instead of .db.
func etcdSnapshotDest(workDir, out string, at time.Time, compress bool) (string, error) {
	name := "k3sm-etcd-snapshot-" + at.Format(etcdSnapshotLayout) + ".db"
	if compress {
		name = "k3sm-etcd-snapshot-" + at.Format(etcdSnapshotLayout) + ".zip"
	}
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
func renderEtcdSnapshotSave(w io.Writer, path string, compressed bool) {
	fmt.Fprintf(w, "k3sm snapshot save — embedded etcd member\n\n")
	fmt.Fprintf(w, "  snapshot   %s\n", path)
	if fi, err := os.Stat(path); err == nil {
		fmt.Fprintf(w, "  size       %d bytes\n", fi.Size())
	}
	if compressed {
		fmt.Fprint(w, "  format     zip archive (compressed)\n")
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
	if res.Compressed {
		fmt.Fprint(w, "  format     zip archive, decompressed and verified before the rebuild\n")
	}
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
	if res.Compressed {
		fmt.Fprint(w, "  format     zip archive (compressed)\n")
	}
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
	if res.Compressed {
		fmt.Fprint(w, "  format     zip archive, decompressed and verified before it was installed\n")
	}
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

// Errors the snapshot management verbs return.
var (
	// errSnapshotName is a delete argument that is not a bare snapshot file name.
	errSnapshotName = errors.New("not a snapshot name (give the bare file name `k3sm snapshot ls` prints)")
	// errSnapshotUnrecognised is a delete argument whose name is not a snapshot name
	// k3sm writes (the scheduled or manual shapes ls reports).
	errSnapshotUnrecognised = errors.New("not a name k3sm gives a snapshot (scheduled or manual); remove it by hand if it must go")
	// errSnapshotNotRemovable is a delete target that is not a regular, final-name file.
	errSnapshotNotRemovable = errors.New("not removable as a snapshot")
	// errSnapshotDirUnsafe is a snapshots directory delete and prune refuse to work in.
	errSnapshotDirUnsafe = errors.New("refusing to remove anything from the snapshots directory")
)

// snapshotManager is what ls, delete and prune need besides their flags; seams so
// the verbs are testable against a fake snapshots directory.
type snapshotManager struct {
	// owners are the uids besides euid the snapshots directory may be owned by: root
	// and the service user.
	owners []uint32
	// euid is the invoking user, who may also own it (a rootless `k3sm dev` cluster).
	euid uint32
	now  func() time.Time
}

// defaultSnapshotManager allows root, the service user and the invoking user to own
// the directory.
func defaultSnapshotManager() snapshotManager {
	owners := []uint32{0}
	if u, err := user.Lookup(install.DefaultServiceUser); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			owners = append(owners, uint32(uid))
		}
	}
	return snapshotManager{owners: owners, euid: uint32(os.Geteuid()), now: time.Now}
}

// snapshotNodeName resolves the node whose scheduled snapshots ls and prune mean, the
// way a restore resolves its member name: --node-name, else the installed server's
// --node-name, else this host's default node name. An unreadable installed server is
// an error only when the flag was not given.
func snapshotNodeName(flagName string, installed func() ([]string, error)) (string, error) {
	if flagName != "" {
		return flagName, nil
	}
	args, err := installed()
	if err != nil {
		return "", fmt.Errorf("read the installed server's --node-name (or pass --node-name): %w", err)
	}
	if n := install.ServerArgValue(args, "node-name"); n != "" {
		return n, nil
	}
	return defaultNodeName(), nil
}

// installedServerArgs reads the installed server's operator flags.
func installedServerArgs() ([]string, error) {
	return install.InstalledServerArgs(os.ReadFile, installedPlistPath(install.ServerLabel), dataroot.DefaultServerArgsRecordPath)
}

// runSnapshotLs parses the flags and lists the snapshots.
func runSnapshotLs(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("snapshot ls", flag.ContinueOnError)
	workDir := snapshotWorkDirFlag(fs)
	nodeName := fs.String("node-name", "", "the node whose scheduled snapshots are kind scheduled (default: the installed server's --node-name, else this host's node name)")
	format := fs.String("o", "text", "output format: text or json")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("snapshot ls takes no positional arguments (got %q)", fs.Arg(0))
	}
	node, err := snapshotNodeName(*nodeName, installedServerArgs)
	if err != nil {
		// Listing is read-only; an unknown node only makes this node's files "other".
		node = defaultNodeName()
	}
	return listSnapshots(w, executor.SnapshotDir(*workDir), node, *format, defaultSnapshotManager())
}

// listSnapshots prints the snapshots in dir. It reads metadata only: no snapshot is
// opened, so nothing derived from a snapshot's bytes can reach the output.
func listSnapshots(w io.Writer, dir, node, format string, m snapshotManager) error {
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown output format %q, want text or json", format)
	}
	infos, err := executor.ListSnapshots(dir, node, m.now())
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	if format == "json" {
		if infos == nil {
			infos = []executor.SnapshotInfo{}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(infos)
	}
	if len(infos) == 0 {
		fmt.Fprintf(w, "No snapshots in %s.\n", sanitizeSnapshotName(dir))
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSIZE\tCREATED\tKIND\tCOMPRESSED")
	for _, in := range infos {
		created := "unknown (dated in the future)"
		if !in.Created.IsZero() {
			created = in.Created.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%t\n", sanitizeSnapshotName(in.Name), in.Size, created, in.Kind, in.Compressed)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(w, "\n%d snapshots in %s; scheduled means scheduled for node %s.\n", len(infos), sanitizeSnapshotName(dir), sanitizeSnapshotName(node))
	return nil
}

// sanitizeSnapshotName makes a file name safe to print to a terminal: a name with a
// control, format or invalid byte is printed quoted with escapes, never raw.
func sanitizeSnapshotName(name string) string {
	if utf8.ValidString(name) && !strings.ContainsFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return name
	}
	return strconv.QuoteToASCII(name)
}

// checkSnapshotName refuses a delete argument that is not a bare file name, before
// anything touches the filesystem.
func checkSnapshotName(name string) error {
	switch {
	case name == "", name == ".", name == "..", strings.HasPrefix(name, "-"),
		strings.ContainsAny(name, "/\x00"), name != filepath.Base(name):
		return fmt.Errorf("%w: %s", errSnapshotName, sanitizeSnapshotName(name))
	}
	return nil
}

// openSnapshotRoot opens dir as an os.Root, which confines every later lookup to it,
// and refuses a directory another user could have planted files in: one that is
// group- or world-writable, or owned by anyone but m's owners or its euid.
func openSnapshotRoot(dir string, m snapshotManager) (*os.Root, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	fi, err := root.Stat(".")
	if err != nil {
		_ = root.Close() // the stat error is the one to report
		return nil, fmt.Errorf("stat %s: %w", dir, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		err = fmt.Errorf("%w: cannot read the owner of %s", errSnapshotDirUnsafe, dir)
	case fi.Mode().Perm()&0o022 != 0:
		err = fmt.Errorf("%w: %s is group- or world-writable (mode %v)", errSnapshotDirUnsafe, dir, fi.Mode().Perm())
	case st.Uid != m.euid && !slices.Contains(m.owners, st.Uid):
		err = fmt.Errorf("%w: %s is owned by uid %d, not root, the %s service user or you", errSnapshotDirUnsafe, dir, st.Uid, install.DefaultServiceUser)
	}
	if err != nil {
		_ = root.Close() // the refusal is the error to report
		return nil, err
	}
	return root, nil
}

// removeSnapshotFile unlinks name inside root when it is a regular, final-name file.
// gone reports a file that was already absent. Every error names the file sanitized
// and never carries the raw *fs.PathError, whose name a hostile file could have set.
func removeSnapshotFile(root *os.Root, name string) (gone bool, err error) {
	fi, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return true, nil
	case err != nil:
		return false, snapshotFileError(name, err)
	case !fi.Mode().IsRegular():
		return false, fmt.Errorf("%w: %s is a %s, not a regular file", errSnapshotNotRemovable, sanitizeSnapshotName(name), fileKind(fi.Mode()))
	case executor.IsPartialSnapshotName(name):
		return false, fmt.Errorf("%w: %s is a partial write, not a snapshot", errSnapshotNotRemovable, sanitizeSnapshotName(name))
	}
	if err := root.Remove(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return true, nil
		}
		return false, snapshotFileError(name, err)
	}
	return false, nil
}

// snapshotFileError reports err about name with the name sanitized: a *fs.PathError
// is replaced by its underlying error, so the raw name never reaches the terminal.
func snapshotFileError(name string, err error) error {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		err = pe.Err
	}
	return fmt.Errorf("%s: %w", sanitizeSnapshotName(name), err)
}

// fileKind names a non-regular file's type for a refusal.
func fileKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "directory"
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&(fs.ModeDevice|fs.ModeCharDevice) != 0:
		return "device"
	case m&fs.ModeSocket != 0:
		return "socket"
	}
	return "special file"
}

// runSnapshotDelete parses the flags and removes the named snapshots.
func runSnapshotDelete(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("snapshot delete", flag.ContinueOnError)
	workDir := snapshotWorkDirFlag(fs)
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	return deleteSnapshots(w, executor.SnapshotDir(*workDir), fs.Args(), defaultSnapshotManager())
}

// deleteSnapshots removes each named snapshot from dir. Every name is checked first,
// and one bad name refuses the whole command before the filesystem is touched.
func deleteSnapshots(w io.Writer, dir string, names []string, m snapshotManager) error {
	if len(names) == 0 {
		return errors.New("snapshot delete needs at least one snapshot name (see `k3sm snapshot ls`)")
	}
	for _, n := range names {
		if err := checkSnapshotName(n); err != nil {
			return err
		}
		if !executor.IsSnapshotName(n) {
			return fmt.Errorf("%w: %s", errSnapshotUnrecognised, sanitizeSnapshotName(n))
		}
	}
	root, err := openSnapshotRoot(dir, m)
	if err != nil {
		return fmt.Errorf("open the snapshots directory %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }() // read-only handle; nothing to flush

	var errs []error
	for _, n := range names {
		gone, err := removeSnapshotFile(root, n)
		switch {
		case err != nil:
			fmt.Fprintf(w, "not removed  %v\n", err)
			errs = append(errs, err)
		case gone:
			fmt.Fprintf(w, "already gone %s\n", sanitizeSnapshotName(n))
		default:
			fmt.Fprintf(w, "removed      %s\n", sanitizeSnapshotName(n))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d snapshots not removed: %w", len(errs), len(names), errors.Join(errs...))
	}
	return nil
}

// runSnapshotPrune parses the flags and prunes this node's scheduled snapshots.
func runSnapshotPrune(args []string, w io.Writer) error {
	fs := flag.NewFlagSet("snapshot prune", flag.ContinueOnError)
	workDir := snapshotWorkDirFlag(fs)
	nodeName := fs.String("node-name", "", "the node whose scheduled snapshots are pruned (default: the installed server's --node-name, else this host's node name)")
	retention := fs.Int("snapshot-retention", executor.DefaultEtcdSnapshotRetention, "how many of this node's scheduled snapshots to keep")
	dryRun := fs.Bool("dry-run", false, "print what would be removed and remove nothing")
	fs.Usage = func() { fmt.Fprint(os.Stderr, snapshotHelp()) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("snapshot prune takes no positional arguments (got %q)", fs.Arg(0))
	}
	if *retention < 1 {
		return fmt.Errorf("%w (got %d)", executor.ErrEtcdSnapshotRetention, *retention)
	}
	node, err := snapshotNodeName(*nodeName, installedServerArgs)
	if err != nil {
		return err
	}
	return pruneSnapshots(w, executor.SnapshotDir(*workDir), node, *retention, *dryRun, defaultSnapshotManager())
}

// pruneSnapshots removes node's scheduled snapshots in dir past the newest retention,
// selected by executor.SelectScheduledPrune (the schedule's own retention), so only
// this node's scheduled snapshots are ever candidates.
func pruneSnapshots(w io.Writer, dir, node string, retention int, dryRun bool, m snapshotManager) error {
	if retention < 1 {
		return fmt.Errorf("%w (got %d)", executor.ErrEtcdSnapshotRetention, retention)
	}
	pnode := sanitizeSnapshotName(node)
	root, err := openSnapshotRoot(dir, m)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(w, "0 scheduled snapshots for node %s, 0 pruned (no snapshots directory %s)\n", pnode, sanitizeSnapshotName(dir))
		return nil
	}
	if err != nil {
		return fmt.Errorf("open the snapshots directory %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }() // read-only handle; nothing to flush

	// Listed now, immediately before anything is unlinked, through the same root the
	// removals go through, so selecting and removing resolve one directory.
	infos, err := executor.ListSnapshotsFS(root.FS(), node, m.now())
	if err != nil {
		return fmt.Errorf("list %s: %w", dir, err)
	}
	scheduled := 0
	for _, in := range infos {
		if in.Kind == executor.SnapshotScheduled {
			scheduled++
		}
	}
	victims := executor.SelectScheduledPrune(infos, retention, "")
	if dryRun {
		for _, v := range victims {
			fmt.Fprintf(w, "would remove %s\n", sanitizeSnapshotName(v.Name))
		}
		fmt.Fprintf(w, "%d scheduled snapshots for node %s, %d would be pruned (dry run, nothing removed)\n", scheduled, pnode, len(victims))
		return nil
	}
	var errs []error
	pruned := 0
	for _, v := range victims {
		gone, err := removeSnapshotFile(root, v.Name)
		switch {
		case err != nil:
			fmt.Fprintf(w, "not removed  %v\n", err)
			errs = append(errs, err)
		case !gone:
			fmt.Fprintf(w, "removed      %s\n", sanitizeSnapshotName(v.Name))
			pruned++
		}
	}
	fmt.Fprintf(w, "%d scheduled snapshots for node %s, %d pruned\n", scheduled, pnode, pruned)
	if scheduled == 0 {
		fmt.Fprint(w, "Scheduled snapshots are an embedded etcd feature; a kine/SQLite server has none to prune.\n")
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d of %d snapshots past the retention not removed: %w", len(errs), len(victims), errors.Join(errs...))
	}
	return nil
}
