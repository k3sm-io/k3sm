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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// Snapshot restore for an embedded etcd server: the analog of k3s's
// `--cluster-reset --cluster-reset-restore-path`. The work is done offline by
// etcdutl, built from the same wrapper module as the etcd server (etcdstage.go), so
// the data dir is written by the exact etcd version that will open it.
//
// The shape is the kine restore's: every refusal before anything on disk moves, a
// rebuild beside the live data, a two-rename swap that puts the original back if
// either rename fails, and the superseded data dir preserved, never deleted. The PKI
// is only ever read (the cluster CA for the token's pin, the etcd CAs' presence).

// EtcdRestoreRevisionBump is how far a restore moves the store's revision past the
// snapshot's (etcdutl --bump-revision). It is the figure the etcd and Kubernetes
// restore guidance uses: every client that watched the cluster after the snapshot
// was taken holds a resourceVersion up to however many writes happened since, and a
// restored store that reused those revisions would hand a watcher pre-restore data
// as if it were current. One billion revisions is more than a cluster writing a
// thousand times a second commits in eleven days, and the 64-bit revision space
// makes the bump free. With --mark-compacted, the old revisions read as compacted,
// so every watcher and informer relists instead of resuming.
const EtcdRestoreRevisionBump uint64 = 1_000_000_000

// Etcd snapshot restore refusals. Each is a typed sentinel the CLI turns into a
// remedy; none is reached after anything on disk has moved.
var (
	// ErrEtcdRestoreNeedsEtcd refuses an etcd restore on a server with no etcd
	// configuration (it is the kine posture).
	ErrEtcdRestoreNeedsEtcd = errors.New("executor: this server is not configured as an embedded etcd member, so an etcd snapshot has nothing to restore into")
	// ErrEtcdRestoreOverSQLite refuses an etcd restore into a work dir that holds a
	// kine SQLite datastore: that work dir is the kine posture whatever flags say.
	ErrEtcdRestoreOverSQLite = errors.New("executor: this work dir holds a kine SQLite datastore (db/state.db), so it is a single-server control plane, not an etcd member")
	// ErrEtcdSnapshotForKine refuses an etcd snapshot handed to the kine posture.
	ErrEtcdSnapshotForKine = errors.New("executor: the file is an etcd snapshot, but this server's datastore is a kine SQLite file; restore it on an embedded etcd server")
	// ErrKineSnapshotForEtcd refuses a kine SQLite snapshot handed to the etcd posture.
	ErrKineSnapshotForEtcd = errors.New("executor: the file is a kine SQLite snapshot, but this server's datastore is an embedded etcd member; there is no SQLite to etcd conversion")
	// ErrEtcdSnapshotNoTrailer refuses an etcd backend without the SHA-256 trailer
	// `k3sm snapshot save` writes: most often a copy of a member's member/snap/db. It
	// cannot be verified, and k3sm does not restore unverified data.
	ErrEtcdSnapshotNoTrailer = errors.New("executor: the file is an etcd backend without the SHA-256 integrity trailer a snapshot carries; it looks like a copy of a member's member/snap/db, which cannot be verified and is not restored (take a snapshot with `k3sm snapshot save` on a running server instead)")
	// ErrEtcdRestoreNoPKI refuses a restore into a work dir without this server's
	// PKI: the restored member starts with the PKI it already has, and a restore
	// never mints one.
	ErrEtcdRestoreNoPKI = errors.New("executor: this work dir holds no cluster CA; a restore keeps the server's existing PKI and never mints one, so put the server's pki directory back first")
	// ErrEtcdRestoreFailed reports a rebuild that did not complete. The live etcd
	// data dir has not been touched.
	ErrEtcdRestoreFailed = errors.New("executor: rebuilding the etcd data dir from the snapshot failed; the existing etcd data dir was not touched")
	// ErrEtcdRestoreInterrupted refuses to start an etcd member in a work dir a
	// restore was interrupted in: <work-dir>/etcd is gone and the restore's .bak or
	// .tmp is beside it. Starting there would bootstrap or join from nothing.
	ErrEtcdRestoreInterrupted = errors.New("executor: an etcd snapshot restore was interrupted in this work dir: the etcd data dir is missing and the restore's directories are beside it")
	// ErrEtcdRestoreSwap reports a failed swap of the rebuilt data dir into place.
	// The original was moved back unless the error says otherwise.
	ErrEtcdRestoreSwap = errors.New("executor: swapping the rebuilt etcd data dir into place failed")
)

// EtcdRestoreOptions parametrizes RestoreEtcdSnapshot.
type EtcdRestoreOptions struct {
	// WorkDir is the server's control-plane state root. Required.
	WorkDir string
	// Snapshot is the file `k3sm snapshot save` wrote. Required.
	Snapshot string
	// Name, PeerIP and PeerPort are this server's member name, etcd peer address and
	// peer port (the server's --node-name, --etcd-peer-ip, --etcd-peer-port).
	Name, PeerIP string
	PeerPort     int
	// ClientPort and APIServerPort are the loopback ports a running server holds
	// (Config.KinePort and the apiserver's). Zero takes the defaults.
	ClientPort, APIServerPort int
	// PayloadBinDir is where a packaged install staged its payload (etcdutl among
	// it). Empty on a dev shell, where etcdutl is built into the work dir's bin.
	PayloadBinDir string
	// Running is an extra live-server probe (the launchd job); nil adds none. The
	// work-dir lock and the port and pid probes run regardless.
	Running LiveControlPlaneProbe
}

// EtcdRestoreResult is what a restore did.
type EtcdRestoreResult struct {
	// Snapshot is the file restored, Bytes its size, DataDir where the member's data
	// now lives.
	Snapshot string
	Bytes    int64
	DataDir  string
	// PreviousDataDir is the superseded data dir, preserved; empty when the work dir
	// had none (a rebuilt server). MovedAside lists the other files moved with it.
	PreviousDataDir string
	MovedAside      []string
	// MemberName and PeerURL are the single member the restored cluster has;
	// ClusterToken is the fresh token its new cluster ID derives from.
	MemberName, PeerURL, ClusterToken string
	// RevisionBump is EtcdRestoreRevisionBump.
	RevisionBump uint64
	// Warnings are advisories about the input that did not stop the restore.
	Warnings []string
}

// etcdRestoreSeams are the restore's injection points.
type etcdRestoreSeams struct {
	// etcdutl resolves the staged etcdutl binary.
	etcdutl func(ctx context.Context, workDir, payloadDir string) (string, error)
	// run runs etcdutl and returns its combined output.
	run func(ctx context.Context, bin string, args []string) ([]byte, error)
	// rename is os.Rename; a test injects a failure into the swap.
	rename func(oldpath, newpath string) error
	// now stamps the .tmp/.bak names and the cluster token.
	now func() time.Time
	// listening reports whether host:port accepts TCP (the peer-port probe).
	listening func(ctx context.Context, hostport string) bool
	// held reports whether a loopback port is held, and by whom (the client and
	// apiserver port probes).
	held func(ctx context.Context, port int) (string, bool)
}

func defaultEtcdRestoreSeams() etcdRestoreSeams {
	return etcdRestoreSeams{
		etcdutl:   resolveEtcdutl,
		run:       runEtcdutl,
		rename:    os.Rename,
		now:       time.Now,
		listening: tcpDial,
		held:      portHeld,
	}
}

// RestoreEtcdSnapshot replaces this server's etcd data dir with a single-member
// cluster rebuilt from a verified snapshot, and returns what it did.
//
// It refuses, before anything on disk moves: a server with no etcd configuration or
// with a kine datastore; a kine snapshot; an unverifiable file; a work dir another
// process holds locked; any sign of a running server (its loopback ports, its peer
// port, the etcd pid it last recorded, the launchd job); a work dir without its PKI;
// and a volume without twice the snapshot's size free. It then rebuilds into
// <WorkDir>/etcd.restore-<ts>.tmp with etcdutl at the server's own pin, under a fresh
// cluster token (a new cluster ID, so the old members are refused by the restored
// one) and with the revision bumped and marked compacted, and swaps it in for the
// live data dir, which becomes <WorkDir>/etcd.restore-<ts>.bak.
//
// It works when the work dir has no etcd data dir at all (a rebuilt server).
func RestoreEtcdSnapshot(ctx context.Context, opts EtcdRestoreOptions) (*EtcdRestoreResult, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("%w: no member name", ErrEtcdRestoreNeedsEtcd)
	}
	ip := net.ParseIP(opts.PeerIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, fmt.Errorf("%w: got --etcd-peer-ip %q", ErrEtcdNeedsNodeIP, opts.PeerIP)
	}
	return restoreEtcdSnapshot(ctx, opts, defaultEtcdRestoreSeams())
}

// restoreEtcdSnapshot is RestoreEtcdSnapshot after the peer address validation the
// exported entry point owns: the loopback integration test restores a member that
// peers on 127.0.0.1, which that validation refuses by design for a real server.
func restoreEtcdSnapshot(ctx context.Context, opts EtcdRestoreOptions, seams etcdRestoreSeams) (*EtcdRestoreResult, error) {
	if opts.WorkDir == "" {
		return nil, errors.New("executor: snapshot restore requires a work dir")
	}
	if opts.Snapshot == "" {
		return nil, errors.New("executor: snapshot restore requires a snapshot to restore")
	}
	if opts.Name == "" || opts.PeerIP == "" {
		return nil, fmt.Errorf("%w: no member name or peer address", ErrEtcdRestoreNeedsEtcd)
	}
	if opts.PeerPort == 0 {
		opts.PeerPort = DefaultEtcdPeerPort
	}
	if opts.ClientPort == 0 {
		opts.ClientPort = DefaultKinePort
	}
	if opts.APIServerPort == 0 {
		opts.APIServerPort = DefaultAPIServerPort
	}
	// The posture is decided by what is on disk, not by whether a member exists: a
	// rebuilt server has no member, and a kine work dir must never grow one.
	if _, err := os.Lstat(StateDBPath(opts.WorkDir)); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrEtcdRestoreOverSQLite, StateDBPath(opts.WorkDir))
	}

	fi, kind, err := sniffSnapshot(opts.Snapshot)
	if err != nil {
		return nil, err
	}
	res := &EtcdRestoreResult{Snapshot: opts.Snapshot, Bytes: fi.Size(), DataDir: EtcdDataDir(opts.WorkDir),
		MemberName: opts.Name, PeerURL: etcdPeerURL(opts.PeerIP, opts.PeerPort), RevisionBump: EtcdRestoreRevisionBump}
	switch kind {
	case snapshotSQLite:
		return nil, fmt.Errorf("%w: %s", ErrKineSnapshotForEtcd, opts.Snapshot)
	case snapshotBoltNoTrailer:
		return nil, fmt.Errorf("%w: %s (%d bytes)", ErrEtcdSnapshotNoTrailer, opts.Snapshot, fi.Size())
	case snapshotUnknown:
		return nil, fmt.Errorf("%w: %s is neither an etcd snapshot nor a kine SQLite database", ErrEtcdSnapshotVerify, opts.Snapshot)
	}
	if w := snapshotModeWarning(opts.Snapshot, fi); w != "" {
		res.Warnings = append(res.Warnings, w)
	}

	unlock, err := lockWorkDir(opts.WorkDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unlock() }()
	if err := refuseRunningEtcd(ctx, opts, seams); err != nil {
		return nil, err
	}
	// VERIFY FIRST: the trailer hash over the whole backend, then a read-only bbolt
	// open with etcd's buckets. Nothing has moved yet.
	if err := verifyEtcdSnapshot(opts.Snapshot); err != nil {
		return nil, fmt.Errorf("%w — nothing was changed", err)
	}
	pin, err := restorePKIPin(opts.WorkDir)
	if err != nil {
		return nil, err
	}
	if err := requireSnapshotSpace(opts.WorkDir, uint64(fi.Size())*snapshotFreeSpaceFactor); err != nil {
		return nil, err
	}
	bin, err := seams.etcdutl(ctx, opts.WorkDir, opts.PayloadBinDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEtcdRestoreFailed, err)
	}

	stamp := seams.now().UTC().Format(snapshotNameLayout)
	tmp := filepath.Join(opts.WorkDir, "etcd.restore-"+stamp+".tmp")
	bak := filepath.Join(opts.WorkDir, "etcd.restore-"+stamp+".bak")
	// A fresh token, so the restored cluster has a new ID: a member left on the old
	// data is then refused by cluster-ID mismatch rather than taken for one of its
	// own. It only matters at this bootstrap; later boots render no token at all.
	res.ClusterToken = etcdClusterToken(pin) + "-r" + stamp
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create %s: %w", ErrEtcdRestoreFailed, tmp, err)
	}
	if err := rebuildEtcdDataDir(ctx, seams, bin, opts, res, tmp); err != nil {
		_ = os.RemoveAll(tmp) // our own partial rebuild; the live data dir is untouched
		return nil, err
	}

	if err := swapEtcdDataDir(seams, opts.WorkDir, tmp, bak, stamp, res); err != nil {
		return res, err
	}
	return res, nil
}

// RefuseInterruptedEtcdRestore refuses an etcd start in a work dir where a restore
// stopped between its renames (a crash or a power cut): the data dir is absent and an
// etcd.restore-*.bak or etcd.restore-*.tmp sibling exists. Started there, an init
// member would bootstrap an empty cluster and a joiner would join as a new member,
// either way stranding the data in the sibling. The error names both ways out.
func RefuseInterruptedEtcdRestore(workDir string) error {
	live := EtcdDataDir(workDir)
	if _, err := os.Lstat(live); err == nil || !errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	baks, err := filepath.Glob(filepath.Join(workDir, "etcd.restore-*.bak"))
	if err != nil {
		return err
	}
	tmps, err := filepath.Glob(filepath.Join(workDir, "etcd.restore-*.tmp"))
	if err != nil {
		return err
	}
	if len(baks) == 0 && len(tmps) == 0 {
		return nil
	}
	// Glob sorts, and the UTC stamp sorts by time: the last is the newest.
	var ways []string
	ways = append(ways, "finish it: re-run `sudo k3sm snapshot restore <the snapshot>`, which rebuilds the data dir from the snapshot (nothing it moved aside is touched)")
	if len(baks) > 0 {
		bak := baks[len(baks)-1]
		ways = append(ways, fmt.Sprintf("or undo it: `sudo mv %s %s` (and move %s back to %s if it exists)",
			bak, live, filepath.Join(workDir, etcdStatusName+".restore-"+restoreStamp(bak)+".bak"), EtcdStatusPath(workDir)))
	}
	if len(tmps) > 0 {
		ways = append(ways, fmt.Sprintf("then remove the unfinished rebuild %s", tmps[len(tmps)-1]))
	}
	return fmt.Errorf("%w (%s); %s", ErrEtcdRestoreInterrupted, strings.Join(append(baks, tmps...), ", "), strings.Join(ways, "; "))
}

// restoreStamp is the <ts> of an etcd.restore-<ts>.bak path.
func restoreStamp(path string) string {
	return strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "etcd.restore-"), ".bak")
}

// rebuildEtcdDataDir runs etcdutl into tmp and gives the result the live data dir's
// mode and ownership.
func rebuildEtcdDataDir(ctx context.Context, seams etcdRestoreSeams, bin string, opts EtcdRestoreOptions, res *EtcdRestoreResult, tmp string) error {
	out, err := seams.run(ctx, bin, etcdutlRestoreArgs(opts.Snapshot, opts.Name, res.PeerURL, res.ClusterToken, tmp))
	if err != nil {
		return fmt.Errorf("%w: etcdutl snapshot restore: %w\n%s", ErrEtcdRestoreFailed, err, tailLines(string(out), 20))
	}
	if fi, err := os.Stat(filepath.Join(tmp, "member", "snap", "db")); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: etcdutl reported success but %s holds no member/snap/db", ErrEtcdRestoreFailed, tmp)
	}
	if err := os.Chmod(tmp, 0o700); err != nil {
		return fmt.Errorf("%w: restrict %s: %w", ErrEtcdRestoreFailed, tmp, err)
	}
	// The member runs as the service user; a restore run under sudo must not hand it
	// a root-owned data dir it cannot write. The owner is the live data dir's, or the
	// work dir's when there is none.
	owner := EtcdDataDir(opts.WorkDir)
	if _, err := os.Stat(owner); err != nil {
		owner = opts.WorkDir
	}
	if err := chownTreeLike(owner, tmp); err != nil {
		return fmt.Errorf("%w: %w", ErrEtcdRestoreFailed, err)
	}
	return nil
}

// swapEtcdDataDir moves the live data dir (and the status record, which describes
// it) aside and the rebuilt one into place. If any rename fails, what moved is moved
// back, so the work dir is either restored or exactly as it was.
func swapEtcdDataDir(seams etcdRestoreSeams, workDir, tmp, bak, stamp string, res *EtcdRestoreResult) error {
	live := EtcdDataDir(workDir)
	status := EtcdStatusPath(workDir)
	statusBak := filepath.Join(workDir, etcdStatusName+".restore-"+stamp+".bak")

	var undo []func() error
	rollback := func(cause error) error {
		var failed []string
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil {
				failed = append(failed, err.Error())
			}
		}
		_ = os.RemoveAll(tmp)
		res.PreviousDataDir, res.MovedAside = "", nil
		if len(failed) > 0 {
			return fmt.Errorf("%w: %w; AND putting the original back failed (%s): the original data dir is at %s", ErrEtcdRestoreSwap, cause, strings.Join(failed, "; "), bak)
		}
		return fmt.Errorf("%w: %w; the original etcd data dir was put back, nothing changed", ErrEtcdRestoreSwap, cause)
	}

	if _, err := os.Lstat(live); err == nil {
		if err := seams.rename(live, bak); err != nil {
			_ = os.RemoveAll(tmp)
			return fmt.Errorf("%w: move %s aside: %w; nothing changed", ErrEtcdRestoreSwap, live, err)
		}
		undo = append(undo, func() error { return seams.rename(bak, live) })
		res.PreviousDataDir = bak
	}
	if _, err := os.Lstat(status); err == nil {
		if err := seams.rename(status, statusBak); err != nil {
			return rollback(fmt.Errorf("move %s aside: %w", status, err))
		}
		undo = append(undo, func() error { return seams.rename(statusBak, status) })
		res.MovedAside = append(res.MovedAside, statusBak)
	}
	if err := seams.rename(tmp, live); err != nil {
		return rollback(fmt.Errorf("install the rebuilt data dir at %s: %w", live, err))
	}
	return nil
}

// etcdutlRestoreArgs is the etcdutl argv. Pure. The integrity hash is always
// checked (--skip-hash-check is never rendered).
func etcdutlRestoreArgs(snapshot, name, peerURL, token, dataDir string) []string {
	return []string{
		"snapshot", "restore", snapshot,
		"--name", name,
		"--data-dir", dataDir,
		"--initial-cluster", name + "=" + peerURL,
		"--initial-cluster-token", token,
		"--initial-advertise-peer-urls", peerURL,
		"--bump-revision", strconv.FormatUint(EtcdRestoreRevisionBump, 10),
		"--mark-compacted",
	}
}

// runEtcdutl runs etcdutl and returns its combined output.
func runEtcdutl(ctx context.Context, bin string, args []string) ([]byte, error) {
	return exec.CommandContext(ctx, bin, args...).CombinedOutput()
}

// resolveEtcdutl finds a staged etcdutl whose marker vouches for the pin: the
// packaged install's payload first, then the work dir's bin. A dev shell with
// neither builds it into the work dir's bin (a packaged install never needs to).
func resolveEtcdutl(ctx context.Context, workDir, payloadDir string) (string, error) {
	c := etcdutlChild(DefaultEtcdVersion)
	for _, d := range []string{payloadDir, binDir(workDir)} {
		if d != "" && c.staged(d) {
			return c.binPath(d), nil
		}
	}
	bd := binDir(workDir)
	if err := os.MkdirAll(bd, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", bd, err)
	}
	if err := ensureEtcdutlInto(ctx, bd, DefaultEtcdVersion); err != nil {
		return "", err
	}
	return c.binPath(bd), nil
}

// refuseRunningEtcd refuses when anything suggests a server, or a leftover etcd
// child, is live on this work dir. The work-dir lock the caller holds covers a
// running daemon; these cover what the lock cannot: a daemon killed with SIGKILL
// releases its lock but can leave its etcd child running, still serving the data
// dir this restore is about to move.
func refuseRunningEtcd(ctx context.Context, opts EtcdRestoreOptions, seams etcdRestoreSeams) error {
	held := func(what string) error {
		return fmt.Errorf("%w: %s; stop it and re-run (moving the etcd data dir from under a live member corrupts both)", ErrControlPlaneRunning, what)
	}
	if st, err := ReadEtcdStatus(opts.WorkDir); err == nil && st.PID > 0 && processIsEtcd(st.PID) {
		return held(fmt.Sprintf("the etcd member this work dir last ran is still alive (pid %d); a server stopped with SIGKILL can leave it behind: `sudo kill %d`", st.PID, st.PID))
	}
	for _, p := range []struct {
		what string
		port int
	}{
		{"the etcd client port", opts.ClientPort},
		{"the apiserver port", opts.APIServerPort},
	} {
		if holder, isHeld := seams.held(ctx, p.port); isHeld {
			return held(fmt.Sprintf("%s 127.0.0.1:%d is held by %s", p.what, p.port, holder))
		}
	}
	peer := net.JoinHostPort(opts.PeerIP, strconv.Itoa(opts.PeerPort))
	if seams.listening(ctx, peer) {
		return held(fmt.Sprintf("the etcd peer port %s accepts connections", peer))
	}
	if opts.Running != nil {
		holder, err := opts.Running(ctx)
		if err != nil {
			return fmt.Errorf("%w: could not determine whether the server is running (refusing to replace the data dir blind): %w", ErrControlPlaneRunning, err)
		}
		if holder != "" {
			return held(holder)
		}
	}
	return nil
}

// restorePKIPin reads the cluster CA's pin and checks the etcd CAs are present.
// Read-only: a restore never writes a CA, a bundle, or a key.
func restorePKIPin(workDir string) (string, error) {
	pin, err := clusterCAPin(workDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%w (%s)", ErrEtcdRestoreNoPKI, certs.ClusterCACertPath(workDir))
		}
		return "", err
	}
	p := certs.EtcdCertPaths(workDir)
	for _, f := range []string{p.ServerCACert, p.ServerCAKey, p.PeerCACert, p.PeerCAKey} {
		if _, err := os.Lstat(f); err != nil {
			return "", fmt.Errorf("%w: %s: %w", ErrEtcdCAsMissing, f, err)
		}
	}
	return pin, nil
}

// chownTreeLike gives every entry under root the uid/gid of like, when they differ
// (lchown: a symlink is re-owned as itself).
func chownTreeLike(like, root string) error {
	fi, err := os.Stat(like)
	if err != nil {
		return fmt.Errorf("stat %s: %w", like, err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(st.Uid), int(st.Gid)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if s, ok := info.Sys().(*syscall.Stat_t); ok && int(s.Uid) == uid && int(s.Gid) == gid {
			return nil
		}
		if err := os.Lchown(path, uid, gid); err != nil {
			return fmt.Errorf("give %s the ownership of %s (uid %d gid %d); the member runs as that user, so re-run with sudo: %w", path, like, uid, gid, err)
		}
		return nil
	})
}

// snapshotKind is what a restore input looks like from its header and size.
type snapshotKind int

const (
	snapshotUnknown snapshotKind = iota
	// snapshotSQLite is a kine SQLite snapshot.
	snapshotSQLite
	// snapshotEtcdBackend is a bbolt backend sized like a snapshot with its trailer.
	snapshotEtcdBackend
	// snapshotBoltNoTrailer is a page-aligned bbolt backend with no trailer: a copy
	// of a member's member/snap/db, not a snapshot.
	snapshotBoltNoTrailer
)

// sqliteHeader opens every SQLite database file.
var sqliteHeader = []byte("SQLite format 3\x00")

// boltMagic is bbolt's meta-page magic, at offset 16 of the file (after the page
// header), little-endian.
const boltMagic = 0xED0CDAED

// sniffSnapshot stats path and classifies it by its header and size. It reads at
// most the first 20 bytes; verification is separate.
func sniffSnapshot(path string) (os.FileInfo, snapshotKind, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, snapshotUnknown, fmt.Errorf("%w: %s: %w", ErrSnapshotNotFound, path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, snapshotUnknown, fmt.Errorf("%w: %s is not a regular file", ErrSnapshotNotFound, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, snapshotUnknown, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 20)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, snapshotUnknown, fmt.Errorf("read %s: %w", path, err)
	}
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, sqliteHeader):
		return fi, snapshotSQLite, nil
	case len(head) == 20 && binary.LittleEndian.Uint32(head[16:20]) == boltMagic:
		if fi.Size()%512 == 0 {
			return fi, snapshotBoltNoTrailer, nil
		}
		return fi, snapshotEtcdBackend, nil
	}
	return fi, snapshotUnknown, nil
}

// refuseEtcdSnapshotForKine is the kine restore's share of the posture preflight:
// an etcd snapshot (with or without its trailer) is never handed to SQLite.
func refuseEtcdSnapshotForKine(path string) error {
	_, kind, err := sniffSnapshot(path)
	if err != nil {
		return err
	}
	if kind == snapshotEtcdBackend || kind == snapshotBoltNoTrailer {
		return fmt.Errorf("%w: %s", ErrEtcdSnapshotForKine, path)
	}
	return nil
}

// snapshotModeWarning warns about a snapshot others can read. It never changes the
// mode: the file is the operator's, and a restore has no business rewriting it.
func snapshotModeWarning(path string, fi os.FileInfo) string {
	if fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fmt.Sprintf("%s is readable beyond its owner (mode %04o); it holds every Secret in the cluster in plaintext. k3sm did not change it: `chmod 600 %s`",
		path, fi.Mode().Perm(), path)
}

// tailLines returns the last n lines of s.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
