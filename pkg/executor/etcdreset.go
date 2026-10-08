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
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Day-2 operations on an etcd member: --cluster-reset (k3s's flag and semantics) and
// an online snapshot save. Restoring a snapshot is RestoreEtcdSnapshot
// (etcdrestore.go).

// Cluster-reset and etcd snapshot failures.
var (
	// ErrClusterResetNeedsEtcd refuses a reset on a server that is not in the etcd
	// posture.
	ErrClusterResetNeedsEtcd = errors.New("executor: --cluster-reset applies only to a server running an embedded etcd member")
	// ErrNoEtcdMember refuses a reset of a work dir that holds no etcd member.
	ErrNoEtcdMember = errors.New("executor: --cluster-reset needs an existing etcd member in this work dir (<work-dir>/etcd/member)")
	// ErrClusterResetFailed reports a reset that did not end with a single-member
	// cluster of this server.
	ErrClusterResetFailed = errors.New("executor: the cluster reset did not leave this server as the only member; restore the etcd data dir from a snapshot")
	// ErrNoEtcdClient reports that the work dir records no local etcd member to
	// snapshot.
	ErrNoEtcdClient = errors.New("executor: no local etcd member is recorded in this work dir")
	// ErrEtcdSnapshotVerify reports a snapshot that failed verification. The file is
	// removed; nothing is left under the destination name.
	ErrEtcdSnapshotVerify = errors.New("executor: the etcd snapshot did not verify")
)

// clusterResetTimeout bounds how long a reset waits for the forced single-member
// cluster to report itself.
const clusterResetTimeout = 2 * time.Minute

// ClusterReset is `k3sm server --cluster-reset`: it turns this server's existing etcd
// member into a single-member cluster that keeps all of its data, the recovery for a
// cluster that has lost quorum for good (on two servers, losing either one).
//
// It takes the work-dir lock the running server holds, so it refuses while that
// server runs (ErrWorkDirLocked), and refuses a work dir without a member
// (ErrNoEtcdMember). It starts the member once with --force-new-cluster, waits until
// the member list is exactly this server with its own peer URL and a leader, stops
// the member, and returns nil: the operator then starts the server normally. Any
// other outcome is ErrClusterResetFailed, which says to restore the data dir from a
// snapshot. A member removed by the reset rejoins only as a fresh learner, after its
// own data dir is wiped.
func ClusterReset(ctx context.Context, cfg Config) error {
	if cfg.Etcd == nil {
		return ErrClusterResetNeedsEtcd
	}
	if err := cfg.Etcd.validate(); err != nil {
		return err
	}
	return clusterReset(ctx, cfg, defaultEtcdSeams())
}

// clusterReset is ClusterReset after the posture's own validation, which the
// exported entry point owns. The loopback integration test calls it directly: its
// members peer on 127.0.0.1, which that validation (ErrEtcdNeedsNodeIP) refuses by
// design for a real server.
func clusterReset(ctx context.Context, cfg Config, seams etcdSeams) error {
	cfg = cfg.withDefaults()
	if cfg.Etcd == nil {
		return ErrClusterResetNeedsEtcd
	}
	unlock, err := lockWorkDir(cfg.WorkDir)
	if err != nil {
		return err
	}
	defer func() { _ = unlock() }()
	if err := RefuseInterruptedEtcdRestore(cfg.WorkDir); err != nil {
		return err
	}
	if !EtcdMemberExists(cfg.WorkDir) {
		return fmt.Errorf("%w: %s is absent", ErrNoEtcdMember, etcdMemberDir(cfg.WorkDir))
	}
	cfg.Etcd.Reset = true
	// The leaves are re-minted exactly as a boot would (the CAs are loaded, never
	// minted: the member exists), so a reset after a long outage has valid ones.
	if err := provisionEtcdCerts(cfg); err != nil {
		return err
	}
	s := NewSupervised(cfg)
	s.etcd = seams
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), StopBound)
		defer cancel()
		_ = s.Stop(stopCtx)
	}()

	etcd, err := s.startEtcd(ctx, true, nil)
	if err != nil {
		return fmt.Errorf("%w: start the member with --force-new-cluster: %w", ErrClusterResetFailed, err)
	}
	if err := awaitHealthy(ctx, etcd.name, etcd.exited, etcd.exitedNow, seams.ready(cfg.KinePort), componentReadyTimeout, 300*time.Millisecond, etcd.exitDetail); err != nil {
		return fmt.Errorf("%w: %w", ErrClusterResetFailed, err)
	}
	admin, err := seams.dial(ctx, cfg.WorkDir, etcdClientURL(cfg.KinePort))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClusterResetFailed, err)
	}
	defer func() { _ = admin.Close() }()
	if err := awaitSoleMember(ctx, s, admin, etcd); err != nil {
		return err
	}
	cfg.Logger.Info("etcd cluster reset complete: this server is the only member and keeps its data; start the server normally, then re-join every other server as a fresh learner with a wiped etcd data dir",
		"component", etcdComponent, "name", cfg.Etcd.Name)
	return nil
}

// awaitSoleMember waits (bounded by clusterResetTimeout on the supervisor's clock)
// for the reset's postcondition: a leader, and a member list of exactly this server
// with exactly its own peer URL.
func awaitSoleMember(ctx context.Context, s *Supervised, m etcdMembers, c *component) error {
	clk := s.etcd.clock
	want := etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort)
	deadline := clk.Now().Add(clusterResetTimeout)
	var last []etcdMember
	for {
		cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
		st, serr := m.Status(cctx)
		members, merr := m.MemberList(cctx)
		cancel()
		if merr == nil {
			last = members
		}
		if serr == nil && merr == nil && st.Leader != 0 && len(members) == 1 &&
			members[0].Name == s.cfg.Etcd.Name && slices.Equal(members[0].PeerURLs, []string{want}) {
			return nil
		}
		if !clk.Now().Before(deadline) {
			return fmt.Errorf("%w: after %s the member list is %s (want only %s at %s)",
				ErrClusterResetFailed, clusterResetTimeout, describeMembers(last), s.cfg.Etcd.Name, want)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrClusterResetFailed, ctx.Err())
		case <-c.exited:
			return fmt.Errorf("%w: %w", ErrClusterResetFailed, etcdExitDetail(c, "during the reset"))
		case <-clk.After(etcdQuorumPoll):
		}
	}
}

// describeMembers renders a member list for an error: names and peer URLs only.
func describeMembers(ms []etcdMember) string {
	if ms == nil {
		return "unknown"
	}
	out := "["
	for i, m := range ms {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%v", m.Name, m.PeerURLs)
		if m.IsLearner {
			out += " (learner)"
		}
	}
	return out + "]"
}

// SnapshotEtcd streams a point-in-time snapshot of the local etcd member to dst
// (mode 0600) and verifies it before it takes dst's name. It is online: the member
// keeps serving and no quorum is spent, which matters on two servers.
//
// The member is found through the status record the running server keeps (its
// loopback client URL); only a loopback https URL is accepted. The file holds every
// Secret in plaintext — keep it 0600 and off shared storage.
func SnapshotEtcd(ctx context.Context, workDir, dst string) error {
	return snapshotEtcd(ctx, workDir, dst, dialEtcdAdmin)
}

func snapshotEtcd(ctx context.Context, workDir, dst string, dial func(context.Context, string, string) (etcdAdmin, error)) error {
	st, err := ReadEtcdStatus(workDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoEtcdClient, err)
	}
	u, err := url.Parse(st.ClientURL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" {
		return fmt.Errorf("%w: recorded client URL %q is not a loopback https URL", ErrNoEtcdClient, st.ClientURL)
	}
	admin, err := dial(ctx, workDir, st.ClientURL)
	if err != nil {
		return err
	}
	defer func() { _ = admin.Close() }()
	return saveEtcdSnapshot(ctx, admin, dst)
}

// saveEtcdSnapshot streams the member's snapshot to dst through
// writeVerifiedEtcdSnapshot. It is the one save path: `k3sm snapshot save` and the
// scheduled snapshots both write through it, so both get the same verification and
// the same 0600 file.
func saveEtcdSnapshot(ctx context.Context, m etcdMembers, dst string) error {
	rc, err := m.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("stream the etcd snapshot: %w", err)
	}
	defer func() { _ = rc.Close() }()
	return writeVerifiedEtcdSnapshot(rc, dst)
}

// writeVerifiedEtcdSnapshot writes the stream to dst.tmp (0600, O_EXCL), verifies
// it, and renames it into place, so a file under dst's name is always a complete,
// verified snapshot.
func writeVerifiedEtcdSnapshot(r io.Reader, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}
	tmp := dst + ".tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clear stale partial snapshot %s: %w", tmp, err)
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, cerr := io.Copy(f, r)
	if cerr == nil {
		cerr = f.Sync()
	}
	if err := f.Close(); cerr == nil {
		cerr = err
	}
	if cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, cerr)
	}
	if err := verifyEtcdSnapshot(tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("restrict %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install snapshot %s: %w", dst, err)
	}
	return nil
}

// etcdSnapshotBuckets are buckets every etcd backend has; a file without them is not
// an etcd snapshot.
var etcdSnapshotBuckets = []string{"key", "meta"}

// verifyEtcdSnapshot checks a Maintenance.Snapshot file: the SHA-256 trailer etcd
// appends must match the bytes before it, and the database must open as bbolt
// (read-only) with etcd's buckets.
func verifyEtcdSnapshot(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEtcdSnapshotVerify, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrEtcdSnapshotVerify, err)
	}
	size := fi.Size()
	// etcd's backend is page-aligned, so a snapshot is a multiple of 512 bytes plus
	// the 32-byte hash (etcdutl's own test for "has a hash").
	if size < sha256.Size || size%512 != sha256.Size {
		return fmt.Errorf("%w: %s is %d bytes, which is not a database plus its SHA-256 trailer", ErrEtcdSnapshotVerify, path, size)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, f, size-sha256.Size); err != nil {
		return fmt.Errorf("%w: hash %s: %w", ErrEtcdSnapshotVerify, path, err)
	}
	trailer := make([]byte, sha256.Size)
	if _, err := io.ReadFull(f, trailer); err != nil {
		return fmt.Errorf("%w: read the trailer of %s: %w", ErrEtcdSnapshotVerify, path, err)
	}
	if !slices.Equal(h.Sum(nil), trailer) {
		return fmt.Errorf("%w: %s does not match its SHA-256 trailer (truncated or corrupted in transit)", ErrEtcdSnapshotVerify, path)
	}
	db, err := bolt.Open(path, 0o400, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return fmt.Errorf("%w: open %s as a bbolt database: %w", ErrEtcdSnapshotVerify, path, err)
	}
	defer func() { _ = db.Close() }()
	return db.View(func(tx *bolt.Tx) error {
		for _, b := range etcdSnapshotBuckets {
			if tx.Bucket([]byte(b)) == nil {
				return fmt.Errorf("%w: %s has no %q bucket, so it is not an etcd backend", ErrEtcdSnapshotVerify, path, b)
			}
		}
		return nil
	})
}
