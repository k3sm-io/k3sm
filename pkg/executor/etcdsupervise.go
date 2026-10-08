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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// Supervision of the etcd member: provisioning its certificates and data dir, the
// bring-up (spawn → accept → [promote] → quorum), the post-quorum checks, and the
// background watcher. The bring-up order is what lets a server whose peers are down
// come up the moment they return without ever being parked by the crash-loop breaker:
// the quorum wait sits outside every bring-up deadline and records no failure of its
// own, so only the etcd child actually dying counts as a crash.

// The etcd supervision cadences.
const (
	// etcdQuorumPoll is how often the quorum wait asks the local member for a leader.
	etcdQuorumPoll = 2 * time.Second
	// etcdQuorumLogEvery is how often the wait says it is still waiting.
	etcdQuorumLogEvery = 15 * time.Second
	// etcdPromoteInterval is the learner-promotion retry cadence.
	etcdPromoteInterval = 5 * time.Second
	// etcdWatchPoll is how often the watcher checks for a leader change.
	etcdWatchPoll = 5 * time.Second
	// etcdAlarmLogEvery is how often the watcher re-reads the alarms, repeats an
	// active NOSPACE at ERROR, and refreshes the status record.
	etcdAlarmLogEvery = 60 * time.Second
	// etcdCallTimeout bounds one admin call against the local member.
	etcdCallTimeout = 5 * time.Second
	// etcdLeafValidity is the lifetime of the three leaves re-minted every boot.
	etcdLeafValidity = 365 * 24 * time.Hour
	// etcdComponent is the supervised component's name (and its binary's).
	etcdComponent = etcdBinaryName
	// etcdAlarmNoSpace is the backend-quota alarm's name.
	etcdAlarmNoSpace = "NOSPACE"
)

// Errors of the etcd posture's provisioning.
var (
	// ErrClusterInitOverSQLite refuses --cluster-init on a work dir that already
	// holds a single-node kine datastore: converting it to etcd is not supported, and
	// starting an empty etcd beside it would present a fresh, empty cluster.
	ErrClusterInitOverSQLite = errors.New("executor: --cluster-init over an existing single-node SQLite datastore is not supported (there is no SQLite→etcd conversion); use a fresh work dir, or keep this server single-node")
	// ErrEtcdCAsMissing reports an etcd posture that must load the etcd CAs but finds
	// them absent: a joining server imports them from the bootstrap bundle, and a
	// restarting member minted or imported them on its first boot. Minting fresh ones
	// here would split the cluster's trust.
	ErrEtcdCAsMissing = errors.New("executor: the etcd CA pairs are missing from the PKI dir (a joining server imports them from the bootstrap bundle; an existing member must keep the ones it was created with)")
	// ErrEtcdChildExited marks a bring-up that ended because the etcd member died
	// during one of the waits that run after it is supervised (the learner check, the
	// promotion, the quorum wait), when that death was ALREADY reported through
	// Config.OnComponentExit. A caller that counts failures must not count the
	// bring-up error again: one death, one record. Match it with errors.Is.
	ErrEtcdChildExited = errors.New("executor: the etcd member exited during bring-up (already reported as a component exit)")
)

// clock is the time seam the etcd loops wait on, so a test drives hours of waiting
// in microseconds.
type clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// etcdSeams are the etcd posture's injection points. NewSupervised fills them with
// the production implementations; a test replaces individual fields.
type etcdSeams struct {
	clock clock
	// dial connects the admin client to the local member at endpoint.
	dial func(ctx context.Context, workDir, endpoint string) (etcdAdmin, error)
	// ready is the client-port accept probe.
	ready func(port int) func(context.Context) bool
	// dialPeer reports whether a peer's host:port accepts TCP (for the wait's log).
	dialPeer func(ctx context.Context, hostport string) bool
	// peerView asks a peer listener about its cluster (the peer cluster-ID check).
	// Nil skips the check.
	peerView func(ctx context.Context, workDir, peerURL string, own uint64) (EtcdPeerView, error)
}

func defaultEtcdSeams() etcdSeams {
	return etcdSeams{clock: realClock{}, dial: dialEtcdAdmin, ready: tcpReady, dialPeer: tcpDial, peerView: peerView}
}

// tcpDial reports whether hostport accepts a TCP connection within a second.
func tcpDial(ctx context.Context, hostport string) bool {
	d := &net.Dialer{Timeout: time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// RefuseClusterInitOverSQLite is the first provision step of an init member: a
// non-empty kine datastore with no etcd member beside it is a single-node cluster
// that --cluster-init would silently abandon. A work dir that already holds a member
// is a restart, where --cluster-init is a no-op (k3s's semantics). It only reads, so
// `k3sm server` also calls it before writing anything into the work dir.
func RefuseClusterInitOverSQLite(cfg Config) error {
	if cfg.Etcd == nil || cfg.Etcd.Role != EtcdInit || EtcdMemberExists(cfg.WorkDir) {
		return nil
	}
	fi, err := os.Stat(StateDBPath(cfg.WorkDir))
	if err != nil || fi.Size() == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s holds %d bytes", ErrClusterInitOverSQLite, StateDBPath(cfg.WorkDir), fi.Size())
}

// provisionEtcdCerts lays down the etcd PKI and data dir for this boot.
//
// The two CAs are minted only by an init member's first boot; every other case
// (a joining server, which imported them from the bundle, or any restart) must find
// them, and a missing pair is ErrEtcdCAsMissing rather than a fresh mint. The three
// leaves are re-minted every boot (365 d): server-client.crt for the loopback client
// listener (SANs 127.0.0.1 and localhost), peer-server-client.crt from the PEER CA for
// the node-IP peer listener, and client.crt (clientAuth only) for the apiserver and
// the admin client. Keys are 0600; the data dir is 0700.
func provisionEtcdCerts(cfg Config) error {
	e := cfg.Etcd
	p := certs.EtcdCertPaths(cfg.WorkDir)
	mint := e.Role == EtcdInit && !EtcdMemberExists(cfg.WorkDir)
	if !mint {
		for _, f := range []string{p.ServerCACert, p.ServerCAKey, p.PeerCACert, p.PeerCAKey} {
			if _, err := os.Lstat(f); err != nil {
				return fmt.Errorf("%w: %s: %w", ErrEtcdCAsMissing, f, err)
			}
		}
	}
	server, peer, err := certs.EnsureEtcdCAs(cfg.WorkDir)
	if err != nil {
		return fmt.Errorf("etcd CAs: %w", err)
	}
	peerIP := net.ParseIP(e.PeerIP)
	if peerIP == nil {
		return fmt.Errorf("%w: got %q", ErrEtcdNeedsNodeIP, e.PeerIP)
	}
	leaves := []struct {
		cert, key string
		issue     func() ([]byte, []byte, error)
	}{
		{p.ServerClientCert, p.ServerClientKey, func() ([]byte, []byte, error) {
			return server.IssueServerClient("etcd-server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, etcdLeafValidity)
		}},
		{p.PeerServerClientCert, p.PeerServerClientKey, func() ([]byte, []byte, error) {
			return peer.IssueServerClient("etcd-peer", nil, []net.IP{peerIP}, etcdLeafValidity)
		}},
		{p.ClientCert, p.ClientKey, func() ([]byte, []byte, error) {
			return server.IssueClient("etcd-client", nil, etcdLeafValidity)
		}},
	}
	for _, l := range leaves {
		certPEM, keyPEM, err := l.issue()
		if err != nil {
			return fmt.Errorf("issue %s: %w", filepath.Base(l.cert), err)
		}
		if err := writeFileAtomic(l.key, keyPEM, 0o600); err != nil {
			return err
		}
		if err := writeFileAtomic(l.cert, certPEM, 0o644); err != nil {
			return err
		}
	}
	dd := EtcdDataDir(cfg.WorkDir)
	if err := os.MkdirAll(dd, 0o700); err != nil {
		return fmt.Errorf("create etcd data dir: %w", err)
	}
	if err := os.Chmod(dd, 0o700); err != nil {
		return fmt.Errorf("restrict etcd data dir: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to path through a temp file + rename, with mode set
// explicitly (an existing file's looser mode is never inherited).
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// clusterCAPin reads the cluster CA's pin (the initial-cluster token's source) from
// the certificate alone.
func clusterCAPin(workDir string) (string, error) {
	b, err := os.ReadFile(certs.ClusterCACertPath(workDir))
	if err != nil {
		return "", fmt.Errorf("read the cluster CA: %w", err)
	}
	return certs.CertPin(b)
}

// startEtcd spawns the etcd member. No secret env: there is no password anywhere in
// this posture; the member authenticates with files under the 0700 PKI dir.
func (s *Supervised) startEtcd(ctx context.Context, memberExists bool, extra func(*etcdArgsInput)) (*component, error) {
	if err := preflightDatastorePort(ctx, s.cfg.KinePort); err != nil {
		return nil, err
	}
	pin, err := clusterCAPin(s.cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	in := etcdArgsInputFor(s.cfg, pin, memberExists)
	if extra != nil {
		extra(&in)
	}
	version, variant := readChildMarker(etcdChild(DefaultEtcdVersion).markerPath(binDir(s.cfg.WorkDir)))
	s.cfg.Logger.Info("starting etcd member", "component", etcdComponent, "version", version, "variant", variant,
		"name", s.cfg.Etcd.Name, "role", s.cfg.Etcd.Role.String(), "first-boot", !memberExists,
		"peer-url", etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort), "reset", s.cfg.Etcd.Reset)
	// The client URL is recorded before the spawn so `k3sm snapshot save` can find the
	// member as soon as it serves, quorum or not.
	rec := EtcdStatus{UpdatedAt: s.etcd.clock.Now().UTC(),
		ClientURL: etcdClientURL(s.cfg.KinePort), MemberName: s.cfg.Etcd.Name,
		ExpectedPeerURL: etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort)}
	if err := writeEtcdStatus(s.cfg.WorkDir, rec); err != nil {
		return nil, err
	}
	c, err := s.spawn(ctx, etcdComponent, etcdArgs(in)...)
	if err != nil {
		return nil, err
	}
	// ...and the pid right after it, the record `k3sm snapshot restore` checks.
	pid := c.cmd.Process.Pid
	s.mu.Lock()
	s.etcdPID = pid
	s.mu.Unlock()
	rec.PID = pid
	if err := writeEtcdStatus(s.cfg.WorkDir, rec); err != nil {
		s.cfg.Logger.Warn("could not record the etcd member's pid", "component", etcdComponent, "err", err)
	}
	return c, nil
}

// bringUpEtcdMember is the etcd posture's datastore bring-up, in the order the
// supervision contract fixes:
//
//  1. spawn, and wait (bounded, fail-fast) for the loopback client port to accept;
//  2. mark the child supervised — from here its death is a CRASH and counts;
//  3. on ANY boot of a joining member, ask the member whether it is still a learner
//     and, if so, run the promote loop (no expiry);
//  4. wait for quorum (no expiry, outside every bring-up deadline);
//  5. the post-quorum checks (local defragment, peer-URL drift, even quorum);
//  6. start the background watcher.
func (s *Supervised) bringUpEtcdMember(ctx context.Context) error {
	memberExists := EtcdMemberExists(s.cfg.WorkDir)
	etcd, err := s.startEtcd(ctx, memberExists, nil)
	if err != nil {
		return bringUpErr(etcdComponent, PhaseBringUp, fmt.Errorf("start etcd: %w", err))
	}
	if err := awaitHealthy(ctx, etcd.name, etcd.exited, etcd.exitedNow, s.etcd.ready(s.cfg.KinePort), componentReadyTimeout, 300*time.Millisecond, etcd.exitDetail); err != nil {
		return bringUpErr(etcd.name, PhaseBringUp, fmt.Errorf("etcd not listening: %w", err))
	}
	if err := s.markSupervised(etcd); err != nil {
		return err
	}
	admin, err := s.etcd.dial(ctx, s.cfg.WorkDir, etcdClientURL(s.cfg.KinePort))
	if err != nil {
		return bringUpErr(etcd.name, PhaseBringUp, err)
	}
	s.mu.Lock()
	s.etcdAdmin = admin
	s.mu.Unlock()
	if err := s.promoteAndAwaitQuorum(ctx, admin, etcd); err != nil {
		return bringUpErr(etcd.name, PhaseBringUp, err)
	}
	s.afterEtcdQuorum(ctx, admin)
	s.startEtcdWatcher(ctx, admin)
	return nil
}

// promoteAndAwaitQuorum is bring-up steps 3 and 4 for a member whose etcd is spawned,
// listening and supervised.
//
// The learner question is asked of the member itself on every boot of a joining
// member, not inferred from whether its data dir existed: a joiner restarted after its
// learner first started but before the promotion landed restarts from its data dir as
// a LEARNER, and a learner never reaches quorum on its own (its apiserver would point
// at a member that refuses it, forever). The member's Status answer carries the flag;
// MemberList cannot be asked, because etcd refuses it on a learner (only Status and
// serializable Range are served there).
func (s *Supervised) promoteAndAwaitQuorum(ctx context.Context, m etcdMembers, c *component) error {
	if s.cfg.Etcd.Role == EtcdJoin {
		learner, err := s.etcdSelfIsLearner(ctx, m, c)
		if err != nil {
			return err
		}
		switch {
		case !learner:
		case s.cfg.Etcd.Promote != nil:
			if err := s.promoteLearner(ctx, c); err != nil {
				return err
			}
		default:
			if err := s.awaitStrandedLearner(ctx, m, c); err != nil {
				return err
			}
		}
	}
	if err := s.awaitEtcdQuorum(ctx, m, c); err != nil {
		return err
	}
	// Quorum among stale members is still the wrong cluster: two of three servers
	// left on the data a restore replaced elect a leader between them. Ask once more
	// with quorum in hand, before anything serves from it.
	return s.checkPeers(ctx, m)
}

// etcdSelfIsLearner asks the local member whether it is a learner, retrying every
// etcdQuorumPoll with no expiry until it answers (a member that has just opened its
// client port may still be loading its backend). It ends early only on ctx or the
// etcd child exiting.
func (s *Supervised) etcdSelfIsLearner(ctx context.Context, m etcdMembers, c *component) (bool, error) {
	clk := s.etcd.clock
	var lastLog time.Time
	for {
		cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
		st, err := m.Status(cctx)
		cancel()
		if err == nil {
			if st.IsLearner {
				s.cfg.Logger.Info("this etcd member is a learner; it must be promoted before the cluster counts it",
					"component", etcdComponent, "member", s.cfg.Etcd.Name)
			}
			return st.IsLearner, nil
		}
		if now := clk.Now(); lastLog.IsZero() || now.Sub(lastLog) >= etcdQuorumLogEvery {
			lastLog = now
			s.cfg.Logger.Info("asking the local etcd member whether it is a learner; retrying", "component", etcdComponent,
				"retry-in", etcdQuorumPoll, "err", err)
		}
		if err := s.etcdWaitTick(ctx, c, etcdQuorumPoll, "while asking whether it is a learner"); err != nil {
			return false, err
		}
	}
}

// EtcdStrandedLearnerRemedy is the fix named when a joining member is still a learner
// and this boot has no way to ask for its promotion.
const EtcdStrandedLearnerRemedy = "this server's etcd member is a learner that was never promoted: re-run it with --server <an existing server's address> and --token <the server token> so it can ask that server for the promotion, or wipe this server's etcd data dir (<work-dir>/etcd) and re-join it"

// etcdStrandedLogEvery is how often a learner with no way to be promoted says so.
const etcdStrandedLogEvery = 60 * time.Second

// awaitStrandedLearner is the wait of a learner whose boot carries no Promote (a
// restarted joiner started without --server/--token). It is a wait, never a crash:
// the remedy is logged at ERROR every etcdStrandedLogEvery, and the member is
// re-asked every etcdQuorumPoll so a promotion made some other way (an operator on an
// existing server) ends the wait. It ends early only on ctx or the etcd child exiting.
func (s *Supervised) awaitStrandedLearner(ctx context.Context, m etcdMembers, c *component) error {
	clk := s.etcd.clock
	start := clk.Now()
	var lastLog time.Time
	for {
		if now := clk.Now(); lastLog.IsZero() || now.Sub(lastLog) >= etcdStrandedLogEvery {
			lastLog = now
			s.cfg.Logger.Error("this etcd member is a learner and this boot cannot ask for its promotion; waiting",
				"component", etcdComponent, "member", s.cfg.Etcd.Name, "waited", now.Sub(start).Round(time.Second),
				"remedy", EtcdStrandedLearnerRemedy)
		}
		if err := s.etcdWaitTick(ctx, c, etcdQuorumPoll, "while waiting as an unpromoted learner"); err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
		st, err := m.Status(cctx)
		cancel()
		if err == nil && !st.IsLearner {
			s.cfg.Logger.Info("etcd learner was promoted elsewhere; continuing", "component", etcdComponent,
				"member", s.cfg.Etcd.Name)
			return nil
		}
	}
}

// etcdWaitTick waits d on the etcd clock, ending early on ctx or the child exiting.
// A ctx that ends because the child died (the daemon's exit callback cancels it)
// reports the death, not a bare cancellation: the exited channel is closed before the
// callback runs, so it is checked first.
func (s *Supervised) etcdWaitTick(ctx context.Context, c *component, d time.Duration, during string) error {
	select {
	case <-ctx.Done():
		select {
		case <-c.exited:
			return s.etcdExitedErr(c, during)
		default:
		}
		return ctx.Err()
	case <-c.exited:
		return s.etcdExitedErr(c, during)
	case <-s.etcd.clock.After(d):
		return nil
	}
}

// etcdExitedErr is the error a no-expiry wait returns when the member died under it.
//
// The child is supervised by now, so two observers see the one death: its reaper,
// which reports it through OnComponentExit, and this wait, whose error ends bring-up
// and is counted by the caller. Exactly one of them may report it, decided under mu
// by the component's reported flag (markSupervised's discipline). The reaper takes
// its decision before it closes exited, so by the time this wait has seen the death
// that decision is made: when the reaper took it (the usual case for a supervised
// member), the error wraps ErrEtcdChildExited so the caller does not count it again;
// when the reaper will not report (no callback is set), this wait claims the report
// and the plain error is the one record.
func (s *Supervised) etcdExitedErr(c *component, during string) error {
	s.mu.Lock()
	claimed := !c.reported
	if claimed {
		c.reported = true
	}
	s.mu.Unlock()
	if claimed {
		return etcdExitDetail(c, during)
	}
	return fmt.Errorf("%w: %w", ErrEtcdChildExited, etcdExitDetail(c, during))
}

// etcdExitDetail describes a dead member: the Wait error and the redacted log tail.
// Safe without the lock: waitErr is written strictly before exited closes, and every
// caller has observed that close.
func etcdExitDetail(c *component, during string) error {
	return fmt.Errorf("%s exited %s: %v; last log lines (%s):\n%s", c.name, during, c.waitErr, c.logPath, RedactedLogTail(c.logPath))
}

// promoteLearner calls Config.Etcd.Promote until it succeeds. A failure is logged
// and retried every etcdPromoteInterval with no expiry: an existing server that is
// briefly unreachable, or a learner still catching up, is a wait, never a crash. It
// ends early only on ctx or the etcd child exiting.
func (s *Supervised) promoteLearner(ctx context.Context, c *component) error {
	for attempt := 1; ; attempt++ {
		err := s.cfg.Etcd.Promote(ctx)
		if err == nil {
			s.cfg.Logger.Info("etcd learner promoted to a voting member", "component", etcdComponent, "attempts", attempt)
			return nil
		}
		s.cfg.Logger.Info("etcd learner not promoted yet; retrying", "component", etcdComponent,
			"attempt", attempt, "retry-in", etcdPromoteInterval, "err", err)
		if err := s.etcdWaitTick(ctx, c, etcdPromoteInterval, "while waiting for promotion"); err != nil {
			return err
		}
	}
}

// awaitEtcdQuorum blocks until the local member reports a leader AND the cluster has
// no active alarm.
//
// It has NO expiry and records nothing: a peer that is powered off for an hour leaves
// this server waiting, logging every etcdQuorumLogEvery, and it comes up the moment
// the peer returns — never parked by the crash-loop breaker, because a missing peer
// is not this server's failure. It ends only on quorum, on ctx, or on the etcd child
// exiting, which IS a crash and is returned so bring-up stops — reported exactly once
// between the reaper and the returned error (etcdExitedErr).
func (s *Supervised) awaitEtcdQuorum(ctx context.Context, m etcdMembers, c *component) error {
	clk := s.etcd.clock
	start := clk.Now()
	lastLog := start
	var lastProbe time.Time
	for {
		select {
		case <-c.exited:
			return s.etcdExitedErr(c, "while waiting for quorum")
		default:
		}
		q := readEtcdQuorum(ctx, m)
		// A member whose cluster was restored elsewhere never reaches quorum with its
		// old peers' help: say so and stop, instead of waiting forever.
		if now := clk.Now(); !q.ok() && (lastProbe.IsZero() || now.Sub(lastProbe) >= etcdSupersededProbeEvery) {
			lastProbe = now
			if err := s.checkPeers(ctx, m); err != nil {
				return err
			}
		}
		if q.ok() {
			s.cfg.Logger.Info("etcd quorum reached", "component", etcdComponent, "waited", clk.Now().Sub(start).Round(time.Second))
			return nil
		}
		if now := clk.Now(); now.Sub(lastLog) >= etcdQuorumLogEvery {
			lastLog = now
			reachable, members := s.reachableMembers(ctx, m)
			s.cfg.Logger.Info("waiting for etcd quorum", "component", etcdComponent,
				"leader", q.leaderState(), "alarms", q.alarmState(),
				"reachable-members", reachable, "members", members, "waited", now.Sub(start).Round(time.Second))
		}
		if err := s.etcdWaitTick(ctx, c, etcdQuorumPoll, "while waiting for quorum"); err != nil {
			return err
		}
	}
}

// etcdQuorum is one reading of the quorum condition: the local member's leader and
// the cluster's active alarms. Quorum requires BOTH a leader and an empty alarm list
// (ok); the rest exists so the wait's log can say which half is missing.
type etcdQuorum struct {
	statusErr error
	leader    uint64
	// alarmsRead is set once the alarm list was answered; alarmErr when it was asked
	// and failed. It is asked only with a leader (the list goes through raft).
	alarmsRead bool
	alarmErr   error
	alarms     []string
}

// readEtcdQuorum reads the leader and, when there is one, the alarm list.
func readEtcdQuorum(ctx context.Context, m etcdMembers) etcdQuorum {
	cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
	defer cancel()
	var q etcdQuorum
	st, err := m.Status(cctx)
	if err != nil {
		q.statusErr = err
		return q
	}
	q.leader = st.Leader
	if q.leader == 0 {
		return q
	}
	alarms, err := m.AlarmList(cctx)
	if err != nil {
		q.alarmErr = err
		return q
	}
	q.alarmsRead = true
	for _, a := range alarms {
		q.alarms = append(q.alarms, a.Alarm)
	}
	return q
}

// ok is the binding quorum rule: a leader AND an empty alarm list.
func (q etcdQuorum) ok() bool { return q.leader != 0 && q.alarmsRead && len(q.alarms) == 0 }

// leaderState renders the leader half for the wait's log.
func (q etcdQuorum) leaderState() string {
	switch {
	case q.statusErr != nil:
		return "unknown (the local member did not answer: " + q.statusErr.Error() + ")"
	case q.leader == 0:
		return "none"
	}
	return strconv.FormatUint(q.leader, 16)
}

// alarmState renders the alarm half for the wait's log: the active alarms by name
// (NOSPACE keeps a cluster read-only, which is why the wait has not ended).
func (q etcdQuorum) alarmState() string {
	switch {
	case q.leader == 0:
		return "unknown (asked only once a leader exists)"
	case q.alarmErr != nil:
		return "unknown (the alarm list did not answer: " + q.alarmErr.Error() + ")"
	case len(q.alarms) == 0:
		return "none"
	}
	return strings.Join(q.alarms, ",")
}

// reachableMembers counts the members whose peer listener accepts TCP (this member
// counts itself), from the local member's serializable view.
func (s *Supervised) reachableMembers(ctx context.Context, m etcdMembers) (reachable, total int) {
	cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
	defer cancel()
	members, err := m.MemberList(cctx)
	if err != nil {
		return 0, 0
	}
	own := etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort)
	for _, mem := range members {
		if slices.Contains(mem.PeerURLs, own) {
			reachable++
			continue
		}
		for _, pu := range mem.PeerURLs {
			if u, err := url.Parse(pu); err == nil && s.etcd.dialPeer(cctx, u.Host) {
				reachable++
				break
			}
		}
	}
	return reachable, len(members)
}

// afterEtcdQuorum runs the one-shot post-quorum checks and records the status. Every
// failure in here is logged and non-fatal: the cluster is serving, and none of these
// is a reason to stop it.
//
//   - Defragment the LOCAL member only (the k3s behaviour): after a cold restart of
//     every server each defragments itself, so no two defrags ever target one member.
//   - Compare this member's registered peer URL with https://<PeerIP>:<PeerPort>. A
//     mismatch (a DHCP lease that moved) is an ERROR naming the remedy and is
//     recorded for `k3sm status`; it never restarts anything.
//   - WARN when the voting member count is even (no better fault tolerance than one
//     fewer member).
func (s *Supervised) afterEtcdQuorum(ctx context.Context, m etcdMembers) EtcdStatus {
	log := s.cfg.Logger
	client := etcdClientURL(s.cfg.KinePort)
	cctx, cancel := context.WithTimeout(ctx, 2*etcdCallTimeout)
	defer cancel()

	before, berr := m.Status(cctx)
	if err := m.Defragment(cctx, client); err != nil {
		log.Error("etcd defragment of the local member failed; continuing", "component", etcdComponent,
			"endpoint", client, "err", err)
	} else if after, aerr := m.Status(cctx); berr == nil && aerr == nil {
		log.Info("etcd defragmented the local member", "component", etcdComponent, "endpoint", client,
			"db-size-before", before.DBSize, "db-size-after", after.DBSize)
	}

	st := s.collectEtcdStatus(cctx, m)
	if st.PeerURLDrift {
		log.Error("this etcd member's registered peer URL is not this server's current node IP; peers will keep dialling the old address",
			"component", etcdComponent, "registered", st.RegisteredPeerURLs, "expected", st.ExpectedPeerURL,
			"remedy", EtcdPeerURLDriftRemedy)
	}
	if st.Members > 0 && st.Members%2 == 0 {
		log.Warn("the etcd cluster has an even number of voting members; it tolerates no more failures than one fewer member would",
			"component", etcdComponent, "voting-members", st.Members)
	}
	if err := writeEtcdStatus(s.cfg.WorkDir, st); err != nil {
		log.Warn("could not record the etcd status", "component", etcdComponent, "err", err)
	}
	return st
}

// EtcdPeerURLDriftRemedy is the fix named when a member's registered peer URL no
// longer matches its node IP.
const EtcdPeerURLDriftRemedy = "server node IPs must be stable (a DHCP reservation): restore the previous etcd peer address (--etcd-peer-ip), or remove this member through another server and re-join it with a wiped etcd data dir"

// collectEtcdStatus reads the local member, the member list and the alarms into a
// status record. Fields it cannot read stay zero.
func (s *Supervised) collectEtcdStatus(ctx context.Context, m etcdMembers) EtcdStatus {
	s.mu.Lock()
	pid := s.etcdPID
	s.mu.Unlock()
	st := EtcdStatus{
		UpdatedAt:       s.etcd.clock.Now().UTC(),
		ClientURL:       etcdClientURL(s.cfg.KinePort),
		MemberName:      s.cfg.Etcd.Name,
		ExpectedPeerURL: etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort),
		PID:             pid,
	}
	local, err := m.Status(ctx)
	if err == nil {
		st.MemberID = local.MemberID
		st.LeaderID = local.Leader
		st.LeaderPresent = local.Leader != 0
		st.DBSizeBytes, st.DBSizeInUseBytes, st.QuotaBytes = local.DBSize, local.DBSizeInUse, local.DBSizeQuota
	}
	if members, err := m.MemberList(ctx); err == nil {
		for _, mem := range members {
			if mem.IsLearner {
				st.Learners++
			} else {
				st.Members++
			}
			if (local.MemberID != 0 && mem.ID == local.MemberID) || (local.MemberID == 0 && mem.Name == s.cfg.Etcd.Name) {
				st.RegisteredPeerURLs = mem.PeerURLs
			}
		}
		st.PeerURLDrift = st.RegisteredPeerURLs != nil &&
			!(len(st.RegisteredPeerURLs) == 1 && st.RegisteredPeerURLs[0] == st.ExpectedPeerURL)
	}
	if st.LeaderPresent {
		if alarms, err := m.AlarmList(ctx); err == nil {
			for _, a := range alarms {
				st.Alarms = append(st.Alarms, a.Alarm)
			}
		}
	}
	return st
}

// startEtcdWatcher runs the background watcher for the supervisor's lifetime: ctx's,
// cut short by Stop. It logs every leader change at INFO, repeats an active NOSPACE
// alarm at ERROR every etcdAlarmLogEvery (the cluster is read-only, not down, so it is
// not a crash), and refreshes the status record on the same cadence.
func (s *Supervised) startEtcdWatcher(ctx context.Context, m etcdMembers) {
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.etcdWatchStop, s.etcdWatchDone = cancel, done
	s.mu.Unlock()
	go func() {
		defer close(done)
		s.watchEtcd(wctx, m)
	}()
}

// watchEtcd is the watcher's loop body.
func (s *Supervised) watchEtcd(ctx context.Context, m etcdMembers) {
	clk := s.etcd.clock
	log := s.cfg.Logger
	var leader uint64
	if st, err := m.Status(ctx); err == nil {
		leader = st.Leader
	}
	lastRefresh := clk.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-clk.After(etcdWatchPoll):
		}
		cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
		if st, err := m.Status(cctx); err == nil && st.Leader != leader {
			log.Info("etcd leader changed", "component", etcdComponent, "from", leader, "to", st.Leader)
			leader = st.Leader
		}
		if now := clk.Now(); now.Sub(lastRefresh) >= etcdAlarmLogEvery {
			lastRefresh = now
			st := s.collectEtcdStatus(cctx, m)
			if f := s.probePeers(cctx, m); f.superseded != nil || len(f.foreign) > 0 {
				f.apply(&st)
				if f.superseded != nil {
					log.Error(EtcdMemberSupersededMessage, "component", etcdComponent, "detail", st.SupersededDetail,
						"remedy", st.SupersededRemedy)
				}
				if st.ForeignPeer != "" {
					log.Warn(EtcdPeerForeignMessage, "component", etcdComponent, "detail", st.ForeignPeer)
				}
			}
			if slices.Contains(st.Alarms, etcdAlarmNoSpace) {
				log.Error("etcd NOSPACE alarm is active: the cluster is read-only until space is reclaimed (compact, defragment, then disarm the alarm)",
					"component", etcdComponent, "db-size", st.DBSizeBytes, "quota", st.QuotaBytes)
			}
			if err := writeEtcdStatus(s.cfg.WorkDir, st); err != nil {
				log.Debug("could not refresh the etcd status record", "err", err)
			}
		}
		cancel()
	}
}

// stopEtcdWatcher cancels the watcher and waits for it (bounded by ctx), then closes
// the admin client. Called by Stop BEFORE the etcd child is signalled.
func (s *Supervised) stopEtcdWatcher(ctx context.Context) {
	s.mu.Lock()
	stop, done, admin := s.etcdWatchStop, s.etcdWatchDone, s.etcdAdmin
	s.etcdWatchStop, s.etcdWatchDone, s.etcdAdmin = nil, nil, nil
	s.mu.Unlock()
	if stop != nil {
		stop()
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	if admin != nil {
		_ = admin.Close()
	}
}

// EtcdStatus is the record a server in the etcd posture keeps for `k3sm status`: the
// cluster as this member last saw it. It is a report, never an input to any decision.
type EtcdStatus struct {
	UpdatedAt time.Time `json:"updatedAt"`
	// ClientURL is the member's loopback client URL.
	ClientURL  string `json:"clientURL"`
	MemberName string `json:"memberName"`
	MemberID   uint64 `json:"memberID,omitempty"`
	// Members counts voting members, Learners the not-yet-promoted ones.
	Members  int `json:"members"`
	Learners int `json:"learners"`
	// LeaderPresent and LeaderID are the local member's view.
	LeaderPresent bool   `json:"leaderPresent"`
	LeaderID      uint64 `json:"leaderID,omitempty"`
	// DBSizeBytes / DBSizeInUseBytes / QuotaBytes are the local backend's sizes.
	DBSizeBytes      int64 `json:"dbSizeBytes"`
	DBSizeInUseBytes int64 `json:"dbSizeInUseBytes"`
	QuotaBytes       int64 `json:"quotaBytes"`
	// Alarms are the active alarms ("NOSPACE", ...).
	Alarms []string `json:"alarms,omitempty"`
	// ExpectedPeerURL is https://<node IP>:<peer port>; RegisteredPeerURLs what the
	// cluster has for this member. PeerURLDrift is set when they differ.
	ExpectedPeerURL    string   `json:"expectedPeerURL"`
	RegisteredPeerURLs []string `json:"registeredPeerURLs,omitempty"`
	PeerURLDrift       bool     `json:"peerURLDrift"`
	// WALFsyncP99Seconds is the local WAL fsync p99 from the metrics endpoint, when
	// something has measured it; nil when not.
	WALFsyncP99Seconds *float64 `json:"walFsyncP99Seconds,omitempty"`
	// PID is the etcd child's pid, so `k3sm snapshot restore` can refuse while a
	// member this work dir started is still alive (a server killed with SIGKILL can
	// leave it behind).
	PID int `json:"pid,omitempty"`
	// Superseded is set when a peer registered in this member's cluster answers as
	// the only member of another cluster, at a revision past a restore's bump: the
	// cluster was restored elsewhere and this member's data belongs to the one it
	// replaced. SupersededDetail names the peer and both IDs; SupersededRemedy is the
	// fix, verification first.
	Superseded       bool   `json:"superseded,omitempty"`
	SupersededDetail string `json:"supersededDetail,omitempty"`
	SupersededRemedy string `json:"supersededRemedy,omitempty"`
	// ForeignPeer names any peer that answers for another cluster WITHOUT the shape of
	// a restore (a Mac reinstalled at a server's address, say): a warning, never a
	// reason to stop.
	ForeignPeer string `json:"foreignPeer,omitempty"`
}

// etcdStatusName is the status record's basename. It lives beside the data dir, not
// in it: etcd warns about unexpected entries in its data dir.
const etcdStatusName = "etcd-status.json"

// EtcdStatusPath is the status record's path for a work dir.
func EtcdStatusPath(workDir string) string { return filepath.Join(workDir, etcdStatusName) }

// ReadEtcdStatus loads the status record.
func ReadEtcdStatus(workDir string) (EtcdStatus, error) {
	var st EtcdStatus
	b, err := os.ReadFile(EtcdStatusPath(workDir))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return EtcdStatus{}, fmt.Errorf("parse %s: %w", EtcdStatusPath(workDir), err)
	}
	return st, nil
}

// writeEtcdStatus persists st atomically, 0600.
func writeEtcdStatus(workDir string, st EtcdStatus) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(EtcdStatusPath(workDir), append(b, '\n'), 0o600)
}

// The peer cluster-ID check. `k3sm snapshot restore` rebuilds a cluster with a new
// cluster ID; a member left on the replaced data must be told, not left waiting for a
// quorum that cannot form. But one peer answering for another cluster is not, by
// itself, proof of a restore: a Mac reinstalled by mistake at a server's address
// answers for a fresh cluster too, and parking a healthy majority on its word, with a
// remedy that deletes this member's data, would turn that mistake into data loss. So
// a park needs the shape a restore leaves and nothing else does: the differing peer
// lists ONLY ITSELF and its store's revision is at or past the restore's bump. Any
// other differing peer is a warning to check that peer.
const (
	// etcdSupersededProbeEvery is how often the quorum wait asks the peers.
	etcdSupersededProbeEvery = 10 * time.Second
	// etcdPeerProbeTimeout bounds one peer's answers; peers are asked concurrently,
	// so a blackholed peer costs one bound, not one per peer.
	etcdPeerProbeTimeout = 2 * time.Second
	// EtcdMemberSupersededMessage is the status row's and the log's sentence for a
	// member whose cluster a restore replaced.
	EtcdMemberSupersededMessage = "this server's etcd member belongs to a cluster that was reset or restored"
	// EtcdPeerForeignMessage is the warning for a peer answering for another cluster
	// without the shape of a restore.
	EtcdPeerForeignMessage = "a peer answers for a different etcd cluster; check it"
)

// ErrEtcdMemberSuperseded matches an *EtcdSupersededError: a bring-up whose member
// belongs to a cluster a restore replaced. It is PERMANENT: every restart finds the
// same data dir.
var ErrEtcdMemberSuperseded = errors.New("executor: " + EtcdMemberSupersededMessage)

// EtcdSupersededError is the evidence a park rests on: the peer, its cluster and
// revision, and this member's cluster.
type EtcdSupersededError struct {
	Peer, PeerURL           string
	PeerCluster, OwnCluster uint64
	PeerRevision            int64
}

func (e *EtcdSupersededError) Error() string {
	return fmt.Sprintf("%v: peer %s at %s answers as the only member of cluster %x at revision %d (at or past the %d a restore adds); this member's cluster is %x",
		ErrEtcdMemberSuperseded, e.Peer, e.PeerURL, e.PeerCluster, e.PeerRevision, EtcdRestoreRevisionBump, e.OwnCluster)
}

// Is makes errors.Is(err, ErrEtcdMemberSuperseded) match.
func (e *EtcdSupersededError) Is(target error) bool { return target == ErrEtcdMemberSuperseded }

// Remedy is the fix, verification first: the destructive step is only right if the
// peer really is the server the operator restored.
func (e *EtcdSupersededError) Remedy() string {
	return fmt.Sprintf("confirm %s (%s, cluster %x) is the server you restored; then wipe <work-dir>/etcd and re-join: stop this server, move <work-dir>/etcd aside, clear the crash-loop record (k3sm server --clear-crashloop) and start it, and it joins the restored cluster as a new member (this member's cluster %x is the one the restore replaced)",
		e.Peer, e.PeerURL, e.PeerCluster, e.OwnCluster)
}

// EtcdPeerView is what a peer's listener reports about its cluster.
type EtcdPeerView struct {
	// ClusterID is the peer's cluster; Members how many members it lists.
	ClusterID uint64
	Members   int
	// Revision is the peer store's current revision. It is read only when the
	// cluster IDs differ (0 otherwise).
	Revision int64
}

// peerFindingKind classifies one peer's answer.
type peerFindingKind int

const (
	peerSameOrUnknown peerFindingKind = iota
	// peerSupersedes: a single-member cluster past the restore bump.
	peerSupersedes
	// peerForeign: a different cluster without the shape of a restore.
	peerForeign
)

// classifyPeer decides what one peer's answer proves. Pure.
func classifyPeer(v EtcdPeerView, err error, own uint64) peerFindingKind {
	switch {
	case err != nil, v.ClusterID == 0, own == 0, v.ClusterID == own:
		return peerSameOrUnknown
	case v.Members == 1 && v.Revision >= int64(EtcdRestoreRevisionBump):
		return peerSupersedes
	}
	return peerForeign
}

// peerFindings is the result of asking every other member.
type peerFindings struct {
	superseded *EtcdSupersededError
	// foreign names each peer that answered for another cluster without the shape
	// of a restore.
	foreign []string
}

// probePeers asks every OTHER member in the local member's view, concurrently and
// each within etcdPeerProbeTimeout. A local member that cannot say its own cluster
// yet, or a peer that does not answer, proves nothing.
func (s *Supervised) probePeers(ctx context.Context, m etcdMembers) peerFindings {
	var out peerFindings
	if s.etcd.peerView == nil {
		return out
	}
	st, err := m.Status(ctx)
	if err != nil || st.ClusterID == 0 {
		return out
	}
	members, err := m.MemberList(ctx)
	if err != nil {
		return out
	}
	own := etcdPeerURL(s.cfg.Etcd.PeerIP, s.cfg.Etcd.PeerPort)
	type answer struct {
		name, url string
		view      EtcdPeerView
		err       error
	}
	var asks []answer
	for _, mem := range members {
		if mem.ID == st.MemberID || slices.Contains(mem.PeerURLs, own) {
			continue
		}
		for _, pu := range mem.PeerURLs {
			asks = append(asks, answer{name: mem.Name, url: pu})
		}
	}
	var wg sync.WaitGroup
	for i := range asks {
		wg.Add(1)
		go func(a *answer) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, etcdPeerProbeTimeout)
			defer cancel()
			a.view, a.err = s.etcd.peerView(pctx, s.cfg.WorkDir, a.url, st.ClusterID)
		}(&asks[i])
	}
	wg.Wait()
	for _, a := range asks {
		switch classifyPeer(a.view, a.err, st.ClusterID) {
		case peerSupersedes:
			if out.superseded == nil {
				out.superseded = &EtcdSupersededError{Peer: a.name, PeerURL: a.url, PeerCluster: a.view.ClusterID,
					OwnCluster: st.ClusterID, PeerRevision: a.view.Revision}
			}
		case peerForeign:
			out.foreign = append(out.foreign, fmt.Sprintf("peer %s at %s answers for cluster %x (%d member(s), revision %d); this member's cluster is %x",
				a.name, a.url, a.view.ClusterID, a.view.Members, a.view.Revision, st.ClusterID))
		}
	}
	return out
}

// apply records the findings on a status record.
func (f peerFindings) apply(st *EtcdStatus) {
	if f.superseded != nil {
		st.Superseded, st.SupersededDetail, st.SupersededRemedy = true, f.superseded.Error(), f.superseded.Remedy()
	}
	if len(f.foreign) > 0 {
		st.ForeignPeer = strings.Join(f.foreign, "; ")
	}
}

// checkPeers is the bring-up's use of probePeers: a superseded member is recorded
// and refused (the error wraps an *EtcdSupersededError); a foreign peer is a warning,
// recorded, and bring-up continues.
func (s *Supervised) checkPeers(ctx context.Context, m etcdMembers) error {
	f := s.probePeers(ctx, m)
	if f.superseded == nil && len(f.foreign) == 0 {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
	st := s.collectEtcdStatus(cctx, m)
	cancel()
	f.apply(&st)
	if err := writeEtcdStatus(s.cfg.WorkDir, st); err != nil {
		s.cfg.Logger.Warn("could not record the etcd status", "component", etcdComponent, "err", err)
	}
	if len(f.foreign) > 0 {
		s.cfg.Logger.Warn(EtcdPeerForeignMessage, "component", etcdComponent, "detail", st.ForeignPeer)
	}
	if f.superseded != nil {
		s.cfg.Logger.Error(EtcdMemberSupersededMessage, "component", etcdComponent, "detail", f.superseded.Error(),
			"remedy", f.superseded.Remedy())
		return f.superseded
	}
	return nil
}

// peerView asks the etcd peer listener at peerURL about its cluster, over the peer
// CA's mutual TLS with this server's peer identity: the X-Etcd-Cluster-ID header and
// the member list of its /members answer and, only when that cluster is not own, the
// current revision from /members/hashkv (the peer route etcd's own corruption check
// uses; a peer's client API listens on its loopback and cannot be asked).
func peerView(ctx context.Context, workDir, peerURL string, own uint64) (EtcdPeerView, error) {
	p := certs.EtcdCertPaths(workDir)
	pair, err := tls.LoadX509KeyPair(p.PeerServerClientCert, p.PeerServerClientKey)
	if err != nil {
		return EtcdPeerView{}, fmt.Errorf("load the etcd peer identity: %w", err)
	}
	caPEM, err := os.ReadFile(p.PeerCACert)
	if err != nil {
		return EtcdPeerView{}, fmt.Errorf("read the etcd peer CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return EtcdPeerView{}, errors.New("the etcd peer CA file holds no certificate")
	}
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	defer client.CloseIdleConnections()
	base := strings.TrimRight(peerURL, "/")

	var v EtcdPeerView
	var members []json.RawMessage
	h, err := peerGet(ctx, client, base+"/members", "", nil, &members)
	if err != nil {
		return v, err
	}
	if v.ClusterID, err = strconv.ParseUint(h.Get("X-Etcd-Cluster-ID"), 16, 64); err != nil {
		return v, fmt.Errorf("%s answered without a cluster ID: %w", peerURL, err)
	}
	v.Members = len(members)
	if v.ClusterID == own {
		return v, nil
	}
	var hash struct {
		Header struct {
			Revision int64 `json:"revision"`
		} `json:"header"`
	}
	if _, err := peerGet(ctx, client, base+"/members/hashkv", h.Get("X-Etcd-Cluster-ID"), []byte("{}"), &hash); err != nil {
		return v, err
	}
	v.Revision = hash.Header.Revision
	return v, nil
}

// peerGet GETs url (with body, for hashkv) and decodes the JSON answer into out.
func peerGet(ctx context.Context, client *http.Client, url, clusterID string, body []byte, out any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if clusterID != "" {
		req.Header.Set("X-Etcd-Cluster-ID", clusterID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered HTTP %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", url, err)
	}
	return resp.Header, nil
}
