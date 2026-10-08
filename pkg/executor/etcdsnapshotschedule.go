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
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Scheduled etcd snapshots, the k3s behaviour: every server takes a snapshot of its
// own member on a cron schedule (k3s's default, every 12 hours) into
// <WorkDir>/db/snapshots, and keeps the newest N of them (default 5).
//
// The loop starts once the member has quorum and the post-quorum checks have run,
// and Stop ends it BEFORE anything else in the teardown: it streams from the admin
// client the watcher holds and from the member Stop is about to kill. Each tick goes
// through saveEtcdSnapshot, the path `k3sm snapshot save` uses, so a scheduled file
// is verified and 0600 exactly like a manual one.
//
// The loop does not sleep until the next cron minute on one timer: a Mac's monotonic
// timers stop while it sleeps, and the wall clock can be stepped. It wakes at least
// every etcdSnapshotWakeEvery and compares the wall clock with the due time, so a Mac
// that slept through one or several cron minutes takes ONE catch-up snapshot on wake
// (logged as late), never a burst.
//
// Retention deletes, so it is narrow on purpose. It runs only after a snapshot has
// been written and verified (a failing schedule never eats the snapshots it has), it
// considers only names this schedule writes for THIS node, so a manual
// `k3sm snapshot save` file (k3sm-etcd-snapshot-<stamp>.db) or a file another
// server's schedule left on a shared directory is never touched, and it never
// deletes the snapshot the tick just took. Snapshots are ordered by the earlier of
// the name's stamp and the file's mtime, and one dated after the current time (taken
// under a clock that was wrong) sorts as the oldest, so it cannot evict real ones.
// A node renamed since its snapshots were taken leaves them under the old name for
// the operator to remove; the schedule never deletes a name it did not write.
//
// At start the schedule removes the partial `.tmp` files its own earlier runs may
// have left (this node's prefix, regular files only, never through a symlink) and
// makes the snapshots directory 0700 when this process owns it.
//
// A tick is skipped, with a warning, when the snapshot directory's volume has less
// free space than snapshotFreeSpaceFactor times the last snapshot's size: a
// snapshot schedule that fills the disk the datastore lives on breaks the cluster it
// exists to protect. A skip and a failure are recorded for `k3sm status` until the
// next success.
//
// The kine posture has no schedule, as in k3s, where the snapshot schedule is an
// etcd feature and a SQLite server is backed up by copying its database file.

const (
	// DefaultEtcdSnapshotCron is k3s's --etcd-snapshot-schedule-cron default:
	// minute 0 of every 12th hour, local time.
	DefaultEtcdSnapshotCron = "0 */12 * * *"
	// DefaultEtcdSnapshotRetention is k3s's --etcd-snapshot-retention default.
	DefaultEtcdSnapshotRetention = 5
	// scheduledSnapshotPrefix starts every scheduled snapshot's name, k3s's
	// etcd-snapshot-<node>-<unix seconds>.
	scheduledSnapshotPrefix = "etcd-snapshot-"
	// etcdScheduledSnapshotTimeout bounds one scheduled snapshot's stream.
	etcdScheduledSnapshotTimeout = 10 * time.Minute
	// etcdSnapshotWakeEvery is the longest the loop waits before it re-reads the wall
	// clock, so a sleep or a clock step delays a due snapshot by at most this much.
	etcdSnapshotWakeEvery = time.Minute
	// etcdSnapshotLateAfter is how far past its due minute a tick has to run before
	// it is logged as a late catch-up.
	etcdSnapshotLateAfter = 2 * etcdSnapshotWakeEvery
	// Skip reasons recorded in EtcdSnapshotSkip.Reason.
	EtcdSnapshotSkipSpace = "space" // the volume has less free space than the floor
	EtcdSnapshotSkipError = "error" // the free space could not be read
)

// EtcdSnapshotSkip is a scheduled snapshot that was not attempted.
type EtcdSnapshotSkip struct {
	At time.Time `json:"at"`
	// Reason is EtcdSnapshotSkipSpace or EtcdSnapshotSkipError; Detail the message.
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

// ErrEtcdSnapshotRetention reports a schedule asked to keep fewer than one snapshot.
var ErrEtcdSnapshotRetention = errors.New("executor: the etcd snapshot retention must keep at least one snapshot")

// EtcdSnapshotSchedule configures the scheduled snapshots of an etcd-posture server.
// A nil *EtcdSnapshotSchedule on EtcdConfig is no schedule
// (`k3sm server --etcd-disable-snapshots`).
type EtcdSnapshotSchedule struct {
	// Cron is when a snapshot is taken, in the server's local time.
	Cron *CronSchedule
	// Retention is how many of this node's scheduled snapshots are kept. At least 1.
	Retention int
}

// validate checks the schedule's own fields.
func (s *EtcdSnapshotSchedule) validate() error {
	if s.Cron == nil {
		return fmt.Errorf("%w: no schedule", ErrCronSpec)
	}
	if s.Retention < 1 {
		return fmt.Errorf("%w (got %d)", ErrEtcdSnapshotRetention, s.Retention)
	}
	return nil
}

// ScheduledEtcdSnapshotName is the basename the schedule writes for node at t:
// etcd-snapshot-<node>-<unix seconds>, the k3s name.
func ScheduledEtcdSnapshotName(node string, t time.Time) string {
	return scheduledSnapshotPrefix + node + "-" + strconv.FormatInt(t.Unix(), 10)
}

// parseScheduledEtcdSnapshot reports whether name is a scheduled snapshot of node,
// and when it was taken. Nothing else matches: not another node's, not a manual
// save's, not a .tmp a failed write left.
func parseScheduledEtcdSnapshot(node, name string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(name, scheduledSnapshotPrefix+node+"-")
	if !ok || rest == "" {
		return time.Time{}, false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return time.Time{}, false
		}
	}
	sec, err := strconv.ParseInt(rest, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, 0).UTC(), true
}

// scheduledSnapshot is one of this node's scheduled snapshots on disk. order is
// what retention sorts by: the earlier of the name's stamp and the file's mtime.
type scheduledSnapshot struct {
	path  string
	taken time.Time
	order time.Time
	size  int64
}

// etcdSnapshotState is the schedule's view for the status record.
type etcdSnapshotState struct {
	// last is the newest scheduled snapshot's time (zero: none), kept how many are
	// on disk.
	last time.Time
	kept int
	// lastErr is the last failed snapshot's error and skipped the last skipped
	// tick; both are cleared by the next success.
	lastErr string
	skipped *EtcdSnapshotSkip
}

// etcdSnapshotScheduler is the schedule loop and its view of what it has kept.
type etcdSnapshotScheduler struct {
	cron      *CronSchedule
	retention int
	dir       string
	node      string
	// loc is the zone the cron expression is read in: the server's local time.
	loc   *time.Location
	clock clock
	// save writes a verified snapshot to dst (saveEtcdSnapshot in production).
	save func(ctx context.Context, dst string) error
	// space refuses a directory with less than want bytes free.
	space func(dir string, want uint64) error
	// dbSize, when non-nil, sizes the floor before the schedule has a snapshot of
	// its own to measure (the member's backend size).
	dbSize func(ctx context.Context) (int64, error)
	log    *slog.Logger

	// mu guards state and lastSize; collectEtcdStatus reads state.
	mu       sync.Mutex
	state    etcdSnapshotState
	lastSize int64
}

// newEtcdSnapshotScheduler builds the scheduler for this server's member: it
// prepares the snapshots directory and reads the snapshots a previous run of this
// server kept, so the status record and the free-space floor are right before the
// first tick.
func (s *Supervised) newEtcdSnapshotScheduler(m etcdMembers) *etcdSnapshotScheduler {
	cfg := s.cfg.Etcd.Snapshots
	sc := &etcdSnapshotScheduler{
		cron:      cfg.Cron,
		retention: cfg.Retention,
		dir:       SnapshotDir(s.cfg.WorkDir),
		node:      s.cfg.Etcd.Name,
		loc:       time.Local,
		clock:     s.etcd.clock,
		save:      func(ctx context.Context, dst string) error { return saveEtcdSnapshot(ctx, m, dst) },
		space:     requireSnapshotSpace,
		dbSize: func(ctx context.Context) (int64, error) {
			st, err := m.Status(ctx)
			return st.DBSize, err
		},
		log: s.cfg.Logger,
	}
	sc.prepare()
	sc.refresh()
	return sc
}

// prepare makes the snapshots directory 0700 and removes this node's own partial
// snapshots. Failures are logged; none of them stops the schedule.
func (sc *etcdSnapshotScheduler) prepare() {
	log := sc.log
	if err := os.MkdirAll(sc.dir, 0o700); err != nil {
		log.Warn("could not create the etcd snapshot directory", "component", etcdComponent, "dir", sc.dir, "err", err)
		return
	}
	// MkdirAll leaves an existing directory's mode alone, and `k3sm snapshot save`
	// or an older release may have created it wider. Tighten it when it is ours.
	if fi, err := os.Lstat(sc.dir); err == nil && fi.IsDir() && fi.Mode().Perm() != 0o700 {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) == os.Geteuid() {
			if err := os.Chmod(sc.dir, 0o700); err != nil {
				log.Warn("could not restrict the etcd snapshot directory to 0700", "component", etcdComponent,
					"dir", sc.dir, "err", err)
			}
		}
	}
	entries, err := os.ReadDir(sc.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		// ReadDir reports a symlink as a symlink, never its target: only a regular
		// file of this node's own .tmp shape is removed.
		base, ok := strings.CutSuffix(e.Name(), ".tmp")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		if _, ours := parseScheduledEtcdSnapshot(sc.node, base); !ours {
			continue
		}
		path := filepath.Join(sc.dir, e.Name())
		if err := os.Remove(path); err != nil {
			log.Warn("could not remove a partial scheduled etcd snapshot", "component", etcdComponent, "path", path, "err", err)
			continue
		}
		log.Info("removed a partial scheduled etcd snapshot an earlier run left", "component", etcdComponent, "path", path)
	}
}

// list returns this node's scheduled snapshots, newest first by order. A snapshot
// whose order is after now (taken under a clock that was ahead) sorts last: its
// real age is unknown, and it must not outrank real snapshots in retention.
func (sc *etcdSnapshotScheduler) list(now time.Time) ([]scheduledSnapshot, error) {
	entries, err := os.ReadDir(sc.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []scheduledSnapshot
	for _, e := range entries {
		taken, ok := parseScheduledEtcdSnapshot(sc.node, e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		snap := scheduledSnapshot{path: filepath.Join(sc.dir, e.Name()), taken: taken, order: taken}
		if fi, err := e.Info(); err == nil {
			snap.size = fi.Size()
			if mt := fi.ModTime(); mt.Before(snap.order) {
				snap.order = mt
			}
		}
		if snap.order.After(now.Add(etcdSnapshotWakeEvery)) {
			snap.order = time.Time{}
		}
		out = append(out, snap)
	}
	slices.SortFunc(out, func(a, b scheduledSnapshot) int {
		if c := b.order.Compare(a.order); c != 0 {
			return c
		}
		return strings.Compare(b.path, a.path)
	})
	return out, nil
}

// refresh re-reads the kept snapshots from disk into the state.
func (sc *etcdSnapshotScheduler) refresh() {
	snaps, err := sc.list(sc.clock.Now())
	if err != nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.state.kept = len(snaps)
	sc.state.last = time.Time{}
	if len(snaps) > 0 && !snaps[0].order.IsZero() {
		sc.state.last, sc.lastSize = snaps[0].taken, snaps[0].size
	}
}

// snapshotState is the schedule's view for the status record.
func (sc *etcdSnapshotScheduler) snapshotState() etcdSnapshotState {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	st := sc.state
	if st.skipped != nil {
		skip := *st.skipped
		st.skipped = &skip
	}
	return st
}

// run ticks on the schedule until ctx ends. It re-reads the wall clock at least
// every etcdSnapshotWakeEvery rather than trusting one long timer, and after a tick
// it plans the next one from the time it finished, so cron minutes missed while the
// Mac slept collapse into the one catch-up tick.
func (sc *etcdSnapshotScheduler) run(ctx context.Context) {
	next := sc.cron.Next(sc.clock.Now().In(sc.loc))
	for {
		if next.IsZero() {
			sc.log.Warn("the etcd snapshot schedule names no future time; no scheduled snapshots will be taken",
				"component", etcdComponent, "schedule", sc.cron.String())
			return
		}
		now := sc.clock.Now()
		if now.Before(next) {
			select {
			case <-ctx.Done():
				return
			case <-sc.clock.After(min(next.Sub(now), etcdSnapshotWakeEvery)):
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if late := now.Sub(next); late >= etcdSnapshotLateAfter {
			sc.log.Info("a scheduled etcd snapshot is late (the Mac slept or the clock moved); taking one now for the missed time",
				"component", etcdComponent, "due", next.UTC().Format(time.RFC3339), "late-by", late.Round(time.Second).String())
		}
		sc.tick(ctx)
		next = sc.cron.Next(sc.clock.Now().In(sc.loc))
	}
}

// skip records and logs a tick that was not attempted.
func (sc *etcdSnapshotScheduler) skip(reason string, err error) {
	msg := "skipped a scheduled etcd snapshot: not enough free space for it"
	if reason == EtcdSnapshotSkipError {
		msg = "skipped a scheduled etcd snapshot: could not read the free space"
	}
	sc.log.Warn(msg, "component", etcdComponent, "dir", sc.dir, "err", err)
	sc.mu.Lock()
	sc.state.skipped = &EtcdSnapshotSkip{At: sc.clock.Now().UTC(), Reason: reason, Detail: err.Error()}
	sc.mu.Unlock()
}

// fail records and logs a failed snapshot.
func (sc *etcdSnapshotScheduler) fail(msg, path string, err error) {
	sc.log.Warn(msg, "component", etcdComponent, "path", path, "err", err)
	sc.mu.Lock()
	sc.state.lastErr = err.Error()
	sc.mu.Unlock()
}

// tick takes one scheduled snapshot and, only when it succeeded, applies retention.
func (sc *etcdSnapshotScheduler) tick(ctx context.Context) {
	if err := os.MkdirAll(sc.dir, 0o700); err != nil {
		sc.fail("scheduled etcd snapshot failed: cannot create the snapshot directory", sc.dir, err)
		return
	}
	sc.mu.Lock()
	basis := sc.lastSize
	sc.mu.Unlock()
	if basis <= 0 && sc.dbSize != nil {
		cctx, cancel := context.WithTimeout(ctx, etcdCallTimeout)
		if n, err := sc.dbSize(cctx); err == nil {
			basis = n
		}
		cancel()
	}
	if basis > 0 {
		if err := sc.space(sc.dir, uint64(basis)*snapshotFreeSpaceFactor); err != nil {
			reason := EtcdSnapshotSkipError
			if errors.Is(err, ErrSnapshotSpace) {
				reason = EtcdSnapshotSkipSpace
			}
			sc.skip(reason, err)
			return
		}
	}

	taken := sc.clock.Now()
	path := filepath.Join(sc.dir, ScheduledEtcdSnapshotName(sc.node, taken))
	sctx, cancel := context.WithTimeout(ctx, etcdScheduledSnapshotTimeout)
	err := sc.save(sctx, path)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			sc.log.Info("a scheduled etcd snapshot was interrupted by shutdown; nothing was kept from it",
				"component", etcdComponent, "path", path)
			return
		}
		sc.fail("scheduled etcd snapshot failed; older snapshots are kept", path, err)
		return
	}
	var size int64
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	sc.log.Info("took a scheduled etcd snapshot", "component", etcdComponent, "path", path, "bytes", size)
	sc.mu.Lock()
	sc.lastSize = size
	sc.state.lastErr, sc.state.skipped = "", nil
	sc.mu.Unlock()
	sc.retain(path)
	sc.refresh()
}

// retain deletes this node's scheduled snapshots past the newest sc.retention,
// never the one just taken.
func (sc *etcdSnapshotScheduler) retain(justTaken string) {
	snaps, err := sc.list(sc.clock.Now())
	if err != nil {
		sc.log.Warn("could not list the scheduled etcd snapshots for retention; none were removed",
			"component", etcdComponent, "dir", sc.dir, "err", err)
		return
	}
	keep := sc.retention
	for _, snap := range snaps {
		if snap.path == justTaken {
			continue
		}
		if keep > 1 {
			keep-- // the slot the just-taken snapshot does not use
			continue
		}
		if err := os.Remove(snap.path); err != nil {
			sc.log.Warn("could not remove a scheduled etcd snapshot past the retention", "component", etcdComponent,
				"path", snap.path, "err", err)
			continue
		}
		sc.log.Info("removed a scheduled etcd snapshot past the retention", "component", etcdComponent,
			"path", snap.path, "retention", sc.retention)
	}
}

// startEtcdSnapshotSchedule runs sc for the supervisor's lifetime: ctx's, cut short
// by Stop.
func (s *Supervised) startEtcdSnapshotSchedule(ctx context.Context, sc *etcdSnapshotScheduler) {
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.etcdSnap, s.etcdSnapStop, s.etcdSnapDone = sc, cancel, done
	s.mu.Unlock()
	s.cfg.Logger.Info("scheduled etcd snapshots are on", "component", etcdComponent, "schedule", sc.cron.String(),
		"retention", sc.retention, "dir", sc.dir)
	go func() {
		defer close(done)
		sc.run(sctx)
	}()
}

// stopEtcdSnapshotSchedule cancels the schedule and waits for it (bounded by ctx).
// Called by Stop first, before the watcher, the admin client and the member.
func (s *Supervised) stopEtcdSnapshotSchedule(ctx context.Context) {
	s.mu.Lock()
	stop, done := s.etcdSnapStop, s.etcdSnapDone
	s.etcdSnapStop, s.etcdSnapDone = nil, nil
	s.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// fillEtcdSnapshotStatus copies the schedule's view into a status record; it leaves
// st untouched when the schedule is off.
func (s *Supervised) fillEtcdSnapshotStatus(st *EtcdStatus) {
	s.mu.Lock()
	sc := s.etcdSnap
	s.mu.Unlock()
	if sc == nil {
		return
	}
	v := sc.snapshotState()
	st.SnapshotSchedule, st.SnapshotRetention = sc.cron.String(), sc.retention
	st.LastScheduledSnapshot, st.ScheduledSnapshotsKept = v.last, v.kept
	st.LastScheduledSnapshotError, st.LastScheduledSnapshotSkipped = v.lastErr, v.skipped
}
