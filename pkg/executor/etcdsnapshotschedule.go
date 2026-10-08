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
	"time"
)

// Scheduled etcd snapshots, the k3s behaviour on an embedded-etcd server: every
// server takes a snapshot of its own member on a cron schedule (k3s's default, every
// 12 hours) into <WorkDir>/db/snapshots, and keeps the newest N of them (default 5).
//
// The loop starts once the member has quorum and the post-quorum checks have run,
// and Stop ends it BEFORE anything else in the teardown: it streams from the admin
// client the watcher holds and from the member Stop is about to kill. Each tick goes
// through saveEtcdSnapshot, the path `k3sm snapshot save` uses, so a scheduled file
// is verified and 0600 exactly like a manual one.
//
// Retention deletes, so it is narrow on purpose. It runs only after a snapshot has
// been written and verified (a failing schedule never eats the snapshots it has), it
// considers only names this schedule writes for THIS node, so a manual
// `k3sm snapshot save` file (k3sm-etcd-snapshot-<stamp>.db) or a file another
// server's schedule left on a shared directory is never touched, and it never
// deletes the snapshot the tick just took.
//
// A tick is skipped, with a warning, when the snapshot directory's volume has less
// free space than snapshotFreeSpaceFactor times the last snapshot's size: a
// snapshot schedule that fills the disk the datastore lives on breaks the cluster it
// exists to protect.
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
)

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

// scheduledSnapshot is one of this node's scheduled snapshots on disk.
type scheduledSnapshot struct {
	path  string
	taken time.Time
	size  int64
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

	// mu guards the summary below, which collectEtcdStatus reads.
	mu       sync.Mutex
	last     time.Time
	kept     int
	lastSize int64
}

// newEtcdSnapshotScheduler builds the scheduler for this server's member, reading the
// snapshots a previous run of this server kept so the status record and the
// free-space floor are right before the first tick.
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
	sc.refresh()
	return sc
}

// list returns this node's scheduled snapshots, newest first.
func (sc *etcdSnapshotScheduler) list() ([]scheduledSnapshot, error) {
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
		snap := scheduledSnapshot{path: filepath.Join(sc.dir, e.Name()), taken: taken}
		if fi, err := e.Info(); err == nil {
			snap.size = fi.Size()
		}
		out = append(out, snap)
	}
	slices.SortFunc(out, func(a, b scheduledSnapshot) int {
		if c := b.taken.Compare(a.taken); c != 0 {
			return c
		}
		return strings.Compare(b.path, a.path)
	})
	return out, nil
}

// refresh re-reads the summary from disk.
func (sc *etcdSnapshotScheduler) refresh() {
	snaps, err := sc.list()
	if err != nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.kept = len(snaps)
	sc.last = time.Time{}
	if len(snaps) > 0 {
		sc.last, sc.lastSize = snaps[0].taken, snaps[0].size
	}
}

// summary is the newest scheduled snapshot's time and how many are kept.
func (sc *etcdSnapshotScheduler) summary() (last time.Time, kept int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.last, sc.kept
}

// run ticks on the schedule until ctx ends.
func (sc *etcdSnapshotScheduler) run(ctx context.Context) {
	for {
		now := sc.clock.Now().In(sc.loc)
		next := sc.cron.Next(now)
		if next.IsZero() {
			sc.log.Warn("the etcd snapshot schedule names no future time; no scheduled snapshots will be taken",
				"component", etcdComponent, "schedule", sc.cron.String())
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-sc.clock.After(next.Sub(now)):
		}
		if ctx.Err() != nil {
			return
		}
		sc.tick(ctx)
	}
}

// tick takes one scheduled snapshot and, only when it succeeded, applies retention.
func (sc *etcdSnapshotScheduler) tick(ctx context.Context) {
	log := sc.log
	if err := os.MkdirAll(sc.dir, 0o700); err != nil {
		log.Warn("scheduled etcd snapshot failed: cannot create the snapshot directory", "component", etcdComponent,
			"dir", sc.dir, "err", err)
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
			log.Warn("skipped a scheduled etcd snapshot: not enough free space for it", "component", etcdComponent,
				"dir", sc.dir, "err", err)
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
			log.Info("a scheduled etcd snapshot was interrupted by shutdown; nothing was kept from it",
				"component", etcdComponent, "path", path)
			return
		}
		log.Warn("scheduled etcd snapshot failed; older snapshots are kept", "component", etcdComponent,
			"path", path, "err", err)
		return
	}
	var size int64
	if fi, err := os.Stat(path); err == nil {
		size = fi.Size()
	}
	log.Info("took a scheduled etcd snapshot", "component", etcdComponent, "path", path, "bytes", size)
	sc.mu.Lock()
	sc.lastSize = size
	sc.mu.Unlock()
	sc.retain(path)
	sc.refresh()
}

// retain deletes this node's scheduled snapshots past the newest sc.retention,
// never the one just taken.
func (sc *etcdSnapshotScheduler) retain(justTaken string) {
	snaps, err := sc.list()
	if err != nil {
		sc.log.Warn("could not list the scheduled etcd snapshots for retention; none were removed",
			"component", etcdComponent, "dir", sc.dir, "err", err)
		return
	}
	for i, snap := range snaps {
		if i < sc.retention || snap.path == justTaken {
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

// etcdSnapshotSummary is the schedule's view for the status record; zero when off.
func (s *Supervised) etcdSnapshotSummary() (schedule string, retention int, last time.Time, kept int) {
	s.mu.Lock()
	sc := s.etcdSnap
	s.mu.Unlock()
	if sc == nil {
		return "", 0, time.Time{}, 0
	}
	last, kept = sc.summary()
	return sc.cron.String(), sc.retention, last, kept
}
