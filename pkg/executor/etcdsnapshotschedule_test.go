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
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestEtcdSnapshotScheduleRetains is B466's gate. With a fake clock and a fake member
// behind the real save path: every tick writes a verified 0600 snapshot named
// etcd-snapshot-<node>-<unix>; retention keeps exactly the N newest scheduled
// snapshots of THIS node and never a manual one, another node's, or a partial file;
// a failed snapshot deletes nothing; a tick below the free-space floor is skipped
// without streaming; and Stop ends the loop before the etcd member is signalled.
func TestEtcdSnapshotScheduleRetains(t *testing.T) {
	good := withTrailer(etcdBackendBytes(t, "key", "meta"))
	cron, err := ParseCron(DefaultEtcdSnapshotCron)
	if err != nil {
		t.Fatal(err)
	}
	const retention = 3
	wd := t.TempDir()
	logs := &lockedBuffer{}
	s := NewSupervised(Config{
		WorkDir: wd,
		Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP,
			Snapshots: &EtcdSnapshotSchedule{Cron: cron, Retention: retention}},
		Logger: slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err := s.cfg.Validate(); err != nil {
		t.Fatalf("Validate = %v", err)
	}
	var streams atomic.Int32
	var stream atomic.Value // func() (io.ReadCloser, error)
	stream.Store(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(good)), nil })
	fake := healthyFake()
	fake.snapshot = func() (io.ReadCloser, error) {
		streams.Add(1)
		return stream.Load().(func() (io.ReadCloser, error))()
	}

	dir := SnapshotDir(wd)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Files retention must never touch: a manual save, another server's scheduled
	// snapshot on the same directory, a partial write, and a near-miss name.
	untouchable := []string{
		"k3sm-etcd-snapshot-20261001T000000Z.db",
		"etcd-snapshot-server-b-1700000000",
		"etcd-snapshot-server-a-1700000000.tmp",
		"etcd-snapshot-server-a-old",
	}
	for _, name := range untouchable {
		mustWrite(t, filepath.Join(dir, name), []byte("not mine to delete"))
	}

	clk := newFakeClock(5 * 24 * time.Hour)
	s.etcd.clock = clk
	sc := s.newEtcdSnapshotScheduler(fake)
	sc.loc = time.UTC
	var floorAsked atomic.Uint64
	sc.space = func(string, uint64) error { return nil }

	scheduled := func() []string {
		t.Helper()
		snaps, err := sc.list()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, sn := range snaps {
			out = append(out, filepath.Base(sn.path))
		}
		return out
	}
	assertUntouched := func() {
		t.Helper()
		for _, name := range untouchable {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("%s was removed: %v", name, err)
			}
		}
	}

	t.Run("ticks write verified snapshots and retention keeps the newest N", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			sc.run(ctx)
		}()
		select {
		case <-clk.reached:
		case <-time.After(30 * time.Second):
			t.Fatal("the schedule never reached the end of the fake clock's run")
		}
		cancel()
		<-done

		// From 2026-10-02T00:00Z for five days at "0 */12 * * *": ten ticks, the last
		// at 2026-10-07T00:00Z.
		if got := streams.Load(); got != 10 {
			t.Fatalf("streamed %d snapshots, want 10 ticks", got)
		}
		last := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
		want := []string{
			ScheduledEtcdSnapshotName("server-a", last),
			ScheduledEtcdSnapshotName("server-a", last.Add(-12*time.Hour)),
			ScheduledEtcdSnapshotName("server-a", last.Add(-24*time.Hour)),
		}
		if got := scheduled(); !slices.Equal(got, want) {
			t.Fatalf("kept %v, want the %d newest %v", got, retention, want)
		}
		if want[0] != "etcd-snapshot-server-a-1791331200" {
			t.Fatalf("name = %q, want k3s's etcd-snapshot-<node>-<unix>", want[0])
		}
		for _, name := range want {
			fi, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v, want 0600", name, fi.Mode().Perm())
			}
			if err := verifyEtcdSnapshot(filepath.Join(dir, name)); err != nil {
				t.Errorf("%s does not verify: %v", name, err)
			}
		}
		assertUntouched()
		if got, kept := sc.summary(); !got.Equal(last) || kept != retention {
			t.Fatalf("summary = %s, %d; want %s, %d", got, kept, last, retention)
		}
		out := logs.String()
		if n := strings.Count(out, "took a scheduled etcd snapshot"); n != 10 {
			t.Errorf("%d snapshot Info lines, want 10:\n%s", n, out)
		}
		if n := strings.Count(out, "removed a scheduled etcd snapshot past the retention"); n != 7 {
			t.Errorf("%d retention Info lines, want 7:\n%s", n, out)
		}
	})

	t.Run("the status record reports the schedule", func(t *testing.T) {
		s.mu.Lock()
		s.etcdSnap = sc
		s.mu.Unlock()
		st := s.collectEtcdStatus(context.Background(), fake)
		if st.SnapshotSchedule != DefaultEtcdSnapshotCron || st.SnapshotRetention != retention ||
			st.ScheduledSnapshotsKept != retention || !st.LastScheduledSnapshot.Equal(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("status = %+v", st)
		}
	})

	for _, tc := range []struct {
		name   string
		stream func() (io.ReadCloser, error)
	}{
		{"the member refuses", func() (io.ReadCloser, error) { return nil, errors.New("member unavailable") }},
		{"the stream does not verify", func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(good[:len(good)-1])), nil
		}},
	} {
		t.Run("a failed snapshot deletes nothing: "+tc.name, func(t *testing.T) {
			before := scheduled()
			stream.Store(tc.stream)
			n := streams.Load()
			sc.tick(context.Background())
			if streams.Load() != n+1 {
				t.Fatal("the tick did not try to snapshot")
			}
			if got := scheduled(); !slices.Equal(got, before) {
				t.Fatalf("after a failed snapshot kept %v, want %v unchanged", got, before)
			}
			assertUntouched()
			entries, _ := os.ReadDir(dir)
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), "etcd-snapshot-server-a-179") && strings.HasSuffix(e.Name(), ".tmp") {
					t.Fatalf("a failed snapshot left %s", e.Name())
				}
			}
			if !strings.Contains(logs.String(), "scheduled etcd snapshot failed; older snapshots are kept") {
				t.Fatalf("no Warn for the failure:\n%s", logs.String())
			}
		})
	}

	t.Run("a tick below the free-space floor is skipped", func(t *testing.T) {
		stream.Store(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(good)), nil })
		before := scheduled()
		sc.space = func(dir string, want uint64) error {
			floorAsked.Store(want)
			return &snapshotSpaceError{dir: dir, avail: 1, want: want}
		}
		n := streams.Load()
		sc.tick(context.Background())
		if streams.Load() != n {
			t.Fatal("a tick below the floor streamed a snapshot")
		}
		if got := scheduled(); !slices.Equal(got, before) {
			t.Fatalf("after a skipped tick kept %v, want %v unchanged", got, before)
		}
		if want := uint64(len(good)) * snapshotFreeSpaceFactor; floorAsked.Load() != want {
			t.Fatalf("floor asked for %d bytes, want %dx the last snapshot = %d", floorAsked.Load(), snapshotFreeSpaceFactor, want)
		}
		if !strings.Contains(logs.String(), "skipped a scheduled etcd snapshot: not enough free space") {
			t.Fatalf("no Warn for the skip:\n%s", logs.String())
		}
	})

	t.Run("Stop ends the loop before the etcd member is signalled", func(t *testing.T) {
		wd2 := t.TempDir()
		logs2 := &lockedBuffer{}
		s2 := NewSupervised(Config{
			WorkDir: wd2,
			Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP,
				Snapshots: &EtcdSnapshotSchedule{Cron: cron, Retention: retention}},
			Logger: slog.New(slog.NewTextHandler(logs2, &slog.HandlerOptions{Level: slog.LevelDebug})),
		})
		s2.etcd.clock = newFakeClock(0) // every wait fires at once
		member := startFakeChild(t, etcdComponent)
		s2.mu.Lock()
		s2.comps = []*component{member}
		s2.started = true
		s2.mu.Unlock()

		sc2 := s2.newEtcdSnapshotScheduler(fake)
		sc2.space = func(string, uint64) error { return nil }
		streaming := make(chan struct{})
		var once atomic.Bool
		// A snapshot in flight when the server stops: it ends only with its context.
		sc2.save = func(ctx context.Context, _ string) error {
			if once.CompareAndSwap(false, true) {
				close(streaming)
			}
			<-ctx.Done()
			return ctx.Err()
		}
		s2.startEtcdSnapshotSchedule(context.Background(), sc2)
		s2.mu.Lock()
		loopDone := s2.etcdSnapDone
		s2.mu.Unlock()
		select {
		case <-streaming:
		case <-time.After(10 * time.Second):
			t.Fatal("the schedule never started a snapshot")
		}

		var loopEndedFirst, sawEtcd bool
		s2.stopping = func(c *component) {
			if c.name != etcdComponent {
				return
			}
			sawEtcd = true
			select {
			case <-loopDone:
				loopEndedFirst = true
			default:
			}
		}
		// The fake member has no reaper, so Stop spends its whole budget waiting to
		// witness the exit; the order under test is decided before that wait.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s2.Stop(ctx)
		if !sawEtcd {
			t.Fatal("Stop never signalled the etcd member")
		}
		if !loopEndedFirst {
			t.Fatal("the snapshot loop was still running when Stop signalled the etcd member")
		}
		out := logs2.String()
		if !strings.Contains(out, "interrupted by shutdown") || strings.Contains(out, "scheduled etcd snapshot failed") {
			t.Fatalf("a snapshot cut short by shutdown should be an Info, not a failure:\n%s", out)
		}
	})
}

// TestScheduledEtcdSnapshotNames: retention's name test admits only this node's
// scheduled snapshots.
func TestScheduledEtcdSnapshotNames(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		node, name string
		want       bool
	}{
		{"server-a", "etcd-snapshot-server-a-1791331200", true},
		{"server-a", "etcd-snapshot-server-a-1791331200.tmp", false},
		{"server-a", "etcd-snapshot-server-a-", false},
		{"server-a", "etcd-snapshot-server-b-1791331200", false},
		{"server-a", "etcd-snapshot-server-a-1-1791331200", false}, // node "server-a-1"
		{"server-a-1", "etcd-snapshot-server-a-1-1791331200", true},
		{"server-a", "k3sm-etcd-snapshot-20261001T000000Z.db", false},
		{"server-a", "etcd-snapshot-server-a-99999999999999999999999", false},
	} {
		if _, got := parseScheduledEtcdSnapshot(tc.node, tc.name); got != tc.want {
			t.Errorf("parseScheduledEtcdSnapshot(%q, %q) = %v, want %v", tc.node, tc.name, got, tc.want)
		}
	}
	if got := ScheduledEtcdSnapshotName("server-a", time.Unix(1791331200, 0)); got != "etcd-snapshot-server-a-1791331200" {
		t.Fatalf("ScheduledEtcdSnapshotName = %q", got)
	}
}
