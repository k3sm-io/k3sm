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
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/certs"
)

// lockedBuffer is a goroutine-safe log sink (reapers and the watcher log too).
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// fakeClock advances only when waited on: After(d) moves Now forward by d and fires at
// once, until the next wake-up would pass limit — then it closes reached and returns a
// channel that never fires, parking the waiter. A zero limit never parks.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	limit   time.Time
	reached chan struct{}
	once    sync.Once
}

func newFakeClock(run time.Duration) *fakeClock {
	start := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	c := &fakeClock{now: start, reached: make(chan struct{})}
	if run > 0 {
		c.limit = start.Add(run)
	}
	return c
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.limit.IsZero() && c.now.Add(d).After(c.limit) {
		c.once.Do(func() { close(c.reached) })
		return make(chan time.Time)
	}
	c.now = c.now.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.now
	return ch
}

// fakeEtcd is an etcdAdmin over canned answers.
type fakeEtcd struct {
	mu              sync.Mutex
	status          etcdMemberStatus
	statusErr       error
	alarms          []etcdAlarm
	members         []etcdMember
	defragErr       error
	defragEndpoints []string
	snapshot        func() (io.ReadCloser, error)
	listCalls       int
	closed          bool
}

func (f *fakeEtcd) Status(context.Context) (etcdMemberStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *fakeEtcd) AlarmList(context.Context) ([]etcdAlarm, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alarms, nil
}

func (f *fakeEtcd) MemberList(context.Context) ([]etcdMember, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	return f.members, nil
}

func (f *fakeEtcd) MemberAddAsLearner(context.Context, string) (etcdMember, []etcdMember, error) {
	return etcdMember{}, nil, errors.New("fakeEtcd: no member add here")
}

func (f *fakeEtcd) MemberPromote(context.Context, uint64) error {
	return errors.New("fakeEtcd: no promote here")
}

func (f *fakeEtcd) MemberRemove(context.Context, uint64) error {
	return errors.New("fakeEtcd: no remove here")
}

func (f *fakeEtcd) Defragment(_ context.Context, endpoint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.defragEndpoints = append(f.defragEndpoints, endpoint)
	return f.defragErr
}

func (f *fakeEtcd) Snapshot(context.Context) (io.ReadCloser, error) {
	if f.snapshot == nil {
		return nil, errors.New("fakeEtcd: no snapshot")
	}
	return f.snapshot()
}

func (f *fakeEtcd) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

const (
	testPeerIP  = "192.0.2.10"
	testOwnPeer = "https://192.0.2.10:2380"
	testOwnID   = 0xabc
)

// healthyFake is a one-member cluster with this server as leader.
func healthyFake() *fakeEtcd {
	return &fakeEtcd{
		status:  etcdMemberStatus{MemberID: testOwnID, Leader: testOwnID, DBSize: 4 << 20, DBSizeQuota: 2 << 30},
		members: []etcdMember{{ID: testOwnID, Name: "server-a", PeerURLs: []string{testOwnPeer}}},
	}
}

// etcdTestSupervised builds an etcd-posture Supervised over a temp work dir with fake
// seams. crashes records OnComponentExit the way the daemon's breaker does.
func etcdTestSupervised(t *testing.T, role EtcdRole, fake *fakeEtcd, clk *fakeClock) (*Supervised, *lockedBuffer, *crashSink) {
	t.Helper()
	wd := t.TempDir()
	logs := &lockedBuffer{}
	sink := &crashSink{}
	s := NewSupervised(Config{
		WorkDir:  wd,
		KinePort: freePort(t),
		Etcd: &EtcdConfig{Role: role, Name: "server-a", PeerIP: testPeerIP,
			InitialCluster: "server-b=https://192.0.2.11:2380,server-a=" + testOwnPeer},
		Logger:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		OnComponentExit: sink.record,
	})
	s.etcd = etcdSeams{
		clock:    clk,
		dial:     func(context.Context, string, string) (etcdAdmin, error) { return fake, nil },
		ready:    func(int) func(context.Context) bool { return func(context.Context) bool { return true } },
		dialPeer: func(context.Context, string) bool { return false },
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	return s, logs, sink
}

// crashSink is the daemon's breaker in miniature: every OnComponentExit is a crash.
type crashSink struct {
	mu  sync.Mutex
	rec CrashRecord
}

func (c *crashSink) record(name string, _ error, _, tail string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rec.Record(time.Now(), CrashOriginCrash, name, tail)
}

func (c *crashSink) snapshot() CrashRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CrashRecord{Crashes: slices.Clone(c.rec.Crashes), TrippedAt: c.rec.TrippedAt}
}

// writeEtcdChild installs a shell script as the etcd binary in wd's bin dir.
func writeEtcdChild(t *testing.T, wd, script string) {
	t.Helper()
	writeChild(t, wd, etcdComponent, "#!/bin/sh\n"+script)
}

// argvChild records its argv beside itself, then idles until signalled. The record is
// written to a temp name and renamed, so waitFile never reads a half-written argv.
const argvChild = `printf '%s\n' "$@" > "$0.argv.tmp" && mv "$0.argv.tmp" "$0.argv"
exec sleep 600
`

// waitFile waits for path to exist.
func waitFile(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s never appeared", path)
	return nil
}

// TestEtcdQuorumWaitNeverTripsBreaker: a member whose peer is absent waits, and keeps
// waiting, through three full crash-loop windows without recording anything; only the
// etcd child itself dying during the wait is a crash.
func TestEtcdQuorumWaitNeverTripsBreaker(t *testing.T) {
	t.Run("peer absent for three crash-loop windows: no exit, no record", func(t *testing.T) {
		fake := &fakeEtcd{
			status: etcdMemberStatus{MemberID: testOwnID}, // no leader
			members: []etcdMember{
				{ID: testOwnID, Name: "server-a", PeerURLs: []string{testOwnPeer}},
				{ID: 0xdef, Name: "server-b", PeerURLs: []string{"https://192.0.2.11:2380"}},
			},
		}
		clk := newFakeClock(3 * CrashLoopWindow)
		s, logs, sink := etcdTestSupervised(t, EtcdInit, fake, clk)
		writeEtcdChild(t, s.cfg.WorkDir, "exec sleep 600\n")
		c, err := s.spawn(t.Context(), etcdComponent)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.markSupervised(c); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- s.awaitEtcdQuorum(ctx, fake, c) }()

		select {
		case <-clk.reached:
		case err := <-done:
			t.Fatalf("the quorum wait ended after %s with %v; it must not expire", clk.Now().Sub(newFakeClock(0).Now()), err)
		case <-time.After(30 * time.Second):
			t.Fatal("the fake clock never reached three crash-loop windows")
		}
		select {
		case err := <-done:
			t.Fatalf("the quorum wait ended with %v after 30 minutes of absent peers", err)
		case <-time.After(200 * time.Millisecond):
		}
		if rec := sink.snapshot(); len(rec.Crashes) != 0 || rec.Tripped() {
			t.Errorf("crash record = %+v, want empty: a missing peer is not this server's failure", rec)
		}
		if n := strings.Count(logs.String(), "waiting for etcd quorum"); n < 100 {
			t.Errorf("logged the wait %d times over 30 minutes, want one every %s", n, etcdQuorumLogEvery)
		}
		if !strings.Contains(logs.String(), "reachable-members=1") || !strings.Contains(logs.String(), "members=2") {
			t.Errorf("the wait line must carry the reachable-member count; logs:\n%s", lastLines(logs.String(), 3))
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("after cancel the wait returned %v, want context.Canceled", err)
		}
	})

	t.Run("the etcd child exiting during the wait is recorded", func(t *testing.T) {
		fake := &fakeEtcd{status: etcdMemberStatus{MemberID: testOwnID}}
		clk := newFakeClock(time.Hour)
		s, _, sink := etcdTestSupervised(t, EtcdInit, fake, clk)
		die := filepath.Join(s.cfg.WorkDir, "die")
		writeEtcdChild(t, s.cfg.WorkDir, "while [ ! -f '"+die+"' ]; do sleep 0.05; done\necho 'etcd: fatal'\nexit 3\n")
		c, err := s.spawn(t.Context(), etcdComponent)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.markSupervised(c); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- s.awaitEtcdQuorum(t.Context(), fake, c) }()
		<-clk.reached
		if err := os.WriteFile(die, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "etcd exited while waiting for quorum") {
				t.Errorf("wait returned %v, want the etcd exit", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the wait did not end when the etcd child died")
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(sink.snapshot().Crashes) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		rec := sink.snapshot()
		if len(rec.Crashes) != 1 || rec.Crashes[0].Component != etcdComponent {
			t.Errorf("crash record = %+v, want exactly one etcd crash", rec.Crashes)
		}
	})
}

// TestEtcdDeathReportedOnce: the etcd member is supervised before its learner check,
// promotion and quorum waits, so its reaper and the wait both see one death. Exactly
// one of them reports it: when the reaper took it, the wait's error wraps
// ErrEtcdChildExited (the caller must not count it); when the wait got there first, it
// claims the report (the reaper then stays silent) and returns the plain error.
func TestEtcdDeathReportedOnce(t *testing.T) {
	t.Run("the claim decides which observer reports", func(t *testing.T) {
		s := NewSupervised(Config{WorkDir: t.TempDir()})
		for _, reaperFirst := range []bool{true, false} {
			c := &component{name: etcdComponent, exited: make(chan struct{}), supervised: true, reported: reaperFirst}
			close(c.exited)
			err := s.etcdExitedErr(c, "while waiting for quorum")
			if got := errors.Is(err, ErrEtcdChildExited); got != reaperFirst {
				t.Errorf("reaper reported first=%v: errors.Is(err, ErrEtcdChildExited) = %v (%v)", reaperFirst, got, err)
			}
			if !c.reported {
				t.Errorf("reaper reported first=%v: the wait left the report unclaimed, so the reaper would report it too", reaperFirst)
			}
		}
	})

	t.Run("a real death in the quorum wait: one record across both observers", func(t *testing.T) {
		// Repeated so both orderings of the reaper and the wait get their chance.
		for i := range 5 {
			fake := &fakeEtcd{status: etcdMemberStatus{MemberID: testOwnID}}
			clk := newFakeClock(time.Hour)
			s, _, sink := etcdTestSupervised(t, EtcdInit, fake, clk)
			if _, err := certs.EnsureHierarchy(s.cfg.WorkDir); err != nil {
				t.Fatal(err)
			}
			die := filepath.Join(s.cfg.WorkDir, "die")
			writeEtcdChild(t, s.cfg.WorkDir, "while [ ! -f '"+die+"' ]; do sleep 0.02; done\necho 'etcd: fatal'\nexit 3\n")
			done := make(chan error, 1)
			go func() { done <- s.bringUpEtcdMember(t.Context()) }()
			select {
			case <-clk.reached:
			case err := <-done:
				t.Fatalf("run %d: bring-up ended early: %v", i, err)
			case <-time.After(30 * time.Second):
				t.Fatalf("run %d: the quorum wait never parked", i)
			}
			if err := os.WriteFile(die, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("run %d: bring-up did not end when the member died", i)
			}
			// Stop waits for the reaper, so its report (if it took it) has landed.
			if serr := s.Stop(context.Background()); serr != nil {
				t.Fatal(serr)
			}
			bringUpCounted := 0
			if !errors.Is(err, ErrEtcdChildExited) {
				bringUpCounted = 1
			}
			if got := len(sink.snapshot().Crashes) + bringUpCounted; got != 1 {
				t.Fatalf("run %d: one etcd death was counted %d times (callback %d, bring-up error %d: %v)",
					i, got, len(sink.snapshot().Crashes), bringUpCounted, err)
			}
		}
	})
}

// TestEtcdQuorumWaitLogsWhy: the binding rule stays a leader AND an empty alarm list,
// and the wait's periodic line says which half is missing — the leader state, and the
// active alarms by name — so an operator can see why the wait has not ended.
func TestEtcdQuorumWaitLogsWhy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fake   *fakeEtcd
		wantIn []string
	}{
		{"a leader but an active NOSPACE alarm", &fakeEtcd{
			status: etcdMemberStatus{MemberID: testOwnID, Leader: testOwnID},
			alarms: []etcdAlarm{{MemberID: testOwnID, Alarm: etcdAlarmNoSpace}},
		}, []string{"leader=abc", "alarms=NOSPACE"}},
		{"no leader", &fakeEtcd{status: etcdMemberStatus{MemberID: testOwnID}},
			[]string{"leader=none", `alarms="unknown (asked only once a leader exists)"`}},
		{"the local member does not answer", &fakeEtcd{statusErr: errors.New("context deadline exceeded")},
			[]string{`leader="unknown (the local member did not answer: context deadline exceeded)"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newFakeClock(time.Minute)
			s, logs, _ := etcdTestSupervised(t, EtcdInit, tc.fake, clk)
			writeEtcdChild(t, s.cfg.WorkDir, "exec sleep 600\n")
			c, err := s.spawn(t.Context(), etcdComponent)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.markSupervised(c); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- s.awaitEtcdQuorum(ctx, tc.fake, c) }()
			select {
			case <-clk.reached:
			case err := <-done:
				t.Fatalf("the wait ended with %v; neither half of quorum holds", err)
			case <-time.After(30 * time.Second):
				t.Fatal("the fake clock never reached a minute")
			}
			cancel()
			<-done
			var line string
			for _, l := range strings.Split(logs.String(), "\n") {
				if strings.Contains(l, "waiting for etcd quorum") {
					line = l
				}
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(line, want) {
					t.Errorf("wait line %q does not carry %s", line, want)
				}
			}
			if strings.Contains(logs.String(), "etcd quorum reached") {
				t.Error("quorum was reported reached")
			}
		})
	}
}

// lastLines returns the last n lines of s, for a readable failure.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// TestEtcdRestartSkipsMemberAdd: a member that already exists restarts from its data
// dir — no initial-cluster flag, and no promotion of a member that already votes —
// while a joining member's first boot starts `existing` from the route's set and, as
// the learner its member reports, is promoted (retrying until it is).
func TestEtcdRestartSkipsMemberAdd(t *testing.T) {
	for _, tc := range []struct {
		name         string
		memberExists bool
		promoteFails int
		wantPromotes int
	}{
		{name: "restart: no initial cluster, never promoted", memberExists: true, wantPromotes: 0},
		{name: "first boot: existing cluster, promoted after a retry", promoteFails: 1, wantPromotes: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := healthyFake()
			fake.status.IsLearner = !tc.memberExists
			s, logs, _ := etcdTestSupervised(t, EtcdJoin, fake, newFakeClock(time.Hour))
			wd := s.cfg.WorkDir
			var mu sync.Mutex
			promotes := 0
			s.cfg.Etcd.Promote = func(context.Context) error {
				mu.Lock()
				defer mu.Unlock()
				promotes++
				if promotes <= tc.promoteFails {
					return errors.New("learner not caught up")
				}
				return nil
			}
			if _, err := certs.EnsureHierarchy(wd); err != nil {
				t.Fatal(err)
			}
			if tc.memberExists {
				if err := os.MkdirAll(etcdMemberDir(wd), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			writeEtcdChild(t, wd, argvChild)
			if err := s.bringUpEtcdMember(t.Context()); err != nil {
				t.Fatalf("bringUpEtcdMember = %v\nlogs:\n%s", err, logs.String())
			}
			args := strings.Split(strings.TrimSpace(string(waitFile(t, filepath.Join(binDir(wd), etcdComponent+".argv")))), "\n")
			mu.Lock()
			got := promotes
			mu.Unlock()
			if got != tc.wantPromotes {
				t.Errorf("Promote called %d times, want %d", got, tc.wantPromotes)
			}
			if tc.memberExists {
				for _, f := range []string{"--initial-cluster", "--initial-cluster-state", "--initial-cluster-token"} {
					if slices.Contains(args, f) {
						t.Errorf("a restart passed %s: %v", f, args)
					}
				}
				return
			}
			if flagValue(args, "--initial-cluster-state") != "existing" ||
				flagValue(args, "--initial-cluster") != s.cfg.Etcd.InitialCluster {
				t.Errorf("first join boot argv = %v, want existing + the route's initial cluster", args)
			}
		})
	}
}

// TestEtcdRestartPromotesStrandedLearner: a joiner restarted after its learner first
// started but before the promotion landed restarts from its data dir as a LEARNER. The
// production bring-up asks the member, finds it a learner, and promotes it before the
// quorum wait — and with no way to promote it (no Promote on this boot) it waits,
// logging the remedy at ERROR, rather than crashing or carrying on as a learner.
func TestEtcdRestartPromotesStrandedLearner(t *testing.T) {
	restartedLearner := func(t *testing.T, clk *fakeClock) (*Supervised, *fakeEtcd, *lockedBuffer, *crashSink) {
		t.Helper()
		fake := healthyFake()
		fake.status.IsLearner = true
		s, logs, sink := etcdTestSupervised(t, EtcdJoin, fake, clk)
		if _, err := certs.EnsureHierarchy(s.cfg.WorkDir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(etcdMemberDir(s.cfg.WorkDir), 0o700); err != nil {
			t.Fatal(err)
		}
		writeEtcdChild(t, s.cfg.WorkDir, argvChild)
		return s, fake, logs, sink
	}

	t.Run("a Promote on this boot: promoted, then the quorum wait", func(t *testing.T) {
		s, fake, logs, _ := restartedLearner(t, newFakeClock(time.Hour))
		var mu sync.Mutex
		promotes := 0
		s.cfg.Etcd.Promote = func(context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			promotes++
			if promotes == 1 {
				return errors.New("learner not caught up")
			}
			fake.mu.Lock()
			fake.status.IsLearner = false
			fake.mu.Unlock()
			return nil
		}
		if err := s.bringUpEtcdMember(t.Context()); err != nil {
			t.Fatalf("bringUpEtcdMember = %v\nlogs:\n%s", err, logs.String())
		}
		mu.Lock()
		got := promotes
		mu.Unlock()
		if got != 2 {
			t.Errorf("Promote called %d times, want 2 (one refusal, one success)", got)
		}
		out := logs.String()
		promoted := strings.Index(out, "etcd learner promoted to a voting member")
		quorum := strings.Index(out, "etcd quorum reached")
		if promoted < 0 || quorum < 0 || promoted > quorum {
			t.Errorf("want the promotion logged, then quorum; promoted at %d, quorum at %d\nlogs:\n%s", promoted, quorum, out)
		}
		args := strings.Split(strings.TrimSpace(string(waitFile(t, filepath.Join(binDir(s.cfg.WorkDir), etcdComponent+".argv")))), "\n")
		if slices.Contains(args, "--initial-cluster") {
			t.Errorf("a restart passed --initial-cluster: %v", args)
		}
	})

	t.Run("no Promote on this boot: waits with the remedy at ERROR, never a crash", func(t *testing.T) {
		clk := newFakeClock(5 * time.Minute)
		s, _, logs, sink := restartedLearner(t, clk)
		s.cfg.Etcd.Promote = nil
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- s.bringUpEtcdMember(ctx) }()
		select {
		case <-clk.reached:
		case err := <-done:
			t.Fatalf("bring-up ended with %v; a stranded learner must wait\nlogs:\n%s", err, logs.String())
		case <-time.After(30 * time.Second):
			t.Fatal("the fake clock never reached five minutes")
		}
		out := logs.String()
		errLines := 0
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "level=ERROR") && strings.Contains(l, "cannot ask for its promotion") &&
				strings.Contains(l, "--server") && strings.Contains(l, "wipe this server's etcd data dir") {
				errLines++
			}
		}
		if errLines < 5 || errLines > 6 {
			t.Errorf("logged the stranded-learner remedy at ERROR %d times over five minutes, want one per %s\nlogs:\n%s",
				errLines, etcdStrandedLogEvery, lastLines(out, 5))
		}
		if strings.Contains(out, "etcd quorum reached") {
			t.Error("a learner that was never promoted reached the quorum step")
		}
		if rec := sink.snapshot(); len(rec.Crashes) != 0 {
			t.Errorf("crash record = %+v, want empty: an unpromoted learner is a wait", rec)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("after cancel bring-up returned %v, want context.Canceled", err)
		}
	})
}

// TestShutdownOrderEtcdLast: the etcd member stops after the apiserver and the
// controllers, exactly where kine does.
func TestShutdownOrderEtcdLast(t *testing.T) {
	order := shutdownOrder([]*component{
		{name: "etcd"}, {name: "kube-apiserver"}, {name: "kube-scheduler"}, {name: "kube-controller-manager"},
	})
	var names []string
	for _, c := range order {
		names = append(names, c.name)
	}
	want := []string{"kube-apiserver", "kube-scheduler", "kube-controller-manager", "etcd"}
	if !slices.Equal(names, want) {
		t.Errorf("shutdown order = %v, want %v", names, want)
	}
}

// TestEtcdDefragLocalOnlyNonFatal: the post-quorum defragment targets the local member
// only, and its failure is logged without stopping anything.
func TestEtcdDefragLocalOnlyNonFatal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		wantLog string
	}{
		{name: "success logs the sizes", wantLog: "etcd defragmented the local member"},
		{name: "failure is logged and non-fatal", err: errors.New("defrag refused"), wantLog: "etcd defragment of the local member failed; continuing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := healthyFake()
			fake.defragErr = tc.err
			s, logs, _ := etcdTestSupervised(t, EtcdInit, fake, newFakeClock(time.Hour))
			st := s.afterEtcdQuorum(t.Context(), fake)
			want := []string{etcdClientURL(s.cfg.KinePort)}
			if !slices.Equal(fake.defragEndpoints, want) {
				t.Errorf("defragmented %v, want only the local member %v", fake.defragEndpoints, want)
			}
			if !strings.Contains(logs.String(), tc.wantLog) {
				t.Errorf("logs lack %q:\n%s", tc.wantLog, logs.String())
			}
			if st.Members != 1 || !st.LeaderPresent {
				t.Errorf("status after defrag = %+v, want the cluster still reported", st)
			}
			if _, err := ReadEtcdStatus(s.cfg.WorkDir); err != nil {
				t.Errorf("status record not written: %v", err)
			}
		})
	}
}

// TestEtcdPeerURLDriftReported: a member whose registered peer URL is not the current
// node IP is reported at ERROR and in the status record, once, with no restart.
func TestEtcdPeerURLDriftReported(t *testing.T) {
	fake := healthyFake()
	fake.members = []etcdMember{
		{ID: testOwnID, Name: "server-a", PeerURLs: []string{"https://192.0.2.99:2380"}},
		{ID: 0xdef, Name: "server-b", PeerURLs: []string{"https://192.0.2.11:2380"}},
	}
	s, logs, sink := etcdTestSupervised(t, EtcdInit, fake, newFakeClock(time.Hour))
	st := s.afterEtcdQuorum(t.Context(), fake)
	if !st.PeerURLDrift || st.ExpectedPeerURL != testOwnPeer {
		t.Errorf("status = %+v, want drift against %s", st, testOwnPeer)
	}
	out := logs.String()
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "registered peer URL") || !strings.Contains(out, "DHCP reservation") {
		t.Errorf("drift must be an ERROR naming the remedy; logs:\n%s", out)
	}
	if !strings.Contains(out, "even number of voting members") {
		t.Errorf("two voting members must WARN about even quorum; logs:\n%s", out)
	}
	rec, err := ReadEtcdStatus(s.cfg.WorkDir)
	if err != nil || !rec.PeerURLDrift || !slices.Equal(rec.RegisteredPeerURLs, []string{"https://192.0.2.99:2380"}) {
		t.Errorf("status record = %+v (%v), want the drift recorded", rec, err)
	}
	if fi, err := os.Stat(EtcdStatusPath(s.cfg.WorkDir)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("status record mode = %v (%v), want 0600", fi.Mode(), err)
	}
	if len(sink.snapshot().Crashes) != 0 {
		t.Error("drift must never be reported as a crash")
	}

	fake.members = []etcdMember{{ID: testOwnID, Name: "server-a", PeerURLs: []string{testOwnPeer}}}
	if st := s.afterEtcdQuorum(t.Context(), fake); st.PeerURLDrift {
		t.Errorf("a matching peer URL reported drift: %+v", st)
	}
}

// TestClusterInitRefusesExistingSQLiteState: --cluster-init over a single-node SQLite
// datastore is refused before the work dir is touched; a restart is not.
func TestClusterInitRefusesExistingSQLiteState(t *testing.T) {
	wd := t.TempDir()
	if err := os.MkdirAll(dbDir(wd), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StateDBPath(wd), []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}}
	err := NewSupervised(cfg).provision(t.Context())
	if !errors.Is(err, ErrClusterInitOverSQLite) {
		t.Fatalf("provision = %v, want ErrClusterInitOverSQLite", err)
	}
	var bu *BringUpError
	if !errors.As(err, &bu) || bu.Component != "provision/cluster-init" {
		t.Errorf("refusal classification = %+v, want provision/cluster-init", bu)
	}
	if _, err := os.Stat(binDir(wd)); !os.IsNotExist(err) {
		t.Error("the refusal ran after provision had started laying the work dir down")
	}

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, wd string)
		cfg   func(wd string) Config
	}{
		{"a restart (member dir present) is not a conversion", func(t *testing.T, wd string) {
			if err := os.MkdirAll(etcdMemberDir(wd), 0o700); err != nil {
				t.Fatal(err)
			}
		}, func(wd string) Config { return Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdInit}} }},
		{"a joining member is not an init", func(*testing.T, string) {},
			func(wd string) Config { return Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdJoin}} }},
		{"the kine posture is untouched", func(*testing.T, string) {},
			func(wd string) Config { return Config{WorkDir: wd} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t, wd)
			if err := RefuseClusterInitOverSQLite(tc.cfg(wd)); err != nil {
				t.Errorf("RefuseClusterInitOverSQLite = %v, want nil", err)
			}
		})
	}
	empty := t.TempDir()
	if err := os.MkdirAll(dbDir(empty), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StateDBPath(empty), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RefuseClusterInitOverSQLite(Config{WorkDir: empty, Etcd: &EtcdConfig{Role: EtcdInit}}); err != nil {
		t.Errorf("an empty state.db holds no cluster; got %v", err)
	}
}

// stageTestPayload writes a payload dir whose markers vouch for every pinned child, so
// provision seeds from it and acquires nothing over the network.
func stageTestPayload(t *testing.T, withEtcd bool) string {
	t.Helper()
	payload := t.TempDir()
	names := append(slices.Clone(cpBinaries), kineBinaryName)
	if withEtcd {
		names = append(names, etcdBinaryName)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(payload, n), []byte("payload-"+n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeKubeMarker(payload, DefaultKubeVersion); err != nil {
		t.Fatal(err)
	}
	if err := writeKineMarker(payload, DefaultKineVersion); err != nil {
		t.Fatal(err)
	}
	if withEtcd {
		if err := etcdChild(DefaultEtcdVersion).writeMarker(payload); err != nil {
			t.Fatal(err)
		}
	}
	return payload
}

// presetSAKeys writes placeholder service-account keys so provision does not shell
// out to openssl.
func presetSAKeys(t *testing.T, wd string) {
	t.Helper()
	if err := os.MkdirAll(wd, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{saKeyPath(wd), saPubPath(wd)} {
		if err := os.WriteFile(p, []byte("placeholder"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestSingleNodeNeverStagesEtcd: the kine posture's provision neither seeds etcd from a
// payload that carries it nor builds it; the etcd posture does both (the non-vacuous
// half — the same seams fire there).
func TestSingleNodeNeverStagesEtcd(t *testing.T) {
	origCache, origBuild := kineModuleCacheDir, runEtcdBuild
	t.Cleanup(func() { kineModuleCacheDir, runEtcdBuild = origCache, origBuild })
	cache := t.TempDir()
	kineModuleCacheDir = func(context.Context) (string, error) { return cache, nil }
	builds := 0
	runEtcdBuild = func(cmd *exec.Cmd) ([]byte, error) {
		builds++
		return nil, os.WriteFile(cmd.Args[slices.Index(cmd.Args, "-o")+1], []byte("built-etcd"), 0o755)
	}

	t.Run("kine posture", func(t *testing.T) {
		builds = 0
		wd := t.TempDir()
		presetSAKeys(t, wd)
		s := NewSupervised(Config{WorkDir: wd, PayloadBinDir: stageTestPayload(t, true), Token: "tok"})
		if err := s.provision(t.Context()); err != nil {
			t.Fatalf("provision = %v", err)
		}
		if builds != 0 {
			t.Errorf("the kine posture built etcd %d times", builds)
		}
		for _, f := range []string{etcdBinaryName, EtcdMarkerName} {
			if _, err := os.Stat(filepath.Join(binDir(wd), f)); !os.IsNotExist(err) {
				t.Errorf("the kine posture staged %s into the work dir (%v)", f, err)
			}
		}
		if _, err := os.Stat(certs.EtcdCertPaths(wd).Dir); !os.IsNotExist(err) {
			t.Errorf("the kine posture minted etcd PKI (%v)", err)
		}
		if !kineStaged(binDir(wd), DefaultKineVersion) {
			t.Error("the kine posture did not stage kine")
		}
	})

	for _, tc := range []struct {
		name        string
		payloadEtcd bool
		wantBuilds  int
		wantBytes   string
	}{
		{"etcd posture seeds etcd from the payload", true, 0, "payload-etcd"},
		{"etcd posture builds etcd when the payload lacks it", false, 1, "built-etcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builds = 0
			wd := t.TempDir()
			presetSAKeys(t, wd)
			s := NewSupervised(Config{WorkDir: wd, PayloadBinDir: stageTestPayload(t, tc.payloadEtcd), Token: "tok",
				Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}})
			if err := s.provision(t.Context()); err != nil {
				t.Fatalf("provision = %v", err)
			}
			if builds != tc.wantBuilds {
				t.Errorf("etcd builds = %d, want %d", builds, tc.wantBuilds)
			}
			if b, _ := os.ReadFile(filepath.Join(binDir(wd), etcdBinaryName)); string(b) != tc.wantBytes {
				t.Errorf("staged etcd = %q, want %q", b, tc.wantBytes)
			}
			if !etcdStaged(binDir(wd), DefaultEtcdVersion) {
				t.Error("etcd not staged under its marker")
			}
			assertEtcdPKI(t, wd)
		})
	}
}

// assertEtcdPKI checks the leaves and the data dir provisionEtcdCerts lays down.
func assertEtcdPKI(t *testing.T, wd string) {
	t.Helper()
	p := certs.EtcdCertPaths(wd)
	for path, mode := range map[string]os.FileMode{
		p.ServerClientKey: 0o600, p.PeerServerClientKey: 0o600, p.ClientKey: 0o600,
		p.ServerClientCert: 0o644, p.PeerServerClientCert: 0o644, p.ClientCert: 0o644,
		EtcdDataDir(wd): 0o700,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if fi.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", path, fi.Mode().Perm(), mode)
		}
	}
}

// TestJoiningMemberNeedsImportedEtcdCAs: a joining server never mints the etcd CAs;
// with none imported, provisioning its leaves fails by name.
func TestJoiningMemberNeedsImportedEtcdCAs(t *testing.T) {
	wd := t.TempDir()
	cfg := Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdJoin, Name: "server-b", PeerIP: testPeerIP}}
	if err := provisionEtcdCerts(cfg); !errors.Is(err, ErrEtcdCAsMissing) {
		t.Fatalf("join without imported CAs = %v, want ErrEtcdCAsMissing", err)
	}
	if _, err := os.Stat(certs.EtcdCertPaths(wd).ServerCACert); !os.IsNotExist(err) {
		t.Error("a joining server minted an etcd CA")
	}
	if _, _, err := certs.EnsureEtcdCAs(wd); err != nil { // stands in for the bundle import
		t.Fatal(err)
	}
	if err := provisionEtcdCerts(cfg); err != nil {
		t.Fatalf("join with imported CAs = %v", err)
	}
	assertEtcdPKI(t, wd)
}

// TestStopKeepsWorkDirLockUntilReaped: a child whose exit Stop could not witness
// inside its budget may still be running after the SIGKILL, so Stop does not release
// the etcd posture's work-dir lock — a reset could otherwise start beside a dying
// member. The lock goes once the child is reaped.
func TestStopKeepsWorkDirLockUntilReaped(t *testing.T) {
	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}})
	unlock, err := lockWorkDir(wd)
	if err != nil {
		t.Fatal(err)
	}
	stuck := fakeStuckComponent(t, etcdComponent)
	s.mu.Lock()
	s.unlockWorkDir = unlock
	s.comps = []*component{stuck}
	s.started = true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := s.Stop(ctx); !errors.Is(err, ErrStopBudgetExceeded) {
		t.Fatalf("Stop = %v, want ErrStopBudgetExceeded for the unreaped child", err)
	}
	if l, err := lockWorkDir(wd); !errors.Is(err, ErrWorkDirLocked) {
		if l != nil {
			_ = l()
		}
		t.Fatalf("lock after a Stop that left a child unreaped = %v, want ErrWorkDirLocked", err)
	}

	// The reaper observes the exit (its close of exited is what this stands in for).
	close(stuck.exited)
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := lockWorkDir(wd)
		if err == nil {
			_ = l()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the lock was never released after the child was reaped: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestEtcdPostureHoldsWorkDirLock: an etcd-posture server holds the work-dir lock from
// Start to Stop, so a reset (which takes the same lock) cannot run beside its member;
// the kine posture takes no lock.
func TestEtcdPostureHoldsWorkDirLock(t *testing.T) {
	origProvision, origBringUp := supervisedProvision, supervisedBringUp
	t.Cleanup(func() { supervisedProvision, supervisedBringUp = origProvision, origBringUp })
	supervisedProvision = func(*Supervised, context.Context) error { return nil }
	supervisedBringUp = func(*Supervised, context.Context) error { return nil }

	wd := t.TempDir()
	s := NewSupervised(Config{WorkDir: wd, Token: "tok", Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}})
	if err := s.Start(t.Context()); err != nil {
		t.Fatalf("Start = %v", err)
	}
	if _, err := lockWorkDir(wd); !errors.Is(err, ErrWorkDirLocked) {
		t.Errorf("lock while the etcd posture runs = %v, want ErrWorkDirLocked", err)
	}
	second := NewSupervised(Config{WorkDir: wd, Token: "tok", Etcd: &EtcdConfig{Role: EtcdInit, Name: "server-a", PeerIP: testPeerIP}})
	if err := second.Start(t.Context()); !errors.Is(err, ErrWorkDirLocked) {
		t.Errorf("a second etcd-posture server on the same work dir: Start = %v, want ErrWorkDirLocked", err)
	}
	if err := s.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockWorkDir(wd)
	if err != nil {
		t.Fatalf("lock after Stop = %v, want it released", err)
	}
	_ = unlock()

	kineWD := t.TempDir()
	k := NewSupervised(Config{WorkDir: kineWD, Token: "tok"})
	if err := k.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k.Stop(context.Background()) }()
	if _, err := os.Stat(WorkDirLockPath(kineWD)); !os.IsNotExist(err) {
		t.Errorf("the kine posture created a lock file (%v)", err)
	}
}
