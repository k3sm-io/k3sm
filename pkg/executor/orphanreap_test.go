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
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// fakeProcTable is an orphanSeams over an in-memory process table: no real
// process is listed, looked up or signalled. A process dies on the first signal
// it does not ignore.
type fakeProcTable struct {
	mu    sync.Mutex
	procs map[int]orphanProc
	// ignore names the signals a pid survives.
	ignore map[int][]syscall.Signal
	// recycled, when set for a pid, is what lookup reports for it instead: the pid
	// now names a different process.
	recycled map[int]orphanProc
	listErr  error
	listed   int
	sent     []fakeSignal
	// onSignal, when set, runs after each signal is recorded (outside mu).
	onSignal func(fakeSignal)
}

type fakeSignal struct {
	target int
	sig    syscall.Signal
}

func newFakeProcTable(procs ...orphanProc) *fakeProcTable {
	f := &fakeProcTable{procs: map[int]orphanProc{}, ignore: map[int][]syscall.Signal{}, recycled: map[int]orphanProc{}}
	for _, p := range procs {
		f.procs[p.pid] = p
	}
	return f
}

func (f *fakeProcTable) seams() orphanSeams {
	return orphanSeams{
		list: func() ([]orphanProc, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.listed++
			if f.listErr != nil {
				return nil, f.listErr
			}
			out := make([]orphanProc, 0, len(f.procs))
			for _, p := range f.procs {
				out = append(out, p)
			}
			return out, nil
		},
		lookup: func(pid int) (orphanProc, bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			if r, ok := f.recycled[pid]; ok {
				return r, true
			}
			p, ok := f.procs[pid]
			return p, ok
		},
		kill: func(target int, sig syscall.Signal) error {
			f.mu.Lock()
			s := fakeSignal{target, sig}
			f.sent = append(f.sent, s)
			pid := target
			if pid < 0 {
				pid = -pid
			}
			if _, ok := f.procs[pid]; !ok {
				f.mu.Unlock()
				return syscall.ESRCH
			}
			dies := true
			for _, ig := range f.ignore[pid] {
				if ig == sig {
					dies = false
				}
			}
			if dies {
				delete(f.procs, pid)
			}
			cb := f.onSignal
			f.mu.Unlock()
			if cb != nil {
				cb(s)
			}
			return nil
		},
	}
}

func (f *fakeProcTable) signals() []fakeSignal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeSignal(nil), f.sent...)
}

func (f *fakeProcTable) alive(pid int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.procs[pid]
	return ok
}

// reapFixture is a work dir with a bin dir, as the kernel would report its
// paths (symlinks resolved), and a daemon start after every planted process.
type reapFixture struct {
	workDir, bin string
	daemon       time.Time
}

func newReapFixture(t *testing.T) reapFixture {
	t.Helper()
	wd := filepath.Join(t.TempDir(), "server")
	if err := os.MkdirAll(binDir(wd), 0o700); err != nil {
		t.Fatal(err)
	}
	bin, err := filepath.EvalSymlinks(binDir(wd))
	if err != nil {
		t.Fatal(err)
	}
	return reapFixture{workDir: wd, bin: bin, daemon: time.Now()}
}

// orphan is pid running bin/<name>, orphaned to launchd, its own group leader,
// started an hour before the daemon.
func (fx reapFixture) orphan(pid int, name string) orphanProc {
	return orphanProc{
		pid: pid, ppid: launchdPPID, pgid: pid,
		startUnixNano: fx.daemon.Add(-time.Hour).UnixNano(),
		exe:           filepath.Join(fx.bin, name),
	}
}

// shortReapWaits shrinks the per-tier grace and the post-SIGKILL wait for one test.
func shortReapWaits(t *testing.T) {
	t.Helper()
	grace, datastore, kill := reapTierGrace, reapDatastoreGrace, reapKillWait
	reapTierGrace, reapDatastoreGrace, reapKillWait = 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { reapTierGrace, reapDatastoreGrace, reapKillWait = grace, datastore, kill })
}

// TestLeftoverNameDecision pins the ownership decision on fake process facts:
// a process is a previous run's leftover only when its resolved executable is a
// known component directly under the resolved bin, its parent is launchd, and it
// started before this daemon.
func TestLeftoverNameDecision(t *testing.T) {
	fx := newReapFixture(t)
	root := filepath.Dir(filepath.Dir(fx.bin))
	before := fx.daemon.Add(-time.Minute).UnixNano()

	// A path that reaches bin through a symlink resolves into it.
	linkRoot := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Dir(fx.bin), linkRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fx.bin, kineBinaryName), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	// A symlink inside bin that points out of it resolves out of it.
	outside := filepath.Join(root, "elsewhere", kineBinaryName)
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	escape := filepath.Join(fx.bin, "kube-scheduler")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}

	own := func(exe string) orphanProc {
		return orphanProc{pid: 4711, ppid: launchdPPID, pgid: 4711, startUnixNano: before, exe: exe}
	}
	cases := []struct {
		name     string
		p        orphanProc
		want     string
		wantOurs bool
	}{
		{"own orphaned kine", own(filepath.Join(fx.bin, "kine")), "kine", true},
		{"own orphaned apiserver", own(filepath.Join(fx.bin, "kube-apiserver")), "kube-apiserver", true},
		{"an unknown name beside the components", own(filepath.Join(fx.bin, "kube-scheduler-x")), "", false},
		{"own orphaned controller-manager", own(filepath.Join(fx.bin, "kube-controller-manager")), "kube-controller-manager", true},
		{"own orphaned registry", own(filepath.Join(fx.bin, registrysvc.ZotBinaryName)), registrysvc.ZotBinaryName, true},
		{"kine reached through a symlinked work dir", own(filepath.Join(linkRoot, "bin", "kine")), "kine", true},
		{"a bin entry that is a symlink out of bin", own(escape), "", false},
		{"helm is not a server child", own(filepath.Join(fx.bin, "helm")), "", false},
		{"kubectl is not a server child", own(filepath.Join(fx.bin, "kubectl")), "", false},
		{"etcd is never reaped", own(filepath.Join(fx.bin, "etcd")), "", false},
		{"a sibling bin2", own(filepath.Join(filepath.Dir(fx.bin), "bin2", "kine")), "", false},
		{"another work dir's bin", own(filepath.Join(root, "other", "bin", "kine")), "", false},
		{"a subdirectory of bin", own(filepath.Join(fx.bin, "sub", "kine")), "", false},
		{"a relative executable path", own("bin/kine"), "", false},
		{"no executable path", own(""), "", false},
		{"a live parent's child", func() orphanProc { p := own(filepath.Join(fx.bin, "kine")); p.ppid = 4242; return p }(), "", false},
		{"launchd itself", func() orphanProc { p := own(filepath.Join(fx.bin, "kine")); p.pid = 1; return p }(), "", false},
		{"started after this daemon", func() orphanProc {
			p := own(filepath.Join(fx.bin, "kine"))
			p.startUnixNano = fx.daemon.Add(time.Second).UnixNano()
			return p
		}(), "", false},
		{"started at this daemon's start", func() orphanProc {
			p := own(filepath.Join(fx.bin, "kine"))
			p.startUnixNano = fx.daemon.UnixNano()
			return p
		}(), "", false},
		{"no start time", func() orphanProc { p := own(filepath.Join(fx.bin, "kine")); p.startUnixNano = 0; return p }(), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := leftoverName(tc.p, fx.bin, fx.daemon)
			if got != tc.want || ok != tc.wantOurs {
				t.Fatalf("leftoverName(%+v) = %q, %v; want %q, %v", tc.p, got, ok, tc.want, tc.wantOurs)
			}
		})
	}
}

// TestReapLeftoversStopsInShutdownOrder: the apiserver first, the controllers
// together, then the registry, and the datastore last, each by SIGTERM to its own
// group, with one Warn line per process; a non-leftover is never signalled.
func TestReapLeftoversStopsInShutdownOrder(t *testing.T) {
	fx := newReapFixture(t)
	stranger := fx.orphan(900, kineBinaryName)
	stranger.ppid = 77
	table := newFakeProcTable(
		fx.orphan(105, kineBinaryName),
		fx.orphan(104, registrysvc.ZotBinaryName),
		fx.orphan(103, "kube-controller-manager"),
		fx.orphan(102, "kube-scheduler"),
		fx.orphan(101, "kube-apiserver"),
		stranger,
	)
	var logs bytes.Buffer
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.NewTextHandler(&logs, nil)), fx.workDir, fx.daemon, table.seams())
	if err != nil {
		t.Fatalf("reapLeftovers = %v", err)
	}
	sent := table.signals()
	if len(sent) != 5 {
		t.Fatalf("signals = %+v, want five SIGTERMs", sent)
	}
	tierOf := map[int]int{-101: 0, -102: 1, -103: 1, -104: 2, -105: 3}
	last := -1
	for _, s := range sent {
		tier, ok := tierOf[s.target]
		if !ok || s.sig != syscall.SIGTERM {
			t.Fatalf("unexpected signal %+v (want SIGTERM to a leftover's group)", s)
		}
		if tier < last {
			t.Fatalf("signals out of shutdown order: %+v", sent)
		}
		last = tier
	}
	if !table.alive(900) {
		t.Fatal("a process with a live parent was stopped")
	}
	if len(reaped) != 5 || reaped[0].Pid != 101 || reaped[4].Pid != 105 {
		t.Fatalf("Reaped = %+v, want five, apiserver first and kine last", reaped)
	}
	for _, r := range reaped {
		if r.Signal != syscall.SIGTERM || r.Age < 59*time.Minute {
			t.Fatalf("reaped %+v, want SIGTERM and an age of about an hour", r)
		}
		if !strings.Contains(logs.String(), "pid="+strconv.Itoa(r.Pid)) {
			t.Fatalf("no Warn line for pid %d:\n%s", r.Pid, logs.String())
		}
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 5 {
		t.Fatalf("%d Warn lines, want one per reaped process:\n%s", n, logs.String())
	}
	// One Info line before (with the candidates and the worst-case bound: four
	// tiers' graces plus four post-SIGKILL waits) and one after.
	wantBound := 3*reapTierGrace + reapDatastoreGrace + 4*reapKillWait
	if !strings.Contains(logs.String(), "candidates=5 bound="+wantBound.String()) ||
		!strings.Contains(logs.String(), "finished stopping a previous run's control-plane processes") ||
		!strings.Contains(logs.String(), "reaped=5") {
		t.Fatalf("missing the before/after Info lines (bound %s):\n%s", wantBound, logs.String())
	}
}

// TestTierGraceDatastoreGetsStopsBudget: the kine tier's SIGTERM grace is the
// budget Stop gives kine; the other tiers keep reapTierGrace.
func TestTierGraceDatastoreGetsStopsBudget(t *testing.T) {
	if reapDatastoreGrace != drainGrace {
		t.Fatalf("reapDatastoreGrace = %s, want drainGrace %s", reapDatastoreGrace, drainGrace)
	}
	for _, tier := range reapTiers {
		want := reapTierGrace
		if tier[0] == kineBinaryName {
			want = drainGrace
		}
		if got := tierGrace(tier); got != want {
			t.Errorf("tierGrace(%v) = %s, want %s", tier, got, want)
		}
	}
}

// TestReapLeftoversZeroCandidatesLogsOneDebugLine: a scan that finds nothing
// says so once at Debug and nothing at Info.
func TestReapLeftoversZeroCandidatesLogsOneDebugLine(t *testing.T) {
	fx := newReapFixture(t)
	stranger := fx.orphan(910, kineBinaryName)
	stranger.ppid = 77
	table := newFakeProcTable(stranger)
	var logs bytes.Buffer
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), fx.workDir, fx.daemon, table.seams())
	if err != nil || len(reaped) != 0 {
		t.Fatalf("reapLeftovers = %+v, %v", reaped, err)
	}
	if strings.Count(logs.String(), "\n") != 1 || !strings.Contains(logs.String(), "level=DEBUG") {
		t.Fatalf("want exactly one Debug line, got:\n%s", logs.String())
	}
}

// TestReapLeftoversEscalatesToSIGKILL: a leftover that outlives its tier's grace
// is SIGKILLed, and reported so.
func TestReapLeftoversEscalatesToSIGKILL(t *testing.T) {
	shortReapWaits(t)
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(200, kineBinaryName))
	table.ignore[200] = []syscall.Signal{syscall.SIGTERM}
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams())
	if err != nil {
		t.Fatalf("reapLeftovers = %v", err)
	}
	if len(reaped) != 1 || reaped[0].Signal != syscall.SIGKILL || table.alive(200) {
		t.Fatalf("Reaped = %+v, alive %v; want pid 200 ended by SIGKILL", reaped, table.alive(200))
	}
}

// TestReapLeftoversSurvivorIsAnError: a leftover still there after its SIGKILL
// is a reap failure naming it.
func TestReapLeftoversSurvivorIsAnError(t *testing.T) {
	shortReapWaits(t)
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(300, kineBinaryName))
	table.ignore[300] = []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}
	_, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams())
	if err == nil || !strings.Contains(err.Error(), "pid 300") {
		t.Fatalf("reapLeftovers = %v, want an error naming pid 300", err)
	}
}

// TestReapLeftoversRechecksIdentityBeforeSignal: a pid that names a different
// process by the time it would be signalled (recycled: another start time) is
// not signalled at all.
func TestReapLeftoversRechecksIdentityBeforeSignal(t *testing.T) {
	fx := newReapFixture(t)
	p := fx.orphan(400, kineBinaryName)
	table := newFakeProcTable(p)
	recycled := p
	recycled.startUnixNano = fx.daemon.Add(-time.Second).UnixNano()
	recycled.exe = "/usr/bin/true"
	table.recycled[400] = recycled
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams())
	if err != nil {
		t.Fatalf("reapLeftovers = %v", err)
	}
	if len(reaped) != 0 || len(table.signals()) != 0 {
		t.Fatalf("Reaped = %+v, signals = %+v; a recycled pid must not be signalled", reaped, table.signals())
	}
}

// TestReapLeftoversSignalsTheProcessWhenNotAGroupLeader: a leftover that does
// not lead its own group is signalled alone, never the group it shares.
func TestReapLeftoversSignalsTheProcessWhenNotAGroupLeader(t *testing.T) {
	fx := newReapFixture(t)
	p := fx.orphan(500, kineBinaryName)
	p.pgid = 499
	table := newFakeProcTable(p)
	if _, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams()); err != nil {
		t.Fatal(err)
	}
	if sent := table.signals(); len(sent) != 1 || sent[0].target != 500 {
		t.Fatalf("signals = %+v, want one to pid 500 alone", sent)
	}
}

// TestReapLeftoversStopsOnCancel: a stop arriving mid-reap ends it with the
// context's error, before any SIGKILL and before the next tier.
func TestReapLeftoversStopsOnCancel(t *testing.T) {
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(601, "kube-apiserver"), fx.orphan(602, kineBinaryName))
	table.ignore[601] = []syscall.Signal{syscall.SIGTERM}
	ctx, cancel := context.WithCancel(t.Context())
	table.onSignal = func(fakeSignal) { cancel() }
	_, err := reapLeftovers(ctx, slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("reapLeftovers = %v, want context.Canceled", err)
	}
	if sent := table.signals(); len(sent) != 1 || sent[0].sig != syscall.SIGTERM {
		t.Fatalf("signals = %+v, want only the apiserver's SIGTERM", sent)
	}
	if !table.alive(602) {
		t.Fatal("kine was stopped after the reap was cancelled")
	}
}

// TestReapLeftoversUnreadableTableReapsNothing: a process table that cannot be
// read proves nothing is ours, so nothing is signalled and the start goes on.
func TestReapLeftoversUnreadableTableReapsNothing(t *testing.T) {
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(700, kineBinaryName))
	table.listErr = errors.New("process table unreadable")
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), fx.workDir, fx.daemon, table.seams())
	if err != nil || len(reaped) != 0 || len(table.signals()) != 0 {
		t.Fatalf("reapLeftovers = %+v, %v (signals %+v); want nothing reaped and no error", reaped, err, table.signals())
	}
}

// TestReapLeftoversNoBinDir: a work dir that never had a bin dir lists nothing.
func TestReapLeftoversNoBinDir(t *testing.T) {
	table := newFakeProcTable()
	reaped, err := reapLeftovers(t.Context(), slog.New(slog.DiscardHandler), filepath.Join(t.TempDir(), "fresh"), time.Now(), table.seams())
	if err != nil || len(reaped) != 0 || table.listed != 0 {
		t.Fatalf("reapLeftovers = %+v, %v, listed %d; want nothing and no table read", reaped, err, table.listed)
	}
}

// reapConfig is a kine-posture Config over workDir with every probed port on a
// free loopback port, so no cluster on this machine is probed.
func reapConfig(t *testing.T, workDir string) Config {
	return Config{
		WorkDir:               workDir,
		KinePort:              freePort(t),
		SchedulerPort:         freePort(t),
		ControllerManagerPort: freePort(t),
	}
}

// TestReapOrphanedControlPlaneHoldsTheLock: the kine posture takes the work-dir
// lock before the reap and returns it held; a failed reap drops it.
func TestReapOrphanedControlPlaneHoldsTheLock(t *testing.T) {
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(800, kineBinaryName))
	res, err := reapOrphanedControlPlane(t.Context(), reapConfig(t, fx.workDir), fx.daemon, table.seams())
	if err != nil {
		t.Fatalf("reap = %v", err)
	}
	if len(res.Reaped) != 1 || res.PortsHeld != nil || res.Hold == nil {
		t.Fatalf("reap = %+v, want pid 800 reaped, the ports free, and a hold", res)
	}
	if _, err := lockWorkDir(fx.workDir); !errors.Is(err, ErrWorkDirLocked) {
		t.Fatalf("lock while the hold is held = %v, want ErrWorkDirLocked", err)
	}
	if err := res.Hold.Release(); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockWorkDir(fx.workDir)
	if err != nil {
		t.Fatalf("lock after Release = %v", err)
	}
	_ = unlock()

	shortReapWaits(t)
	stuck := newFakeProcTable(fx.orphan(801, kineBinaryName))
	stuck.ignore[801] = []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL}
	res, err = reapOrphanedControlPlane(t.Context(), reapConfig(t, fx.workDir), fx.daemon, stuck.seams())
	var bu *BringUpError
	if !errors.As(err, &bu) || bu.Phase != PhaseProvision {
		t.Fatalf("failed reap = %v, want a provision-phase BringUpError", err)
	}
	if res.Hold != nil {
		t.Fatal("a failed reap returned a hold")
	}
	unlock, err = lockWorkDir(fx.workDir)
	if err != nil {
		t.Fatalf("lock after a failed reap = %v, want it released", err)
	}
	_ = unlock()
}

// TestReapOrphanedControlPlaneUnderAnotherHoldersLock: a work dir a running
// server holds is a bring-up failure, and its processes are never even listed.
func TestReapOrphanedControlPlaneUnderAnotherHoldersLock(t *testing.T) {
	fx := newReapFixture(t)
	unlock, err := lockWorkDir(fx.workDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unlock() }()
	table := newFakeProcTable(fx.orphan(810, kineBinaryName))
	res, err := reapOrphanedControlPlane(t.Context(), reapConfig(t, fx.workDir), fx.daemon, table.seams())
	var bu *BringUpError
	if !errors.Is(err, ErrWorkDirLocked) || !errors.As(err, &bu) {
		t.Fatalf("reap = %v, want a BringUpError wrapping ErrWorkDirLocked", err)
	}
	if res.Hold != nil || table.listed != 0 || len(table.signals()) != 0 {
		t.Fatalf("reap under another holder's lock = %+v, listed %d, signals %+v; want nothing touched", res, table.listed, table.signals())
	}
}

// TestReapOrphanedControlPlaneEtcdPostureIsANoOp pins the exclusion: with an etcd
// member configured nothing is listed, signalled or locked here.
func TestReapOrphanedControlPlaneEtcdPostureIsANoOp(t *testing.T) {
	fx := newReapFixture(t)
	table := newFakeProcTable(fx.orphan(820, kineBinaryName))
	cfg := reapConfig(t, fx.workDir)
	cfg.Etcd = &EtcdConfig{}
	res, err := reapOrphanedControlPlane(t.Context(), cfg, fx.daemon, table.seams())
	if err != nil || res.Hold != nil || len(res.Reaped) != 0 {
		t.Fatalf("etcd-posture reap = %+v, %v; want a zero result", res, err)
	}
	if table.listed != 0 || len(table.signals()) != 0 {
		t.Fatalf("etcd posture listed %d processes and sent %+v", table.listed, table.signals())
	}
	if _, err := os.Stat(WorkDirLockPath(fx.workDir)); !os.IsNotExist(err) {
		t.Fatalf("the etcd posture's reap created the lock file (%v)", err)
	}
}

// TestWorkDirHoldAdoptOnce: Start adopts a hold once; Release after adoption is a
// no-op, a nil hold is safe, and a released hold cannot be adopted.
func TestWorkDirHoldAdoptOnce(t *testing.T) {
	var nilHold *WorkDirHold
	if err := nilHold.Release(); err != nil {
		t.Fatal(err)
	}
	if _, ok := nilHold.adopt(); ok {
		t.Fatal("a nil hold was adopted")
	}
	calls := 0
	h := &WorkDirHold{unlock: func() error { calls++; return nil }}
	unlock, ok := h.adopt()
	if !ok {
		t.Fatal("first adopt refused")
	}
	if _, ok := h.adopt(); ok {
		t.Fatal("second adopt allowed")
	}
	if err := h.Release(); err != nil || calls != 0 {
		t.Fatalf("Release after adopt = %v, unlock calls %d; want a no-op", err, calls)
	}
	_ = unlock()
	released := &WorkDirHold{unlock: func() error { calls++; return nil }}
	_ = released.Release()
	_ = released.Release()
	if _, ok := released.adopt(); ok || calls != 2 {
		t.Fatalf("released hold adopted %v, unlock calls %d; want refused and one more unlock", ok, calls)
	}
}
