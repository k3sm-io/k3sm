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
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"k3sm.io/k3sm/pkg/registrysvc"
)

// Reaping the control plane a killed server left behind.
//
// Every control-plane child runs in its own process group (spawnEnv), so a
// SIGKILL of the server reaches none of them: kine, the apiserver, the scheduler,
// the controller-manager and the registry's zot keep running under launchd
// (ppid 1), still holding their ports. The server launchd starts next then finds
// the datastore port held and refuses, correctly for a foreign holder, and parks
// on the crash-loop breaker after five refusals.
//
// So a server's start first stops exactly those leftovers. A process is this
// work dir's leftover only when ALL of these hold:
//
//   - this process holds the work dir's lock, so no live server is supervising
//     anything there (a live server's children are never candidates);
//   - its executable, as the kernel reports it (proc_pidpath) and resolved, is one
//     of the known component binaries directly under the resolved <work-dir>/bin;
//   - its parent is launchd (ppid 1): the server that spawned it is gone;
//   - it started before this server did.
//
// Anything else that holds a port keeps the ordinary preflight refusal
// (ErrDatastorePortHeld, ErrComponentPortHeld), unchanged.
//
// The embedded-etcd posture is excluded: when Config.Etcd is set nothing is
// reaped and no lock is taken here (Start takes it, as before). An etcd member is
// a quorum participant whose stop is not this start's decision to make.

// reapTierGrace is how long each shutdown tier gets between its SIGTERM and the
// SIGKILL escalation, for every tier but the datastore's; the processes of one
// tier are signalled together. A var only so a unit test can shorten it.
var reapTierGrace = 2500 * time.Millisecond

// reapDatastoreGrace is the datastore tier's SIGTERM grace: the same budget Stop
// gives kine (drainGrace), so a leftover kine gets as long to close its database
// cleanly as it would at an ordinary shutdown. A var only so a unit test can
// shorten it.
var reapDatastoreGrace = drainGrace

// reapKillWait bounds the wait for a process to be gone after its SIGKILL. A
// SIGKILLed process exits at once; the bound only keeps a wedged exit from
// holding the start open. A var only so a unit test can shorten it.
var reapKillWait = 5 * time.Second

// reapPoll is how often a reap checks whether a signalled process is gone.
const reapPoll = 50 * time.Millisecond

// reapPortWait bounds the re-probe of the control-plane ports after a reap. A
// listening socket closes with its process, so this only covers the kernel
// finishing the close.
const reapPortWait = 2 * time.Second

// launchdPPID is the parent pid an orphan is re-parented to on macOS.
const launchdPPID = 1

// reapTiers is the order the leftovers are stopped in: the apiserver drains first,
// then the controllers, as Stop does (shutdownOrder), then the registry's zot (which
// an ordinary shutdown stops before the control plane, outside Stop), and the
// datastore last so nothing loses it mid-shutdown. helm and
// kubectl are deliberately absent: they are not long-running server children
// (helm runs inside pods, which the node re-attaches).
var reapTiers = [][]string{
	{"kube-apiserver"},
	{"kube-scheduler", "kube-controller-manager"},
	{registrysvc.ZotBinaryName},
	{kineBinaryName},
}

// orphanProc is one process as the reap sees it.
type orphanProc struct {
	pid, ppid, pgid int
	// startUnixNano is the kernel's start time (kinfo_proc p_starttime).
	startUnixNano int64
	// exe is the executable path the kernel reports (proc_pidpath), unresolved.
	exe string
}

// orphanSeams are the process-table reads and the signal a reap uses. The
// production set is defaultOrphanSeams (orphanreap_darwin.go); a test replaces
// them to drive the decisions without real processes.
type orphanSeams struct {
	// list returns the live, non-zombie processes of this uid.
	list func() ([]orphanProc, error)
	// lookup re-reads one pid; ok is false when it is gone (or a zombie).
	lookup func(pid int) (orphanProc, bool)
	// kill sends sig to pid (negative: the process group).
	kill func(pid int, sig syscall.Signal) error
}

// ReapedProcess is one leftover the reap stopped.
type ReapedProcess struct {
	// Pid is the process id it had.
	Pid int
	// Exe is its resolved executable path.
	Exe string
	// Age is how long it had been running when the reap found it.
	Age time.Duration
	// Signal is the signal that ended it: SIGTERM, or SIGKILL after the grace.
	Signal syscall.Signal
}

// OrphanReap is the result of ReapOrphanedControlPlane.
type OrphanReap struct {
	// Hold is the work-dir lock the reap took, for the server to hand to Start
	// through Config.WorkDirHold. Nil in the etcd posture, which takes no lock
	// here.
	Hold *WorkDirHold
	// Reaped lists the leftovers stopped, in stop order.
	Reaped []ReapedProcess
	// PortsHeld is the probe of the datastore and component ports after the
	// reap (waited on briefly when something was stopped): nil when they are
	// free, otherwise the refusal the bring-up preflight
	// will return for them (it wraps ErrDatastorePortHeld or
	// ErrComponentPortHeld). It is a report only: the refusal itself stays where it
	// has always been, at bring-up, so it is counted on the crash-loop breaker the
	// ordinary way.
	PortsHeld error
}

// WorkDirHold is the server's hold on its work dir's lock, taken before the
// orphan reap and handed to Start, which keeps it until Stop has reaped every
// child. It is safe for concurrent use.
type WorkDirHold struct {
	mu      sync.Mutex
	unlock  func() error
	adopted bool
}

// Release drops the lock unless Start has adopted it (Stop releases it then). It
// is idempotent and a no-op on a nil hold, so a server can defer it
// unconditionally.
func (h *WorkDirHold) Release() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.adopted || h.unlock == nil {
		return nil
	}
	unlock := h.unlock
	h.unlock = nil
	return unlock()
}

// adopt hands the lock to the caller, once. ok is false when the hold was
// already adopted or released, and the caller takes the lock itself.
func (h *WorkDirHold) adopt() (unlock func() error, ok bool) {
	if h == nil {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.adopted || h.unlock == nil {
		return nil, false
	}
	h.adopted = true
	unlock = h.unlock
	h.unlock = nil
	return unlock, true
}

// ReapOrphanedControlPlane stops the control-plane children a previous run of
// cfg.WorkDir left running, before a server starts its own. daemonStart is this
// server process's start time: only a process that started before it can be a
// previous run's.
//
// In the kine posture it first takes the work-dir lock, which it returns in
// OrphanReap.Hold; a lock another holder has is ErrWorkDirLocked, and nothing is
// touched. With cfg.Etcd set it does nothing and returns a zero OrphanReap.
//
// A process table that cannot be read is logged and treated as "nothing is
// provably ours": the preflight then refuses any holder, as before. An error is
// returned for the lock, for a leftover that is still running after its SIGKILL,
// and for ctx ending mid-reap; each comes back as a provision-phase BringUpError,
// so the daemon records it on the breaker like any other failed bring-up.
func ReapOrphanedControlPlane(ctx context.Context, cfg Config, daemonStart time.Time) (OrphanReap, error) {
	return reapOrphanedControlPlane(ctx, cfg, daemonStart, defaultOrphanSeams)
}

func reapOrphanedControlPlane(ctx context.Context, cfg Config, daemonStart time.Time, seams orphanSeams) (OrphanReap, error) {
	cfg = cfg.withDefaults()
	if cfg.Etcd != nil {
		// The etcd posture is out of scope: no lock here, no reap.
		return OrphanReap{}, nil
	}
	unlock, err := lockWorkDir(cfg.WorkDir)
	if err != nil {
		return OrphanReap{}, provisionStep("reap-orphans", err)
	}
	res := OrphanReap{Hold: &WorkDirHold{unlock: unlock}}
	reaped, err := reapLeftovers(ctx, cfg.Logger, cfg.WorkDir, daemonStart, seams)
	res.Reaped = reaped
	if err != nil {
		_ = res.Hold.Release()
		return OrphanReap{Reaped: reaped}, provisionStep("reap-orphans", err)
	}
	wait := time.Duration(0)
	if len(reaped) > 0 {
		wait = reapPortWait
	}
	res.PortsHeld = awaitControlPlanePortsFree(ctx, cfg, wait)
	return res, nil
}

// reapLeftovers finds this work dir's leftovers and stops them tier by tier.
// The caller holds the work-dir lock.
func reapLeftovers(ctx context.Context, logger *slog.Logger, workDir string, daemonStart time.Time, seams orphanSeams) ([]ReapedProcess, error) {
	bin, err := filepath.EvalSymlinks(binDir(workDir))
	if err != nil {
		// No bin dir: nothing was ever spawned from this work dir.
		return nil, nil
	}
	procs, err := seams.list()
	if err != nil {
		logger.Warn("could not read the process table to look for a previous run's control-plane processes; any port they hold is refused as before",
			"err", err)
		return nil, nil
	}
	byName := make(map[string][]orphanProc)
	candidates := 0
	for _, p := range procs {
		if name, ok := leftoverName(p, bin, daemonStart); ok {
			byName[name] = append(byName[name], p)
			candidates++
		}
	}
	if candidates == 0 {
		logger.Debug("no control-plane process a previous run of this server left running", "work-dir", workDir)
		return nil, nil
	}
	// The worst case is every non-empty tier spending its whole grace and the
	// post-SIGKILL wait; said up front so a long reap is never a silent block.
	var bound time.Duration
	for _, tier := range reapTiers {
		for _, name := range tier {
			if len(byName[name]) > 0 {
				bound += tierGrace(tier) + reapKillWait
				break
			}
		}
	}
	logger.Info("stopping the control-plane processes a previous run of this server left running",
		"work-dir", workDir, "candidates", candidates, "bound", bound.String())
	began := time.Now()
	var reaped []ReapedProcess
	defer func() {
		logger.Info("finished stopping a previous run's control-plane processes",
			"work-dir", workDir, "reaped", len(reaped), "took", time.Since(began).Round(time.Millisecond).String())
	}()
	for _, tier := range reapTiers {
		var batch []orphanProc
		for _, name := range tier {
			batch = append(batch, byName[name]...)
		}
		if len(batch) == 0 {
			continue
		}
		done, err := reapTier(ctx, batch, tierGrace(tier), bin, daemonStart, seams)
		for _, r := range done {
			logger.Warn("stopped a control-plane process a previous run of this server left running",
				"pid", r.Pid, "exe", r.Exe, "age", r.Age.Round(time.Second).String(), "signal", r.Signal.String())
		}
		reaped = append(reaped, done...)
		if err != nil {
			return reaped, err
		}
	}
	return reaped, nil
}

// leftoverName reports whether p is a previous run's control-plane child of the
// work dir whose resolved bin is bin, and which component it is. Every condition
// must hold (see the file comment); the lock is the caller's.
func leftoverName(p orphanProc, bin string, daemonStart time.Time) (string, bool) {
	if p.pid <= launchdPPID || p.ppid != launchdPPID {
		return "", false
	}
	if p.startUnixNano <= 0 || p.startUnixNano >= daemonStart.UnixNano() {
		return "", false
	}
	exe := resolveExe(p.exe)
	if exe == "" || filepath.Dir(exe) != bin {
		return "", false
	}
	name := filepath.Base(exe)
	for _, tier := range reapTiers {
		for _, n := range tier {
			if n == name {
				return name, true
			}
		}
	}
	return "", false
}

// resolveExe resolves the kernel-reported executable path. A path that no longer
// resolves (the file was replaced) is compared as the kernel reported it.
func resolveExe(exe string) string {
	if exe == "" || !filepath.IsAbs(exe) {
		return ""
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		return r
	}
	return filepath.Clean(exe)
}

// stillLeftover re-reads p and reports whether it is still the same leftover:
// same pid, same start time, still orphaned, same executable.
//
// It is called immediately before every signal. The window it cannot close is
// the one between this read and the kill(2): the process could exit and its pid
// be handed to a new process in those microseconds. macOS allocates pids
// sequentially, so a recycle needs the whole pid space to wrap inside that
// window; the residual risk is accepted, as it is for every pid-based signal.
func stillLeftover(p orphanProc, bin string, daemonStart time.Time, seams orphanSeams) bool {
	now, ok := seams.lookup(p.pid)
	if !ok || now.startUnixNano != p.startUnixNano {
		return false
	}
	_, ok = leftoverName(now, bin, daemonStart)
	return ok
}

// tierGrace is a tier's SIGTERM grace: the datastore's is Stop's drainGrace,
// every other tier's is reapTierGrace.
func tierGrace(tier []string) time.Duration {
	for _, name := range tier {
		if name == kineBinaryName {
			return reapDatastoreGrace
		}
	}
	return reapTierGrace
}

// reapTier stops one tier's leftovers together: SIGTERM, grace for them to
// exit, SIGKILL for whatever has not, then a bounded wait for them to be gone.
func reapTier(ctx context.Context, batch []orphanProc, grace time.Duration, bin string, daemonStart time.Time, seams orphanSeams) ([]ReapedProcess, error) {
	now := time.Now()
	var live []orphanProc
	for _, p := range batch {
		if !stillLeftover(p, bin, daemonStart, seams) {
			continue
		}
		if err := seams.kill(signalTarget(p), syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("SIGTERM the previous run's %s (pid %d): %w", filepath.Base(p.exe), p.pid, err)
		}
		live = append(live, p)
	}
	signal := make(map[int]syscall.Signal, len(live))
	for _, p := range live {
		signal[p.pid] = syscall.SIGTERM
	}
	left, err := awaitOrphansGone(ctx, live, grace, seams)
	if err != nil {
		return nil, err
	}
	for _, p := range left {
		if !stillLeftover(p, bin, daemonStart, seams) {
			continue
		}
		if err := seams.kill(signalTarget(p), syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("SIGKILL the previous run's %s (pid %d): %w", filepath.Base(p.exe), p.pid, err)
		}
		signal[p.pid] = syscall.SIGKILL
	}
	stuck, err := awaitOrphansGone(ctx, left, reapKillWait, seams)
	if err != nil {
		return nil, err
	}
	if len(stuck) > 0 {
		return nil, fmt.Errorf("the previous run's %s (pid %d) is still running %s after SIGKILL",
			filepath.Base(stuck[0].exe), stuck[0].pid, reapKillWait)
	}
	out := make([]ReapedProcess, 0, len(live))
	for _, p := range live {
		out = append(out, ReapedProcess{
			Pid:    p.pid,
			Exe:    resolveExe(p.exe),
			Age:    now.Sub(time.Unix(0, p.startUnixNano)),
			Signal: signal[p.pid],
		})
	}
	return out, nil
}

// signalTarget is the process group when p still leads one (spawnEnv makes every
// child a group leader, and the group also reaches anything it started), and p
// alone otherwise.
func signalTarget(p orphanProc) int {
	if p.pgid == p.pid {
		return -p.pid
	}
	return p.pid
}

// awaitOrphansGone polls until every process in procs is gone (no longer in the table,
// or its pid now names a different process), bound passes, or ctx ends. It
// returns the ones still there at the bound; ctx ending is an error.
func awaitOrphansGone(ctx context.Context, procs []orphanProc, bound time.Duration, seams orphanSeams) ([]orphanProc, error) {
	deadline := time.Now().Add(bound)
	for {
		var left []orphanProc
		for _, p := range procs {
			if now, ok := seams.lookup(p.pid); ok && now.startUnixNano == p.startUnixNano {
				left = append(left, p)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left, nil
		}
		procs = left
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("reap of the previous run's control plane interrupted: %w", ctx.Err())
		case <-time.After(reapPoll):
		}
	}
}

// awaitControlPlanePortsFree re-probes the datastore and component ports after a
// reap, with the same preflights bring-up runs, until they are free or wait
// passes (zero: one probe), and returns the last probe's refusal (nil when free).
func awaitControlPlanePortsFree(ctx context.Context, cfg Config, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := errors.Join(
			preflightDatastorePort(ctx, cfg.KinePort),
			preflightComponentPort(ctx, "scheduler", cfg.SchedulerPort),
			preflightComponentPort(ctx, "controller-manager", cfg.ControllerManagerPort),
		)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(reapPoll):
		}
	}
}
