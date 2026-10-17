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

package install

import (
	"context"
	"errors"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	runtimed "k3sm.io/runtimed/pkg/runtime"
	"k3sm.io/runtimed/pkg/supervisor"
)

// Uninstall's pod teardown.
//
// A native pod's processes are session leaders that outlive the node daemon on
// purpose: a daemon restart re-attaches to them. So booting the daemon out
// stops nothing, and without this step an uninstall left every pod running, and
// a later reinstall would have found them and re-attached. The runtime records
// every pod process group it spawns in its reap store (<data root>/podreap) and
// exports the one reader of it (runtime.ReadPodReapRecords); the uninstall reads
// those records after the daemons are booted out (so no daemon
// can start a replacement) and stops each recorded group.
//
// The identity guard is the runtime's own: a group is signalled only while its
// leader (pid == pgid) is alive with exactly the recorded start time. A pgid the
// kernel recycled to another process has a different start and is left alone.
// A root kill aimed by a stale record is the failure this guard exists to make
// unreachable.
//
// A container runs under a resident shim that leads its group, so the group's
// leader is the shim and the container is the shim's child in the same group.
// The record carries the child's identity too (ChildPid, ChildStartUnixNano).
// When the shim has died and the container has not, the leader is gone but the
// group is still the pod's, and the child proves it: a group whose leader is
// gone is signalled only when the recorded child is alive, still a member of
// that group, with exactly its recorded start time. A child whose start differs
// or that left the group, and a record with no child identity, prove nothing,
// so those groups are left alone (the runtime's recovery runbook for leaked
// process groups covers them).
//
// A record can also name Survivors: processes of the container's tree that
// outlived the runtime's own teardown kill (a setsid escapee among them) and
// that it could not see gone within its budget. Their group is usually empty
// and their leader gone, so the group rules above never reach them. Each one is
// SIGKILLed by pid only while its live start time equals the recorded one, the
// rule the runtime's startup reap applies to the same list, and only while its
// live session is the recorded one and not the sweeper's own; a survivor that
// led its own session leads its own group too, and that group is killed under
// the same guard. A pid whose start or session differs was recycled and is
// skipped, and the sweeper's own pid and pid 1 are never signalled.

// podGroupStopGrace is how long the recorded pod groups get to exit after
// SIGTERM before they are sent SIGKILL: the kubelet's default
// terminationGracePeriodSeconds is 30s, but an uninstall is an operator at a
// terminal, and 10s is the bound the runtime's own graceful stop starts from.
const podGroupStopGrace = 10 * time.Second

// teardownPodGroups stops every live pod process group the runtime recorded:
// SIGTERM to each verified group, a shared podGroupStopGrace for them to exit,
// then SIGKILL to each survivor. Every step is logged. It returns the first
// error, for the caller to report after the rest of the teardown has run.
func teardownPodGroups(ctx context.Context, sys System, cfg Config) error {
	recs, err := sys.ReadPodReapRecords(cfg.DataRoot)
	if err != nil {
		cfg.Logger.Warn("could not read the pod process records; a pod process may survive the uninstall", "data-root", cfg.DataRoot, "err", err)
	}
	err = errors.Join(err, killRecordedSurvivors(sys, cfg, recs))
	var stopping []runtimed.PodReapRecord
	for _, rec := range recs {
		if rec.Pgid <= 1 || rec.StartUnixNano == 0 {
			cfg.Logger.Warn("pod process record is not usable; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			continue
		}
		if !podGroupIsRecorded(sys, cfg, rec) {
			continue
		}
		cfg.Logger.Info("stopping pod process group (SIGTERM)", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
		if serr := sys.SignalProcessGroup(rec.Pgid, syscall.SIGTERM); serr != nil {
			cfg.Logger.Warn("could not signal pod process group", "pod", rec.PodID, "pgid", rec.Pgid, "signal", "SIGTERM", "err", serr)
			err = errors.Join(err, serr)
		}
		stopping = append(stopping, rec)
	}
	if len(stopping) == 0 {
		return err
	}
	pgids := make([]int, len(stopping))
	for i, rec := range stopping {
		pgids[i] = rec.Pgid
	}
	left := map[int]bool{}
	for _, pgid := range sys.WaitProcessGroupsGone(ctx, pgids, podGroupStopGrace) {
		left[pgid] = true
	}
	for _, rec := range stopping {
		if !left[rec.Pgid] {
			cfg.Logger.Info("pod process group stopped", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			continue
		}
		// Re-verified at this moment: the group may have emptied, and its pgid
		// been reused, during the grace.
		if !podGroupIsRecorded(sys, cfg, rec) {
			continue
		}
		cfg.Logger.Warn("pod process group did not exit within the grace period; killing it (SIGKILL)", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid, "grace", podGroupStopGrace)
		if serr := sys.SignalProcessGroup(rec.Pgid, syscall.SIGKILL); serr != nil {
			cfg.Logger.Warn("could not signal pod process group", "pod", rec.PodID, "pgid", rec.Pgid, "signal", "SIGKILL", "err", serr)
			err = errors.Join(err, serr)
		}
	}
	return err
}

// podGroupIsRecorded reports whether rec's process group is still provably the
// recorded pod's: its leader alive with the recorded start, or, when the leader
// is gone, the recorded child alive in that group with its recorded start. Each
// refusal is logged.
func podGroupIsRecorded(sys System, cfg Config, rec runtimed.PodReapRecord) bool {
	start, alive := sys.ProcessGroupLeaderStart(rec.Pgid)
	if alive {
		if start != rec.StartUnixNano {
			cfg.Logger.Info("pod process group id now belongs to another process; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			return false
		}
		return true
	}
	if rec.ChildPid <= 1 || rec.ChildStartUnixNano == 0 {
		cfg.Logger.Info("pod process group leader is gone; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
		return false
	}
	childStart, childAlive := sys.ProcessGroupMemberStart(rec.Pgid, rec.ChildPid)
	switch {
	case !childAlive:
		cfg.Logger.Info("pod process group leader and container are gone; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid, "pid", rec.ChildPid)
		return false
	case childStart != rec.ChildStartUnixNano:
		cfg.Logger.Info("pod process group leader is gone and its container pid now belongs to another process; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid, "pid", rec.ChildPid)
		return false
	}
	cfg.Logger.Info("pod process group leader (its shim) is gone; the container is verified by its own identity", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid, "pid", rec.ChildPid)
	return true
}

// survivorProcs is the per-process seam the survivor kill needs: a process's
// kernel start time and session, the sweeper's own pid and session, and a
// signal to one process. A System that does not provide it is served by
// runtimeProcs.
type survivorProcs interface {
	ProcessStart(pid int) (startUnixNano int64, alive bool)
	ProcessSession(pid int) (sid int, ok bool)
	Self() (pid, sid int)
	SignalProcess(pid int, sig syscall.Signal) error
}

// runtimeProcs is survivorProcs over the runtime's exported primitives
// (supervisor.ProcStartTimeNano, supervisor.KillPID: the pair its startup reap
// kills recorded survivors with) and getsid(2).
type runtimeProcs struct{}

func (runtimeProcs) ProcessStart(pid int) (int64, bool) { return supervisor.ProcStartTimeNano(pid) }

func (runtimeProcs) ProcessSession(pid int) (int, bool) {
	sid, err := unix.Getsid(pid)
	return sid, err == nil
}

func (runtimeProcs) Self() (int, int) {
	sid, err := unix.Getsid(0)
	if err != nil {
		sid = -1 // unknown: no recorded session equals it, so nothing is spared by it
	}
	return os.Getpid(), sid
}

func (runtimeProcs) SignalProcess(pid int, sig syscall.Signal) error {
	return supervisor.KillPID(pid, sig)
}

// survivorIsRecorded reports whether s is still exactly the recorded process
// and safe for the sweeper to kill: not pid 1 or below, not the sweeper
// itself, alive with exactly the recorded start time, and in exactly the
// recorded session, which is not the sweeper's own. It mirrors the identity
// rule of the runtime's startup reap of the same list
// (runtime.(*Runtime).reapRecordedSurvivors), which exports no helper for it,
// and adds the session match on top.
func survivorIsRecorded(procs survivorProcs, s runtimed.ReapSurvivor) bool {
	selfPid, selfSid := procs.Self()
	if s.Pid <= 1 || s.Pid == selfPid || s.StartUnixNano == 0 {
		return false
	}
	if start, alive := procs.ProcessStart(s.Pid); !alive || start != s.StartUnixNano {
		return false
	}
	sid, ok := procs.ProcessSession(s.Pid)
	return ok && sid == s.Sid && sid != selfSid
}

// killRecordedSurvivors SIGKILLs every recorded survivor still alive as exactly
// its recorded instance (survivorIsRecorded). A survivor that leads its own
// session (Sid == Pid) leads its own group, which is killed whole while that
// group's leader is the same instance; any other survivor is killed alone. A
// survivor that fails the identity check is skipped without a signal. The
// count killed is logged per record; the first signal error is returned.
func killRecordedSurvivors(sys System, cfg Config, recs []runtimed.PodReapRecord) error {
	procs, ok := sys.(survivorProcs)
	if !ok {
		procs = runtimeProcs{}
	}
	var err error
	for _, rec := range recs {
		killed := 0
		for _, s := range rec.Survivors {
			if !survivorIsRecorded(procs, s) {
				continue
			}
			var serr error
			if lstart, alive := sys.ProcessGroupLeaderStart(s.Pid); s.Sid == s.Pid && alive && lstart == s.StartUnixNano {
				serr = sys.SignalProcessGroup(s.Pid, syscall.SIGKILL)
			} else {
				serr = procs.SignalProcess(s.Pid, syscall.SIGKILL)
			}
			if serr != nil {
				cfg.Logger.Warn("could not kill a recorded pod survivor", "pod", rec.PodID, "container", rec.Container, "pid", s.Pid, "err", serr)
				err = errors.Join(err, serr)
				continue
			}
			killed++
		}
		if killed > 0 {
			cfg.Logger.Info("killed the recorded survivors of a pod's process tree (SIGKILL)", "pod", rec.PodID, "container", rec.Container, "killed", killed)
		}
	}
	return err
}
