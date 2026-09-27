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
	"syscall"
	"time"

	runtimed "k3sm.io/runtimed/pkg/runtime"
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
// kernel recycled to another process has a different start and is left alone,
// and a group whose leader is gone is left alone too, because nothing proves it
// is still the pod's (the runtime's recovery runbook for leaked process groups
// covers that case). A root kill aimed by a stale record is the failure this
// guard exists to make unreachable.

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
	var stopping []runtimed.PodReapRecord
	for _, rec := range recs {
		if rec.Pgid <= 1 || rec.StartUnixNano == 0 {
			cfg.Logger.Warn("pod process record is not usable; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			continue
		}
		start, alive := sys.ProcessGroupLeaderStart(rec.Pgid)
		switch {
		case !alive:
			cfg.Logger.Info("pod process group leader is gone; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
			continue
		case start != rec.StartUnixNano:
			cfg.Logger.Info("pod process group id now belongs to another process; not signalled", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid)
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
		cfg.Logger.Warn("pod process group did not exit within the grace period; killing it (SIGKILL)", "pod", rec.PodID, "container", rec.Container, "pgid", rec.Pgid, "grace", podGroupStopGrace)
		if serr := sys.SignalProcessGroup(rec.Pgid, syscall.SIGKILL); serr != nil {
			cfg.Logger.Warn("could not signal pod process group", "pod", rec.PodID, "pgid", rec.Pgid, "signal", "SIGKILL", "err", serr)
			err = errors.Join(err, serr)
		}
	}
	return err
}
