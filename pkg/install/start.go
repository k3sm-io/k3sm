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
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// ErrUserStopped is returned by Restart on a node the user stopped, when
// --start was not given.
var ErrUserStopped = errors.New("this node was stopped by the user")

// startPrecondition makes the host safe for a fresh netd after a stop: any
// daemon an interrupted stop left loaded is booted out (so nothing re-adds
// what the flush removes), an interrupted stop's workloads are torn down, and
// the host network flush is re-run. What it cannot remove is logged; it never
// refuses the start.
func startPrecondition(ctx context.Context, sys System, cfg Config, d installedDaemons, m StopMarker, merr error) {
	for _, label := range slices.Concat(d.node, []string{NetdLabel}) {
		if label == NetdLabel && !d.netd {
			continue
		}
		if !loaded(sys, label) {
			continue
		}
		if err := sys.LaunchctlBootout(label); err != nil {
			cfg.Logger.Warn("could not boot out a daemon an interrupted stop left loaded", "label", label, "err", err)
			continue
		}
		if err := awaitUnloaded(ctx, sys, label, restartBudgetFor(label)); err != nil {
			cfg.Logger.Warn("a daemon an interrupted stop left loaded did not unload", "label", label, "err", err)
		}
	}
	var left []LeftoverItem
	if merr != nil || m.Phase != StopPhaseStopped {
		left = teardownWorkloads(ctx, sys, cfg)
	}
	hostLeft, _ := flushHostNetwork(sys, cfg, recordedFlushPrefixes(sys, cfg), interconnectNodeIndex(sys))
	for _, item := range append(left, hostLeft...) {
		cfg.Logger.Warn("start: the pre-start teardown left state behind; starting anyway", "what", item.Kind, "err", item.Err)
	}
}

// Start is `k3sm start`: on a stopped node it re-runs the stop's host flush
// (and, after an interrupted stop, its workload teardown) as a precondition,
// enables and bootstraps netd and then the node daemon through the restart
// sequence (await unloaded, retrying bootstrap, await running, netd answering
// before the node daemon goes), removes the stop marker only once they are
// up, and uncordons the node, retrying until the apiserver answers within
// uncordonBudget (ErrNodeStillCordoned, and the uncordon-pending marker, when
// it does not). A node with no stop marker and every daemon running is
// already started: Start restarts nothing. With the uncordon-pending marker
// it re-runs the full uncordon (the repair); without it, one best-effort
// attempt, which changes nothing on a node no stop annotated.
func Start(ctx context.Context, sys System, cfg Config, actor, reason string) error {
	cfg = cfg.withDefaults()
	actor, reason, err := lifecycleIdentity(actor, reason)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	d, err := readInstalledDaemons(sys, cfg)
	if err != nil {
		return fmt.Errorf("start: %w", err)
	}
	cfg.Role = d.role
	marker, present, merr := readStopMarker(sys, cfg)
	if !present && !slices.ContainsFunc(d.labels(), func(l string) bool {
		pid, err := sys.LaunchctlServicePID(l)
		return err != nil || pid == 0
	}) {
		// A start whose uncordon ran out of budget left the running node
		// cordoned and recorded it; re-running the start is the repair, with
		// the full budget. Otherwise one bounded, best-effort attempt: on a
		// node no stop annotated it changes nothing, and an apiserver that is
		// down must not turn a harmless re-run into a failure.
		if uncordonPendingPresent(sys, cfg) {
			if err := uncordonAfterStart(ctx, sys, cfg, actor, reason); err != nil {
				return fmt.Errorf("start: %w", err)
			}
		} else {
			markNode(ctx, cfg, false, actor, reason)
		}
		lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm start: already running, nothing to do", "actor", actor, "reason", reason, "result", "already-running")
		return nil
	}
	lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm start: starting", "actor", actor, "reason", reason)
	if present {
		if merr != nil {
			cfg.Logger.Warn("the stop marker is unreadable; treating the node as stopped part-way", "err", merr)
		}
		startPrecondition(ctx, sys, cfg, d, marker, merr)
		// The explicit override past the marker: the marker itself stays until
		// the daemons are up, so a start that fails leaves the node reported
		// as stopped, which is what it is.
		cfg.Start = true
	}
	if err := restartDaemons(ctx, sys, cfg, d.manifest(cfg)); err != nil {
		lifecycleLog(ctx, sys, cfg, slog.LevelError, "k3sm start: failed", "actor", actor, "reason", reason, "result", "failed", "err", err)
		return fmt.Errorf("start: %w (the stop marker is kept, so the node still reads as stopped; re-run `sudo k3sm start`)", err)
	}
	if present {
		if err := sys.RemoveStopMarker(cfg.StopMarker); err != nil {
			lifecycleLog(ctx, sys, cfg, slog.LevelError, "k3sm start: failed", "actor", actor, "reason", reason, "result", "failed", "err", err)
			return fmt.Errorf("start: the daemons are running but the stop marker %s could not be removed (re-run `sudo k3sm start`): %w", cfg.StopMarker, err)
		}
	}
	if err := uncordonAfterStart(ctx, sys, cfg, actor, reason); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	lifecycleLog(ctx, sys, cfg, slog.LevelInfo, "k3sm start: started", "actor", actor, "reason", reason, "result", "started")
	return nil
}

// uncordonAfterStart undoes what a stop did to the Node (awaitMarkNode within
// uncordonBudget), for Start and for install --start. Success removes the
// uncordon-pending marker. Running out of budget writes it, so a later
// `k3sm start` on the running node repairs the cordon. A failure is one Error
// line naming the last error's class, and is returned: the daemons are up,
// but a node left cordoned is not started.
func uncordonAfterStart(ctx context.Context, sys System, cfg Config, actor, reason string) error {
	err := awaitMarkNode(ctx, cfg, false, actor, reason, uncordonBudget)
	if err == nil {
		if cerr := clearUncordonPending(sys, cfg); cerr != nil {
			cfg.Logger.Warn("the node is uncordoned, but the uncordon-pending marker stays; the next start retries an uncordon that is already done", "err", cerr)
		}
		return nil
	}
	if errors.Is(err, ErrNodeStillCordoned) {
		if werr := writeUncordonPending(sys, cfg, actor, time.Now()); werr != nil {
			err = errors.Join(err, werr)
		}
	}
	class, _ := markNodeErrorClass(err)
	lifecycleLog(ctx, sys, cfg, slog.LevelError, "k3sm start: the node is still cordoned", "actor", actor, "reason", reason, "result", "still-cordoned", "class", class, "err", err)
	return err
}

// Restart is `k3sm restart`: the daemons are restarted through the restart
// sequence and pods keep running (a node daemon restart re-attaches to them).
// On a node the user stopped it refuses with ErrUserStopped, unless cfg.Start,
// in which case it is Start.
func Restart(ctx context.Context, sys System, cfg Config, actor, reason string) error {
	cfg = cfg.withDefaults()
	marker, present, merr := readStopMarker(sys, cfg)
	if present {
		if cfg.Start {
			return Start(ctx, sys, cfg, actor, reason)
		}
		if merr != nil {
			return fmt.Errorf("restart: %w (%v); run `sudo k3sm start`, or `sudo k3sm restart --start`", ErrUserStopped, merr)
		}
		return fmt.Errorf("restart: %w (%s, %q, at %s; marker %s); run `sudo k3sm start`, or `sudo k3sm restart --start`",
			ErrUserStopped, marker.Actor, marker.Reason, marker.At.UTC().Format(time.RFC3339), marker.Phase)
	}
	d, err := readInstalledDaemons(sys, cfg)
	if err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	cfg.Role = d.role
	if err := restartDaemons(ctx, sys, cfg, d.manifest(cfg)); err != nil {
		return fmt.Errorf("restart: %w", err)
	}
	return nil
}

// clearUserStop is uninstall's half of the lifecycle: when a stop marker is
// present, each daemon label in m is enabled (clearing the disable a stop
// left in launchd's override database) and then the marker is removed. With
// no marker it does nothing. A failed enable keeps the marker, so a re-run of
// uninstall retries.
func clearUserStop(sys System, cfg Config, m []artifact) error {
	if _, present, _ := readStopMarker(sys, cfg); !present {
		return nil
	}
	var errs error
	for _, a := range m {
		if a.kind != kindDaemon || a.oneshot {
			continue
		}
		if err := sys.LaunchctlEnable(a.label); err != nil {
			errs = errors.Join(errs, fmt.Errorf("clear the stop's disable of %s (run: sudo launchctl enable system/%s): %w", a.label, a.label, err))
		}
	}
	if errs != nil {
		return errs
	}
	if err := sys.RemoveStopMarker(cfg.StopMarker); err != nil {
		return fmt.Errorf("remove the stop marker %s: %w", cfg.StopMarker, err)
	}
	cfg.Logger.Info("cleared the user stop: labels enabled, stop marker removed", "marker", cfg.StopMarker)
	return nil
}

// manifest returns the long-running daemons as the artifacts restartDaemons
// walks, netd first.
func (d installedDaemons) manifest(cfg Config) []artifact {
	var m []artifact
	for _, l := range d.labels() {
		m = append(m, artifact{kind: kindDaemon, label: l, path: cfg.plistPath(l), disp: dispRemove})
	}
	return m
}

// UncordonBound is the longest a start retries the uncordon for.
func UncordonBound() time.Duration { return uncordonBudget.running }

// StartTimeBound is the longest a server start can take: booting out what an
// interrupted stop left loaded, that stop's workload teardown, then the
// restart sequence for netd (await unloaded, retrying bootstrap, await
// running, then answering) and for the node daemon, and the uncordon's whole
// retry window (uncordonBudget, which bounds every attempt inside it).
func StartTimeBound() time.Duration {
	precondition := serverRestartBudget.unload + netdRestartBudget.unload + podGroupStopGrace + vmHostKillWait
	netd := 2*netdRestartBudget.unload + 2*netdRestartBudget.running
	node := 2*serverRestartBudget.unload + serverRestartBudget.running
	return precondition + netd + node + uncordonBudget.running
}
