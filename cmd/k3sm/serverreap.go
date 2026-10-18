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

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/hostnet"
)

// daemonStartTime is this server process's start time: only a process that
// started before it can be a previous run's leftover. A var so the gate test can
// stand in for a daemon that started after the processes it plants.
var daemonStartTime = executor.ProcessStartTime

// reapOrphanedControlPlane is the executor's reap; a var so a unit test can
// drive reapServerOrphans' recording decision without real processes.
var reapOrphanedControlPlane = executor.ReapOrphanedControlPlane

// reapServerOrphans is the first step of a server start: it stops the
// control-plane children a previous run of this work dir left running (a server
// killed with SIGKILL leaves every one of them under launchd, still holding its
// port), so that run's own datastore never reads as a foreign holder.
//
// It runs before the crash-loop park check and before any port preflight, so a
// successful reap never counts toward the breaker. A failed reap (a leftover
// survived its SIGKILL, the scan was interrupted) is recorded on the breaker as a
// bring-up failure, the ordinary way, and returned. The one exception is
// ErrWorkDirLocked: another live server holds this work dir, so this start is a
// second server started beside it, and recording that would count toward the
// live server's own breaker (the record lives in the shared work dir). It is
// logged and returned, never recorded. A port still held
// after the reap is only logged here: the executor's bring-up preflight refuses it,
// unchanged. The embedded-etcd posture reaps nothing (executor.ReapOrphanedControlPlane).
func reapServerOrphans(ctx context.Context, opts serverOptions, breaker *crashBreaker, logger *slog.Logger) (executor.OrphanReap, error) {
	start, err := daemonStartTime()
	if err != nil {
		// Without the bound nothing is provably a previous run's: reap nothing,
		// keep the lock semantics (the zero time matches no process).
		logger.Warn("could not read this server's start time; not looking for a previous run's control-plane processes", "err", err)
		start = time.Time{}
	}
	res, err := reapOrphanedControlPlane(ctx, opts.executorConfig(logger), start)
	if err != nil {
		if errors.Is(err, executor.ErrWorkDirLocked) {
			logger.Error("another running server holds this work dir; not starting a second control plane on it (not recorded on the crash-loop breaker)",
				"work-dir", opts.workDir, "err", err)
		} else {
			noteBringUpFailure(ctx, breaker, logger, err)
		}
		return res, fmt.Errorf("stop the previous run's control plane: %w", err)
	}
	if res.PortsHeld != nil {
		logger.Warn("a control-plane port is held by a process that is not provably this server's; bring-up will refuse it", "err", res.PortsHeld)
	}
	return res, nil
}

// reapThenAdmitServerStart is the start of a server's bring-up: the previous
// run's leftover control plane is stopped first (reapServerOrphans), then
// secrets encryption and a tripped crash-loop breaker may PARK the daemon
// (admitServerStart). The work-dir lock the reap took is left in
// opts.workDirHold for the executor to adopt; the caller defers its Release,
// which drops it on any path that never reaches Start.
//
// A failed reap, already recorded on the breaker, still reaches the park check.
// The reap runs before that check on every start, so a reap that failed and
// returned at once would be recorded again on every respawn and never park;
// reaching the check lets the failure that trips the breaker park this start,
// the way a bring-up failure's trip parks the next one. A reap cut short by this
// daemon's own stop returns at once.
func reapThenAdmitServerStart(ctx context.Context, opts *serverOptions, breaker *crashBreaker, mode hostnet.Mode, logger *slog.Logger) (encryptionConfig string, done bool, err error) {
	reap, reapErr := reapServerOrphans(ctx, *opts, breaker, logger)
	opts.workDirHold = reap.Hold
	if reapErr != nil && ctx.Err() != nil {
		return "", true, reapErr
	}
	encryptionConfig, done, err = admitServerStart(ctx, *opts, breaker, mode, logger)
	if reapErr == nil || (done && err == nil) {
		return encryptionConfig, done, err
	}
	return "", true, errors.Join(reapErr, err)
}
