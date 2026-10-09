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
	"log/slog"
	"os"
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/executor"
	"k3sm.io/k3sm/pkg/status"
)

// crashLoopPollInterval is how often a PARKED daemon looks for its marker to be
// cleared. Parked means resident and idle, so this is the whole cost of the
// give-up state; five seconds keeps the operator's clear visible within one
// status refresh.
const crashLoopPollInterval = 5 * time.Second

// crashBreaker is the daemon-side face of pkg/executor's crash record: one path,
// one clock, and the mutex that orders the two writers — the component-exit
// callback (records a crash) and the healthy-window timer (clears the record).
// Without the mutex the timer could observe "no crash yet", the callback could
// record one, and the timer's clear could then erase it: a lost crash is a loop
// that never trips.
type crashBreaker struct {
	path   string
	now    func() time.Time
	logger *slog.Logger

	mu      sync.Mutex
	crashed bool // set by record; read by resetIfHealthy under mu
}

func newCrashBreaker(workDir string, logger *slog.Logger) *crashBreaker {
	return &crashBreaker{path: executor.CrashLoopPath(workDir), now: time.Now, logger: logger}
}

// load reads the record, pruned to the window. A malformed record is logged and
// treated as empty: refusing to boot over corrupt bookkeeping would be a second
// way to lose the control plane, and the operator can read the file themselves.
func (b *crashBreaker) load() executor.CrashRecord {
	r, err := executor.ReadCrashRecord(b.path)
	if err != nil {
		b.logger.Warn("crash-loop record unreadable; treating as empty", "path", b.path, "err", err)
		return executor.CrashRecord{}
	}
	r.Prune(b.now())
	return r
}

// record appends one component crash and reports whether it tripped the
// breaker. Detail is the redacted, capped tail the callback received.
func (b *crashBreaker) record(component, detail string) (tripped bool) {
	return b.recordOrigin(executor.CrashOriginCrash, component, detail)
}

// recordLeaderLost appends one leader-lease loss — a leader-elected component
// that exited as upstream intends when its lease could not be renewed — and
// reports whether it tripped the breaker. It never counts toward the crash
// threshold; it has its own, executor.LeaderLostThreshold, so a lease that
// flaps forever still parks the server instead of restarting it forever.
func (b *crashBreaker) recordLeaderLost(component, detail string) (tripped bool) {
	return b.write(func(r *executor.CrashRecord, now time.Time) bool {
		return r.RecordLeaderLost(now, component, detail)
	})
}

// recordBringUp appends one BRING-UP failure — a control plane that never came
// up at all, which the component-exit callback never sees because the child
// either never started or died before it was marked supervised. Detail is the
// bring-up error text, already redacted by pkg/executor before it was formatted.
//
// The two record sites must never count one failure twice. OnComponentExit fires
// only for a component that was already marked supervised, and for every component
// but one that mark is the last step of its bring-up. The exception is the etcd
// member, which is supervised BEFORE its learner promotion and quorum waits; a
// death during those waits is seen by both observers, and pkg/executor gives the
// report to exactly one of them — when the exit callback took it, the bring-up
// error wraps executor.ErrEtcdChildExited and noteBringUpFailure skips it.
func (b *crashBreaker) recordBringUp(component, detail string) (tripped bool) {
	return b.recordOrigin(executor.CrashOriginBringUp, component, detail)
}

// recordBringUpPermanent appends one PERMANENT bring-up failure, which trips
// the breaker on its own (executor.CrashRecord.RecordPermanent). remedy is the
// fix the status row will name.
func (b *crashBreaker) recordBringUpPermanent(component, detail, remedy string) (tripped bool) {
	return b.write(func(r *executor.CrashRecord, now time.Time) bool {
		return r.RecordPermanent(now, executor.CrashOriginBringUp, component, detail, remedy)
	})
}

func (b *crashBreaker) recordOrigin(origin, component, detail string) (tripped bool) {
	return b.write(func(r *executor.CrashRecord, now time.Time) bool {
		return r.Record(now, origin, component, detail)
	})
}

// write is the one locked read-modify-write of the record; add appends the
// entry and reports whether it tripped the breaker.
func (b *crashBreaker) write(add func(*executor.CrashRecord, time.Time) bool) (tripped bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.crashed = true
	r := b.load()
	tripped = add(&r, b.now())
	if err := executor.WriteCrashRecord(b.path, r); err != nil {
		b.logger.Error("could not persist the crash-loop record", "path", b.path, "err", err)
	}
	return tripped
}

// noteBringUpFailure records a failed control-plane bring-up on the breaker,
// under the component that failed. It is the whole of the daemon's answer to a
// PERSISTENT bring-up fault: every bring-up failure used to return from
// executor.Start, exit the daemon 1, and be respawned by the server plist's bare
// KeepAlive with no throttle and no give-up — so a kine that could not open its
// database looped forever, and `k3sm install` was satisfied by any resident pid.
// Counting it here puts it under the same threshold a crash loop already has.
//
// A failure executor.Start did not classify (a Config validation error, a token
// it could not mint) is still recorded, under "control-plane": the loop it would
// otherwise produce is the same loop, and an unnamed count is better than none.
//
// A PERMANENT failure — executor.ErrNoGoToolchain, matched with errors.Is
// through BringUpError's chain — trips the breaker on this one failure: the
// launchd PATH that lacked `go` this lap lacks it on every lap. (The joining
// server's permanent member-route refusal is the other permanent class; it fails
// before the executor starts, so noteEtcdMemberRouteFailure records it.)
func noteBringUpFailure(b *crashBreaker, logger *slog.Logger, err error) {
	component := "control-plane"
	var bu *executor.BringUpError
	if errors.As(err, &bu) {
		component = bu.Component
	}
	if errors.Is(err, executor.ErrEtcdChildExited) {
		// The exit callback already recorded this death as a crash; recording the
		// bring-up error too would count one death twice toward the threshold.
		logger.Error("the control plane did not come up: its etcd member exited, already recorded as a crash",
			"component", component, "err", err)
		return
	}
	var superseded *executor.EtcdSupersededError
	if errors.As(err, &superseded) {
		// Every restart finds the same data dir, so this cannot heal on retry. The
		// remedy names the peer and both clusters, so the operator confirms the
		// restore before deleting anything.
		remedy := superseded.Remedy()
		logger.Error("the control plane did not come up: "+executor.EtcdMemberSupersededMessage+"; parking on this failure",
			"component", component, "err", err, "remedy", remedy)
		if b.recordBringUpPermanent(component, err.Error(), remedy) {
			logger.Error("crash-loop breaker tripped on a permanent fault; the next start will park until an operator clears the record",
				"path", b.path)
		}
		return
	}
	if errors.Is(err, executor.ErrKinePayloadStale) {
		// Checked before ErrNoGoToolchain, which it also wraps: the missing toolchain
		// is incidental here, and the remedy is the install that brings the payload.
		logger.Error("the control plane did not come up: the k3sm binary was replaced without its payload; parking on this failure",
			"component", component, "err", err, "remedy", executor.KinePayloadStaleRemedy)
		if b.recordBringUpPermanent(component, err.Error(), executor.KinePayloadStaleRemedy) {
			logger.Error("crash-loop breaker tripped on a permanent fault; the next start will park until an operator clears the record",
				"path", b.path)
		}
		return
	}
	if errors.Is(err, executor.ErrNoGoToolchain) {
		logger.Error("the control plane did not come up with a fault that cannot heal on retry; parking on this failure",
			"component", component, "err", err, "remedy", executor.NoGoToolchainRemedy)
		if b.recordBringUpPermanent(component, err.Error(), executor.NoGoToolchainRemedy) {
			logger.Error("crash-loop breaker tripped on a permanent fault; the next start will park until an operator clears the record",
				"path", b.path)
		}
		return
	}
	logger.Error("the control plane did not come up; recording it on the crash-loop breaker",
		"component", component, "err", err)
	if b.recordBringUp(component, err.Error()) {
		logger.Error("crash-loop breaker tripped; the next start will park until an operator clears the record",
			"path", b.path, "threshold", executor.CrashLoopThreshold, "window", executor.CrashLoopWindow)
	}
}

// noteEtcdMemberRouteFailure records a joining server's member-route failure on the
// breaker when, and only when, it is PERMANENT (errEtcdMemberRoutePermanent): such a
// refusal reproduces on every lap, exactly like executor.ErrNoGoToolchain, so it
// trips the breaker on the first one. Anything else that reaches here is a shutdown
// during the step's in-process retry, which is not a failure at all. The detail is
// redacted here because the error is this command's own text.
func noteEtcdMemberRouteFailure(b *crashBreaker, logger *slog.Logger, err error) {
	if !errors.Is(err, errEtcdMemberRoutePermanent) {
		return
	}
	remedy := etcdMemberRouteRemedyFor(err)
	logger.Error("the existing server permanently refused this server's etcd member; parking on this failure",
		"component", etcdMemberRouteComponent, "err", err, "remedy", remedy)
	if b.recordBringUpPermanent(etcdMemberRouteComponent, status.Redact(err.Error()), remedy) {
		logger.Error("crash-loop breaker tripped on a permanent fault; the next start will park until an operator clears the record",
			"path", b.path)
	}
}

// noted reports whether THIS process has already recorded a failure. It is what
// keeps the agent's single funnel from counting one start failure twice: the
// terminal paths record before they back off (agentTerminal), and runAgent then
// records only what did not already pass through one of them.
func (b *crashBreaker) noted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.crashed
}

// agentComponent is the component name the agent records its start failures
// under. A worker has no supervised components to name — its start is one
// sequence (token join or credential resume, then the mesh and the datapath) —
// so the role IS the component, and an installer reading the record learns
// which daemon failed without knowing the agent's internal stages.
const agentComponent = "agent"

// noteAgentStartFailure records one agent start failure as a BRING-UP failure,
// under agentComponent. It is noteBringUpFailure's sibling for the worker role,
// and differs from it in exactly two ways, both of which belong to the role:
//
//   - It never parks and never asks the caller to. `k3sm agent` already waits
//     agentTerminalBackoff between terminal start attempts, so the unthrottled
//     spawn loop the server's park exists to stop cannot happen here. The record
//     is kept for its OTHER reader — `k3sm install`, which cannot otherwise tell
//     a join that happened during this install from a credential an earlier one
//     left behind.
//   - The detail is redacted HERE. A server's bring-up error arrives already
//     redacted from pkg/executor; an agent's start error is this command's own
//     text and can quote a token it was handed, so it passes through
//     pkg/status's redactor on its way into a file an operator will read.
func noteAgentStartFailure(b *crashBreaker, logger *slog.Logger, err error) {
	logger.Error("this agent did not start; recording it on the crash-loop record",
		"component", agentComponent, "path", b.path, "err", err)
	if b.recordBringUp(agentComponent, status.Redact(err.Error())) {
		// Logged, not acted on: the threshold is what `k3sm status` and an
		// operator read as "this has been failing for a while", and the agent
		// keeps retrying either way.
		logger.Error("the agent's crash-loop record reached the threshold; it keeps retrying rather than parking",
			"path", b.path, "threshold", executor.CrashLoopThreshold, "window", executor.CrashLoopWindow)
	}
}

// resetIfHealthy clears the record when this process has seen no crash. It is
// the healthy-window timer's body: a bring-up that stayed up for the whole
// window has proved the fault was transient.
func (b *crashBreaker) resetIfHealthy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.crashed {
		return
	}
	if err := executor.ClearCrashRecord(b.path); err != nil {
		b.logger.Warn("could not clear the crash-loop record after a healthy window", "path", b.path, "err", err)
		return
	}
	b.logger.Info("control plane healthy for the crash-loop window; crash record cleared", "window", executor.CrashLoopWindow)
}

// parkReason is the park message, which says which of the two failures the
// breaker counted last. The distinction is the operator's first diagnostic step:
// a control plane that came up and then died is a different search through the
// log than one that never came up at all, and the record is the only place that
// difference survives the restart. The remedy is the same either way and is
// logged beside this.
func parkReason(last executor.Crash) string {
	if last.Origin == executor.CrashOriginLeaderLost {
		return "crash-loop breaker tripped on repeated leader-lease loss (last: " + last.Component +
			"); this server keeps losing etcd quorum; parking until an operator clears the record"
	}
	if last.Origin == executor.CrashOriginBringUp {
		return "crash-loop breaker tripped; the control plane never came up (last: " + last.Component +
			"); parking until an operator clears the record"
	}
	return "crash-loop breaker tripped; parking the control plane until an operator clears the record"
}

// parkUntilCleared is the give-up. It is called INSTEAD of bring-up when the
// record is tripped, and returns nil — never an error — when either the marker
// disappears (an operator cleared it, so the process exits and launchd respawns
// a clean boot) or ctx is done (SIGTERM: a bootout or kickstart -k).
//
// It parks rather than exits because the server plist's KeepAlive is a bare
// `true`: launchd respawns the job on any exit, so an exit here of any status
// would be one more lap of the loop. A resident, idle process is the only
// "stopped" state that plist can express without a plist change.
func parkUntilCleared(ctx context.Context, path string, poll time.Duration, logger *slog.Logger) error {
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("parked control plane received a stop; exiting")
			return nil
		case <-t.C:
			if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
				logger.Info("crash-loop record cleared by an operator; exiting so launchd starts a clean boot", "path", path)
				return nil
			}
		}
	}
}
