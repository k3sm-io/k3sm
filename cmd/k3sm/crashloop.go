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
	b.mu.Lock()
	defer b.mu.Unlock()
	b.crashed = true
	r := b.load()
	tripped = r.Record(b.now(), component, detail)
	if err := executor.WriteCrashRecord(b.path, r); err != nil {
		b.logger.Error("could not persist the crash-loop record", "path", b.path, "err", err)
	}
	return tripped
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
