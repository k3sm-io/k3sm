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

package socket

import (
	"context"
	"errors"
	"log/slog"
	"sync"
)

// RefusalLog is the store side of the refusal audit: the server's append
// surface over the audit log, *keystore.ServerLogs in production. Each call
// takes the store lock, waiting a bounded time, and draws on the audit
// log's pre-frame budget; a line it does not write it counts as dropped and
// carries into the uid's next summary line.
type RefusalLog interface {
	Refused(ctx context.Context, uid uint32, reason string) error
	Dropped(ctx context.Context, uid uint32, n uint64) error
}

// StoreAuditor is the production RefusalAuditor: it writes each refusal
// and each dropped-count summary through a RefusalLog. A line the log does
// not write is logged at Warn, with no figure from the log; the connection
// is refused whatever happens to its line.
type StoreAuditor struct {
	log    RefusalLog
	logger *slog.Logger
}

// NewStoreAuditor returns a StoreAuditor over log, refusing a nil log or
// logger.
func NewStoreAuditor(log RefusalLog, logger *slog.Logger) (*StoreAuditor, error) {
	switch {
	case log == nil:
		return nil, errors.New("keystore socket: nil refusal log")
	case logger == nil:
		return nil, errors.New("keystore socket: nil logger")
	}
	return &StoreAuditor{log: log, logger: logger}, nil
}

// Refused implements RefusalAuditor.
func (a *StoreAuditor) Refused(uid uint32, reason string) {
	a.refusedContext(context.Background(), uid, reason)
}

// Dropped implements RefusalAuditor.
func (a *StoreAuditor) Dropped(uid uint32, n uint64) {
	a.droppedContext(context.Background(), uid, n)
}

// refusedContext is Refused under ctx, which bounds the store-lock wait.
func (a *StoreAuditor) refusedContext(ctx context.Context, uid uint32, reason string) {
	if err := a.log.Refused(ctx, uid, reason); err != nil {
		a.logger.Warn("keystore socket: a refused line was not written; it is counted as dropped", "uid", uid, "reason", reason, "err", err)
	}
}

// droppedContext is Dropped under ctx, which bounds the store-lock wait.
func (a *StoreAuditor) droppedContext(ctx context.Context, uid uint32, n uint64) {
	if err := a.log.Dropped(ctx, uid, n); err != nil {
		a.logger.Warn("keystore socket: a dropped-count summary line was not written; the count is kept for the next", "uid", uid, "err", err)
	}
}

// LogReopener is the store side of the reopen after maintenance:
// *keystore.ServerLogs's Reopen and *keystore.FileStore's
// MaintenanceMarked in production.
type LogReopener interface {
	// MaintenanceMarked reports whether the maintenance marker stands.
	MaintenanceMarked() (bool, error)
	// Reopen takes the store lock exclusively, reopens the audit and floor
	// append descriptors and recounts what is charged from the new files
	// before releasing it.
	Reopen(ctx context.Context) error
}

// ReopenAfterMaintenance returns the Supervisor's MaintenanceMarked check
// over r: it reports the marker as r reads it, and when the marker is
// clear for the first time, and the first time after it stood, it reopens
// the append descriptors (Reopen) before reporting it clear, so the
// listener starts, and every later append is charged, against the new
// files. A Reopen that fails is the check's error, so the listener stays
// down (fail closed) and the next poll tries again.
func ReopenAfterMaintenance(r LogReopener) func() (bool, error) {
	var mu sync.Mutex
	stale := true // nothing reopened yet
	return func() (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		marked, err := r.MaintenanceMarked()
		if err != nil || marked {
			stale = true
			return marked, err
		}
		if stale {
			if err := r.Reopen(context.Background()); err != nil {
				return false, err
			}
			stale = false
		}
		return false, nil
	}
}
