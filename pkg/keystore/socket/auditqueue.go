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
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"
)

// The refusal audit's queue: the rate limiter hands each line it passes,
// and each summary, to a bounded queue that one writer goroutine drains
// into the RefusalAuditor, so a slow audit append (a store-lock wait and an
// fsync) never holds up accept.
const (
	// AuditQueueLen is how many refusal lines and summaries wait for the
	// writer; one that finds the queue full is counted as dropped for its
	// uid, never waited on.
	AuditQueueLen = 256
	// AuditDrainWait is how long a stopping Serve lets the writer drain
	// the queue; past it the writer's context is cancelled, the call in
	// flight is asked to give up and what is left is discarded and logged.
	AuditDrainWait = 5 * time.Second
)

// contextAuditor is a RefusalAuditor whose calls take a context, which the
// writer cancels once AuditDrainWait has passed on stop. StoreAuditor is
// one: its store-lock wait ends with the context. An auditor that is not
// holds a stopping Serve until its call in flight returns.
type contextAuditor interface {
	refusedContext(ctx context.Context, uid uint32, reason string)
	droppedContext(ctx context.Context, uid uint32, n uint64)
}

// pendingFlusher is an auditor that keeps dropped counts of its own (lines
// it could not write) and can be asked to write them: StoreAuditor is one.
// The listener's minute pass asks it every minute, whether or not the rate
// limit dropped anything.
type pendingFlusher interface {
	flushPending(ctx context.Context)
}

// auditItem is one queued call: a refusal when reason is set, a request to
// write the auditor's pending counts when flush is, otherwise a summary of
// dropped.
type auditItem struct {
	uid     uint32
	reason  string
	dropped uint64
	flush   bool
}

// auditQueue is the RefusalAuditor the rate limiter writes to: it queues
// each call for the writer, and counts one the queue has no room for as
// dropped through overflow.
type auditQueue struct {
	audit    RefusalAuditor
	items    chan auditItem
	overflow func(uid uint32, n uint64)
	log      *slog.Logger
}

func newAuditQueue(audit RefusalAuditor, log *slog.Logger) *auditQueue {
	return &auditQueue{audit: audit, items: make(chan auditItem, AuditQueueLen), log: log}
}

// Refused implements RefusalAuditor.
func (q *auditQueue) Refused(uid uint32, reason string) {
	q.put(auditItem{uid: uid, reason: reason}, 1)
}

// Dropped implements RefusalAuditor.
func (q *auditQueue) Dropped(uid uint32, n uint64) {
	q.put(auditItem{uid: uid, dropped: n}, n)
}

// flush queues a request to write the auditor's pending counts, when it
// keeps any; a full queue skips it until the next minute.
func (q *auditQueue) flush() {
	if _, ok := q.audit.(pendingFlusher); !ok {
		return
	}
	select {
	case q.items <- auditItem{flush: true}:
	default:
	}
}

// put queues it, or counts n dropped for its uid when the queue is full.
func (q *auditQueue) put(it auditItem, n uint64) {
	select {
	case q.items <- it:
	default:
		q.overflow(it.uid, n)
	}
}

// run writes each queued call to the auditor until the queue is closed and
// empty, or ctx is done; after ctx it discards what is left and logs the
// count. A panic in the auditor is recovered and costs that call only.
func (q *auditQueue) run(ctx context.Context) {
	for it := range q.items {
		if ctx.Err() != nil {
			q.discard(it)
			return
		}
		q.write(ctx, it)
	}
}

// write gives it to the auditor.
func (q *auditQueue) write(ctx context.Context, it auditItem) {
	defer func() {
		if v := recover(); v != nil {
			q.log.Error("keystore socket: recovered a panic", "goroutine", "refusal audit", "panic", fmt.Sprint(v), "stack", string(debug.Stack()))
		}
	}()
	if it.flush {
		q.audit.(pendingFlusher).flushPending(ctx) // only queued for a pendingFlusher
		return
	}
	ca, isCtx := q.audit.(contextAuditor)
	switch {
	case it.reason != "" && isCtx:
		ca.refusedContext(ctx, it.uid, it.reason)
	case it.reason != "":
		q.audit.Refused(it.uid, it.reason)
	case isCtx:
		ca.droppedContext(ctx, it.uid, it.dropped)
	default:
		q.audit.Dropped(it.uid, it.dropped)
	}
}

// discard drops first and the rest of the closed queue, logging how many
// lines went unwritten.
func (q *auditQueue) discard(first auditItem) {
	lost := lostOf(first)
	for it := range q.items {
		lost += lostOf(it)
	}
	q.log.Warn("keystore socket: refusal lines left unwritten at stop", "lines", lost)
}

func lostOf(it auditItem) uint64 {
	if it.flush {
		return 0
	}
	if it.reason != "" {
		return 1
	}
	return it.dropped
}
