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
	"sync"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// This file is the post-frame refused line's limiter and the reasons the
// socket gives for a request it refuses itself (docs/design/keystore.md §
// "The audit log", refused lines): at most RefusalLinesPerMinute lines per
// uid in any sliding minute, the rest counted and written as one summary
// line, at most once a minute (the first a minute after the uid's first
// refusal), the next time that uid is refused. So a uid
// gets at most RefusalLinesPerMinute+1 lines a minute however many of its
// requests are refused, a rate-limited answer's included.

// errBadValue and errNotServed mark the refusals whose reason is the
// value and an operation not served yet; any other ErrRequestRefused from
// the socket is the header's.
var (
	errBadValue  = errors.New("the value")
	errNotServed = errors.New("not served")
)

// refusalReason is the post-frame refused line's reason for err, one of
// keystore's Refused* closed set, or "" for an error the socket did not
// give itself (the store's, which the store has audited).
func refusalReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrRateLimited):
		return keystore.RefusedRateLimited
	case errors.Is(err, ErrAuditFailing):
		return keystore.RefusedAuditFailing
	case errors.Is(err, errNotServed):
		return keystore.RefusedNotServed
	case errors.Is(err, errBadValue):
		return keystore.RefusedBadValue
	case errors.Is(err, ErrRequestRefused):
		return keystore.RefusedBadHeader
	}
	return ""
}

// auditOpName is op as the audit log names it.
func auditOpName(op string) string {
	if op == OpReadForExec {
		return "exec-read"
	}
	return op
}

// refusedLines is the per-uid limiter of post-frame refused lines, on the
// injected clock.
type refusedLines struct {
	now func() time.Time

	mu   sync.Mutex // guards uids
	uids map[uint32]*refusedCount
}

// refusedCount is one uid's lines written in the last window, its dropped
// count since its last summary, and when that summary was written.
type refusedCount struct {
	passed     []time.Time // within the last window, oldest first
	dropped    uint64
	summarized time.Time
}

func newRefusedLines(now func() time.Time) *refusedLines {
	return &refusedLines{now: now, uids: map[uint32]*refusedCount{}}
}

// take decides one refusal of uid: whether its line is written, and the
// dropped count to summarize first, zero for no summary. A summary is due
// once a window has passed since the uid's last one.
func (l *refusedLines) take(uid uint32) (pass bool, summary uint64) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.uids) >= pruneAt {
		for u, rc := range l.uids {
			rc.expire(now)
			if len(rc.passed) == 0 && rc.dropped == 0 {
				delete(l.uids, u)
			}
		}
	}
	rc := l.uids[uid]
	if rc == nil {
		// The first summary is due a window after the uid is first seen.
		rc = &refusedCount{summarized: now}
		l.uids[uid] = rc
	}
	rc.expire(now)
	if rc.dropped > 0 && !now.Before(rc.summarized.Add(refusalWindow)) {
		summary, rc.dropped, rc.summarized = rc.dropped, 0, now
	}
	if len(rc.passed) < RefusalLinesPerMinute {
		rc.passed = append(rc.passed, now)
		return true, summary
	}
	rc.dropped++
	return false, summary
}

// count adds n to uid's dropped count: lines, or a summary, that could
// not be written.
func (l *refusedLines) count(uid uint32, n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rc := l.uids[uid]
	if rc == nil {
		rc = &refusedCount{summarized: l.now()}
		l.uids[uid] = rc
	}
	rc.dropped += n
}

// pending is uid's dropped count not yet summarized.
func (l *refusedLines) pending(uid uint32) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if rc := l.uids[uid]; rc != nil {
		return rc.dropped
	}
	return 0
}

// expire forgets the lines a window or more old.
func (rc *refusedCount) expire(now time.Time) {
	i := 0
	for i < len(rc.passed) && !now.Before(rc.passed[i].Add(refusalWindow)) {
		i++
	}
	rc.passed = rc.passed[i:]
}

// Refused implements Store: the post-frame refused line of op for p,
// refused for reason, behind the per-uid limiter, with the uid's dropped
// count summarized first when one is due. A line or summary that cannot
// be written (past the uid's share, the store lock not had, appends
// failing) is counted dropped for the next summary.
func (b *FileStoreBridge) Refused(ctx context.Context, p Peer, op, reason string) {
	pass, summary := b.refusals.take(p.UID)
	if !pass && summary == 0 {
		return
	}
	u, err := b.view(p)
	if err != nil {
		if pass {
			summary++
		}
		b.refusals.count(p.UID, summary)
		return
	}
	if err := u.RefusedDropped(ctx, summary); err != nil {
		b.refusals.count(p.UID, summary)
	}
	if pass {
		if err := u.Refused(ctx, auditOpName(op), reason); err != nil {
			b.refusals.count(p.UID, 1)
		}
	}
}
