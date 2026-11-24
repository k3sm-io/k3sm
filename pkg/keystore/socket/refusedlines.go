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
// refusal), the next time that uid is refused. The dropped count is the
// store's, persisted in its server-counts file. So a uid
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

// postFrameCounter is the store's persisted count of each uid's post-frame
// refused lines dropped and not yet summarized
// (keystore.FileStore.AddPostFrameDropped): the limiter keeps no count of
// its own, so the count outlasts the server and a root rotate that wrote
// it takes it out of memory too.
type postFrameCounter interface {
	AddPostFrameDropped(uid uint32, n uint64)
	PostFrameDropped(uid uint32) uint64
	PostFrameSummarized(uid uint32, n uint64)
}

// refusedLines is the per-uid limiter of post-frame refused lines, on the
// injected clock, over the store's dropped count.
type refusedLines struct {
	now     func() time.Time
	dropped postFrameCounter

	mu   sync.Mutex // guards uids; taken before the counter's own lock
	uids map[uint32]*refusedCount
}

// refusedCount is one uid's lines written in the last window and when its
// last summary was due.
type refusedCount struct {
	passed     []time.Time // within the last window, oldest first
	summarized time.Time
}

func newRefusedLines(now func() time.Time, dropped postFrameCounter) *refusedLines {
	return &refusedLines{now: now, dropped: dropped, uids: map[uint32]*refusedCount{}}
}

// take decides one refusal of uid: whether its line is written, and the
// dropped count to summarize first, zero for no summary. A summary is due
// once a window has passed since the uid's last one. The count stays the
// store's until the summary is written (summarized); a line not passed is
// the caller's to count (count).
func (l *refusedLines) take(uid uint32) (pass bool, summary uint64) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.uids) >= pruneAt {
		for u, rc := range l.uids {
			rc.expire(now)
			if len(rc.passed) == 0 && l.dropped.PostFrameDropped(u) == 0 {
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
	if n := l.dropped.PostFrameDropped(uid); n > 0 && !now.Before(rc.summarized.Add(refusalWindow)) {
		summary, rc.summarized = n, now
	}
	if len(rc.passed) < RefusalLinesPerMinute {
		rc.passed = append(rc.passed, now)
		return true, summary
	}
	return false, summary
}

// count adds n to uid's dropped count, the store's: lines that could not
// be written.
func (l *refusedLines) count(uid uint32, n uint64) { l.dropped.AddPostFrameDropped(uid, n) }

// summarized takes n, a summary written for uid, out of its dropped count.
func (l *refusedLines) summarized(uid uint32, n uint64) { l.dropped.PostFrameSummarized(uid, n) }

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
// count summarized first when one is due. A line that cannot be written
// (past the limiter or the uid's share, the store lock not had, appends
// failing) is handed to the store's dropped count, which persists it; a
// summary that cannot be written leaves the count there for the next.
func (b *FileStoreBridge) Refused(ctx context.Context, p Peer, op, reason string) {
	pass, summary := b.refusals.take(p.UID)
	if !pass {
		b.refusals.count(p.UID, 1)
		if summary == 0 {
			return
		}
	}
	u, err := b.view(p)
	if err != nil {
		if pass {
			b.refusals.count(p.UID, 1)
		}
		return
	}
	if summary > 0 {
		if err := u.RefusedDropped(ctx, summary); err == nil {
			b.refusals.summarized(p.UID, summary)
		}
	}
	if pass {
		if err := u.Refused(ctx, auditOpName(op), reason); err != nil {
			b.refusals.count(p.UID, 1)
		}
	}
}
