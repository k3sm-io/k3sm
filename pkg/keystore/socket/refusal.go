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
	"cmp"
	"slices"
	"sync"
	"time"
)

// RefusalAuditor receives the pre-frame refusals that pass the per-uid rate
// limit, and once a minute the count each uid had dropped. The production
// auditor writes them to the audit log as refused lines.
type RefusalAuditor interface {
	// Refused records one refused connection from uid, for a reason in the
	// closed set of Reason* constants.
	Refused(uid uint32, reason string)
	// Dropped records that dropped refusals from uid went unrecorded
	// since its last summary.
	Dropped(uid uint32, dropped uint64)
}

// The reasons a connection is refused before its first frame: a closed set.
const (
	ReasonRoot           = "root"            // uid 0
	ReasonServiceUID     = "service-uid"     // the service uid, which every native Pod shares
	ReasonSystemUID      = "system-uid"      // a uid below 501, a system account
	ReasonHighUID        = "high-uid"        // a uid at 2^31 or above, nobody among them
	ReasonSandboxed      = "sandboxed"       // a sandboxed process, whatever its uid
	ReasonCredUnreadable = "cred-unreadable" // the peer credentials could not be read
	ReasonSandboxUnknown = "sandbox-unknown" // the sandbox check failed
	ReasonTokenMismatch  = "token-mismatch"  // the audit token names another euid or pid than LOCAL_PEERCRED and LOCAL_PEERPID
)

// NoUID is the uid a refusal names when the peer's could not be read:
// (uid_t)-1, which no process runs as.
const NoUID = ^uint32(0)

// RefusalLinesPerMinute is how many refusals of one uid reach the auditor in
// any minute; the rest are counted and summarized once a minute.
const RefusalLinesPerMinute = 10

// refusalWindow is the rate limit's window, and the summary's period.
const refusalWindow = time.Minute

// refusalLimiter passes at most RefusalLinesPerMinute refusals per uid in any
// sliding minute to its auditor and counts the rest. The auditor is called
// with mu released.
type refusalLimiter struct {
	audit RefusalAuditor
	now   func() time.Time

	mu   sync.Mutex // guards uids
	uids map[uint32]*refusalCount
}

// refusalCount is one uid's recent passed refusals and its dropped count.
type refusalCount struct {
	passed  []time.Time // within the last window, oldest first
	dropped uint64
}

func newRefusalLimiter(audit RefusalAuditor, now func() time.Time) *refusalLimiter {
	return &refusalLimiter{audit: audit, now: now, uids: make(map[uint32]*refusalCount)}
}

// refuse passes the refusal to the auditor or counts it dropped.
func (l *refusalLimiter) refuse(uid uint32, reason string) {
	now := l.now()
	l.mu.Lock()
	rc := l.uids[uid]
	if rc == nil {
		rc = &refusalCount{}
		l.uids[uid] = rc
	}
	rc.expire(now)
	pass := len(rc.passed) < RefusalLinesPerMinute
	if pass {
		rc.passed = append(rc.passed, now)
	} else {
		rc.dropped++
	}
	l.mu.Unlock()
	if pass {
		l.audit.Refused(uid, reason)
	}
}

// count adds n to uid's dropped count, for its next summary: a line or a
// summary the audit queue had no room for.
func (l *refusalLimiter) count(uid uint32, n uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rc := l.uids[uid]
	if rc == nil {
		rc = &refusalCount{}
		l.uids[uid] = rc
	}
	rc.dropped += n
}

// expire forgets the passed refusals a window or more old.
func (rc *refusalCount) expire(now time.Time) {
	i := 0
	for i < len(rc.passed) && !now.Before(rc.passed[i].Add(refusalWindow)) {
		i++
	}
	rc.passed = rc.passed[i:]
}

// summarize sends each uid's dropped count, in uid order, and forgets the
// uids with nothing recent left.
func (l *refusalLimiter) summarize() {
	now := l.now()
	type summary struct {
		uid     uint32
		dropped uint64
	}
	var out []summary
	l.mu.Lock()
	for uid, rc := range l.uids {
		if rc.dropped > 0 {
			out = append(out, summary{uid, rc.dropped})
			rc.dropped = 0
		}
		rc.expire(now)
		if len(rc.passed) == 0 {
			delete(l.uids, uid)
		}
	}
	l.mu.Unlock()
	slices.SortFunc(out, func(a, b summary) int { return cmp.Compare(a.uid, b.uid) })
	for _, s := range out {
		l.audit.Dropped(s.uid, s.dropped)
	}
}
