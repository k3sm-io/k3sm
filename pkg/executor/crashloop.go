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

package executor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The crash-loop circuit breaker.
//
// After k3sm#336 a control-plane child that dies takes `k3sm server` down with
// it, and launchd's KeepAlive brings the daemon back. That is the k3s-faithful
// answer to a transient fault. A PERSISTENT fault — a kine that cannot open its
// database, an apiserver whose flags no longer parse — turns it into a loop with
// no throttle beyond launchd's default, no give-up, and no signal: the job reads
// as running for the ~90 s each bring-up takes, crashes, and is respawned into
// the same failure, with the only evidence a climbing spawn count in a wide
// status view (k3sm#344).
//
// The record below is the daemon's own memory of that loop. Every component
// crash appends one entry; the window and the threshold are constants (a
// runtime knob here would be a feature flag on a daemon-lifecycle decision, which
// .claude/rules/plans-default-hard-cut.md forbids); once the threshold is
// reached inside the window the record is TRIPPED and stays tripped until an
// operator clears it — that is the point: a loop that quietly self-resets has no
// operator in it.
//
// The trip has two tiers, and which one applies is fixed at compile time. A
// failure the daemon cannot classify counts toward CrashLoopThreshold, because
// it may be transient (a slow network, a port still in TIME_WAIT) and the
// window is what gives it room to heal. A PERMANENT failure trips the breaker
// on its first occurrence (RecordPermanent): it is deterministic under the
// daemon's own environment, so each further lap would reproduce it exactly and
// buy the operator nothing but a four-lap delay before the park. The permanent
// classes are a bring-up that fails with ErrNoGoToolchain — no `go` on the
// launchd PATH, which is the same PATH on every respawn — and a joining HA
// server whose existing server refuses its etcd member outright (a 4xx refusal of
// the request, a token that does not parse, the wrong cluster's CA). The
// classification is an errors.Is or a status code at the record site
// (cmd/k3sm), never a match on output text, and network failures are never
// permanent: the window exists for them. A permanent entry carries its Remedy so a
// parked daemon's status row can name the fix instead of pointing at this file.
//
// What "give up" means is decided by launchd, not here. The server plist's
// KeepAlive is a bare `true`, which respawns the job on ANY exit, zero included;
// there is no exit status that stops it. So a tripped daemon does not exit: it
// PARKS (cmd/k3sm parkUntilCleared) — resident, serving nothing, answering
// SIGTERM, watching for the marker to be cleared. The alternative, a plist
// change (SuccessfulExit / ThrottleInterval), was ruled out because it bounds
// only the respawn floor and cannot express "stop and wait for a human".
//
// The record lives in the control-plane work dir beside state.db, 0600, owned
// by the service user. It is therefore readable by `sudo k3sm status` and not by
// a plain-user status run, which reports that honestly; and it is forgeable by
// any pod, because every pod shares the service uid and the work dir is outside
// runtimed's protected prefixes — exactly the exposure state.db already has, so
// the breaker adds no capability a pod did not have.
const (
	// CrashLoopThreshold is how many component crashes inside CrashLoopWindow
	// trip the breaker. Five is two more than the three bring-ups an operator
	// watching `k3sm status` would already have noticed, and one fewer than the
	// ten-minute window allows at the ~90 s bring-up cadence measured on #344.
	CrashLoopThreshold = 5
	// CrashLoopWindow bounds both the trip decision (crashes older than this do
	// not count) and the reset (a bring-up that stays healthy this long clears
	// the record).
	CrashLoopWindow = 10 * time.Minute
	// LeaderLostThreshold is how many leader-lease losses inside CrashLoopWindow
	// trip the breaker. A lease loss is not a crash: on an HA server that loses
	// etcd quorum, kube-controller-manager and kube-scheduler exit on purpose
	// (upstream's OnStoppedLeading), and the daemon restarts to take part in the
	// next election. So these entries never count toward CrashLoopThreshold, and
	// they get a bound of their own only so that a lease that flaps forever
	// cannot restart the daemon forever. Twice the crash threshold, not more,
	// because the count shares the crash window and must stay reachable inside
	// it: one lap is a daemon restart, a bring-up (tens of seconds once quorum is
	// back), the upstream 15 s lease duration before a new holder can acquire,
	// and the 10 s renew deadline before it loses the lease again — roughly a
	// minute, so ten laps fit the ten-minute window while a few quorum blips do
	// not come close.
	LeaderLostThreshold = 2 * CrashLoopThreshold
	// crashLoopFile is the record's name under the work dir.
	crashLoopFile = "crashloop.json"
)

// The two ways the daemon can fail, which the record keeps apart because the
// remedy conversation differs: a component that came up and later died is a
// crash, and one that never came up at all is a bring-up failure an operator
// will look for in a different part of the log. The give-up is the same for
// both — the breaker counts them together and the park ends the same way.
//
// The third origin is not a failure: a leader-elected component that exited
// because it lost its lease. It is recorded so an operator can see it, and it
// is counted apart from the other two (LeaderLostThreshold).
const (
	// CrashOriginCrash is a component that was supervised and then exited
	// (OnComponentExit's path).
	CrashOriginCrash = "crash"
	// CrashOriginBringUp is a bring-up that never reached supervision: a
	// provision step or a component that would not start, listen, or stay up
	// (BringUpError's path).
	CrashOriginBringUp = "bring-up"
	// CrashOriginLeaderLost is a supervised kube-controller-manager or
	// kube-scheduler that exited because it lost its leader lease while the
	// rest of the control plane was alive — upstream's intended exit on an HA
	// server that lost etcd quorum, not a crash. cmd/k3sm classifies it.
	CrashOriginLeaderLost = "leader-lost"
)

// Crash is one control-plane failure the breaker counted.
type Crash struct {
	At        time.Time `json:"at"`
	Component string    `json:"component"`
	// Origin is CrashOriginCrash, CrashOriginBringUp or CrashOriginLeaderLost. It is omitempty, and an
	// empty value reads as a crash: records written before the daemon counted
	// bring-up failures hold only crashes.
	Origin string `json:"origin,omitempty"`
	// Detail is the redacted, byte-capped log tail OnComponentExit received —
	// the same bytes that reach the daemon logger, never the raw component log.
	Detail string `json:"detail,omitempty"`
	// Permanent marks a failure that cannot heal on retry under the same
	// environment; it tripped the breaker on its own (RecordPermanent).
	Permanent bool `json:"permanent,omitempty"`
	// Remedy is the operator's fix for a permanent failure: a fixed string the
	// recording site owns (NoGoToolchainRemedy), never text taken from a log.
	Remedy string `json:"remedy,omitempty"`
}

// CrashRecord is the persisted breaker state.
type CrashRecord struct {
	Crashes []Crash `json:"crashes"`
	// TrippedAt is set when the threshold was reached inside the window and
	// cleared only by ClearCrashRecord. It survives Prune on purpose.
	TrippedAt *time.Time `json:"tripped_at,omitempty"`
}

// CrashLoopPath is the record's path for a control-plane work dir.
func CrashLoopPath(workDir string) string { return filepath.Join(workDir, crashLoopFile) }

// ParseCrashRecord decodes a record from its on-disk bytes. It is exported for
// the readers that reach the file through a filesystem seam of their own — the
// installer's root-privileged System.ReadFile, which is how `k3sm install`
// checks that the server it just restarted is not parked — so those readers
// share this decoder instead of re-deriving the shape.
func ParseCrashRecord(b []byte) (CrashRecord, error) {
	var r CrashRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return CrashRecord{}, err
	}
	return r, nil
}

// ReadCrashRecord loads the record at path. An absent file is an empty record,
// not an error; an unreadable or malformed one is returned as an error so a
// caller can decide (the daemon treats a malformed record as empty and logs it,
// because refusing to boot over a corrupt bookkeeping file would be a second
// way to lose the control plane).
func ReadCrashRecord(path string) (CrashRecord, error) {
	var r CrashRecord
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	r, err = ParseCrashRecord(b)
	if err != nil {
		return CrashRecord{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return r, nil
}

// WriteCrashRecord persists r at path atomically (temp file + rename), mode
// 0600: the details are redacted, but the file still describes a failure an
// operator has not read yet.
func WriteCrashRecord(path string, r CrashRecord) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ClearCrashRecord removes the record. An absent file is success: the operator's
// intent ("nothing is tripped") already holds.
func ClearCrashRecord(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Prune drops crashes older than the window. A crash dated in the future (a
// clock that stepped backwards) is kept: dropping it would let a loop escape the
// count by way of a bad clock. TrippedAt is untouched.
func (r *CrashRecord) Prune(now time.Time) {
	cutoff := now.Add(-CrashLoopWindow)
	kept := r.Crashes[:0]
	for _, c := range r.Crashes {
		if !c.At.Before(cutoff) {
			kept = append(kept, c)
		}
	}
	r.Crashes = kept
}

// Record appends one failure, prunes, and trips the breaker when the window now
// holds the threshold. It reports whether THIS call tripped it. origin is
// CrashOriginCrash or CrashOriginBringUp — a required argument rather than a
// default, because the caller is the only one that knows which of the two it
// observed.
func (r *CrashRecord) Record(now time.Time, origin, component, detail string) (tripped bool) {
	return r.record(now, Crash{At: now, Origin: origin, Component: component, Detail: detail})
}

// RecordPermanent appends one PERMANENT failure and trips the breaker on it
// alone, whatever the window holds — the second tier of the trip (see the
// design comment above). remedy is the fix the status row names. It reports
// whether THIS call tripped it: false only when the breaker was already open.
func (r *CrashRecord) RecordPermanent(now time.Time, origin, component, detail, remedy string) (tripped bool) {
	return r.record(now, Crash{At: now, Origin: origin, Component: component, Detail: detail,
		Permanent: true, Remedy: remedy})
}

// RecordLeaderLost appends one leader-lease loss and trips the breaker when the
// window now holds LeaderLostThreshold of them. Lease losses never count toward
// CrashLoopThreshold, and crashes never count toward this one. It reports
// whether THIS call tripped the breaker.
func (r *CrashRecord) RecordLeaderLost(now time.Time, component, detail string) (tripped bool) {
	r.Crashes = append(r.Crashes, Crash{At: now, Origin: CrashOriginLeaderLost, Component: component, Detail: detail})
	r.Prune(now)
	return r.trip(now, r.LeaderLost(now) >= LeaderLostThreshold)
}

func (r *CrashRecord) record(now time.Time, c Crash) (tripped bool) {
	r.Crashes = append(r.Crashes, c)
	r.Prune(now)
	return r.trip(now, c.Permanent || r.Recent(now) >= CrashLoopThreshold)
}

// trip opens the breaker when reached and it is not open already, and reports
// whether it did.
func (r *CrashRecord) trip(now time.Time, reached bool) bool {
	if r.TrippedAt == nil && reached {
		t := now
		r.TrippedAt = &t
		return true
	}
	return false
}

// Tripped reports whether the breaker is open — the daemon must park, not
// bring up.
func (r CrashRecord) Tripped() bool { return r.TrippedAt != nil }

// Recent counts the crashes and bring-up failures inside the window ending at
// now — the entries CrashLoopThreshold counts. Leader-lease losses are not
// failures and are counted by LeaderLost instead.
func (r CrashRecord) Recent(now time.Time) int {
	return r.count(now, func(c Crash) bool { return c.Origin != CrashOriginLeaderLost })
}

// LeaderLost counts the leader-lease losses inside the window ending at now.
func (r CrashRecord) LeaderLost(now time.Time) int {
	return r.count(now, func(c Crash) bool { return c.Origin == CrashOriginLeaderLost })
}

func (r CrashRecord) count(now time.Time, match func(Crash) bool) int {
	cutoff := now.Add(-CrashLoopWindow)
	n := 0
	for _, c := range r.Crashes {
		if !c.At.Before(cutoff) && match(c) {
			n++
		}
	}
	return n
}

// Last returns the most recent crash, or false when there is none.
func (r CrashRecord) Last() (Crash, bool) {
	if len(r.Crashes) == 0 {
		return Crash{}, false
	}
	return r.Crashes[len(r.Crashes)-1], true
}
