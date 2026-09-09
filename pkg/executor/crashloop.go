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
	// crashLoopFile is the record's name under the work dir.
	crashLoopFile = "crashloop.json"
)

// Crash is one component exit the breaker counted.
type Crash struct {
	At        time.Time `json:"at"`
	Component string    `json:"component"`
	// Detail is the redacted, byte-capped log tail OnComponentExit received —
	// the same bytes that reach the daemon logger, never the raw component log.
	Detail string `json:"detail,omitempty"`
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
	if err := json.Unmarshal(b, &r); err != nil {
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

// Record appends one crash, prunes, and trips the breaker when the window now
// holds the threshold. It reports whether THIS call tripped it.
func (r *CrashRecord) Record(now time.Time, component, detail string) (tripped bool) {
	r.Crashes = append(r.Crashes, Crash{At: now, Component: component, Detail: detail})
	r.Prune(now)
	if r.TrippedAt == nil && len(r.Crashes) >= CrashLoopThreshold {
		t := now
		r.TrippedAt = &t
		return true
	}
	return false
}

// Tripped reports whether the breaker is open — the daemon must park, not
// bring up.
func (r CrashRecord) Tripped() bool { return r.TrippedAt != nil }

// Recent counts the crashes inside the window ending at now.
func (r CrashRecord) Recent(now time.Time) int {
	cutoff := now.Add(-CrashLoopWindow)
	n := 0
	for _, c := range r.Crashes {
		if !c.At.Before(cutoff) {
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
