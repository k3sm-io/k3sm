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

package status

import (
	"errors"
	"fmt"
	"os"
	"time"

	"k3sm.io/k3sm/pkg/executor"
)

// The crash-loop breaker's status face (k3sm#344). launchd's own view of the
// server job has a spawn count but no timeline, so a job that is up for the
// ~90 s each bring-up takes, crashes, and is respawned reads as `running` with a
// Runs figure only the wide view shows. The daemon's crash record IS the
// timeline: cmd/k3sm writes one entry per component crash and trips it at the
// threshold, so the row can say "restarting into the same failure" while
// launchd still says "running", and can name the remedy once the daemon has
// parked.
//
// The record is a 0600 file in the 0700 work dir. A plain-user status run
// cannot read it and says so — the same posture the datastore row has — while
// `sudo k3sm status` reads it. The row NEVER quotes the record's detail field:
// it is already redacted, but a status report is the one output an operator
// pastes into an issue, and a component name plus a count is what the decision
// needs.

// CrashLoopPosture is what the record says about the server job. Exactly one
// of the Severity-bearing states is returned; a record that is absent or empty
// inside the window is PostureQuiet, and the row is left to launchd's verdict.
type CrashLoopPosture int

const (
	// PostureQuiet: no record, or no crash inside the window — nothing to add.
	PostureQuiet CrashLoopPosture = iota
	// PostureRestarting: crashes inside the window but the breaker has not
	// tripped; launchd is respawning the daemon into a fault that may or may
	// not be persistent yet.
	PostureRestarting
	// PostureParked: the breaker tripped; the daemon is resident but serves
	// nothing until an operator clears the record.
	PostureParked
	// PostureUnreadable: the record exists (or may) but this process may not
	// read it — a plain-user run against the service-owned work dir.
	PostureUnreadable
)

// CrashLoopVerdict is the row-shaped reading of a record.
type CrashLoopVerdict struct {
	Posture CrashLoopPosture
	Detail  string
	Remedy  string
}

// restartingFloor is how many crashes inside the window make the row say so.
// One crash is a fact for the log; two is a pattern worth a WARN before the
// breaker's own threshold turns it into a FAIL.
const restartingFloor = 2

// ClassifyCrashLoop reads a record into a verdict. Pure: the caller passes the
// record (or the read error) and the clock.
func ClassifyCrashLoop(rec executor.CrashRecord, readErr error, path string, now time.Time) CrashLoopVerdict {
	if readErr != nil {
		if errors.Is(readErr, os.ErrPermission) {
			return CrashLoopVerdict{Posture: PostureUnreadable,
				Detail: "crash-loop record not readable by this user (run as root to read it)"}
		}
		return CrashLoopVerdict{Posture: PostureUnreadable,
			Detail: "crash-loop record unreadable: " + errText(readErr)}
	}
	last, _ := rec.Last()
	if rec.Tripped() {
		n := rec.Recent(*rec.TrippedAt)
		detail := fmt.Sprintf("crash-loop breaker tripped at %s: %s crashed %d times within %s; the daemon is parked and serves nothing",
			rec.TrippedAt.Format(time.RFC3339), last.Component, n, executor.CrashLoopWindow)
		if neverCameUp(last) {
			detail = fmt.Sprintf("crash-loop breaker tripped at %s: the control plane never came up (last: %s), %d failures within %s; the daemon is parked and serves nothing",
				rec.TrippedAt.Format(time.RFC3339), last.Component, n, executor.CrashLoopWindow)
		}
		return CrashLoopVerdict{
			Posture: PostureParked,
			Detail:  detail,
			Remedy:  "sudo k3sm server --clear-crashloop   # after fixing the fault named in " + path + "; the parked daemon restarts itself",
		}
	}
	if n := rec.Recent(now); n >= restartingFloor {
		detail := fmt.Sprintf("restarted %d times in the last %s (last crash: %s at %s); trips at %d",
			n, executor.CrashLoopWindow, last.Component, last.At.Format(time.RFC3339), executor.CrashLoopThreshold)
		if neverCameUp(last) {
			detail = fmt.Sprintf("the control plane never came up (last: %s), %d failures in the last %s (latest at %s); trips at %d",
				last.Component, n, executor.CrashLoopWindow, last.At.Format(time.RFC3339), executor.CrashLoopThreshold)
		}
		return CrashLoopVerdict{
			Posture: PostureRestarting,
			Detail:  detail,
			Remedy:  "sudo tail -n 50 " + path + "   # the failures, with redacted log tails",
		}
	}
	return CrashLoopVerdict{Posture: PostureQuiet}
}

// neverCameUp reports whether the record's last entry was a BRING-UP failure
// rather than a crash. The breaker counts two different failures now, and they
// send an operator to different places: a crash has a component log with a fatal
// line at the end of it, while a control plane that never came up often has no
// component log at all, and the reason is in the daemon's own log instead. A row
// that called the second one a crash would cost the operator that first step.
//
// An entry with no origin reads as a crash: records written before the daemon
// counted bring-up failures hold only crashes, and the row must not invent a
// distinction the file does not carry.
func neverCameUp(last executor.Crash) bool { return last.Origin == executor.CrashOriginBringUp }

// applyCrashLoop folds the verdict into the server row. A parked daemon is a
// FAIL whatever launchd says (it is running, and serving nothing); restarting
// is a WARN on a running row; unreadable is a wide-view note only, never a
// severity, because "we could not look" is not a finding.
func applyCrashLoop(row *Row, v CrashLoopVerdict) {
	switch v.Posture {
	case PostureParked:
		row.State, row.Severity = StateCrashLoop, SeverityFail
		row.Detail, row.Remedy = v.Detail, v.Remedy
		row.Wide["crash-loop"] = "tripped"
	case PostureRestarting:
		if row.Severity == SeverityOK {
			row.State, row.Severity = StateCrashLoop, SeverityWarn
		}
		row.Detail = v.Detail
		if row.Remedy == "" {
			row.Remedy = v.Remedy
		}
		row.Wide["crash-loop"] = "restarting"
	case PostureUnreadable:
		row.Wide["crash-loop"] = v.Detail
	}
}
