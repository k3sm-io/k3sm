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
	"strconv"
	"strings"
)

// DaemonInfo is everything this package takes from `launchctl print
// system/<label>`. It is deliberately a HANDFUL OF SCALARS and never the text
// they came from: launchctl echoes the job's whole argv, and the k3sm server's
// argv carries the cluster join token, so the parsed struct is the boundary that
// keeps a secret out of a status row (pinned by TestReportNeverContainsSecrets).
type DaemonInfo struct {
	// Loaded reports that the job is bootstrapped in the system domain — i.e.
	// launchctl print exited 0 and had something to say about it.
	Loaded bool
	// Disabled reports a launchctl-disabled job, read from the separate
	// print-disabled output by MarkDisabled.
	Disabled bool
	// State is launchd's own state word ("running", "not running", "spawn
	// scheduled", …), verbatim and lowercase as launchctl prints it.
	State string
	// PID is the job's process id, 0 when it has none.
	PID int
	// Runs is how many times launchd has spawned the job. A high count next to a
	// non-zero exit is what distinguishes a crash loop from a single failure.
	Runs int
	// LastExit is the job's last exit code, nil when it has never exited.
	LastExit *int
	// KeysMatched counts the distinct keys actually recognised in the output. It
	// exists so a launchctl output-format change reads as "unknown" rather than
	// as a healthy-looking zero value: no keys means the parse learned nothing.
	KeysMatched int
}

// launchctlKeys are the four `key = value` lines the parser recognises, in the
// order launchctl prints them. Nothing else in the output is read.
var launchctlKeys = []string{"state", "pid", "runs", "last exit code"}

// neverExited is launchctl's sentinel value for a job that has not exited yet.
const neverExited = "(never exited)"

// ParseLaunchctlPrint extracts the four scalars from `launchctl print
// system/<label>` output.
//
// exitErr non-nil means the job is not bootstrapped in the system domain, and
// the output is IGNORED entirely — launchctl writes a usage/diagnostic blob on
// failure, and parsing it would invent state for a job that does not exist.
//
// Within the output the FIRST occurrence of each key wins: launchctl nests
// sub-dictionaries (endpoints, spawn statistics) that repeat some key names, and
// the job's own values come first.
func ParseLaunchctlPrint(out []byte, exitErr error) DaemonInfo {
	if exitErr != nil {
		return DaemonInfo{}
	}
	d := DaemonInfo{Loaded: true}
	seen := make(map[string]bool, len(launchctlKeys))
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		for _, key := range launchctlKeys {
			if seen[key] {
				continue
			}
			value, ok := strings.CutPrefix(line, key+" = ")
			if !ok {
				continue
			}
			value = strings.TrimSpace(value)
			switch key {
			case "state":
				d.State = value
				seen[key] = true
			case "pid":
				if n, err := strconv.Atoi(value); err == nil {
					d.PID = n
					seen[key] = true
				}
			case "runs":
				if n, err := strconv.Atoi(value); err == nil {
					d.Runs = n
					seen[key] = true
				}
			case "last exit code":
				// "(never exited)" is a recognised value, not a parse miss: the
				// key was found and it says the job has never exited.
				if value == neverExited {
					seen[key] = true
					break
				}
				if n, err := strconv.Atoi(value); err == nil {
					code := n
					d.LastExit = &code
					seen[key] = true
				}
			}
			break
		}
	}
	d.KeysMatched = len(seen)
	return d
}

// MarkDisabled sets d.Disabled when label appears in `launchctl print-disabled
// system` output as disabled. A disabled job can be bootstrapped and idle, which
// looks exactly like a cleanly stopped one in print output — but the remedy is
// different (it must be enabled, not merely kickstarted), so the two are read
// from different commands and reported as different states.
func MarkDisabled(d *DaemonInfo, printDisabledOut []byte, label string) {
	if d == nil {
		return
	}
	marker := "\"" + label + "\" => disabled"
	if strings.Contains(string(printDisabledOut), marker) {
		d.Disabled = true
	}
}

// DaemonClass is the verdict ClassifyDaemon reduces a DaemonInfo to.
type DaemonClass int

const (
	// ClassRunning: launchd has a live process for the job.
	ClassRunning DaemonClass = iota
	// ClassCrashLooping: the job is not running, exited non-zero, and has been
	// spawned more than once — launchd is restarting it into the same failure.
	ClassCrashLooping
	// ClassFailed: the job is not running and its single run exited non-zero.
	ClassFailed
	// ClassStopped: the job is loaded and idle, with no failure to report.
	ClassStopped
	// ClassNotLoaded: the job is not bootstrapped in the system domain.
	ClassNotLoaded
	// ClassDisabled: the job is disabled, so launchd will not start it.
	ClassDisabled
	// ClassUnknown: the output could not be read as a job state. This is the
	// verdict a launchctl format change produces, and it must never be confused
	// with a healthy one.
	ClassUnknown
)

// classStates maps a class to the STATE token its row carries.
var classStates = map[DaemonClass]RowState{
	ClassRunning:      StateRunning,
	ClassCrashLooping: StateCrashLoop,
	ClassFailed:       StateFailed,
	ClassStopped:      StateStopped,
	ClassNotLoaded:    StateNotLoaded,
	ClassDisabled:     StateDisabled,
	ClassUnknown:      StateUnknown,
}

// State returns the row STATE token for a class.
func (c DaemonClass) State() RowState {
	if s, ok := classStates[c]; ok {
		return s
	}
	return StateUnknown
}

// String renders the class as its row STATE token.
func (c DaemonClass) String() string { return string(c.State()) }

// Severity maps a class onto the report's health axis. Every non-running class
// except Unknown is a FAIL: the two k3sm daemons are KeepAlive jobs that are
// supposed to be up, so "loaded and idle" is not a benign posture — it is a
// cluster that is not serving.
func (c DaemonClass) Severity() Severity {
	switch c {
	case ClassRunning:
		return SeverityOK
	case ClassUnknown:
		return SeverityUnknown
	default:
		return SeverityFail
	}
}

// ClassifyDaemon reduces a parsed DaemonInfo to one class.
//
// The ORDER of these tests is the contract. Not-loaded and disabled are read
// first because they are facts about the job's existence rather than its last
// run; the KeysMatched==0 test comes next so an unparseable output can never
// fall through into a state verdict; and the crash-loop/failed split is decided
// by the run count, because one non-zero exit is a failure and many is a loop.
func ClassifyDaemon(d DaemonInfo) DaemonClass {
	switch {
	case !d.Loaded:
		return ClassNotLoaded
	case d.Disabled:
		return ClassDisabled
	case d.KeysMatched == 0:
		return ClassUnknown
	case d.State == "running" && d.PID > 0:
		return ClassRunning
	case d.State != "running" && d.LastExit != nil && *d.LastExit != 0 && d.Runs > 1:
		return ClassCrashLooping
	case d.State != "running" && d.LastExit != nil && *d.LastExit != 0:
		return ClassFailed
	case d.State != "running" && (d.LastExit == nil || *d.LastExit == 0):
		return ClassStopped
	default:
		return ClassUnknown
	}
}
