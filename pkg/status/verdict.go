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

import "fmt"

// Verdict is the one-word answer `k3sm status` leads with, and the source of the
// process exit code. It is a closed set: the numbers behind ExitCode are a
// machine contract (scripts branch on them), so entries are ADDITIVE ONLY and an
// existing code is never renumbered.
type Verdict int

const (
	// VerdictRunning means the control plane is serving and every probed
	// subsystem is healthy or deliberately skipped.
	VerdictRunning Verdict = iota
	// VerdictDegraded means the control plane is serving but at least one
	// subsystem failed or warned.
	VerdictDegraded
	// VerdictStopped means k3sm is installed and the control plane is not
	// serving — whether it was stopped cleanly or is crash-looping.
	VerdictStopped
	// VerdictNotInstalled means this Mac has no k3sm install to report on.
	VerdictNotInstalled
	// VerdictUnknown means the state could not be determined, typically because
	// the reporting user cannot read the daemons' files. It is deliberately NOT
	// an error: nothing went wrong, the answer is simply not visible from here.
	VerdictUnknown
)

// verdictNames is the wire vocabulary — lowercase, hyphenated, stable. It backs
// both String and the text marshalling, so the word in JSON and the word on
// screen can never drift.
var verdictNames = map[Verdict]string{
	VerdictRunning:      "running",
	VerdictDegraded:     "degraded",
	VerdictStopped:      "stopped",
	VerdictNotInstalled: "not-installed",
	VerdictUnknown:      "unknown",
}

// String renders the verdict as the lowercase word the report leads with.
func (v Verdict) String() string {
	if s, ok := verdictNames[v]; ok {
		return s
	}
	return "unknown"
}

// ExitCode is the process exit status for a verdict. 1 and 2 are deliberately
// NOT in this map: they mean "an internal error" and "bad usage", neither of
// which is a verdict about the cluster.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictRunning:
		return 0
	case VerdictStopped:
		return 3
	case VerdictDegraded:
		return 4
	case VerdictNotInstalled:
		return 5
	default:
		return 6
	}
}

// MarshalText renders the verdict as its lowercase word for JSON.
func (v Verdict) MarshalText() ([]byte, error) { return []byte(v.String()), nil }

// UnmarshalText parses the lowercase word back into a Verdict. An unrecognised
// word is an error rather than a silent VerdictUnknown: a consumer that cannot
// name the verdict has read something this binary does not define.
func (v *Verdict) UnmarshalText(b []byte) error {
	for k, name := range verdictNames {
		if name == string(b) {
			*v = k
			return nil
		}
	}
	return fmt.Errorf("unknown status verdict %q", string(b))
}

// Severity is a row's health, and the axis Aggregate folds into the verdict. It
// is five-valued because "could not probe" (SeverityUnknown) and "nothing to
// probe" (SeveritySkip) are both real answers that must never read as healthy.
type Severity int

const (
	// SeverityOK means the subsystem was probed and is healthy.
	SeverityOK Severity = iota
	// SeverityWarn means the subsystem works but something is off.
	SeverityWarn
	// SeverityFail means the subsystem is broken.
	SeverityFail
	// SeveritySkip means there was deliberately nothing to probe (a fresh node
	// with no datastore yet). Distinct from OK: nothing was verified.
	SeveritySkip
	// SeverityUnknown means the probe could not see the answer — almost always
	// because the reporting user lacks the privilege to read it.
	SeverityUnknown
)

// severityNames is the wire vocabulary for a row's severity.
var severityNames = map[Severity]string{
	SeverityOK:      "ok",
	SeverityWarn:    "warn",
	SeverityFail:    "fail",
	SeveritySkip:    "skip",
	SeverityUnknown: "unknown",
}

// String renders the severity as its lowercase word.
func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// MarshalText renders the severity as its lowercase word for JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses the lowercase word back into a Severity.
func (s *Severity) UnmarshalText(b []byte) error {
	for k, name := range severityNames {
		if name == string(b) {
			*s = k
			return nil
		}
	}
	return fmt.Errorf("unknown status severity %q", string(b))
}

// Glyph is the one-character health mark rendered ahead of a row's name when
// Style.Glyphs is on. It is decoration only — the STATE word is always present,
// so a terminal that cannot draw these loses nothing.
func (s Severity) Glyph() string {
	switch s {
	case SeverityOK:
		return "✓"
	case SeverityWarn:
		return "!"
	case SeverityFail:
		return "✗"
	case SeveritySkip:
		return "-"
	default:
		return "?"
	}
}
