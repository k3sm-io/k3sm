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

package dataroot

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"
)

// AgentArgsRecordVersion is the schema version WriteAgentArgsRecord stamps and
// ReadAgentArgsRecord accepts. A record written by a newer k3sm is REFUSED
// rather than guessed at, for the same reason ServerArgsRecordVersion is: the
// record is what a reinstall re-renders the agent LaunchDaemon from.
const AgentArgsRecordVersion = 1

// DefaultAgentArgsRecordPath is where k3sm keeps the agent-arguments record:
// beside the server-arguments record, in root-owned /Library/Preferences, and
// for the same privilege reason — see DefaultServerArgsRecordPath. The two
// never cross: a Mac is installed in one role, and each role reads only its own
// file, so an uninstall-then-install that switches roles cannot splice a
// server's flags onto an agent's argv.
//
// It is a var only so tests can point it at a fixture; production never changes
// it.
var DefaultAgentArgsRecordPath = "/Library/Preferences/io.k3sm.agent-args.json"

// agentArgsRecordMode is the record's file mode: root-owned, ROOT-ONLY, the
// same 0600 the server record carries and for the same reason — an operator
// argument can carry a credential.
const agentArgsRecordMode fs.FileMode = 0o600

// ManagedAgentFlags are the `k3sm agent` flag names (leading dashes stripped) a
// record may never carry.
//
// It is exactly --token, and that is the whole point of the list: the join
// credential reaches the daemon as a FILE the installer renders --token-file
// for, never as a value on an argv a 0644 plist publishes to every process on
// the Mac. A record that names --token is not a stale record, it is an attempt
// to hand the agent a credential of the file's choosing, so it is rejected
// outright rather than filtered.
var ManagedAgentFlags = []string{"token"}

// ErrAgentArgsRejected is the sentinel every agent-record content refusal
// wraps. Match it with errors.Is, never by string.
var ErrAgentArgsRejected = errors.New("agent arguments record carries arguments k3sm refuses to render")

// AgentArgsRecord is k3sm's note of the operator-supplied `k3sm agent`
// arguments the installed worker was last configured with — everything on the
// agent LaunchDaemon's argv that the installer does not render itself.
//
// It is the sibling of ServerArgsRecord and exists for the same reason: `k3sm
// uninstall` removes the LaunchDaemon it laid down, so a later `k3sm install
// --agent` would have no plist to read the operator's arguments off and would
// silently re-render the stock template.
type AgentArgsRecord struct {
	// Version is the schema version; always AgentArgsRecordVersion on write.
	Version int `json:"version"`
	// Args are the operator-supplied arguments, in their original order and
	// verbatim. They are validated on both write and read; see ValidateAgentArgs.
	Args []string `json:"args"`
	// CreatedBy names the k3sm version that wrote the record.
	CreatedBy string `json:"createdBy"`
	// CreatedAt is when the record was written, in UTC.
	CreatedAt time.Time `json:"createdAt"`
}

// ValidateAgentArgs reports why args may not be rendered into an agent
// LaunchDaemon, or nil when they may. The bounds and the refusals are the
// server record's (validateRecordArgs), with ManagedAgentFlags as the set no
// file may set.
func ValidateAgentArgs(args []string) error {
	return validateRecordArgs(args, ManagedAgentFlags, ErrAgentArgsRejected)
}

// validateRecordArgs is the shared content gate both argument records apply.
//
// It is one function rather than two because both records are read by the same
// root installer and spliced into the same launchd ProgramArguments array, so
// every bound here is a bound on what a file can make launchd exec: a managed
// flag the file may not set, a count, a length, and the two byte classes (NUL,
// newline) that break the plist encoding and every line-oriented reader
// downstream. Two copies of that reasoning would let one record's rules drift
// below the other's.
func validateRecordArgs(args []string, managed []string, rejected error) error {
	if len(args) > MaxServerArgs {
		return fmt.Errorf("%w: %d arguments, the limit is %d", rejected, len(args), MaxServerArgs)
	}
	for _, arg := range args {
		if len(arg) > MaxServerArgLen {
			return fmt.Errorf("%w: an argument of %d bytes, the limit is %d", rejected, len(arg), MaxServerArgLen)
		}
		if strings.ContainsAny(arg, "\x00\n\r") {
			return fmt.Errorf("%w: an argument contains a NUL or a newline", rejected)
		}
		name := recordArgFlagName(arg)
		for _, m := range managed {
			if name == m {
				return fmt.Errorf("%w: --%s is rendered by the installer and may not come from a file", rejected, m)
			}
		}
	}
	return nil
}

// ReadAgentArgsRecord reads the agent-arguments record at path, with
// ReadServerArgsRecord's contract: a missing record is (nil, nil) — the
// first-install posture — while a record that does not parse, carries an
// unknown version, or fails ValidateAgentArgs is an error.
func ReadAgentArgsRecord(fsys FileReader, path string) (*AgentArgsRecord, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read agent arguments record %s: %w", path, err)
	}
	var r AgentArgsRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse agent arguments record %s: %w", path, err)
	}
	if r.Version != AgentArgsRecordVersion {
		return nil, fmt.Errorf("agent arguments record %s: unknown version %d, this k3sm understands %d", path, r.Version, AgentArgsRecordVersion)
	}
	if err := ValidateAgentArgs(r.Args); err != nil {
		return nil, fmt.Errorf("agent arguments record %s: %w", path, err)
	}
	return &r, nil
}

// EncodeAgentArgsRecord returns the exact bytes WriteAgentArgsRecord writes,
// with the version stamped by the writer rather than by the caller. It is
// exported so a test fake standing in for the privileged write seam produces
// the bytes a real installer would.
func EncodeAgentArgsRecord(r AgentArgsRecord) ([]byte, error) {
	r.Version = AgentArgsRecordVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode agent arguments record: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteAgentArgsRecord writes r to path atomically, 0600 and root-owned in
// production. The arguments are validated FIRST, so an install can never
// produce a record its own next run would refuse.
func WriteAgentArgsRecord(path string, r AgentArgsRecord) error {
	if err := ValidateAgentArgs(r.Args); err != nil {
		return fmt.Errorf("write agent arguments record %s: %w", path, err)
	}
	data, err := EncodeAgentArgsRecord(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, ".io.k3sm.agent-args-*.json", agentArgsRecordMode, data, "agent arguments record")
}
