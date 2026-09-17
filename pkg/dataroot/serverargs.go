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

// ServerArgsRecordVersion is the schema version WriteServerArgsRecord stamps and
// ReadServerArgsRecord accepts. A record written by a newer k3sm is REFUSED
// rather than guessed at, for the same reason RecordVersion is: the record is
// what a reinstall re-renders the server LaunchDaemon from, and a
// half-understood record would put an operator's node back on the stock
// template without saying so.
const ServerArgsRecordVersion = 1

// DefaultServerArgsRecordPath is where k3sm keeps the server-arguments record:
// beside the data-volume record, in root-owned /Library/Preferences.
//
// NOT inside the data root, and the difference is a privilege boundary rather
// than a filing preference. The data root is owned by the unprivileged _k3sm
// uid, so that uid can replace any file in it — including a record a later
// root-run `k3sm install` would read and splice straight into the server
// LaunchDaemon's argv. Keeping the record in a directory only root can write
// means the only thing that can change the daemon's arguments is something that
// was already root.
//
// It is a var only so tests can point it at a fixture; production never changes
// it.
var DefaultServerArgsRecordPath = "/Library/Preferences/io.k3sm.server-args.json"

// serverArgsRecordMode is the record's file mode: root-owned, ROOT-ONLY.
//
// 0600 rather than the data-volume record's 0644 because an operator argument
// can carry a credential — `--datastore-endpoint postgres://user:password@host`
// is the obvious one — and a world-readable copy of a datastore password is a
// leak no amount of redaction in the logs would undo.
const serverArgsRecordMode fs.FileMode = 0o600

// ManagedServerFlags are the `k3sm server` flag names (leading dashes stripped)
// that the INSTALLER renders itself and a record may therefore never carry.
//
// This is the one home of that vocabulary: pkg/install builds its own
// managed-flag set from this slice rather than re-typing it, so the flags the
// installer refuses to preserve and the flags a record is refused for are the
// same list by construction. A record carrying one is rejected outright rather
// than filtered, because a file that tries to set --token is not a stale record,
// it is an attempt to hand the daemon a credential.
var ManagedServerFlags = []string{"runtime", "token"}

// The bounds a server-arguments record must satisfy. They are not tuning knobs:
// the record is re-rendered into a root LaunchDaemon's ProgramArguments, so
// every one of them is a bound on what a file can make launchd exec.
const (
	// MaxServerArgs is the most arguments a record may carry. A real
	// configuration is a handful of flags; hundreds is a file nobody wrote by
	// hand.
	MaxServerArgs = 64
	// MaxServerArgLen is the longest single argument, in bytes.
	MaxServerArgLen = 4096
)

// ErrServerArgsRejected is the sentinel every content refusal wraps. Match it
// with errors.Is, never by string.
var ErrServerArgsRejected = errors.New("server arguments record carries arguments k3sm refuses to render")

// ServerArgsRecord is k3sm's note of the operator-supplied `k3sm server`
// arguments the installed control plane was last configured with — everything
// on the server LaunchDaemon's argv that the installer does not render itself.
//
// It exists because the plist is not durable across an uninstall: `k3sm
// uninstall` removes the LaunchDaemon it laid down, so a later `k3sm install`
// found no plist to read the operator's arguments off and silently re-rendered
// the stock template. The record is the second copy that survives that gap.
type ServerArgsRecord struct {
	// Version is the schema version; always ServerArgsRecordVersion on write.
	Version int `json:"version"`
	// Args are the operator-supplied arguments, in their original order and
	// verbatim — never a distilled subset, because the next install renders
	// exactly what is here. They are validated on both write and read; see
	// ValidateServerArgs for what they may not be.
	Args []string `json:"args"`
	// CreatedBy names the k3sm version that wrote the record.
	CreatedBy string `json:"createdBy"`
	// CreatedAt is when the record was written, in UTC. Diagnostics quote it so
	// an operator can tell a record from the install they remember from one an
	// older binary left behind.
	CreatedAt time.Time `json:"createdAt"`
}

// ValidateServerArgs reports why args may not be rendered into a server
// LaunchDaemon, or nil when they may.
//
// The record is the ONE input to the installed daemon's command line that is not
// derived from the installer's own Config, so it is treated as input rather than
// as data k3sm wrote: the file could have been restored from a backup, synced
// from another Mac, or replaced by anything that once had root. Four refusals,
// each closing a way a file could turn into an argv k3sm never intended:
//
//   - a MANAGED flag (ManagedServerFlags) — the record trying to set --token
//     would hand the daemon a credential of the file's choosing, in place of the
//     one this install just minted;
//   - more than MaxServerArgs arguments, or one longer than MaxServerArgLen —
//     bounds on what a file can make launchd exec;
//   - a NUL or a newline in any argument — neither can occur in an argument
//     k3sm rendered, and both are the shapes that break the plist encoding and
//     anything downstream that reads a line at a time.
//
// It is applied on WRITE as well as on read, so the installer can never produce
// a record its own next run would refuse.
func ValidateServerArgs(args []string) error {
	return validateRecordArgs(args, ManagedServerFlags, ErrServerArgsRejected)
}

// recordArgFlagName is the flag name an argument names, with leading dashes
// stripped and any inline =value removed, or "" for a non-flag argument. Both
// spellings collapse to one name (Go's flag package accepts -x and --x), and
// --token=… is the same name as --token. It serves both argument records.
//
// pkg/install has a richer splitter for walking an argv (it needs the value and
// whether it was inline); this one exists because pkg/dataroot cannot import the
// package that imports it. The NAMES the two decide about are single-sourced in
// ManagedServerFlags / ManagedAgentFlags, which is the part that must not drift.
func recordArgFlagName(arg string) string {
	if !strings.HasPrefix(arg, "-") {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	return name
}

// ReadServerArgsRecord reads the server-arguments record at path.
//
// A missing record is not an error: it reports (nil, nil), which is both the
// first-install posture and the posture of any Mac installed before records
// existed. A record that does not parse, that carries an unknown version, or
// whose arguments ValidateServerArgs refuses IS an error — mistaking any of
// those for "no arguments were configured" is precisely the silent re-render
// this record exists to end, and quietly dropping a rejected argument would hide
// the more interesting fact that something put it there.
//
// It takes a FileReader rather than the package's FS because reading one small
// file is all it does, and the installer reaches the record through its own
// privileged read seam rather than through a filesystem interface.
func ReadServerArgsRecord(fsys FileReader, path string) (*ServerArgsRecord, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read server arguments record %s: %w", path, err)
	}
	var r ServerArgsRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse server arguments record %s: %w", path, err)
	}
	if r.Version != ServerArgsRecordVersion {
		return nil, fmt.Errorf("server arguments record %s: unknown version %d, this k3sm understands %d", path, r.Version, ServerArgsRecordVersion)
	}
	if err := ValidateServerArgs(r.Args); err != nil {
		return nil, fmt.Errorf("server arguments record %s: %w", path, err)
	}
	return &r, nil
}

// EncodeServerArgsRecord returns the exact bytes WriteServerArgsRecord writes,
// with the version stamped by the writer rather than by the caller.
//
// It is exported so a test fake standing in for the privileged write seam can
// produce the bytes a real installer would, and the read-back then goes through
// the real decoder. A fake with its own encoder would be a second encoding of
// this record, which is the drift the single record type exists to prevent.
func EncodeServerArgsRecord(r ServerArgsRecord) ([]byte, error) {
	r.Version = ServerArgsRecordVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode server arguments record: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteServerArgsRecord writes r to path atomically — the same temp-and-rename
// WriteRecord uses, through the same helper — so a reader never observes a
// half-written record. The file is 0600 and root-owned in production; see
// serverArgsRecordMode for why it is not the sibling record's 0644.
//
// The arguments are validated FIRST: a record this package would refuse to read
// is one it must refuse to write, or an install would succeed and leave the next
// one failing on a file it produced itself.
func WriteServerArgsRecord(path string, r ServerArgsRecord) error {
	if err := ValidateServerArgs(r.Args); err != nil {
		return fmt.Errorf("write server arguments record %s: %w", path, err)
	}
	data, err := EncodeServerArgsRecord(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, ".io.k3sm.server-args-*.json", serverArgsRecordMode, data, "server arguments record")
}
