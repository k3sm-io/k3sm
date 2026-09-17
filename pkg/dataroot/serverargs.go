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
	"path/filepath"
	"time"
)

// ServerArgsRecordVersion is the schema version WriteServerArgsRecord stamps and
// ReadServerArgsRecord accepts. A record written by a newer k3sm is REFUSED
// rather than guessed at, for the same reason RecordVersion is: the record is
// what a reinstall re-renders the server LaunchDaemon from, and a
// half-understood record would put an operator's node back on the stock
// template without saying so.
const ServerArgsRecordVersion = 1

// serverArgsRecordName is the record's leaf name inside the data root. It is
// stated once and joined onto whichever data root a caller names, so no second
// literal can spell it differently.
const serverArgsRecordName = "server-args.json"

// ServerArgsRecordPath is where k3sm keeps the server-arguments record for a
// data root: <dataRoot>/server-args.json.
//
// Inside the data root is deliberate. The data root is what `k3sm uninstall`
// preserves and what a `--data-volume` migration carries across, so a record
// kept here survives exactly the two events the record exists for — and a
// deliberate reset of the data root discards the carried arguments along with
// the cluster state they belonged to, which is the model an operator already
// holds about that directory.
func ServerArgsRecordPath(dataRoot string) string {
	return filepath.Join(dataRoot, serverArgsRecordName)
}

// ServerArgsRecord is k3sm's note of the operator-supplied `k3sm server`
// arguments the installed control plane was last configured with — everything
// on the server LaunchDaemon's argv that the installer does not render itself.
//
// It exists because the plist is not durable across an uninstall: `k3sm
// uninstall` removes the LaunchDaemon it laid down, so a later `k3sm install`
// found no plist to read the operator's arguments off and silently re-rendered
// the stock template. The record is the second copy that survives that gap.
//
// It holds no secret: the install-managed flags (--token, --runtime) are
// re-derived on every install and are never written here.
type ServerArgsRecord struct {
	// Version is the schema version; always ServerArgsRecordVersion on write.
	Version int `json:"version"`
	// Args are the operator-supplied arguments, in their original order and
	// verbatim — never a distilled subset, because the next install renders
	// exactly what is here.
	Args []string `json:"args"`
	// CreatedBy names the k3sm version that wrote the record.
	CreatedBy string `json:"createdBy"`
	// CreatedAt is when the record was written, in UTC. Diagnostics quote it so
	// an operator can tell a record from the install they remember from one an
	// older binary left behind.
	CreatedAt time.Time `json:"createdAt"`
}

// ReadServerArgsRecord reads the server-arguments record at path.
//
// A missing record is not an error: it reports (nil, nil), which is both the
// first-install posture and the posture of any Mac installed before records
// existed. A record that does not parse, or that carries an unknown version, IS
// an error — mistaking one for "no arguments were configured" is precisely the
// silent re-render this record exists to end.
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
// half-written record. The file is 0644 (root-owned in production, like the
// plist it mirrors) because it carries nothing secret.
func WriteServerArgsRecord(path string, r ServerArgsRecord) error {
	data, err := EncodeServerArgsRecord(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, ".io.k3sm.serverargs-*.json", data, "server arguments record")
}
