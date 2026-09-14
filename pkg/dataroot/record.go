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
	"os"
	"path/filepath"
)

// RecordVersion is the schema version WriteRecord stamps and ReadRecord
// accepts. A record written by a newer k3sm is refused rather than guessed at:
// the record declares a mount point, and a misread declaration is exactly the
// shadow the package exists to prevent.
const RecordVersion = 1

// DefaultRecordPath is where k3sm keeps the data-volume record. It is outside
// the data root it describes (so it survives the volume being unmounted) and
// outside the install directory (so `k3sm uninstall` does not sweep it away).
// The .json extension is deliberate: plist-globbing tools skip it.
//
// It is a var only so tests can point it at a fixture; production never
// changes it.
var DefaultRecordPath = "/Library/Preferences/io.k3sm.datavol.json"

// Record is k3sm's declaration that a data root lives on an APFS volume k3sm
// created or adopted. It is written ONLY by k3sm, and only after a mount has
// been verified, which is what makes it trustworthy as a declaration source
// alongside /etc/fstab (see the package comment).
type Record struct {
	// Version is the schema version; always RecordVersion on write.
	Version int `json:"version"`
	// UUID is the APFS volume UUID — the stable handle every diskutil verb
	// takes, unlike the device node, which renumbers.
	UUID string `json:"uuid"`
	// Name is the APFS volume name (its label), e.g. "k3sm".
	Name string `json:"name"`
	// Mountpoint is the data root the volume is mounted at.
	Mountpoint string `json:"mountpoint"`
	// QuotaBytes is the APFS quota observed at creation or adoption, 0 when
	// the volume carries none (it can then grow to fill the container).
	QuotaBytes uint64 `json:"quotaBytes"`
	// Encrypted reports that the volume is encrypted with a passphrase k3sm
	// keeps in the System keychain.
	Encrypted bool `json:"encrypted"`
	// CreatedBy names the k3sm version that wrote the record.
	CreatedBy string `json:"createdBy"`
	// CreatedAt is when the record was written, RFC 3339 in UTC.
	CreatedAt string `json:"createdAt"`
	// Adopted reports that k3sm took over a volume it did not create.
	Adopted bool `json:"adopted"`
}

// ReadRecord reads the data-volume record at path.
//
// A missing record is not an error: it reports (nil, nil), the ordinary
// posture of an install that never asked for a volume. A record that does not
// parse, or that carries an unknown version, IS an error — a declaration that
// cannot be read must not be mistaken for no declaration at all.
func ReadRecord(fsys FS, path string) (*Record, error) {
	data, err := fsys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read data volume record %s: %w", path, err)
	}
	var r Record
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse data volume record %s: %w", path, err)
	}
	if r.Version != RecordVersion {
		return nil, fmt.Errorf("data volume record %s: unknown version %d, this k3sm understands %d", path, r.Version, RecordVersion)
	}
	return &r, nil
}

// WriteRecord writes r to path atomically: a temp file in the same directory,
// then a rename, so a reader never observes a half-written declaration. The
// file is 0644 (root-owned in production) and r.Version is forced to
// RecordVersion — the caller does not get to stamp a version it did not write.
func WriteRecord(path string, r Record) error {
	r.Version = RecordVersion
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode data volume record: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".io.k3sm.datavol-*.json")
	if err != nil {
		return fmt.Errorf("create temp data volume record in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename succeeded

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp data volume record %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp data volume record %s: %w", name, err)
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return fmt.Errorf("chmod temp data volume record %s: %w", name, err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("install data volume record %s: %w", path, err)
	}
	return nil
}

// RemoveRecord deletes the record at path. A record that is already gone is
// not an error: removal is idempotent because `k3sm datavol delete` may be
// re-run after a partial failure.
func RemoveRecord(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove data volume record %s: %w", path, err)
	}
	return nil
}
