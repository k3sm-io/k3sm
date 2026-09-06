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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// DatastorePosture reads the kine SQLite datastore posture WITHOUT creating,
// writing, or checkpointing the db. It os.Stat's the path first (absent →
// present false), then opens the file READ-ONLY and parses the 100-byte SQLite
// database header directly:
//
//	offset 0..15  magic string "SQLite format 3\000"
//	offset 18     file-format write version (1 = rollback journal, 2 = WAL)
//	offset 60..63 user_version (big-endian uint32)
//
// This is strictly read-only: a naive sql.Open()+Ping() would CREATE an empty
// state.db on a fresh node — a forbidden side effect — and would need a cgo
// sqlite driver dependency. The header parse avoids both.
//
// It lives here rather than beside `k3sm doctor` because both commands report
// the same posture, and two header parsers would eventually disagree about what
// "wal" means.
func DatastorePosture(path string) (present bool, userVersion int, journalMode string, err error) {
	if _, statErr := os.Stat(path); statErr != nil {
		if os.IsNotExist(statErr) {
			return false, 0, "", nil
		}
		return false, 0, "", statErr
	}
	f, err := os.Open(path) // read-only; never creates
	if err != nil {
		return false, 0, "", err
	}
	defer func() { _ = f.Close() }()

	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false, 0, "", fmt.Errorf("read sqlite header: %w", err)
	}
	if string(hdr[0:16]) != "SQLite format 3\x00" {
		return false, 0, "", errors.New("not a sqlite database (bad header magic)")
	}
	userVersion = int(binary.BigEndian.Uint32(hdr[60:64]))
	switch hdr[18] {
	case 2:
		journalMode = "wal"
	case 1:
		journalMode = "rollback"
	default:
		journalMode = fmt.Sprintf("unknown(%d)", hdr[18])
	}
	return true, userVersion, journalMode, nil
}
