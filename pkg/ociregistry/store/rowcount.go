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

package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// rowsDir is the state directory's subdirectory that holds, per repository,
// the row count the store recorded for its index.json.
//
// The record lives in the state directory, not beside index.json, for two
// reasons. The repository layout stays exactly the one zot writes and reads.
// And a fault that replaces the repository directory as a whole (a restore of
// it from an older copy, a foreign writer) rolls back a record kept inside it
// along with the rows, so only one kept outside it can tell.
const rowsDir = "rows"

// maxRowCountLen bounds a row count record's read.
const maxRowCountLen = 64 << 10

// ErrRowsLost is a repository whose index.json holds fewer rows than the store
// recorded: rows were dropped by something other than the store, such as an
// index.json rolled back or rewritten behind its back. The blobs those rows
// named are no longer described by any row, so a collector must not sweep the
// repository until the rows are restored or the record is removed.
var ErrRowsLost = errors.New("index.json holds fewer rows than the store recorded")

// rowCount is a row count record: how many rows the store believes the
// repository's index.json holds. Store binds it to the store id, so a record
// written for another store, or before the store had an id, is not trusted.
type rowCount struct {
	Store      string `json:"store"`
	Repository string `json:"repository"`
	Rows       int    `json:"rows"`
}

// recordedRows returns the record for the repository in dir, whether one that
// this store wrote exists, and its path. The returned record carries the
// current store id and the repository's name, ready to be written. A missing
// record, a malformed one, or one bound to another store id is reported as
// absent: it is rewritten from the index and never blocks anything.
func (s *Store) recordedRows(dir string) (rowCount, bool, string, error) {
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return rowCount{}, false, "", fmt.Errorf("row count: %w", err)
	}
	name := filepath.ToSlash(rel)
	sum := sha256.Sum256([]byte(name))
	p := filepath.Join(s.state, rowsDir, hex.EncodeToString(sum[:]))
	// A bad id fails every sweep (gc refuses it), so a push need not; the
	// record then binds to no id, and is rewritten once the id is repaired.
	id, _, _ := s.ID()
	want := rowCount{Store: id, Repository: name}
	b, err := readRegular(p, maxRowCountLen)
	if errors.Is(err, os.ErrNotExist) {
		return want, false, p, nil
	}
	if err != nil {
		return rowCount{}, false, "", fmt.Errorf("row count: %w", err)
	}
	var got rowCount
	if json.Unmarshal(b, &got) != nil || got.Store != id || got.Repository != name || got.Rows < 0 {
		return want, false, p, nil
	}
	want.Rows = got.Rows
	return want, true, p, nil
}

// writeRowCount replaces the record at p durably: a temp file in the same
// directory, F_FULLFSYNC, rename, directory sync.
func (s *Store) writeRowCount(p string, rc rowCount) error {
	b, err := json.Marshal(rc)
	if err != nil {
		return fmt.Errorf("encode row count: %w", err)
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("row count: %w", err)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+id)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, fileMode)
	if err != nil {
		return fmt.Errorf("stage row count: %w", err)
	}
	_, werr := f.Write(append(b, '\n'))
	if werr == nil {
		werr = fullSync(f)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		_ = os.Remove(tmp) // best effort; the next write uses a new name
		return fmt.Errorf("write row count: %w", werr)
	}
	return syncDir(dir)
}

// removeRowCount removes the record of the repository in dir, when there is one.
func (s *Store) removeRowCount(dir string) error {
	_, _, p, err := s.recordedRows(dir)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove row count: %w", err)
	}
	return nil
}

// CheckRows compares index.json's rows with the count the store recorded, and
// returns ErrRowsLost when the index holds fewer. A missing record (a store
// written before records were kept, or one whose id changed) is written from
// the index as it is, and passes.
func (l *Locked) CheckRows() error {
	idx, err := readIndex(l.dir)
	if err != nil {
		return err
	}
	rc, ok, p, err := l.s.recordedRows(l.dir)
	if err != nil {
		return err
	}
	have := len(idx.Manifests)
	if !ok {
		rc.Rows = have
		return l.s.writeRowCount(p, rc)
	}
	if have < rc.Rows {
		return fmt.Errorf("%w: %s holds %d rows, the store recorded %d; restore the rows, or remove %s to accept the index as it is",
			ErrRowsLost, l.n, have, rc.Rows, p)
	}
	return nil
}
