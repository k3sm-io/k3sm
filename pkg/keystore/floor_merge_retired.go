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

package keystore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// The retired record: what a merge retired and buried live, which the merge
// writes root-owned beside its renamed input, as
// keystore-floor.json.merged-<unix>.retired, so the reverse merge of an undo
// (MergeOptions.Undo) can tell a version the restore retired from an entry
// deleted since. It is written under its pending name,
// keystore-floor.json.pre-restore.retired, before the floor, and renamed with
// the input (renameMerged), so a rerun after a failed rename keeps the first
// run's sets.

const (
	// retiredSuffix ends the retired record's name.
	retiredSuffix = ".retired"
	// retiredPendingName is the record before the merge renames its input.
	retiredPendingName = floorPreRestoreName + retiredSuffix
	// mergedPrefix starts the renamed input's name: keystore-floor.json.merged-.
	mergedPrefix = floorName + ".merged-"
)

// retiredRecord is the retired record's content: each set sorted, without
// repeats, every name a valid entry name.
type retiredRecord struct {
	Retired    []string `json:"retired"`
	BuriedLive []string `json:"buriedLive"`
}

// marshalRetired is the record's one encoding, a trailing newline included.
func marshalRetired(rec retiredRecord) ([]byte, error) {
	if rec.Retired == nil {
		rec.Retired = []string{}
	}
	if rec.BuriedLive == nil {
		rec.BuriedLive = []string{}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// parseRetired decodes a retired record, refusing anything a merge would not
// have written: an unknown field, a name that is not valid, a set out of
// order or with a repeat, or any encoding but marshalRetired's.
func parseRetired(b []byte) (retiredRecord, error) {
	var rec retiredRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&rec); err != nil {
		return retiredRecord{}, fmt.Errorf("%w: the retired record does not parse: %w", ErrCorrupt, err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return retiredRecord{}, fmt.Errorf("%w: the retired record holds more than one value", ErrCorrupt)
	}
	for _, set := range [][]string{rec.Retired, rec.BuriedLive} {
		for i, n := range set {
			if err := checkName(n); err != nil {
				return retiredRecord{}, fmt.Errorf("%w: the retired record: %w", ErrCorrupt, err)
			}
			if i > 0 && set[i-1] >= n {
				return retiredRecord{}, fmt.Errorf("%w: the retired record's names are not sorted without repeats", ErrCorrupt)
			}
		}
	}
	if again, err := marshalRetired(rec); err != nil || !bytes.Equal(again, b) {
		return retiredRecord{}, fmt.Errorf("%w: the retired record is not in its one encoding", ErrCorrupt)
	}
	return rec, nil
}

// writeRetiredPending writes rec under its pending name through l.root,
// root-owned at the floor's mode, durably.
func (s *FileStore) writeRetiredPending(l *floorLock, r MergeReport) error {
	b, err := marshalRetired(retiredRecord{Retired: r.Retired, BuriedLive: r.BuriedLive})
	if err != nil {
		return err
	}
	return s.writeFileAs(l.root, retiredPendingName, b, uint32(s.floorUID), uint32(s.floorGID), floorFileMode)
}

// errNoRetiredRecord refuses an undo with no retired record in the data
// root.
var errNoRetiredRecord = errors.New("--undo reads what the restore's merge retired from the record it left in the data root, keystore-floor.json.merged-<unix>.retired, and there is none: a merge from before that record cannot be undone by --undo. Nothing is written")

// readRetired reads the newest retired record in the data root (the one
// with the highest <unix>), through l.root, judged as the floor is: a
// regular file, never followed, owned by root (floorUID), not group- or
// other-writable, at most floorSizeLimit, and in its one encoding.
func (s *FileStore) readRetired(l *floorLock) (retiredRecord, error) {
	d, err := l.root.Open(".")
	if err != nil {
		return retiredRecord{}, err
	}
	names, err := d.Readdirnames(maxDirNames + 1)
	_ = d.Close() // read-only
	if err != nil && !errors.Is(err, io.EOF) {
		return retiredRecord{}, err
	}
	if len(names) > maxDirNames {
		return retiredRecord{}, fmt.Errorf("%w: the data root holds more than %d names", errFloorUntrusted, maxDirNames)
	}
	var newest string
	var at uint64
	for _, n := range names {
		ts, ok := strings.CutPrefix(n, mergedPrefix)
		if !ok {
			continue
		}
		ts, ok = strings.CutSuffix(ts, retiredSuffix)
		if !ok {
			continue
		}
		u, err := strconv.ParseUint(ts, 10, 63)
		if err != nil || strconv.FormatUint(u, 10) != ts {
			continue
		}
		if newest == "" || u > at {
			newest, at = n, u
		}
	}
	if newest == "" {
		return retiredRecord{}, errNoRetiredRecord
	}
	named, err := l.root.Lstat(newest)
	if err != nil {
		return retiredRecord{}, err
	}
	if !named.Mode().IsRegular() {
		return retiredRecord{}, fmt.Errorf("%w: %s has mode %s", errFloorUntrusted, newest, named.Mode())
	}
	b, fi, err := readFile(l.root, newest, int64(floorSizeLimit))
	if errors.Is(err, errBadFile) {
		return retiredRecord{}, fmt.Errorf("%w: %s: %w", errFloorUntrusted, newest, err)
	}
	if err != nil {
		return retiredRecord{}, err
	}
	if err := s.floorOwned(fi); err != nil {
		return retiredRecord{}, fmt.Errorf("%w: %s: %w", errFloorUntrusted, newest, err)
	}
	return parseRetired(b)
}

// classifyUndo splits r's buried-live names, in the reverse merge of an
// undo, into those the restore's merge retired (rec), which --keep brings
// back, and those deleted since the restore, which stay deleted, and
// refuses a keep of one of the latter: kept names r would otherwise have
// buried live.
func classifyUndo(r *MergeReport, rec retiredRecord) error {
	for _, n := range r.BuriedLive {
		if slices.Contains(rec.Retired, n) {
			r.RetiredByRestore = append(r.RetiredByRestore, n)
		} else {
			r.DeletedSinceRestore = append(r.DeletedSinceRestore, n)
		}
	}
	var refused []string
	for _, n := range r.Kept {
		if !slices.Contains(r.Recorded, n) && !slices.Contains(rec.Retired, n) {
			refused = append(refused, n)
		}
	}
	if len(refused) > 0 {
		return fmt.Errorf("--keep names %s, deleted since the restore: the restore's merge did not retire it, so the undo keeps it deleted. Nothing is written; run the merge again without it", strings.Join(refused, ", "))
	}
	return nil
}
