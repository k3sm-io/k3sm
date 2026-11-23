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
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// retiredRecord is the retired record's content, the merge's commit
// marker: the sha256 of the merge input (the guard file's bytes), of the
// live floor's bytes the merge read (Base), and of the floor bytes it writes
// (Floor, Base again when it changes nothing), and what it committed. Each set is
// sorted, without repeats (Dropped, one name per burial dropped, may
// repeat), every name a valid entry name.
type retiredRecord struct {
	Input      string   `json:"input"`
	Base       string   `json:"base"`
	Floor      string   `json:"floor"`
	Retired    []string `json:"retired"`
	BuriedLive []string `json:"buriedLive"`
	Kept       []string `json:"kept"`
	Recorded   []string `json:"recorded"`
	Dropped    []string `json:"dropped"`
}

// sha256Hex is the lowercase hex sha256 of b.
func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// isSHA256Hex reports whether s is a lowercase hex sha256.
func isSHA256Hex(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// unionRecord is rec with add's sets unioned in: the record a rerun writes
// when it has to write one, so it never loses what the first run recorded.
// Input and Floor stay rec's.
func unionRecord(rec, add retiredRecord) retiredRecord {
	out := rec
	out.Retired = unionNames(rec.Retired, add.Retired)
	out.BuriedLive = unionNames(rec.BuriedLive, add.BuriedLive)
	out.Kept = unionNames(rec.Kept, add.Kept)
	out.Recorded = unionNames(rec.Recorded, add.Recorded)
	// Dropped repeats a name once per burial: the union keeps each name's
	// larger count.
	count := map[string]int{}
	for _, n := range rec.Dropped {
		count[n]++
	}
	more := map[string]int{}
	for _, n := range add.Dropped {
		more[n]++
	}
	for n, c := range more {
		count[n] = max(count[n], c)
	}
	out.Dropped = nil
	for n, c := range count {
		for range c {
			out.Dropped = append(out.Dropped, n)
		}
	}
	slices.Sort(out.Dropped)
	return out
}

// marshalRetired is the record's one encoding, a trailing newline included.
func marshalRetired(rec retiredRecord) ([]byte, error) {
	if rec.Retired == nil {
		rec.Retired = []string{}
	}
	if rec.BuriedLive == nil {
		rec.BuriedLive = []string{}
	}
	if rec.Kept == nil {
		rec.Kept = []string{}
	}
	if rec.Recorded == nil {
		rec.Recorded = []string{}
	}
	if rec.Dropped == nil {
		rec.Dropped = []string{}
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
	if !isSHA256Hex(rec.Input) || !isSHA256Hex(rec.Base) || !isSHA256Hex(rec.Floor) {
		return retiredRecord{}, fmt.Errorf("%w: the retired record's input, base and floor are not lowercase hex sha256 digests", ErrCorrupt)
	}
	for k, set := range [][]string{rec.Retired, rec.BuriedLive, rec.Kept, rec.Recorded, rec.Dropped} {
		repeats := k == 4
		for i, n := range set {
			if err := checkName(n); err != nil {
				return retiredRecord{}, fmt.Errorf("%w: the retired record: %w", ErrCorrupt, err)
			}
			if i > 0 && (set[i-1] > n || !repeats && set[i-1] == n) {
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
func (s *FileStore) writeRetiredPending(l *floorLock, rec retiredRecord) error {
	b, err := marshalRetired(rec)
	if err != nil {
		return err
	}
	return s.writeFileAs(l.root, retiredPendingName, b, uint32(s.floorUID), uint32(s.floorGID), floorFileMode)
}

// readRetiredFile reads the retired record name through l.root, judged as
// the floor is: a regular file, never followed, owned by root (floorUID),
// not group- or other-writable, at most floorSizeLimit, and in its one
// encoding.
func (s *FileStore) readRetiredFile(l *floorLock, name string) (retiredRecord, error) {
	named, err := l.root.Lstat(name)
	if err != nil {
		return retiredRecord{}, err
	}
	if !named.Mode().IsRegular() {
		return retiredRecord{}, fmt.Errorf("%w: %s has mode %s", errFloorUntrusted, name, named.Mode())
	}
	b, fi, err := readFile(l.root, name, int64(floorSizeLimit))
	if errors.Is(err, errBadFile) {
		return retiredRecord{}, fmt.Errorf("%w: %s: %w", errFloorUntrusted, name, err)
	}
	if err != nil {
		return retiredRecord{}, err
	}
	if err := s.floorOwned(fi); err != nil {
		return retiredRecord{}, fmt.Errorf("%w: %s: %w", errFloorUntrusted, name, err)
	}
	rec, err := parseRetired(b)
	if err != nil {
		return retiredRecord{}, fmt.Errorf("%s: %w", name, err)
	}
	return rec, nil
}

// readPendingRetired reads the pending retired record, the commit marker a
// first run writes before the floor: nil when there is none.
func (s *FileStore) readPendingRetired(l *floorLock) (*retiredRecord, error) {
	rec, err := s.readRetiredFile(l, retiredPendingName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// errNoRetiredRecord refuses an undo with no retired record in the data
// root.
var errNoRetiredRecord = errors.New("--undo reads what the restore's merge retired from the record it left in the data root, keystore-floor.json.merged-<unix>.retired, and there is none: a merge from before that record cannot be undone by --undo. Nothing is written")

// errNoMatchingRetired refuses an undo whose live floor is no retired
// record's input.
func errNoMatchingRetired(n int) error {
	return fmt.Errorf("--undo uses only the retired record of the merge it undoes, the one whose input is the live floor (an undo puts the first merge's input, keystore-floor.json.merged-<unix>, back as keystore-floor.json), and none of the %d keystore-floor.json.merged-<unix>.retired records in the data root has that input: each is from another merge. Nothing is written. Put back as keystore-floor.json the keystore-floor.json.merged-<unix> of the merge to undo, as docs/user/keys.md describes, and run the undo again", n)
}

// readRetired reads the retired record of the merge an undo reverses: of
// the data root's keystore-floor.json.merged-<unix>.retired records, each
// judged as the floor is (readRetiredFile), the one whose input sha256 is
// liveSum, the sha256 of the live floor's bytes, which an undo makes the
// first merge's input. The <unix> in a name never chooses a record, so a
// clock stepped back between merges cannot pick another merge's; of two
// with the same input, the higher <unix> is read. It refuses when there is
// no record (errNoRetiredRecord) or none matches (errNoMatchingRetired).
func (s *FileStore) readRetired(l *floorLock, liveSum string) (retiredRecord, error) {
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
	type cand struct {
		name string
		at   uint64
	}
	var cands []cand
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
		cands = append(cands, cand{n, u})
	}
	if len(cands) == 0 {
		return retiredRecord{}, errNoRetiredRecord
	}
	slices.SortFunc(cands, func(a, b cand) int { return cmp.Compare(b.at, a.at) })
	for _, c := range cands {
		rec, err := s.readRetiredFile(l, c.name)
		if err != nil {
			return retiredRecord{}, err
		}
		if rec.Input == liveSum {
			return rec, nil
		}
	}
	return retiredRecord{}, errNoMatchingRetired(len(cands))
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
