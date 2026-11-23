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
	"io/fs"
	"log/slog"
	"slices"
)

// The rm-dropped record: each burial a Delete run under a pending merge
// dropped from the floor, at the per-name cap or in the write's prune. rm
// is never refused while a merge is pending, and the floor it writes may
// then lack a burial the pending retired record's floors hold, which a
// rerun would otherwise take for a floor changed by something else and
// refuse forever (buriedSince, rmSince), leaving the guard set. The record
// is root-owned, written durably before the floor write that drops what it
// lists, and bound to the pending retired record by that record's input
// and base sha256: a record of another one is not of this merge and is
// ignored. renameMerged and finishRenamed remove it with the guard.
//
// rm is never refused for it either: when the record would list more than
// maxRmDropped burials, does not read, or cannot be written, the Delete
// replaces it with a mark (Unusable), root-owned and bound to the pending
// record, and buries regardless. A rerun that finds the mark cannot tell
// the floor rm left from one changed by anything else, so it accepts no
// drops and stops, committed, for the operator to inspect. Fail-closed
// even when the mark cannot be written: the floor then lacks a burial the
// record does not list, or the record does not read, and the rerun refuses
// either.

const (
	// rmDroppedName is the record's name in the data root.
	rmDroppedName = floorPreRestoreName + ".rm-dropped"
	// maxRmDropped bounds how many burials the record lists. A Delete
	// that would list more marks the record unusable and buries
	// regardless (markRmDropped).
	maxRmDropped = 4096
)

// rmDroppedSizeLimit bounds the record's encoding: maxRmDropped burials,
// each its name, its generation and the punctuation, plus the two sums.
func rmDroppedSizeLimit() int { return 256 + maxRmDropped*(maxNameLen+2*generationSize+48) }

// rmDropRecord is the rm-dropped record's content: the pending retired
// record's Input and Base, and each burial dropped, in the order dropped,
// without repeats. Unusable is the mark: the burials an rm under this
// record dropped are not all listed, and Dropped is empty.
type rmDropRecord struct {
	Input    string   `json:"input"`
	Base     string   `json:"base"`
	Unusable bool     `json:"unusable,omitempty"`
	Dropped  []rmDrop `json:"dropped"`
}

// rmDrop is one burial an rm under the guard dropped.
type rmDrop struct {
	Name       string `json:"name"`
	Generation string `json:"generation"`
}

// marshalRmDropped is the record's one encoding, a trailing newline
// included.
func marshalRmDropped(rec rmDropRecord) ([]byte, error) {
	if rec.Dropped == nil {
		rec.Dropped = []rmDrop{}
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// parseRmDropped decodes an rm-dropped record, refusing anything rm would
// not have written: an unknown field, a sum that is not a lowercase hex
// sha256, a burial whose name or generation is not valid, a repeat, more
// than maxRmDropped burials, a mark that lists any, or any encoding but
// marshalRmDropped's.
func parseRmDropped(b []byte) (rmDropRecord, error) {
	var rec rmDropRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&rec); err != nil {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record does not parse: %w", ErrCorrupt, err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record holds more than one value", ErrCorrupt)
	}
	if !isSHA256Hex(rec.Input) || !isSHA256Hex(rec.Base) {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record's input and base are not lowercase hex sha256 digests", ErrCorrupt)
	}
	if len(rec.Dropped) > maxRmDropped {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record lists more than %d burials", ErrCorrupt, maxRmDropped)
	}
	if rec.Unusable && len(rec.Dropped) > 0 {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record is marked unusable and lists burials", ErrCorrupt)
	}
	seen := map[floorBurial]bool{}
	for _, x := range rec.Dropped {
		if !floorGeneration(x.Name, x.Generation) {
			return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record lists a burial whose name or generation is not valid", ErrCorrupt)
		}
		k := floorBurial{x.Name, x.Generation}
		if seen[k] {
			return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record lists a burial twice", ErrCorrupt)
		}
		seen[k] = true
	}
	if again, err := marshalRmDropped(rec); err != nil || !bytes.Equal(again, b) {
		return rmDropRecord{}, fmt.Errorf("%w: the rm-dropped record is not in its one encoding", ErrCorrupt)
	}
	return rec, nil
}

// readRmDroppedFile reads the rm-dropped record through l.root, judged as
// the floor is: a regular file, never followed, owned by root (floorUID),
// not group- or other-writable, at most rmDroppedSizeLimit, and in its one
// encoding. An absent record is (nil, nil).
func (s *FileStore) readRmDroppedFile(l *floorLock) (*rmDropRecord, error) {
	named, err := l.root.Lstat(rmDroppedName)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s has mode %s", errFloorUntrusted, rmDroppedName, named.Mode())
	}
	b, fi, err := readFile(l.root, rmDroppedName, int64(rmDroppedSizeLimit()))
	if errors.Is(err, errBadFile) {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, rmDroppedName, err)
	}
	if err != nil {
		return nil, err
	}
	if err := s.floorOwned(fi); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errFloorUntrusted, rmDroppedName, err)
	}
	rec, err := parseRmDropped(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rmDroppedName, err)
	}
	return &rec, nil
}

// rmDroppedOf is the set of burials the rm-dropped record lists for the
// pending retired record rec: empty when there is no record, or when the
// record is of another input or base (another merge, or a first run that
// planned again from the floor rm left, which already lacks them). A record
// that is not trusted or does not parse refuses, and one of rec marked
// unusable (markRmDropped) refuses committed: the merge cannot tell what
// rm dropped, and never accepts a drop it cannot account for.
func (s *FileStore) rmDroppedOf(l *floorLock, rec retiredRecord) (map[floorBurial]bool, error) {
	got, err := s.readRmDroppedFile(l)
	if err != nil {
		return nil, err
	}
	out := map[floorBurial]bool{}
	if got == nil || got.Input != rec.Input || got.Base != rec.Base {
		return out, nil
	}
	if got.Unusable {
		return nil, fmt.Errorf("%w: %s is marked unusable: an rm under this merge dropped burials it could not list (it would have listed more than %d, or it did not read or could not be written then), so the merge cannot tell the floor rm left from one changed by anything else, and it accepts no drops. Nothing more is done; inspect keystore-floor.json against %s", errCommitted, rmDroppedName, maxRmDropped, retiredPendingName)
	}
	for _, x := range got.Dropped {
		out[floorBurial{x.Name, x.Generation}] = true
	}
	return out, nil
}

// recordRmDropped appends each burial in dropped to the rm-dropped record
// of the pending retired record rec, writing it durably, root-owned at the
// floor's mode, before the floor write that drops them. A record of another
// input or base is replaced by one of rec's. It never refuses the write: a
// record that is not trusted or does not parse, one that would list more
// than maxRmDropped burials, and a write that fails are each replaced by
// the mark (markRmDropped), and a record of rec already marked stays so.
func (s *FileStore) recordRmDropped(l *floorLock, rec retiredRecord, dropped []pruned) {
	if len(dropped) == 0 {
		return
	}
	got, err := s.readRmDroppedFile(l)
	if err != nil {
		s.markRmDropped(l, rec, fmt.Sprintf("it does not read: %v", err))
		return
	}
	out := rmDropRecord{Input: rec.Input, Base: rec.Base}
	if got != nil && got.Input == rec.Input && got.Base == rec.Base {
		if got.Unusable {
			// Already marked: the rerun refuses whatever rm drops now.
			return
		}
		out.Dropped = slices.Clone(got.Dropped)
	}
	for _, p := range dropped {
		x := rmDrop{Name: p.name, Generation: p.generation}
		if !slices.Contains(out.Dropped, x) {
			out.Dropped = append(out.Dropped, x)
		}
	}
	if len(out.Dropped) > maxRmDropped {
		s.markRmDropped(l, rec, fmt.Sprintf("it would list more than %d burials, the most it holds", maxRmDropped))
		return
	}
	b, err := marshalRmDropped(out)
	if err == nil {
		err = s.writeFileAs(l.root, rmDroppedName, b, uint32(s.floorUID), uint32(s.floorGID), floorFileMode)
	}
	if err != nil {
		s.markRmDropped(l, rec, fmt.Sprintf("it could not be written: %v", err))
	}
}

// markRmDropped replaces the rm-dropped record with the mark of rec, why
// being the reason the burials could not be listed, root-owned at the
// floor's mode, and logs it. A mark that cannot be written is logged too:
// the burial lands regardless, and the rerun still refuses, since the
// floor then lacks a burial the record does not list, or the record does
// not read.
func (s *FileStore) markRmDropped(l *floorLock, rec retiredRecord, why string) {
	b, err := marshalRmDropped(rmDropRecord{Input: rec.Input, Base: rec.Base, Unusable: true})
	if err == nil {
		err = s.writeFileAs(l.root, rmDroppedName, b, uint32(s.floorUID), uint32(s.floorGID), floorFileMode)
	}
	if err != nil {
		slog.Warn("keystore: the burials this delete drops while a merge is pending cannot be recorded, and "+rmDroppedName+" cannot be marked unusable either; the delete goes on, and the merge's rerun refuses, since the floor lacks a burial the record does not list", "why", why, "err", err)
		return
	}
	slog.Warn("keystore: the burials this delete drops while a merge is pending cannot be recorded, so "+rmDroppedName+" is marked unusable; the delete goes on, and the merge's rerun stops, committed, until the operator inspects the floor", "why", why)
}
