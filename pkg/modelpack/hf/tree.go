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

package hf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	artifactv1 "k3sm.io/apis/artifact/v1"
)

// Bounds on the tree listing, across all of its pages.
const (
	// MaxTreeBytes is the most listing bytes read.
	MaxTreeBytes = 16 << 20
	// MaxTreeEntries is the most entries, files and directories, accepted.
	MaxTreeEntries = 100_000
	// maxTreePages is the most pages followed.
	maxTreePages = 128
)

// Bounds on one file the listing names.
const (
	// MaxFileBytes is the largest LFS file accepted.
	MaxFileBytes = 256 << 30
	// MaxSmallFileBytes is the largest small (non-LFS) file accepted. The Hub
	// moves anything over 10 MB to LFS.
	MaxSmallFileBytes = 64 << 20
)

// The entry types the tree listing carries.
const (
	entryFile      = "file"
	entryDirectory = "directory"
)

// ErrBadListing is a tree listing that is not what the Hub sends: not one
// JSON array of entries, an entry of an unknown type, a hash in an unknown
// form, a size out of bounds, or more entries or bytes than the bounds allow.
var ErrBadListing = errors.New("unrecognised Hub tree listing")

// Entry is one entry of the tree listing at a commit.
type Entry struct {
	// Type is "file" or "directory".
	Type string `json:"type"`
	// OID is the git object id: for a small file, its blob id; for an LFS
	// file, the id of the pointer, which says nothing about the content.
	OID string `json:"oid"`
	// Size is the file's size in bytes (the content's, for an LFS file).
	Size int64 `json:"size"`
	// Path is the slash-separated path from the repository root.
	Path string `json:"path"`
	// LFS is set for a file stored in LFS.
	LFS *LFS `json:"lfs,omitempty"`
}

// LFS is the LFS record of a file: OID is the sha256 of its content.
type LFS struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// parseTree decodes one page of the tree listing: a JSON array of entries
// and nothing after it. It accepts at most limit entries, and checks each:
// a known type, a path the artifact/v1 rules accept, a 40-hex git id, and a
// size in bounds; an LFS file names a 64-hex sha256 and the same size, and a
// directory has no LFS record and size zero. Unknown object keys are
// ignored (the Hub adds fields); unknown values are refused.
func parseTree(data []byte, limit int) ([]Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadListing, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, fmt.Errorf("%w: not a JSON array", ErrBadListing)
	}
	var out []Entry
	for dec.More() {
		if len(out) >= limit {
			return nil, fmt.Errorf("%w: more than %d entries", ErrBadListing, MaxTreeEntries)
		}
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %v", ErrBadListing, len(out), err)
		}
		if err := checkEntry(e); err != nil {
			return nil, fmt.Errorf("%w: entry %d: %w", ErrBadListing, len(out), err)
		}
		out = append(out, e)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadListing, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: data after the array", ErrBadListing)
	}
	return out, nil
}

// checkEntry applies parseTree's rules to one entry.
func checkEntry(e Entry) error {
	if err := artifactv1.ValidatePath(e.Path); err != nil {
		return err
	}
	if !isLowerHex(e.OID, 40) {
		return fmt.Errorf("%q: git id %q is not 40 lowercase hex digits", e.Path, e.OID)
	}
	switch e.Type {
	case entryDirectory:
		if e.LFS != nil || e.Size != 0 {
			return fmt.Errorf("%q: a directory with a size or an LFS record", e.Path)
		}
		return nil
	case entryFile:
	default:
		return fmt.Errorf("%q: entry type %q", e.Path, e.Type)
	}
	if e.Size < 0 {
		return fmt.Errorf("%q: size %d", e.Path, e.Size)
	}
	if e.LFS == nil {
		if e.Size > MaxSmallFileBytes {
			return fmt.Errorf("%q: a small file of %d bytes, at most %d", e.Path, e.Size, MaxSmallFileBytes)
		}
		return nil
	}
	if e.Size > MaxFileBytes {
		return fmt.Errorf("%q: %d bytes, at most %d", e.Path, e.Size, int64(MaxFileBytes))
	}
	if !isLowerHex(e.LFS.OID, 64) {
		return fmt.Errorf("%q: LFS sha256 %q is not 64 lowercase hex digits", e.Path, e.LFS.OID)
	}
	if e.LFS.Size != e.Size {
		return fmt.Errorf("%q: LFS size %d, listed size %d", e.Path, e.LFS.Size, e.Size)
	}
	return nil
}

// nextLink returns the target of the rel="next" link in a Link header value,
// "" when there is none. A value it cannot parse is an error, never a
// silently shorter listing.
func nextLink(v string) (string, error) {
	for {
		v = strings.TrimLeft(v, " \t,")
		if v == "" {
			return "", nil
		}
		if v[0] != '<' {
			return "", fmt.Errorf("%w: Link header", ErrBadListing)
		}
		end := strings.IndexByte(v, '>')
		if end < 0 {
			return "", fmt.Errorf("%w: Link header", ErrBadListing)
		}
		target, params := v[1:end], v[end+1:]
		v = ""
		if i := strings.IndexByte(params, '<'); i >= 0 {
			params, v = params[:i], params[i:]
		}
		if linkRelNext(params) {
			return target, nil
		}
	}
}

// linkRelNext reports whether a link's parameters carry rel="next" (or
// rel=next).
func linkRelNext(params string) bool {
	for p := range strings.SplitSeq(params, ";") {
		k, val, ok := strings.Cut(strings.Trim(p, " \t,"), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "rel") {
			continue
		}
		for r := range strings.FieldsSeq(strings.Trim(strings.TrimSpace(val), `"`)) {
			if strings.EqualFold(r, "next") {
				return true
			}
		}
	}
	return false
}
