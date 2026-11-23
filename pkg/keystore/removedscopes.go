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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// The removed-scopes record (docs/design/keystore.md § "A removed scope
// stays removed"): rm-scope lists, per uid, the identity of each scope key
// it removed and the floor's byte size at the removal, in
// keystore-removed-scopes.json in the data root, so a scope directory
// copied back after rm-scope, whose scope.key still opens under the
// unchanged master, is refused at every open, and floor --rebuild drops the
// uid's floor lines written before the removal, and only those.

const (
	// removedScopesName is the record, in the data root.
	removedScopesName = "keystore-removed-scopes.json"
	// removedScopesTemp is the name it is written at before its rename.
	removedScopesTemp = removedScopesName + ".new"
	// removedScopesMode is its mode: root's, readable by the service user,
	// whose opens check it.
	removedScopesMode = 0o644
	// maxRemovedScopeKeys bounds the scope keys the record lists, across
	// every uid; a full record keeps rm-scope working (RemoveScope).
	maxRemovedScopeKeys = 1024
	// maxRemovedScopesSize bounds the file: the most keys at the longest
	// uid, each record about 100 bytes, is about 100 KiB.
	maxRemovedScopesSize = 256 << 10
	// removedScopesVersion is the file's format version.
	removedScopesVersion = 1
	// scopeKeyIDLabel separates the scope-key identity from any other
	// digest of K_u.
	scopeKeyIDLabel = "k3sm removed-scope key id v1\x00"
)

// errScopeRemoved refuses a scope whose scope.key root removed with
// rm-scope: the directory was copied back, or restored, after the removal.
var errScopeRemoved = fmt.Errorf("%w: this user scope was removed by root (sudo k3sm keys rm-scope), and its scope.key is the removed one: root must delete the scope directory keystore/%s/<uid>/, after which the user's next put mints a fresh scope", ErrCorrupt, userScopesName)

// errRemovedScopesBad is a removed-scopes record that does not judge or
// parse: every open of a user scope, rm-scope and floor --rebuild refuse
// while it stands (fail closed).
var errRemovedScopesBad = errors.New("the removed-scopes record " + removedScopesName + " in the data root is damaged or untrusted, so no user scope opens: restore it from a backup, or, as root, fix it")

// scopeKeyID is the stable identity of a scope key: a labelled SHA-256 of
// the scope and K_u, which Rewrap leaves as it is (it re-seals the same
// K_u) and a re-minted scope never shares (it gets a fresh K_u).
func scopeKeyID(scope string, ku []byte) string {
	h := sha256.New()
	h.Write([]byte(scopeKeyIDLabel))
	h.Write([]byte(scope))
	h.Write([]byte{0})
	h.Write(ku)
	return hex.EncodeToString(h.Sum(nil))
}

// removedScopes is the parsed record: per uid, the identities of its
// removed scope keys and the floor offset its lines are dropped before.
type removedScopes struct {
	Version int            `json:"version"`
	Scopes  []removedScope `json:"scopes"`
}

// removedScope is one uid's removed scope keys. FloorSize is the user-scope
// floor's byte size when rm-scope last listed a key of the uid: floor
// --rebuild drops the uid's floor lines that start before it, every one
// written while a removed scope stood, and keeps those at or after it, a
// re-minted scope's. A rebuild sets it to 0 before its swap commits, since
// the offset names a position in the floor the swap retires; 0 drops
// nothing.
type removedScope struct {
	UID       uint32   `json:"uid"`
	Keys      []string `json:"keys"`
	FloorSize int64    `json:"floor_size"`
}

// has reports whether uid's scope key id is listed.
func (r *removedScopes) has(uid uint32, id string) bool {
	for _, sc := range r.Scopes {
		if sc.UID == uid {
			return slices.Contains(sc.Keys, id)
		}
	}
	return false
}

// listed reports whether any scope key of uid is listed.
func (r *removedScopes) listed(uid uint32) bool {
	return slices.ContainsFunc(r.Scopes, func(sc removedScope) bool { return sc.UID == uid })
}

// dropBefore maps each user scope with a nonzero floor offset to it: the
// rebuild drops that scope's floor lines starting before the offset.
func (r *removedScopes) dropBefore() map[string]int64 {
	out := map[string]int64{}
	for _, sc := range r.Scopes {
		if sc.FloorSize > 0 {
			out[userScopeOf(sc.UID)] = sc.FloorSize
		}
	}
	return out
}

// clearFloorSizes sets every nonzero floor offset to 0, and reports
// whether any was set.
func (r *removedScopes) clearFloorSizes() bool {
	changed := false
	for i := range r.Scopes {
		if r.Scopes[i].FloorSize != 0 {
			r.Scopes[i].FloorSize = 0
			changed = true
		}
	}
	return changed
}

// keys is the count of scope keys listed.
func (r *removedScopes) keys() int {
	n := 0
	for _, sc := range r.Scopes {
		n += len(sc.Keys)
	}
	return n
}

// add lists uid's scope key id with the floor's byte size floorSize at the
// removal, and reports false, changing nothing, when the record is full.
func (r *removedScopes) add(uid uint32, id string, floorSize int64) bool {
	if r.keys() >= maxRemovedScopeKeys {
		return false
	}
	for i := range r.Scopes {
		if r.Scopes[i].UID == uid {
			r.Scopes[i].Keys = append(r.Scopes[i].Keys, id)
			r.Scopes[i].FloorSize = floorSize
			return true
		}
	}
	r.Scopes = append(r.Scopes, removedScope{UID: uid, Keys: []string{id}, FloorSize: floorSize})
	return true
}

// parseRemovedScopes parses the record strictly: one JSON object of the
// version, with no unknown field and no trailing data; each uid nonzero and
// listed once, each key 64 lowercase hex digits and listed once, at most
// maxRemovedScopeKeys keys in all, each floor offset not negative (a
// record without one has offset 0, which drops nothing).
func parseRemovedScopes(b []byte) (*removedScopes, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r removedScopes
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data")
	}
	if r.Version != removedScopesVersion {
		return nil, fmt.Errorf("version %d, want %d", r.Version, removedScopesVersion)
	}
	uids := map[uint32]bool{}
	ids := map[string]bool{}
	for _, sc := range r.Scopes {
		if sc.UID == 0 || uids[sc.UID] || len(sc.Keys) == 0 {
			return nil, fmt.Errorf("uid %d is zero, listed twice or lists no key", sc.UID)
		}
		if sc.FloorSize < 0 {
			return nil, fmt.Errorf("uid %d has a negative floor offset", sc.UID)
		}
		uids[sc.UID] = true
		for _, k := range sc.Keys {
			if len(k) != 2*sha256.Size || ids[k] || !isLowerHex(k) {
				return nil, fmt.Errorf("uid %d lists a key that is not 64 lowercase hex digits, or lists it twice", sc.UID)
			}
			ids[k] = true
		}
	}
	if len(ids) > maxRemovedScopeKeys {
		return nil, fmt.Errorf("it lists %d keys, past %d", len(ids), maxRemovedScopeKeys)
	}
	return &r, nil
}

// isLowerHex reports whether s is lowercase hex digits only.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// readRemovedScopes reads the record through the judged data root dfd
// with O_NOFOLLOW and judges it on its descriptor: a regular file with one
// link, the data root's owner's (root), neither group- nor other-writable,
// within maxRemovedScopesSize, then parses it strictly. A missing record
// lists nothing. Anything else is errRemovedScopesBad.
func (s *FileStore) readRemovedScopes(dfd int) (*removedScopes, error) {
	fd, err := unix.Openat(dfd, removedScopesName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return &removedScopes{Version: removedScopesVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open: %w", errRemovedScopesBad, err)
	}
	f := os.NewFile(uintptr(fd), removedScopesName)
	defer func() { _ = f.Close() }() // read-only
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: stat: %w", errRemovedScopesBad, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int64(st.Uid) != int64(s.floorUID) || st.Mode&0o022 != 0 || st.Size > maxRemovedScopesSize {
		return nil, fmt.Errorf("%w: it is not a regular file with one link, of the data root's owner, closed to group and other writes, within %d bytes", errRemovedScopesBad, maxRemovedScopesSize)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRemovedScopesSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read: %w", errRemovedScopesBad, err)
	}
	if len(b) > maxRemovedScopesSize {
		return nil, fmt.Errorf("%w: past %d bytes", errRemovedScopesBad, maxRemovedScopesSize)
	}
	r, err := parseRemovedScopes(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errRemovedScopesBad, err)
	}
	return r, nil
}

// writeRemovedScopes writes r through the data root dfd: a temporary file,
// created O_EXCL|O_NOFOLLOW after any leftover is unlinked, set to
// removedScopesMode, written, fsynced, renamed over the record, and the
// data root fsynced. Root runs it, so the file is root's.
func writeRemovedScopes(dfd int, r *removedScopes) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := unix.Unlinkat(dfd, removedScopesTemp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("remove a leftover %s: %w", removedScopesTemp, err)
	}
	fd, err := unix.Openat(dfd, removedScopesTemp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, removedScopesMode)
	if err != nil {
		return fmt.Errorf("create %s: %w", removedScopesTemp, err)
	}
	f := os.NewFile(uintptr(fd), removedScopesTemp)
	err = unix.Fchmod(fd, removedScopesMode)
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, removedScopesTemp, 0) // a partial temporary file is never read
		return fmt.Errorf("write %s: %w", removedScopesTemp, err)
	}
	if err := unix.Renameat(dfd, removedScopesTemp, dfd, removedScopesName); err != nil {
		return fmt.Errorf("rename %s: %w", removedScopesTemp, err)
	}
	return unix.Fsync(dfd)
}

// checkScopeNotRemoved refuses a scope key root removed: it reads the
// record through the judged data root and refuses when uid's id is listed
// (errScopeRemoved), and when the record does not read (fail closed). A
// store with no data root has no record.
func (s *FileStore) checkScopeNotRemoved(uid uint32, id string) error {
	if s.dataRoot == "" {
		return nil
	}
	dfd, err := s.openLogDataRoot()
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(dfd) }() // read-only directory descriptor
	r, err := s.readRemovedScopes(dfd)
	if err != nil {
		return err
	}
	if r.has(uid, id) {
		return errScopeRemoved
	}
	return nil
}
