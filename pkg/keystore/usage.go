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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// This file is the user scope's usage figure: docs/design/keystore.md §
// "Quotas" and "Lock modes and fairness". A put or rotate judges the scope's
// quota (quota.go, judgeScopeQuota) against a figure this process keeps per scope, the bytes
// of every entry by name, so the judgement costs no walk of the scope under
// the store lock. The figure lives in memory only, and its crash model is
// the process's:
//
//   - It is built by a walk of the scope taken before the store lock, under
//     the uid's mutation lock, which every put, rotate and rm of the uid
//     holds, so no write of this process lands in the scope while it walks.
//   - Under the store lock it is trusted only when the scope.key it was built
//     beside is still the one on disk (the same bytes): a scope root removed
//     and minted again (rm-scope), or a Rewrap that re-sealed scope.key, makes
//     it stale, and the quota is judged by a walk under the lock instead,
//     which then becomes the figure.
//   - Every committed put, rotate and rm of this process changes it in the
//     same hold, by the bytes it wrote or removed; any of them that fails
//     after it may have written, or whose outcome is not known, drops it, and
//     the next put or rotate walks again.
//   - A restart, a crash included, starts with no figure: the first put or
//     rotate of each scope walks it, before the lock.
//
// So a figure that is lost, or that may be stale, is recomputed from the
// files, never trusted. No other process writes a user scope's entries but
// root's rm-scope, which removes the scope with its scope.key.

// scopeUsage is one scope's figure: every entry name in entries/ with its
// sealed bytes, as walkScopeEntries counts them, beside the digest of
// the scope.key it was taken under (zero: no scope.key).
type scopeUsage struct {
	key     [sha256.Size]byte
	entries map[string]int64
}

// usageTable is the store's figures and the uids' mutation locks.
type usageTable struct {
	mu    sync.Mutex
	byUID map[uint32]*scopeUsage
	locks map[uint32]chan struct{}
}

func newUsageTable() *usageTable {
	return &usageTable{byUID: map[uint32]*scopeUsage{}, locks: map[uint32]chan struct{}{}}
}

// lockUID takes uid's mutation lock, which serialises the uid's own put,
// rotate and rm in this process, before the store lock (storelock.go has
// the order), waiting at most wait, or until ctx is done. Only the uid's
// own operations wait on it. The returned function releases it. A nil t
// (a store a test built without New) holds nothing.
func (t *usageTable) lockUID(ctx context.Context, uid uint32, wait time.Duration) (func(), error) {
	if t == nil {
		return func() {}, nil
	}
	t.mu.Lock()
	ch, ok := t.locks[uid]
	if !ok {
		ch = make(chan struct{}, 1)
		t.locks[uid] = ch
	}
	t.mu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errLockTimeout
	}
}

// get is uid's figure, when it has one and it was taken beside the
// scope.key whose digest is key; nil otherwise.
func (t *usageTable) get(uid uint32, key [sha256.Size]byte) *scopeUsage {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.byUID[uid]; f != nil && f.key == key {
		return f
	}
	return nil
}

// has reports whether uid has a figure, whatever scope.key it was taken
// beside.
func (t *usageTable) has(uid uint32) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byUID[uid] != nil
}

func (t *usageTable) set(uid uint32, f *scopeUsage) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.byUID[uid] = f
	t.mu.Unlock()
}

// forget drops uid's figure: the next put or rotate walks the scope.
func (t *usageTable) forget(uid uint32) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.byUID, uid)
	t.mu.Unlock()
}

// update changes uid's figure for name with fn, when it has one.
func (t *usageTable) update(uid uint32, fn func(entries map[string]int64)) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if f := t.byUID[uid]; f != nil {
		fn(f.entries)
	}
	t.mu.Unlock()
}

// scopeKeyDigest is the digest of dir's scope.key bytes, the zero digest
// when it has none: what a figure is bound to.
func scopeKeyDigest(dir *os.Root) ([sha256.Size]byte, error) {
	b, _, err := readFile(dir, scopeKeyName, int64(maxScopeKeyRecordSize))
	if errors.Is(err, fs.ErrNotExist) {
		return [sha256.Size]byte{}, nil
	}
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// prepareUsage builds uid's figure by walking the scope before the store
// lock, when it has none: the caller holds the uid's mutation lock. It is
// best effort: a scope that cannot be walked now leaves no figure, and the
// judgement under the lock walks then.
func (u *UserScope) prepareUsage() {
	if u.s.usage == nil || u.s.usage.has(u.uid) {
		return
	}
	root, err := u.s.openDir(u.s.dir, false)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }() // read-only
	if f, err := u.walkUsage(root, false); err == nil {
		u.s.usage.set(u.uid, f)
	}
}

// walkUsage walks the scope under root into a figure: underLock says
// whether the caller holds the store lock, for the walk's counting seam. A
// scope with no scope.key, or no entries/, is an empty figure.
func (u *UserScope) walkUsage(root *os.Root, underLock bool) (*scopeUsage, error) {
	f := &scopeUsage{entries: map[string]int64{}}
	dir, err := u.openScopeDir(root, false)
	if errors.Is(err, errNoScopeKey) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }() // read-only
	if f.key, err = scopeKeyDigest(dir); err != nil {
		return nil, err
	}
	entries, err := u.s.openSubdir(dir, scopeEntriesName, false)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = entries.Close() }() // read-only
	var lstat func()
	if hook := u.s.usageLstat; hook != nil {
		lstat = func() { hook(underLock) }
	}
	if f.entries, err = walkScopeEntries(entries, lstat); err != nil {
		return nil, err
	}
	return f, nil
}

// usageUnderLock is the scope's figure for a quota judgement under the
// store lock: the one this process keeps when it is bound to the scope.key
// on disk, else a walk now, which becomes the figure.
func (u *UserScope) usageUnderLock(root *os.Root) (map[string]int64, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, err
	}
	key, err := scopeKeyDigest(dir)
	_ = dir.Close() // read-only
	if err != nil {
		return nil, err
	}
	if f := u.s.usage.get(u.uid, key); f != nil {
		return f.entries, nil
	}
	f, err := u.walkUsage(root, true)
	if err != nil {
		return nil, err
	}
	u.s.usage.set(u.uid, f)
	return f.entries, nil
}

// checkUsageQuota is judgeScopeQuota on the scope's figure and its
// deliveries record's size.
func (u *UserScope) checkUsageQuota(root *os.Root, name string, value []byte) error {
	base, err := u.deliveriesBytes(root)
	if err != nil {
		return err
	}
	used, err := u.usageUnderLock(root)
	if err != nil {
		return err
	}
	return judgeScopeQuota(used, name, value, base)
}

// usageAfterPut records the entry a committed put wrote: its few files.
func (u *UserScope) usageAfterPut(entries *os.Root, name string) {
	size, err := entryBytes(entries, name, nil)
	if err != nil {
		u.s.usage.forget(u.uid)
		return
	}
	u.s.usage.update(u.uid, func(m map[string]int64) { m[name] = size })
}

// lstatSize is the size of dir's file name, without following a symlink.
func lstatSize(dir *os.Root, name string) (int64, error) {
	fi, err := dir.Lstat(name)
	if err != nil {
		return 0, err
	}
	if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", name)
	}
	return fi.Size(), nil
}
