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
	"maps"
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

// fresh reports whether uid has a figure taken beside the scope.key whose
// digest is key.
func (t *usageTable) fresh(uid uint32, key [sha256.Size]byte) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.byUID[uid]
	return f != nil && f.key == key
}

// get is a copy of uid's figure's entries, when it has one taken beside
// the scope.key whose digest is key; nil otherwise. A copy, so the caller
// reads it outside t.mu.
func (t *usageTable) get(uid uint32, key [sha256.Size]byte) map[string]int64 {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.byUID[uid]; f != nil && f.key == key {
		return maps.Clone(f.entries)
	}
	return nil
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

// forgetAll drops every uid's figure: a tree put in place under the store
// (a restore's merge) may hold any scope's entries under its same
// scope.key, so no figure taken before it is trusted.
func (t *usageTable) forgetAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	clear(t.byUID)
	t.mu.Unlock()
}

// usageOp is one put, rotate or rm's hold on its uid's figure across a
// write that can change the scope's usage. begin takes the figure out of
// the table before the first such write, so from then on the table holds
// none for the uid: an error path that skips the update, an outcome not
// known, or a panic anywhere up to confirm (the socket's listener
// recovers one and serves on) leaves the uid with no figure, and the next
// judgement walks. Only the op's own confirm puts it back, updated.
//
// The figure the op took is its token: confirm puts back that figure and
// never replaces one set since. Two ops of one uid never overlap here
// anyway, since each holds the uid's mutation lock from before begin to
// after confirm; the token keeps an op from writing over a figure it did
// not take should that change.
type usageOp struct {
	t   *usageTable
	uid uint32
	f   *scopeUsage
}

// begin takes uid's figure out of the table for an op about to write.
func (t *usageTable) begin(uid uint32) *usageOp {
	o := &usageOp{t: t, uid: uid}
	if t == nil {
		return o
	}
	t.mu.Lock()
	o.f = t.byUID[uid]
	delete(t.byUID, uid)
	t.mu.Unlock()
	return o
}

// confirm ends the op: its figure, changed by fn (nil leaves it as it
// was, for an op that wrote nothing after all), goes back into the table,
// unless another figure was set for the uid since. A second confirm does
// nothing; an op never confirmed leaves the uid with no figure.
func (o *usageOp) confirm(fn func(entries map[string]int64)) {
	if o == nil || o.t == nil || o.f == nil {
		return
	}
	f := o.f
	o.f = nil
	if fn != nil {
		fn(f.entries)
	}
	o.t.mu.Lock()
	if _, ok := o.t.byUID[o.uid]; !ok {
		o.t.byUID[o.uid] = f
	}
	o.t.mu.Unlock()
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
// lock, when it has none bound to the scope.key on disk: the caller holds
// the uid's mutation lock. A figure bound to another scope.key (an rm-scope
// and a new mint, a Rewrap's re-seal) is rebuilt here, outside the hold. It
// is best effort: a scope that cannot be walked now, or a ctx done during
// the walk, leaves no new figure, and the judgement under the lock walks
// then.
func (u *UserScope) prepareUsage(ctx context.Context) {
	if u.s.usage == nil || ctx.Err() != nil {
		return
	}
	root, err := u.s.openDir(u.s.dir, false)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }() // read-only
	if key, err := u.scopeKeyOf(root); err == nil && u.s.usage.fresh(u.uid, key) {
		return
	}
	if f, err := u.walkUsage(ctx, root, false); err == nil {
		u.s.usage.set(u.uid, f)
	}
}

// scopeKeyOf is the digest of the scope's scope.key under root, the zero
// digest when the scope has none.
func (u *UserScope) scopeKeyOf(root *os.Root) ([sha256.Size]byte, error) {
	dir, err := u.openScopeDir(root, false)
	if errors.Is(err, errNoScopeKey) {
		return [sha256.Size]byte{}, nil
	}
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer func() { _ = dir.Close() }() // read-only
	return scopeKeyDigest(dir)
}

// walkUsage walks the scope under root into a figure: underLock says
// whether the caller holds the store lock, for the walk's counting seam. A
// scope with no scope.key, or no entries/, is an empty figure. A ctx done
// stops the walk with its error, before each file.
func (u *UserScope) walkUsage(ctx context.Context, root *os.Root, underLock bool) (*scopeUsage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	hook := u.s.usageLstat
	lstat := func() error {
		if hook != nil {
			hook(underLock)
		}
		return ctx.Err()
	}
	if f.entries, err = walkScopeEntries(entries, lstat); err != nil {
		return nil, err
	}
	return f, nil
}

// usageUnderLock is the scope's figure for a quota judgement under the
// store lock, a copy the caller owns: the one this process keeps when it is
// bound to the scope.key on disk, else a walk now, which becomes the
// figure.
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
	if m := u.s.usage.get(u.uid, key); m != nil {
		return m, nil
	}
	f, err := u.walkUsage(context.Background(), root, true)
	if err != nil {
		return nil, err
	}
	u.s.usage.set(u.uid, f)
	return maps.Clone(f.entries), nil
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

// usageAfterPut ends op, the put's hold on the figure, with the entry it
// wrote: its few files. One that cannot be counted leaves no figure.
func (u *UserScope) usageAfterPut(op *usageOp, entries *os.Root, name string) {
	size, err := entryBytes(entries, name, nil)
	if err != nil {
		return
	}
	op.confirm(func(m map[string]int64) { m[name] = size })
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
