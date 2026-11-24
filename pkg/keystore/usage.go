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
	"syscall"
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
//   - Under the store lock it is trusted only when the scope it was built
//     in is still the one on disk (scopeBinding): the same scope.key bytes,
//     and the same entries/ directory, by device and inode. A scope root
//     removed and minted again (rm-scope), or a Rewrap that re-sealed
//     scope.key, changes the first; a scope tree renamed into place under
//     the same scope.key bytes (a copy put back while the server was
//     stopped, say) changes the second. Either makes the figure stale, and
//     the quota is judged by a walk under the lock instead, which then
//     becomes the figure.
//   - Every committed put, rotate and rm of this process changes it in the
//     same hold, by the bytes it wrote or removed; any of them that fails
//     after it may have written, or whose outcome is not known, drops it, and
//     the next put or rotate walks again.
//   - A restart, a crash included, starts with no figure: the first put or
//     rotate of each scope walks it, before the lock. So does a listener
//     start (FileStore.StartUserScopes, which the socket's supervisor runs
//     on every start pass) and a restore's merge, which drop every figure
//     (forgetAll); a figure taken before either is never put back.
//
// So a figure that is lost, or that may be stale, is recomputed from the
// files, never trusted. No other process writes a user scope's entries but
// root's rm-scope, which removes the scope with its scope.key.

// scopeUsage is one scope's figure: every entry name in entries/ with its
// sealed bytes, as walkScopeEntries counts them, beside the binding of the
// scope it was taken in.
type scopeUsage struct {
	bind    scopeBinding
	entries map[string]int64
}

// scopeBinding is what a figure is bound to: the digest of the scope's
// scope.key bytes (zero: no scope.key), and the device and inode of its
// entries/ directory (zero: no entries/). The directory bound is entries/,
// not .user/<uid>, because entries/ is the tree the figure counts: a scope
// directory renamed into place brings its own entries/, so the binding
// sees that, and it sees an entries/ replaced inside a scope directory
// that stayed, which the scope directory's identity would not. A user
// operation never creates or replaces entries/ (a mint creates it with
// scope.key, which changes the digest in the same hold), so the binding
// changes only when the tree under the figure did.
type scopeBinding struct {
	key      [sha256.Size]byte
	dev, ino uint64
}

// usageTable is the store's figures and the uids' mutation locks.
type usageTable struct {
	mu    sync.Mutex
	byUID map[uint32]*scopeUsage
	locks map[uint32]chan struct{}
	// gen counts forgetAll calls: a figure taken, or a walk begun, before
	// one is never put back after it (setAt, confirm).
	gen uint64
}

func newUsageTable() *usageTable {
	return &usageTable{byUID: map[uint32]*scopeUsage{}, locks: map[uint32]chan struct{}{}}
}

// lockUID takes uid's mutation lock, which serialises the uid's own put,
// rotate and rm in this process, before the store lock (storelock.go has
// the order), waiting at most wait, or until ctx is done. Only the uid's
// own operations wait on it. The returned function releases it, once
// however often it is called. A nil t
// (a store a test built without New) holds nothing. A ctx already done
// takes nothing and returns its error, as prefLock.acquire does: a select
// with the lock free would otherwise pick at random between the two.
func (t *usageTable) lockUID(ctx context.Context, uid uint32, wait time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
		var once sync.Once
		return func() { once.Do(func() { <-ch }) }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, errLockTimeout
	}
}

// fresh reports whether uid has a figure bound to b.
func (t *usageTable) fresh(uid uint32, b scopeBinding) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.byUID[uid]
	return f != nil && f.bind == b
}

// get is a copy of uid's figure's entries, when it has one bound to b; nil
// otherwise. A copy, so the caller reads it outside t.mu.
func (t *usageTable) get(uid uint32, b scopeBinding) map[string]int64 {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if f := t.byUID[uid]; f != nil && f.bind == b {
		return maps.Clone(f.entries)
	}
	return nil
}

// generation is the table's forgetAll count, read before a walk whose
// figure setAt then keeps.
func (t *usageTable) generation() uint64 {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.gen
}

// setAt keeps f as uid's figure, a walk's begun at generation gen: unless
// a forgetAll ran since, when the walk may have counted a tree no longer in
// place and f is dropped.
func (t *usageTable) setAt(uid uint32, f *scopeUsage, gen uint64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.gen == gen {
		t.byUID[uid] = f
	}
	t.mu.Unlock()
}

// forgetAll drops every uid's figure, and moves the generation on so that
// no figure taken before it is put back after it: a tree put in place
// under the store (a restore's merge) may hold any scope's entries under
// its same scope.key, and a listener that starts again
// (FileStore.StartUserScopes) may follow writes this process did not see.
func (t *usageTable) forgetAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	clear(t.byUID)
	t.gen++
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
	gen uint64
}

// begin takes uid's figure out of the table for an op about to write.
func (t *usageTable) begin(uid uint32) *usageOp {
	o := &usageOp{t: t, uid: uid}
	if t == nil {
		return o
	}
	t.mu.Lock()
	o.f, o.gen = t.byUID[uid], t.gen
	delete(t.byUID, uid)
	t.mu.Unlock()
	return o
}

// confirm ends the op: its figure, changed by fn (nil leaves it as it
// was, for an op that wrote nothing after all), goes back into the table,
// unless another figure was set for the uid since, or a forgetAll ran
// since begin (the generation moved), when it is dropped. A second confirm
// does nothing; an op never confirmed leaves the uid with no figure.
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
	if _, ok := o.t.byUID[o.uid]; !ok && o.t.gen == o.gen {
		o.t.byUID[o.uid] = f
	}
	o.t.mu.Unlock()
}

// bindingOf is the binding of the scope directory dir: its scope.key's
// digest and its entries/ directory's identity, each zero when absent.
// entries/ is Lstat'd, so a symlink under its name binds the link, and the
// walk then refuses it as openSubdir does.
func bindingOf(dir *os.Root) (scopeBinding, error) {
	var b scopeBinding
	raw, _, err := readFile(dir, scopeKeyName, int64(maxScopeKeyRecordSize))
	switch {
	case err == nil:
		b.key = sha256.Sum256(raw)
	case !errors.Is(err, fs.ErrNotExist):
		return scopeBinding{}, err
	}
	fi, err := dir.Lstat(scopeEntriesName)
	if errors.Is(err, fs.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return scopeBinding{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return scopeBinding{}, fmt.Errorf("%s: no device and inode", scopeEntriesName)
	}
	b.dev, b.ino = uint64(st.Dev), st.Ino // Dev is int32 on darwin
	return b, nil
}

// prepareUsage builds uid's figure by walking the scope before the store
// lock, when it has none bound to the scope on disk (scopeBinding): the
// caller holds the uid's mutation lock. A figure bound to another scope.key
// (an rm-scope and a new mint, a Rewrap's re-seal) or another entries/ (a
// tree renamed into place) is rebuilt here, outside the hold. It
// is best effort: a scope that cannot be walked now leaves no new figure,
// and the judgement under the lock walks then; a ctx done during the walk
// leaves none either, and the caller returns ctx's error before the store
// lock (put, rotate).
func (u *UserScope) prepareUsage(ctx context.Context) {
	if u.s.usage == nil || ctx.Err() != nil {
		return
	}
	gen := u.s.usage.generation()
	root, err := u.s.openDir(u.s.dir, false)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }() // read-only
	if b, err := u.bindingIn(root); err == nil && u.s.usage.fresh(u.uid, b) {
		return
	}
	if f, err := u.walkUsage(ctx, root, false); err == nil {
		u.s.usage.setAt(u.uid, f, gen)
	}
}

// bindingIn is the binding of the scope under root, the zero binding when
// the scope has no directory.
func (u *UserScope) bindingIn(root *os.Root) (scopeBinding, error) {
	dir, err := u.openScopeDir(root, false)
	if errors.Is(err, errNoScopeKey) {
		return scopeBinding{}, nil
	}
	if err != nil {
		return scopeBinding{}, err
	}
	defer func() { _ = dir.Close() }() // read-only
	return bindingOf(dir)
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
	if f.bind, err = bindingOf(dir); err != nil {
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
// bound to the scope on disk (scopeBinding), else a walk now, which becomes
// the figure. That walk is the one scope walk a put or rotate hold can do:
// the figure is still absent or stale at the lock when the walk before it
// failed, a root rm-scope and a new mint, a Rewrap or a tree put in place
// landed between that walk and the lock, or the put minted the scope under
// this hold.
func (u *UserScope) usageUnderLock(root *os.Root) (map[string]int64, error) {
	dir, err := u.openScopeDir(root, false)
	if err != nil {
		return nil, err
	}
	b, err := bindingOf(dir)
	_ = dir.Close() // read-only
	if err != nil {
		return nil, err
	}
	if m := u.s.usage.get(u.uid, b); m != nil {
		return m, nil
	}
	gen := u.s.usage.generation()
	f, err := u.walkUsage(context.Background(), root, true)
	if err != nil {
		return nil, err
	}
	u.s.usage.setAt(u.uid, f, gen)
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
