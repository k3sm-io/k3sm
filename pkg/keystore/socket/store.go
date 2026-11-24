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

package socket

import (
	"context"
	"errors"
	"fmt"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// Store is the socket server's interface onto the keystore: the calls the
// operations make, each for one admitted peer, whose uid is the only scope
// it reaches. Entries are named in the API grammar, user/<uid>/<name>; any
// name outside the peer's own scope, another uid's or a system/ name,
// answers keystore.ErrNotFound worded as an absent entry of the peer's own.
//
// It has no reveal, show or rewrap method, and no unaudited read: a value
// leaves the store only through ReadForExec, audited as exec-read
// (docs/design/keystore.md § "The socket", U35). Every call appends its
// audit line with via socket and the peer as caller.
type Store interface {
	// Put stores value as version 1 of a new entry of kind (a grant: its
	// audit line before its first write).
	Put(ctx context.Context, p Peer, entry string, kind keystore.Kind, value []byte) (keystore.Version, error)
	// Rotate seals value as the entry's next version (a revocation:
	// commit, then audit).
	Rotate(ctx context.Context, p Peer, entry string, value []byte) (keystore.Version, error)
	// RotateFrom writes version from's value forward as the entry's next
	// version.
	RotateFrom(ctx context.Context, p Peer, entry string, from uint64) (keystore.Version, error)
	// Remove deletes the entry and every version of it.
	Remove(ctx context.Context, p Peer, entry string) error
	// List returns the metadata of every entry of the peer's scope, with
	// no values.
	List(ctx context.Context, p Peer) ([]keystore.Entry, error)
	// ReadForExec returns the entry's current value, for exec injection.
	ReadForExec(ctx context.Context, p Peer, entry string) (keystore.Version, []byte, error)
	// Admit judges a request of op (one of the Op* names) for p after
	// its header and value passed and before it reaches the store: while
	// the store's audit appends fail for everyone, a mutation or read
	// outside the revocation class is ErrAuditFailing. Every operation
	// calls it, the delivery placeholders included.
	Admit(p Peer, op string) error
}

// ErrAuditFailing refuses a mutation or read while the store's audit
// appends fail for everyone (keystore.FileStore.AuditFailing): the
// fail-closed rule (docs/design/keystore.md § "The audit log"). rotate, rm
// and withdraw, the revocation class, are never refused so. It is answered
// refused, the code of the global append failure.
var ErrAuditFailing = fmt.Errorf("%w: the audit log takes no appends, so mutations and reads are refused until one succeeds", ErrRequestRefused)

// revocationOp reports whether op is in the revocation class, which goes
// ahead while appends fail (its line dropped and counted unaudited).
func revocationOp(op string) bool {
	switch op {
	case OpRotate, OpRm, OpWithdraw:
		return true
	}
	return false
}

// ListsPerSecond is how many list requests one uid may make a second
// (docs/design/keystore.md § "The socket", "Bounds"); past it a list is
// ErrRateLimited before it reaches the store, so it writes no line and is
// charged nothing.
const ListsPerSecond = 5

// FileStoreBridge is the Store over the keystore on disk: each call opens
// the peer's own view of the store, stamped with the socket as its origin
// and the peer's pid, and makes the one user-scope call it names. It holds
// no view between calls, so no request acts for another's peer.
type FileStoreBridge struct {
	fs    *keystore.FileStore
	lists *uidRate
}

var _ Store = (*FileStoreBridge)(nil)

// NewFileStoreBridge returns the Store over fs, timing its per-uid rate
// limits with now. The server runs fs's start step (StartUserScopes)
// before it serves; until then every call is refused as the user scope
// off.
func NewFileStoreBridge(fs *keystore.FileStore, now func() time.Time) (*FileStoreBridge, error) {
	switch {
	case fs == nil:
		return nil, errors.New("keystore socket: nil store")
	case now == nil:
		return nil, errors.New("keystore socket: nil clock")
	}
	return &FileStoreBridge{fs: fs, lists: newUIDRate(ListsPerSecond, time.Second, now)}, nil
}

// view is p's view of the store for one call: its uid's scope, its lines
// stamped via socket with p as caller.
func (b *FileStoreBridge) view(p Peer) (*keystore.UserScope, error) {
	u, err := b.fs.UserScope(p.UID)
	if err != nil {
		return nil, err
	}
	return u.WithOrigin(keystore.SocketOrigin(p.PID)), nil
}

// Put implements Store.
func (b *FileStoreBridge) Put(ctx context.Context, p Peer, entry string, kind keystore.Kind, value []byte) (keystore.Version, error) {
	u, err := b.view(p)
	if err != nil {
		return keystore.Version{}, err
	}
	return u.Put(ctx, entry, kind, value)
}

// Rotate implements Store.
func (b *FileStoreBridge) Rotate(ctx context.Context, p Peer, entry string, value []byte) (keystore.Version, error) {
	u, err := b.view(p)
	if err != nil {
		return keystore.Version{}, err
	}
	return u.Rotate(ctx, entry, value)
}

// RotateFrom implements Store.
func (b *FileStoreBridge) RotateFrom(ctx context.Context, p Peer, entry string, from uint64) (keystore.Version, error) {
	u, err := b.view(p)
	if err != nil {
		return keystore.Version{}, err
	}
	return u.RotateFrom(ctx, entry, from)
}

// Remove implements Store.
func (b *FileStoreBridge) Remove(ctx context.Context, p Peer, entry string) error {
	u, err := b.view(p)
	if err != nil {
		return err
	}
	return u.Delete(ctx, entry)
}

// List implements Store. A list past the uid's rate limit is refused
// before the store is reached.
func (b *FileStoreBridge) List(ctx context.Context, p Peer) ([]keystore.Entry, error) {
	if !b.lists.allow(p.UID) {
		return nil, ErrRateLimited
	}
	u, err := b.view(p)
	if err != nil {
		return nil, err
	}
	return u.List(ctx)
}

// Admit implements Store: the fail-closed rule, judged from the store's
// own account of its appends, before the store is called.
func (b *FileStoreBridge) Admit(_ Peer, op string) error {
	if !revocationOp(op) && b.fs.AuditFailing() {
		return ErrAuditFailing
	}
	return nil
}

// ReadForExec implements Store.
func (b *FileStoreBridge) ReadForExec(ctx context.Context, p Peer, entry string) (keystore.Version, []byte, error) {
	u, err := b.view(p)
	if err != nil {
		return keystore.Version{}, nil, err
	}
	return u.ReadForExec(ctx, entry)
}
