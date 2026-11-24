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
	// its header and value passed and before it reaches the store: past
	// p's uid's rate limit for op it is ErrRateLimited; while the store's
	// audit appends fail for everyone, a mutation or read
	// outside the revocation class is ErrAuditFailing. Every operation
	// calls it, the delivery placeholders included.
	Admit(p Peer, op string) error
	// Refused records a request of op for p that the socket refused
	// itself, for reason (keystore's Refused* closed set): a post-frame
	// refused line under p's uid, rate-limited per uid with a summary of
	// the count dropped. It is best effort and reports nothing.
	Refused(ctx context.Context, p Peer, op, reason string)
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

// The per-uid rate limits (docs/design/keystore.md § "The socket",
// "Bounds"), each a sliding window on the bridge's clock. Past one, a
// request is ErrRateLimited before it reaches the store, so it writes no
// store line and is charged nothing.
const (
	// MutationsPerSecond is how many mutating requests one uid may make a
	// second, put, rotate, rm, deliver and withdraw together.
	MutationsPerSecond = 5
	// ListsPerSecond is how many list and deliveries requests one uid may
	// make a second, the two together.
	ListsPerSecond = 5
	// ExecReadsPerMinute is how many read-for-exec requests one uid may
	// make a minute.
	ExecReadsPerMinute = 30
)

// FileStoreBridge is the Store over the keystore on disk: each call opens
// the peer's own view of the store, stamped with the socket as its origin
// and the peer's pid, and makes the one user-scope call it names. It holds
// no view between calls, so no request acts for another's peer.
type FileStoreBridge struct {
	fs        *keystore.FileStore
	mutations *uidRate
	lists     *uidRate
	execReads *uidRate
	refusals  *refusedLines
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
	return &FileStoreBridge{
		fs:        fs,
		mutations: newUIDRate(MutationsPerSecond, time.Second, now),
		lists:     newUIDRate(ListsPerSecond, time.Second, now),
		execReads: newUIDRate(ExecReadsPerMinute, time.Minute, now),
		refusals:  newRefusedLines(now),
	}, nil
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

// List implements Store.
func (b *FileStoreBridge) List(ctx context.Context, p Peer) ([]keystore.Entry, error) {
	u, err := b.view(p)
	if err != nil {
		return nil, err
	}
	return u.List(ctx)
}

// Admit implements Store: p's rate limit for op, then the fail-closed
// rule, judged from the store's own account of its appends, before the
// store is called. A request refused by the fail-closed rule has been
// counted against the rate limit.
func (b *FileStoreBridge) Admit(p Peer, op string) error {
	var r *uidRate
	switch op {
	case OpPut, OpRotate, OpRm, OpDeliver, OpWithdraw:
		r = b.mutations
	case OpList, OpDeliveries:
		r = b.lists
	case OpReadForExec:
		r = b.execReads
	default:
		return fmt.Errorf("%w: no operation %q", ErrRequestRefused, op)
	}
	if !r.allow(p.UID) {
		return ErrRateLimited
	}
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
