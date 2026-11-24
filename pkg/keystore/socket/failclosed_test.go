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
	"os"
	"sync"
	"testing"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// spyStore is a Store that counts the calls reaching the store behind it,
// by method; Admit and the refused lines are the socket's own and are not
// counted.
type spyStore struct {
	Store
	mu    sync.Mutex
	calls map[string]int
}

func newSpyStore(s Store) *spyStore { return &spyStore{Store: s, calls: map[string]int{}} }

func (s *spyStore) hit(m string) { s.mu.Lock(); s.calls[m]++; s.mu.Unlock() }

func (s *spyStore) n(m string) int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls[m] }

func (s *spyStore) Put(ctx context.Context, p Peer, e string, k keystore.Kind, v []byte) (keystore.Version, error) {
	s.hit("Put")
	return s.Store.Put(ctx, p, e, k, v)
}

func (s *spyStore) Rotate(ctx context.Context, p Peer, e string, v []byte) (keystore.Version, error) {
	s.hit("Rotate")
	return s.Store.Rotate(ctx, p, e, v)
}

func (s *spyStore) RotateFrom(ctx context.Context, p Peer, e string, from uint64) (keystore.Version, error) {
	s.hit("RotateFrom")
	return s.Store.RotateFrom(ctx, p, e, from)
}

func (s *spyStore) Remove(ctx context.Context, p Peer, e string) error {
	s.hit("Remove")
	return s.Store.Remove(ctx, p, e)
}

func (s *spyStore) List(ctx context.Context, p Peer) ([]keystore.Entry, error) {
	s.hit("List")
	return s.Store.List(ctx, p)
}

func (s *spyStore) ReadForExec(ctx context.Context, p Peer, e string) (keystore.Version, []byte, error) {
	s.hit("ReadForExec")
	return s.Store.ReadForExec(ctx, p, e)
}

// mendAudit makes the audit log writable again after breakAudit.
func (r *bridgeRig) mendAudit(t *testing.T) {
	t.Helper()
	if err := os.Chmod(r.auditPath(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAuditFailureRefusesOps (U32): while the store's appends fail for
// everyone, the socket refuses put, list, read-for-exec and the delivery
// placeholders with refused before the store is called, for every uid,
// a uid with no scope included; rotate and rm, the revocation class, still
// run and are counted unaudited; the next append that succeeds ends the
// state.
func TestAuditFailureRefusesOps(t *testing.T) {
	r := newStartedBridge(t, nil)
	spy := newSpyStore(r.b)
	h, err := NewOpsHandler(time.Now, spy)
	if err != nil {
		t.Fatal(err)
	}
	a, b := dialOps(t, h, uidA), dialOps(t, h, uidB)
	for _, n := range []string{"a", "b", "c"} {
		a.mustReply(t, hdr(t, OpPut, entryOf(uidA, n), nil), []byte("v1"), nil)
	}
	r.breakAudit(t)
	// The first read meets the failed append in the store, which refuses
	// it and enters the global append failure.
	if code := codeOf(t, a.call(t, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil)); code != CodeRefused {
		t.Fatalf("a read whose line fails: code %q, want refused", code)
	}
	if !r.fs.AuditFailing() {
		t.Fatal("a read whose line failed did not enter the global append failure")
	}
	before := map[string]int{}
	for _, m := range []string{"Put", "List", "ReadForExec"} {
		before[m] = spy.n(m)
	}
	for _, c := range []struct {
		name string
		w    *wire
		hdr  string
		val  []byte
	}{
		{"put", a, hdr(t, OpPut, entryOf(uidA, "d"), nil), []byte("v")},
		{"list", a, hdr(t, OpList, "", nil), nil},
		{"read-for-exec", a, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil},
		{"another uid's put", b, hdr(t, OpPut, entryOf(uidB, "x"), nil), []byte("v")},
		{"list for a uid with no scope", b, hdr(t, OpList, "", nil), nil},
		{"deliver", a, hdr(t, OpDeliver, entryOf(uidA, "a"), nil), nil},
		{"deliveries", a, hdr(t, OpDeliveries, "", nil), nil},
	} {
		if code := codeOf(t, c.w.call(t, c.hdr, c.val)); code != CodeRefused {
			t.Errorf("%s while appends fail: code %q, want refused", c.name, code)
		}
	}
	for m, n := range before {
		if got := spy.n(m); got != n {
			t.Errorf("%s reached the store %d times while appends fail, want none", m, got-n)
		}
	}
	// The revocation class goes ahead, its lines dropped and counted.
	var rot struct {
		VersionReply
		Warning string `json:"warning"`
	}
	a.mustReply(t, hdr(t, OpRotate, entryOf(uidA, "a"), nil), []byte("v2"), &rot)
	if rot.Version != 2 || rot.Warning != WarnAuditFailed {
		t.Fatalf("rotate while appends fail replied %+v, want version 2 and %q", rot, WarnAuditFailed)
	}
	a.mustReply(t, hdr(t, OpRotate, entryOf(uidA, "a"), map[string]any{"from_version": 1}), nil, &rot)
	if f := a.mustReply(t, hdr(t, OpRm, entryOf(uidA, "b"), nil), nil, nil); string(f.Header) != `{"warning":"committed; audit failed"}` {
		t.Fatalf("rm while appends fail replied %s", f.Header)
	}
	if n := r.fs.UnauditedOps(); n != 3 {
		t.Fatalf("UnauditedOps = %d after three committed, unaudited revocations, want 3", n)
	}
	// A revocation's append that succeeds ends the state for everyone.
	r.mendAudit(t)
	a.mustReply(t, hdr(t, OpRm, entryOf(uidA, "c"), nil), nil, nil)
	if r.fs.AuditFailing() {
		t.Fatal("a revocation's successful append did not end the global append failure")
	}
	b.mustReply(t, hdr(t, OpPut, entryOf(uidB, "x"), nil), []byte("v"), nil)
	a.mustReply(t, hdr(t, OpReadForExec, entryOf(uidA, "a"), nil), nil, nil)
}

// A list for a uid with no scope whose own line fails is refused, never
// served as an empty list with no line: the store's scope-absent answer
// does not hide the failed append.
func TestAuditFailureRefusesScopelessList(t *testing.T) {
	r := newOpsRig(t, nil)
	w := dialOps(t, r.ops, uidB)
	r.breakAudit(t)
	if r.fs.AuditFailing() {
		t.Fatal("the store is failing before any append")
	}
	f := w.call(t, hdr(t, OpList, "", nil), nil)
	if code := codeOf(t, f); code != CodeRefused {
		t.Fatalf("a scopeless list whose line fails: code %q (%s), want refused", code, f.Header)
	}
	if !r.fs.AuditFailing() {
		t.Fatal("the scopeless list's failed append did not enter the global append failure")
	}
}
