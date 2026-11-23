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
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"k3sm.io/k3sm/pkg/keystore"
)

// gatedAuditor records what reaches it, each call first waiting for gate
// to close; as a contextAuditor it gives up the wait when its context ends.
type gatedAuditor struct {
	fakeAuditor
	gate     chan struct{}
	ctxAware bool

	mu        sync.Mutex
	cancelled int
}

func (g *gatedAuditor) wait(ctx context.Context) bool {
	if !g.ctxAware {
		<-g.gate
		return true
	}
	select {
	case <-g.gate:
		return true
	case <-ctx.Done():
		g.mu.Lock()
		g.cancelled++
		g.mu.Unlock()
		return false
	}
}

func (g *gatedAuditor) Refused(uid uint32, reason string) {
	g.wait(context.Background())
	g.fakeAuditor.Refused(uid, reason)
}

func (g *gatedAuditor) Dropped(uid uint32, n uint64) {
	g.wait(context.Background())
	g.fakeAuditor.Dropped(uid, n)
}

// ctxGatedAuditor is a gatedAuditor that takes the writer's context.
type ctxGatedAuditor struct{ *gatedAuditor }

func (g ctxGatedAuditor) refusedContext(ctx context.Context, uid uint32, reason string) {
	if g.wait(ctx) {
		g.fakeAuditor.Refused(uid, reason)
	}
}

func (g ctxGatedAuditor) droppedContext(ctx context.Context, uid uint32, n uint64) {
	if g.wait(ctx) {
		g.fakeAuditor.Dropped(uid, n)
	}
}

// TestRefusalAuditOffTheAcceptPath checks that a blocked auditor never
// holds up admission: refusals queue, a full queue counts its overflow as
// dropped for each uid, which a later summary reports, and Serve leaves
// no goroutine behind.
func TestRefusalAuditOffTheAcceptPath(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := &gatedAuditor{gate: make(chan struct{})}
		r := startRigAudit(t, serviceUID, g)
		// One in flight, AuditQueueLen queued, and extra past them.
		const extra = 7
		n := AuditQueueLen + 1 + extra
		for i := range n {
			r.dial(uint32(1 + i%499)).refused(t)
		}
		// Admission still runs while the auditor is blocked.
		p := r.dial(501)
		p.admitted(t)
		p.close()
		if got, _ := g.lines(); len(got) != 0 {
			t.Fatalf("the blocked auditor recorded %v", got)
		}
		close(g.gate)
		synctest.Wait()
		got, _ := g.lines()
		if len(got) != n-extra {
			t.Fatalf("%d refused lines reached the auditor, want %d", len(got), n-extra)
		}
		advance(refusalWindow)
		_, drops := g.lines()
		var dropped uint64
		for _, d := range drops {
			dropped += d.dropped
		}
		if dropped != extra {
			t.Fatalf("summaries %v count %d dropped, want %d", drops, dropped, extra)
		}
		if err := r.stop(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
	})
}

// TestRefusalAuditDrainIsBounded checks that a stopping Serve waits at
// most AuditDrainWait for the writer, then cancels the call in flight and
// discards the rest.
func TestRefusalAuditDrainIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		g := &gatedAuditor{gate: make(chan struct{}), ctxAware: true}
		r := startRigAudit(t, serviceUID, ctxGatedAuditor{g})
		for uid := range uint32(5) {
			r.dial(uid + 1).refused(t)
		}
		start := time.Now()
		r.cancel()
		synctest.Wait()
		select {
		case <-r.done:
			t.Fatal("Serve returned before the drain wait while the writer was blocked")
		default:
		}
		if err := <-r.done; err != nil {
			t.Fatalf("Serve = %v", err)
		}
		if took := time.Since(start); took != AuditDrainWait {
			t.Fatalf("Serve took %v to stop, want the drain wait %v", took, AuditDrainWait)
		}
		g.mu.Lock()
		cancelled := g.cancelled
		g.mu.Unlock()
		if cancelled != 1 {
			t.Fatalf("%d calls were cancelled, want the one in flight", cancelled)
		}
		if got, _ := g.lines(); !slices.Equal(got, nil) {
			t.Fatalf("lines written after the drain wait: %v", got)
		}
	})
}

// TestPendingDroppedReachesLogWithNextLine checks that a dropped count the
// log kept (a line not written for the store lock) reaches the log with
// the next line written, and that the minute's summary pass writes it when
// no line follows and the rate limit dropped nothing.
func TestPendingDroppedReachesLogWithNextLine(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := newStoreRig(t)
		if err := store.logs.Reopen(t.Context()); err != nil { // creates the lock file
			t.Fatal(err)
		}
		r := startRigWith(t, serviceUID, newStoreAuditor(t, store.logs))
		lock, err := os.Open(filepath.Join(store.data, "server", "keystore", ".lock"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		hold := func(how int) {
			t.Helper()
			if err := syscall.Flock(int(lock.Fd()), how); err != nil {
				t.Fatal(err)
			}
		}

		// The lock held elsewhere: uid 501's sandboxed refusal waits out the
		// lock bound and is counted.
		hold(syscall.LOCK_EX)
		r.dialAs(501, true, false, false).refused(t)
		advance(keystore.ServerAppendLockWait)
		hold(syscall.LOCK_UN)
		if got := store.logs.PendingDropped(501); got != 1 {
			t.Fatalf("uid 501 pending = %d, want 1", got)
		}
		// The next line written, root's, carries it.
		r.dial(0).refused(t)
		lines, _ := readAudit(t, store.auditPath())
		rs, ds := refusedOf(t, lines)
		if !slices.Equal(rs, []refusal{{0, ReasonRoot}}) || !slices.Equal(ds, []drop{{501, 1}}) {
			t.Fatalf("audit log refusals %v, summaries %v; want root's, then uid 501 dropped 1", rs, ds)
		}
		if got := store.logs.PendingDropped(501); got != 0 {
			t.Fatalf("uid 501 pending after its summary = %d", got)
		}

		// No line follows: the minute pass writes it, though the rate limit
		// dropped nothing.
		hold(syscall.LOCK_EX)
		r.dialAs(600, true, false, false).refused(t)
		advance(keystore.ServerAppendLockWait)
		hold(syscall.LOCK_UN)
		advance(refusalWindow)
		lines, _ = readAudit(t, store.auditPath())
		if _, ds = refusedOf(t, lines); !slices.Equal(ds, []drop{{501, 1}, {600, 1}}) {
			t.Fatalf("summaries after the minute = %v, want uid 600 dropped 1 after uid 501's", ds)
		}
		if _, d := r.audit.lines(); len(d) != 0 {
			t.Fatalf("the rate limit summarized %v; it dropped nothing", d)
		}
		if err := r.stop(); err != nil {
			t.Fatalf("Serve = %v", err)
		}
	})
}
