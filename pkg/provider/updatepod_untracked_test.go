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

package provider

import (
	"context"
	"fmt"
	"testing"
)

// TestUpdateAfterDeleteAcquiresNothing: Virtual Kubelet can hold an update it decided
// on while a track existed, and the delete may return before the update is checked.
// The update's object need carry no deletion stamp, as the reaper's and a force
// delete's do not. Fails when the update reads no tombstone: it allocates a /32 and
// registers references that nothing owns, until the daemon restarts.
func TestUpdateAfterDeleteAcquiresNothing(t *testing.T) {
	ctx := context.Background()

	assertStopped := func(t *testing.T, x *terminalUpdateFixture, p *netProbe) {
		t.Helper()
		setups, releases := p.counts()
		if err := x.r.UpdatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Errorf("UpdatePod = %v, want nil for a deleted pod", err)
		}
		if after, _ := p.counts(); after != setups {
			t.Errorf("pod network setups %d -> %d, want no new one", setups, after)
		}
		x.assertForgotten(t)
		if _, n := p.counts(); n != releases {
			t.Errorf("releases %d -> %d, want no new one", releases, n)
		}
		if n := x.f.updateCount(); n != 0 {
			t.Errorf("runtime UpdatePod calls = %d, want 0", n)
		}
	}

	t.Run("a running pod's delete", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		assertStopped(t, x, p)
	})

	t.Run("the orphan reaper's teardown", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		x.r.reapOrphan(ctx, x.pod.DeepCopy(), x.r.trackByID(string(x.pod.UID)))
		assertStopped(t, x, p)
	})

	t.Run("a refused pod's delete", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		p := probeNetwork(x)
		x.refuseNow(ctx, t)
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		assertStopped(t, x, p)
	})

	// A failed RPC deleted nothing, and Virtual Kubelet retries it: the pod may run
	// on. Fails when the tombstone goes in before the runtime has answered.
	t.Run("a delete that failed leaves no tombstone", func(t *testing.T) {
		x := newTerminalUpdateFixture(t, compressorAt(10))
		id := string(x.pod.UID)
		if err := x.r.CreatePod(ctx, x.pod.DeepCopy()); err != nil {
			t.Fatalf("the create: %v", err)
		}
		x.f.mu.Lock()
		x.f.deleteFIFO = append(x.f.deleteFIFO, fmt.Errorf("the runtime is away"))
		x.f.mu.Unlock()
		if err := x.r.DeletePod(ctx, x.pod.DeepCopy()); err == nil {
			t.Fatal("DeletePod = nil, want the runtime's error")
		}
		x.r.mu.Lock()
		remembered := x.r.tombstones.has(id)
		x.r.mu.Unlock()
		if remembered {
			t.Error("a delete that failed left a tombstone")
		}
	})
}

// TestUIDTombstonesAreBounded: the set never grows past its cap, evicts the oldest
// first, and a repeat of a remembered UID takes no second slot.
func TestUIDTombstonesAreBounded(t *testing.T) {
	var u uidTombstones
	if u.has("never") {
		t.Error("the zero value remembers a UID")
	}
	uid := func(i int) string { return fmt.Sprintf("uid-%d", i) }
	for i := range uidTombstoneCap {
		u.add(uid(i))
		u.add(uid(i))
	}
	if !u.has(uid(0)) || len(u.seen) != uidTombstoneCap {
		t.Fatalf("at the cap: has(oldest) = %v, size = %d, want true, %d", u.has(uid(0)), len(u.seen), uidTombstoneCap)
	}
	for i := uidTombstoneCap; i < 3*uidTombstoneCap+5; i++ {
		u.add(uid(i))
		if len(u.seen) != uidTombstoneCap || len(u.ring) != uidTombstoneCap {
			t.Fatalf("after add %d: seen = %d, ring = %d, want both %d", i, len(u.seen), len(u.ring), uidTombstoneCap)
		}
	}
	last := 3*uidTombstoneCap + 4
	if !u.has(uid(last)) || !u.has(uid(last-uidTombstoneCap+1)) {
		t.Error("a UID inside the window was forgotten")
	}
	if u.has(uid(last - uidTombstoneCap)) {
		t.Error("the UID just past the window is still remembered")
	}
}
