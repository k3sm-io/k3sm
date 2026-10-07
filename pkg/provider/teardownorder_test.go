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
	"net/netip"
	"sync"
	"testing"

	"k3sm.io/darwin-net/pkg/proxy"
)

// TestTeardownDropsTransportBeforeAlias pins the B440 teardown order: when a vm
// pod is deleted, the generation that drops its override (which closes the
// node's relay on the published address) is handed to the proxy while the
// pod's /32 is still allocated, and the allocation (with its lo0 alias) is
// released only after. The reverse order would pull the address out from under
// the relay's live sockets.
func TestTeardownDropsTransportBeforeAlias(t *testing.T) {
	t.Parallel()
	n := newLeaseNode(t)
	pod := portedVMPod("team-a", "ordered")
	id := string(pod.UID)

	var mu sync.Mutex
	var droppedWithAlias, droppedWithoutAlias int
	var pub netip.Addr
	n.sink.onSet = func(m map[netip.Addr]proxy.VMPodTransport) {
		mu.Lock()
		defer mu.Unlock()
		if !pub.IsValid() {
			return
		}
		if _, ok := m[pub]; ok {
			return
		}
		if _, held := n.ipam.allocations()[id]; held {
			droppedWithAlias++
		} else {
			droppedWithoutAlias++
		}
	}

	if err := n.r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	n.watch(t)
	p := netip.MustParseAddr(n.published(t, id))
	mu.Lock()
	pub = p
	mu.Unlock()

	n.rt.push(t, id, leaseFirst)
	n.awaitOverrides(t, map[string]string{p.String(): leaseFirst})

	if err := n.r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	n.awaitOverrides(t, map[string]string{})
	if _, held := n.ipam.allocations()[id]; held {
		t.Fatal("the pod's /32 is still allocated after DeletePod")
	}
	mu.Lock()
	defer mu.Unlock()
	if droppedWithAlias != 1 || droppedWithoutAlias != 0 {
		t.Errorf("override drops: %d while the /32 was held, %d after it was released; want exactly 1 and 0",
			droppedWithAlias, droppedWithoutAlias)
	}
}

// racingNetwork is the leaseNode's adapter with a hook run inside Teardown, on
// either side of the real alias release: the two instants a concurrent status
// observation can land while releasePodNetwork is in progress.
type racingNetwork struct {
	*PodNetAdapter
	before, after func(podID string)
}

func (n *racingNetwork) Teardown(podID string) error {
	if n.before != nil {
		n.before(podID)
	}
	err := n.PodNetAdapter.Teardown(podID)
	if n.after != nil {
		n.after(podID)
	}
	return err
}

// TestReleaseRefusesARacingReinstall pins the security-critique condition on
// releasePodNetwork: a status observation that reports the guest's lease while
// the pod's network is being released (after the override drop, before or after
// the alias removal) must not leave an override, and so a relay, behind. Each
// interleaving is a separate case because each is closed by a different guard:
// before the alias removal the release mark refuses it, after it the under-lock
// guest re-check does.
func TestReleaseRefusesARacingReinstall(t *testing.T) {
	t.Parallel()
	for _, at := range []string{"before alias release", "after alias release", "after release returns"} {
		t.Run(at, func(t *testing.T) {
			t.Parallel()
			n := newLeaseNode(t)
			pod := portedVMPod("team-a", "racer")
			id := string(pod.UID)
			race := func() { n.r.observeTransport(pod, leaseStatus(id, "", leaseFirst)) }
			net := &racingNetwork{PodNetAdapter: n.adapt}
			switch at {
			case "before alias release":
				net.before = func(string) { race() }
			case "after alias release":
				net.after = func(string) { race() }
			}
			n.r.network = net

			if err := n.r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			n.watch(t)
			pub := n.published(t, id)
			n.rt.push(t, id, leaseFirst)
			n.awaitOverrides(t, map[string]string{pub: leaseFirst})

			n.r.releasePodNetwork(pod)
			if at == "after release returns" {
				race()
			}

			if n.r.transport.has(id) {
				t.Error("an override survived the release")
			}
			if _, last := n.sink.snapshot(); len(last) != 0 {
				t.Errorf("the proxy's last generation still names %v after the release", renderOverrides(last))
			}
		})
	}
}

// TestObserveRechecksTheGuestUnderTheLock pins the second guard: an observation
// whose caller read the guest record before the release removed it (the
// time-of-check/time-of-use race releasePodNetwork cannot see) re-checks the
// record under the feed lock and installs nothing, dropping any override it
// finds instead.
func TestObserveRechecksTheGuestUnderTheLock(t *testing.T) {
	t.Parallel()
	sink := &recordingSink{}
	feed := newTransportFeed(sink, nil)
	pub, live := netip.MustParseAddr("100.64.0.9"), netip.MustParseAddr(leaseFirst)
	gone := func() bool { return false }

	feed.observe("pod-1", pub, live, []uint16{80}, gone)
	if feed.has("pod-1") {
		t.Fatal("an observation whose guest is gone installed an override")
	}
	feed.observe("pod-1", pub, live, []uint16{80}, nil)
	feed.observe("pod-1", pub, netip.MustParseAddr(leaseSecond), []uint16{80}, gone)
	if feed.has("pod-1") {
		t.Error("an observation whose guest is gone left the previous override in place")
	}
	if _, last := sink.snapshot(); len(last) != 0 {
		t.Errorf("last generation = %v, want empty", renderOverrides(last))
	}
}
