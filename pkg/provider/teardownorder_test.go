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
