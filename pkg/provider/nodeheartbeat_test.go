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
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// hangingPing is a node provider whose Ping never answers: it ignores its
// context and blocks until the test releases it. Everything else is the real
// NodeStatusProvider.
type hangingPing struct {
	*NodeStatusProvider
	release <-chan struct{}
	calls   atomic.Int32
}

func (h *hangingPing) Ping(context.Context) error {
	h.calls.Add(1)
	<-h.release
	return nil
}

// TestNodeStatusKeepsPostingWhenPingIsSlow pins that a provider Ping which does
// not answer cannot stop the node's heartbeat. In Virtual Kubelet a ping that has
// not answered gates node registration, and a failed ping suppresses both the
// status update and the Lease renewal; a kubelet has no such gate, and k3sm
// reports runtime health as the Ready condition instead. So with a Ping that hangs
// for the whole test the node must still register, keep posting its status, and
// renew its Lease, and Node.Heartbeat must say so.
func TestNodeStatusKeepsPostingWhenPingIsSlow(t *testing.T) {
	const nodeName = "mac-slow-ping"
	cs := k8sfake.NewSimpleClientset()
	var statusPosts, leaseWrites atomic.Int32
	cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "status" {
			statusPosts.Add(1)
		}
		return false, nil, nil
	})
	countLease := func(k8stesting.Action) (bool, runtime.Object, error) {
		leaseWrites.Add(1)
		return false, nil, nil
	}
	cs.PrependReactor("create", "leases", countLease)
	cs.PrependReactor("update", "leases", countLease)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var status *NodeStatusProvider
	var guarded *hangingPing
	n, err := vkadapter.NewNode(nodeName, vkadapter.NodeConfig{
		Client:         cs,
		Provider:       NewHostProcess(nodeName, t.TempDir(), "100.64.9.1", nil),
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
		NodeProvider: func(nd *corev1.Node) (vkadapter.NodeProvider, error) {
			p, perr := NewNodeStatusProvider(NodeStatusConfig{
				Node:     nd,
				DataRoot: t.TempDir(),
				Interval: 100 * time.Millisecond,
			})
			if perr != nil {
				return nil, perr
			}
			p.sample = func(string) (hostStats, error) { return healthyStats(), nil }
			status = p
			guarded = &hangingPing{NodeStatusProvider: p, release: release}
			return guarded, nil
		},
	})
	if err != nil {
		t.Fatalf("vkadapter.NewNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	statusDone := make(chan error, 1)
	go func() { runDone <- n.Run(ctx) }()
	go func() { statusDone <- status.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		waitReturn(t, runDone, "vkadapter.Node.Run")
		waitReturn(t, statusDone, "NodeStatusProvider.Run")
	})

	const wantPosts = 3
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if statusPosts.Load() >= wantPosts && leaseWrites.Load() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := guarded.calls.Load(); got == 0 {
		t.Fatal("the hanging Ping was never called; the test is not exercising the ping path")
	}
	if got := statusPosts.Load(); got < wantPosts {
		t.Fatalf("node status PATCHes = %d within 15s while Ping hangs, want at least %d", got, wantPosts)
	}
	if got := leaseWrites.Load(); got < 1 {
		t.Fatalf("Lease writes = %d within 15s while Ping hangs, want at least 1", got)
	}
	hb := n.Heartbeat()
	if hb.StatusPosted.IsZero() || hb.LeaseRenewed.IsZero() {
		t.Fatalf("Node.Heartbeat = %+v, want both writes recorded", hb)
	}
}
