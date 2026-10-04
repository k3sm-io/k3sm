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
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"k3sm.io/k3sm/pkg/netserve"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// podCall is one recorded pods list or watch and the field selector it carried.
type podCall struct {
	verb     string
	selector string
}

// podCallRecorder wraps a fake clientset and records every pods list and watch.
// The fake object tracker ignores field selectors, so the selector is read from
// the action's restrictions — what the apiserver (and its Node authorizer) would
// have seen.
type podCallRecorder struct {
	cs *k8sfake.Clientset

	mu    sync.Mutex // guards calls
	calls []podCall
}

func newPodCallRecorder() *podCallRecorder {
	r := &podCallRecorder{cs: k8sfake.NewClientset()}
	r.cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r.record("list", a.(k8stesting.ListAction).GetListRestrictions().Fields.String())
		return false, nil, nil
	})
	r.cs.PrependWatchReactor("pods", func(a k8stesting.Action) (bool, watch.Interface, error) {
		r.record("watch", a.(k8stesting.WatchAction).GetWatchRestrictions().Fields.String())
		return false, nil, nil
	})
	return r
}

func (r *podCallRecorder) record(verb, selector string) {
	r.mu.Lock()
	r.calls = append(r.calls, podCall{verb: verb, selector: selector})
	r.mu.Unlock()
}

func (r *podCallRecorder) snapshot() []podCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]podCall(nil), r.calls...)
}

// waitFor polls until verb has been recorded at least once, or the deadline.
func (r *podCallRecorder) waitFor(t *testing.T, verb string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, c := range r.snapshot() {
			if c.verb == verb {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no pods %s recorded within %v (calls so far: %v); the consumer never reached the apiserver, so the scope assertion would be vacuous", verb, within, r.snapshot())
}

// assertNodeScoped fails on any recorded pods list/watch whose field selector is
// not exactly spec.nodeName=<node>, and on an empty recording.
func (r *podCallRecorder) assertNodeScoped(t *testing.T, node string) {
	t.Helper()
	calls := r.snapshot()
	if len(calls) == 0 {
		t.Fatal("no pods list/watch recorded: the assertion is vacuous")
	}
	want := "spec.nodeName=" + node
	for _, c := range calls {
		if c.selector != want {
			t.Errorf("pods %s with field selector %q, want %q: the Node authorizer refuses system:node:%s anything wider than its own pods", c.verb, c.selector, want, node)
		}
	}
}

// TestNoClusterWidePodListFromTheNode drives every pod consumer that runs under
// a joined worker's node identity (system:node:<name>) through its real
// constructor and asserts that none lists or watches pods beyond the node's own
// (spec.nodeName=<name>). The Node authorizer refuses a node's cluster-wide pod
// list, so a consumer that issues one retries forever and never syncs.
//
// The consumers: the worker datapath (netserve.New with the worker shape, run
// through the unprivileged RunPolicyWatch so no socket is bound), which starts
// no policy informer at all, because the watcher's cluster-wide NetworkPolicies
// and Namespaces reads are not granted to a node; the same datapath once it is
// told to enforce, whose pods view must still be the node's own; the VK node's
// pod informer (vkadapter.NewNode + Run with no TLS config, so no kubelet
// listener starts); and the orphan-reap pod source.
func TestNoClusterWidePodListFromTheNode(t *testing.T) {
	t.Parallel()
	const node = "mac-worker-2"
	workerDatapath := func(cs *k8sfake.Clientset, enforce bool) *netserve.Server {
		return netserve.New(netserve.Config{
			Client:               cs,
			WorkDir:              t.TempDir(),
			DNSVIP:               "10.43.0.10",
			ClusterDomain:        "cluster.local",
			NodeIP:               "100.64.2.1",
			NodeAddress:          "100.64.2.1",
			PodCIDR:              "100.64.2.0/24",
			MeshEgressIP:         "100.64.2.1",
			EnforceNetworkPolicy: enforce,
			PodScopeNode:         node,
		})
	}

	t.Run("worker datapath starts no policy informer", func(t *testing.T) {
		t.Parallel()
		rec := newPodCallRecorder()
		var mu sync.Mutex // guards seen
		var seen []string
		note := func(a k8stesting.Action) {
			mu.Lock()
			seen = append(seen, a.GetVerb()+" "+a.GetResource().Resource)
			mu.Unlock()
		}
		rec.cs.PrependReactor("list", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
			note(a)
			return false, nil, nil
		})
		rec.cs.PrependWatchReactor("*", func(a k8stesting.Action) (bool, watch.Interface, error) {
			note(a)
			return false, nil, nil
		})
		srv := workerDatapath(rec.cs, false)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if err := srv.RunPolicyWatch(ctx); err != nil {
			t.Fatalf("RunPolicyWatch: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != 0 {
			t.Errorf("worker policy path issued %v; the node identity is granted neither the NetworkPolicies nor the Namespaces read, so a worker must start no policy informer", seen)
		}
	})

	t.Run("enforcing node-scoped datapath lists only the node's pods", func(t *testing.T) {
		t.Parallel()
		rec := newPodCallRecorder()
		srv := workerDatapath(rec.cs, true)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.RunPolicyWatch(ctx) }()
		rec.waitFor(t, "watch", 10*time.Second)
		cancel()
		waitReturn(t, done, "RunPolicyWatch")
		rec.assertNodeScoped(t, node)
	})

	t.Run("VK node pod informer", func(t *testing.T) {
		t.Parallel()
		rec := newPodCallRecorder()
		// HostProcess is wired straight into the VK node as the provider (the
		// hostprocess node path), so it is the real Provider here.
		var p vkadapter.Provider = NewHostProcess(node, t.TempDir(), "100.64.2.1", nil)
		n, err := vkadapter.NewNode(node, vkadapter.NodeConfig{
			Client:         rec.cs,
			Provider:       p,
			HTTPListenAddr: "127.0.0.1:0",
			NumWorkers:     1,
			ConfigureNode:  func(*corev1.Node) {},
		})
		if err != nil {
			t.Fatalf("vkadapter.NewNode: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- n.Run(ctx) }()
		rec.waitFor(t, "watch", 10*time.Second)
		cancel()
		waitReturn(t, done, "vkadapter.Node.Run")
		rec.assertNodeScoped(t, node)
	})

	t.Run("orphan-reap pod source", func(t *testing.T) {
		t.Parallel()
		rec := newPodCallRecorder()
		if _, err := newClientPodSource(rec.cs).listNodePods(context.Background(), node); err != nil {
			t.Fatalf("listNodePods: %v", err)
		}
		rec.assertNodeScoped(t, node)
	})
}

// waitReturn waits a bounded time for a cancelled consumer to return, so a
// consumer that ignores cancellation fails the test instead of leaking.
func waitReturn(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return within 10s of cancellation", what)
	}
}
