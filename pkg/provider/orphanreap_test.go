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
	"errors"
	"slices"
	"sync"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	netv1 "k3sm.io/apis/net/v1"
	"k3sm.io/runtimed/pkg/sandbox"
)

// fakePodSource is the apiserver the reaper reads, scripted per tick: the pods
// the node-scoped List returns (or its error), and what a direct Get answers.
type fakePodSource struct {
	mu       sync.Mutex
	listed   []corev1.Pod
	listErr  error
	got      map[string]*corev1.Pod // ns/name -> pod; absent answers NotFound
	getErr   error
	lists    int
	gets     int
	listNode string
}

func (s *fakePodSource) listNodePods(_ context.Context, nodeName string) ([]corev1.Pod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	s.listNode = nodeName
	if s.listErr != nil {
		return nil, s.listErr
	}
	return slices.Clone(s.listed), nil
}

func (s *fakePodSource) getPod(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if s.getErr != nil {
		return nil, s.getErr
	}
	if p, ok := s.got[namespace+"/"+name]; ok {
		return p.DeepCopy(), nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, name)
}

// recordingNetwork is a PodNetwork that records every Teardown — the /32
// release the full teardown path must perform.
type recordingNetwork struct {
	mu        sync.Mutex
	teardowns []string
}

func (n *recordingNetwork) Setup(context.Context, string) (string, error) { return "100.64.0.7", nil }
func (n *recordingNetwork) MarkHostNetwork(string)                        {}
func (n *recordingNetwork) SetupGuest(context.Context, string, netv1.DNSConfig) (sandbox.GuestNetworkConfig, error) {
	return sandbox.GuestNetworkConfig{}, nil
}
func (n *recordingNetwork) Teardown(podID string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.teardowns = append(n.teardowns, podID)
	return nil
}

func (n *recordingNetwork) tornDown(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Contains(n.teardowns, id)
}

func (f *fakeRuntimeServer) deletedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.deleteIDs)
}

// tick is one reaper tick's view of the apiserver for the pod under test.
type tick int

const (
	tickGone       tick = iota // absent from the List, the Get answers NotFound
	tickListed                 // present in the List
	tickGetPresent             // absent from the List, but the Get returns it (same UID)
	tickGetErr                 // absent from the List, the Get fails at the transport
	tickListErr                // the List itself fails at the transport
)

var errTransport = errors.New("dial tcp 192.168.1.1:6443: connect: connection refused")

// TestDanglingPodReapedAfterTombstone is the gate for the post-partition
// orphan: a pod the apiserver no longer holds (force-deleted while this Mac
// was partitioned) must be torn down by the provider's own reconcile, through
// the full delete path, after orphanReapThreshold consecutive live not-found
// verdicts — and never on a verdict that is stale, partial, or unknown.
//
// On main there is no reaper: the tracked pod runs until the daemon restarts,
// so every "reaped" expectation below fails.
func TestDanglingPodReapedAfterTombstone(t *testing.T) {
	tests := []struct {
		name  string
		ticks []tick
		// reapAt is the 1-based tick after which the pod must be reaped (it
		// must NOT be reaped after any earlier tick); 0 means never.
		reapAt int
	}{
		{name: "gone three consecutive ticks is reaped", ticks: []tick{tickGone, tickGone, tickGone}, reapAt: 3},
		{name: "reappears at tick 2 is not reaped", ticks: []tick{tickGone, tickListed, tickGone, tickGone}, reapAt: 0},
		{name: "reappears via the live Get at tick 2 resets the run", ticks: []tick{tickGone, tickGetPresent, tickGone, tickGone, tickGone}, reapAt: 5},
		{name: "a Get transport error resets nothing and reaps nothing", ticks: []tick{tickGone, tickGone, tickGetErr, tickGone}, reapAt: 4},
		{name: "a List transport error resets nothing and reaps nothing", ticks: []tick{tickGone, tickGone, tickListErr, tickGone}, reapAt: 4},
		{name: "transport errors alone never reap", ticks: []tick{tickGetErr, tickListErr, tickGetErr, tickListErr, tickGetErr}, reapAt: 0},
		{name: "listed every tick is never reaped", ticks: []tick{tickListed, tickListed, tickListed, tickListed}, reapAt: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			r, f, nw, src := newReaperFixture(t)
			pod := runtimedPod("default", "web")
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			id := string(pod.UID)
			for i, tk := range tt.ticks {
				n := i + 1
				src.mu.Lock()
				src.listed, src.listErr, src.got, src.getErr = nil, nil, map[string]*corev1.Pod{}, nil
				switch tk {
				case tickListed:
					src.listed = []corev1.Pod{*pod}
				case tickGetPresent:
					src.got["default/web"] = pod
				case tickGetErr:
					src.getErr = errTransport
				case tickListErr:
					src.listErr = errTransport
				}
				listsBefore := src.lists
				src.mu.Unlock()

				r.reapOrphans(ctx)

				src.mu.Lock()
				if src.lists != listsBefore+1 || src.listNode != "n" {
					t.Fatalf("tick %d: lists %d→%d on node %q, want exactly one node-scoped List for \"n\"", n, listsBefore, src.lists, src.listNode)
				}
				src.mu.Unlock()
				reaped := r.trackByID(id) == nil
				wantReaped := tt.reapAt != 0 && n >= tt.reapAt
				if reaped != wantReaped {
					t.Fatalf("tick %d (%v): reaped = %v, want %v", n, tk, reaped, wantReaped)
				}
				if !reaped {
					if slices.Contains(f.deletedIDs(), id) || nw.tornDown(id) {
						t.Fatalf("tick %d: pod still tracked but a teardown step ran (delete RPCs %v)", n, f.deletedIDs())
					}
				}
			}
			if tt.reapAt == 0 {
				return
			}
			// The FULL teardown ran, not a bare untrack: the runtime delete RPC
			// and the /32 release both happened, once.
			if got := f.deletedIDs(); !slices.Equal(got, []string{id}) {
				t.Errorf("runtime DeletePod ids = %v, want exactly [%s]", got, id)
			}
			if !nw.tornDown(id) {
				t.Errorf("pod network %s was not released", id)
			}
			r.orphanMu.Lock()
			_, gauge := r.orphanGauges[id]
			r.orphanMu.Unlock()
			if gauge {
				t.Errorf("reaped pod %s left an orphan gauge behind", id)
			}
		})
	}

	t.Run("same-name different-UID successor is never touched", func(t *testing.T) {
		ctx := context.Background()
		r, f, nw, src := newReaperFixture(t)
		pred := runtimedPod("default", "web")
		pred.UID = types.UID("uid-pred")
		succ := runtimedPod("default", "web")
		succ.UID = types.UID("uid-succ")
		for _, p := range []*corev1.Pod{pred, succ} {
			if err := r.CreatePod(ctx, p); err != nil {
				t.Fatalf("CreatePod %s: %v", p.UID, err)
			}
		}
		// The apiserver holds only the successor, under the shared name.
		src.listed = []corev1.Pod{*succ}
		src.got = map[string]*corev1.Pod{"default/web": succ}
		succTrack := r.trackByID("uid-succ")
		for n := 1; n <= 5; n++ {
			r.reapOrphans(ctx)
			if got := r.trackByID("uid-succ"); got != succTrack {
				t.Fatalf("tick %d: successor track changed (%p → %p)", n, succTrack, got)
			}
			if n < int(orphanReapThreshold) && r.trackByID("uid-pred") == nil {
				t.Fatalf("tick %d: predecessor reaped before the threshold", n)
			}
		}
		if r.trackByID("uid-pred") != nil {
			t.Fatal("predecessor was not reaped although the name holds a different UID")
		}
		if got := f.deletedIDs(); !slices.Equal(got, []string{"uid-pred"}) {
			t.Errorf("runtime DeletePod ids = %v, want exactly [uid-pred]", got)
		}
		if nw.tornDown("uid-succ") {
			t.Error("the successor's /32 was released")
		}
		if !nw.tornDown("uid-pred") {
			t.Error("the predecessor's /32 was not released")
		}
	})

	t.Run("a stale verdict never reaps a replaced track", func(t *testing.T) {
		ctx := context.Background()
		r, f, nw, _ := newReaperFixture(t)
		pod := runtimedPod("default", "web")
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		id := string(pod.UID)
		stale := r.trackByID(id)
		// An idempotent re-create installs a fresh track for the same id after
		// the verdict was reached against the old one.
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("re-CreatePod: %v", err)
		}
		fresh := r.trackByID(id)
		if fresh == stale {
			t.Fatal("fixture: re-create did not install a new track")
		}
		r.reapOrphan(ctx, pod, stale)
		if r.trackByID(id) != fresh {
			t.Fatal("the replacement track was forgotten by a stale reap")
		}
		if len(f.deletedIDs()) != 0 || nw.tornDown(id) {
			t.Fatalf("a stale reap ran teardown (delete RPCs %v)", f.deletedIDs())
		}
	})
}

// TestClientPodSourceIsNodeScoped pins the production source's List to ONE
// request carrying the spec.nodeName field selector.
func TestClientPodSourceIsNodeScoped(t *testing.T) {
	cs := k8sfake.NewClientset()
	var selectors []string
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		selectors = append(selectors, a.(k8stesting.ListAction).GetListRestrictions().Fields.String())
		return false, nil, nil
	})
	if _, err := newClientPodSource(cs).listNodePods(context.Background(), "mac-1"); err != nil {
		t.Fatalf("listNodePods: %v", err)
	}
	if !slices.Equal(selectors, []string{"spec.nodeName=mac-1"}) {
		t.Fatalf("List field selectors = %v, want [spec.nodeName=mac-1]", selectors)
	}
	if newClientPodSource(nil) != nil {
		t.Fatal("a nil client must disable the reaper (nil source)")
	}
}

func newReaperFixture(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer, *recordingNetwork, *fakePodSource) {
	t.Helper()
	f := newFakeRuntimeServer()
	nw := &recordingNetwork{}
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: testNodeIP,
		Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Network: nw,
	}, nil, nil)
	src := &fakePodSource{got: map[string]*corev1.Pod{}}
	r.podSource = src
	return r, f, nw, src
}
