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

package vkadapter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// statusTrace fails the node controller's status reads and writes on demand and
// records when each status post landed.
type statusTrace struct {
	mu       sync.Mutex
	fail     bool
	failures int
	posts    []time.Time
}

func (s *statusTrace) setFail(v bool) {
	s.mu.Lock()
	s.fail = v
	s.mu.Unlock()
}

func (s *statusTrace) counts() (failures int, posts []time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures, append([]time.Time(nil), s.posts...)
}

// waitFor polls cond until it holds, failing the test after stepTimeout.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(stepTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readyNode is the node a provider pushes: Ready with the given status.
func readyNode(name string, s corev1.ConditionStatus) *corev1.Node {
	n := defaultNodeSpec(name)
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: s}}
	return n
}

// startResyncNode runs a node with a supplied naive NodeProvider over a fake
// clientset whose node GETs and status PATCHes fail while the trace says so,
// pushes Ready=True once, and waits for that post to land.
func startResyncNode(t *testing.T, name string, timings nodeTimings) (*nodeHarness, *NaiveNodeProvider, *statusTrace) {
	t.Helper()
	h := newNodeHarness(t)
	tr := &statusTrace{}
	h.cs.PrependReactor("*", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		verb := a.GetVerb()
		if verb != "get" && verb != "patch" {
			return false, nil, nil
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		if tr.fail {
			tr.failures++
			return true, nil, errors.New("injected: path down")
		}
		if verb == "patch" && a.GetSubresource() == "status" {
			tr.posts = append(tr.posts, time.Now())
		}
		return false, nil, nil
	})
	np := NewNaiveNodeProvider()
	n, err := newNode(name, NodeConfig{
		Client:         h.cs,
		Provider:       newRecordingProvider(),
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
		NodeProvider:   func(*corev1.Node) (NodeProvider, error) { return np, nil },
		Log:            discardLogger(),
	}, timings)
	if err != nil {
		t.Fatalf("newNode: %v", err)
	}
	runNode(t, n)
	if err := np.UpdateStatus(context.Background(), readyNode(name, corev1.ConditionTrue)); err != nil {
		t.Fatalf("push Ready: %v", err)
	}
	waitFor(t, "the first status post", func() bool { return nodeReadyTrue(h, name) })
	return h, np, tr
}

// TestStatusPostedSoonAfterFailedPost: once the path returns, a status post
// that failed is retried within a resync check, not at the next status
// interval. The status interval is 100 times the resync interval, so a
// controller that waits for its interval misses the bound by seconds.
func TestStatusPostedSoonAfterFailedPost(t *testing.T) {
	const name = "k3sm-resync-fail"
	timings := nodeTimings{statusInterval: 5 * time.Second, resyncInterval: 50 * time.Millisecond}
	_, np, tr := startResyncNode(t, name, timings)

	tr.setFail(true)
	if err := np.UpdateStatus(context.Background(), readyNode(name, corev1.ConditionTrue)); err != nil {
		t.Fatalf("push Ready: %v", err)
	}
	waitFor(t, "a failed status post", func() bool { f, _ := tr.counts(); return f > 0 })
	// Stay down for a while, as a real outage would.
	time.Sleep(200 * time.Millisecond)

	_, before := tr.counts()
	recovered := time.Now()
	tr.setFail(false)
	waitFor(t, "a status post after the path returned", func() bool { _, p := tr.counts(); return len(p) > len(before) })
	_, after := tr.counts()
	if d := after[len(before)].Sub(recovered); d > time.Second {
		t.Fatalf("first status post landed %s after the path returned, want within ~2 resync intervals (%s)", d, timings.resyncInterval)
	}
}

// TestStatusPostedSoonAfterReadyRewritten: when the apiserver's Ready condition
// is not the provider's (the node lifecycle controller set it Unknown while the
// node was unreachable), the provider's status is posted within a resync check.
func TestStatusPostedSoonAfterReadyRewritten(t *testing.T) {
	const name = "k3sm-resync-unknown"
	timings := nodeTimings{statusInterval: 5 * time.Second, resyncInterval: 50 * time.Millisecond}
	h, _, _ := startResyncNode(t, name, timings)

	gvr := corev1.SchemeGroupVersion.WithResource("nodes")
	obj, err := h.cs.Tracker().Get(gvr, "", name)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	node := obj.(*corev1.Node).DeepCopy()
	for i := range node.Status.Conditions {
		if node.Status.Conditions[i].Type == corev1.NodeReady {
			node.Status.Conditions[i].Status = corev1.ConditionUnknown
		}
	}
	rewritten := time.Now()
	if err := h.cs.Tracker().Update(gvr, node, ""); err != nil {
		t.Fatalf("set Ready=Unknown: %v", err)
	}
	waitFor(t, "Ready=True posted again", func() bool { return nodeReadyTrue(h, name) })
	if d := time.Since(rewritten); d > time.Second {
		t.Fatalf("Ready returned to True %s after the apiserver marked it Unknown, want within ~2 resync intervals (%s)", d, timings.resyncInterval)
	}
}

// TestStatusSteadyStateCadence: with nothing failing and the apiserver agreeing
// with the provider, the resync check posts nothing of its own, so the node
// posts once per status interval.
func TestStatusSteadyStateCadence(t *testing.T) {
	const name = "k3sm-resync-steady"
	timings := nodeTimings{statusInterval: 200 * time.Millisecond, resyncInterval: 10 * time.Millisecond}
	_, _, tr := startResyncNode(t, name, timings)

	_, before := tr.counts()
	const window = time.Second
	time.Sleep(window)
	_, after := tr.counts()
	got := len(after) - len(before)
	// window/statusInterval = 5 posts; a resync that posted every check would
	// make about 100.
	if got < 3 || got > 7 {
		t.Fatalf("%d status posts in %s at a %s status interval, want about %d", got, window, timings.statusInterval, int(window/timings.statusInterval))
	}
}
