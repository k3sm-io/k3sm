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

package operator

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/interconnect"
	"k3sm.io/k3sm/pkg/mlx"
)

// desiredListing is a node's desired annotation as the interconnect resolver
// writes it for an armed member: the given models are the interconnect MLXModels.
func desiredListing(t *testing.T, models ...*mlxv1alpha1.MLXModel) string {
	t.Helper()
	d := netv1alpha1.InterconnectDesired{
		Schema:       netv1alpha1.InterconnectAnnotationSchema,
		Interconnect: interconnect.Name,
		Fallback:     netv1alpha1.InterconnectFallbackNetwork,
	}
	for _, m := range models {
		d.MLXModels = append(d.MLXModels, netv1alpha1.InterconnectModelRef{Namespace: m.Namespace, Name: m.Name, UID: string(m.UID)})
	}
	v, err := d.Encode()
	if err != nil {
		t.Fatalf("encode desired annotation: %v", err)
	}
	return v
}

// setDesired rewrites a node's desired annotation, standing in for the
// interconnect resolver.
func (h *harness) setDesired(t *testing.T, node, value string) {
	t.Helper()
	n, err := h.kube.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	metav1.SetMetaDataAnnotation(&n.ObjectMeta, netv1alpha1.AnnotationInterconnectDesired, value)
	if _, err := h.kube.CoreV1().Nodes().Update(context.Background(), n, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// setPath rewrites the seeded model's spec.distributed.interconnect.
func (h *harness) setPath(t *testing.T, path mlxv1alpha1.MLXInterconnect) {
	t.Helper()
	res := h.dyn.Resource(mlxModelResource).Namespace(testNamespace)
	raw, err := res.Get(context.Background(), testModelName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := toModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	m.Spec.Distributed.Interconnect = path
	u, err := toUnstructured(m)
	if err != nil {
		t.Fatal(err)
	}
	u.SetResourceVersion(raw.GetResourceVersion())
	if _, err := res.Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// requeue is one AddAfter the controller made.
type requeue struct {
	key   string
	after time.Duration
}

// recordingQueue records AddAfter instead of scheduling it; the test drives
// reconciles by hand.
type recordingQueue struct {
	workqueue.TypedRateLimitingInterface[string]
	mu    sync.Mutex
	added []requeue
}

func (q *recordingQueue) AddAfter(key string, after time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.added = append(q.added, requeue{key, after})
}

// take returns and clears what was recorded.
func (q *recordingQueue) take() []requeue {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := q.added
	q.added = nil
	return out
}

// recordRequeues swaps the controller's queue for a recording one.
func (h *harness) recordRequeues() *recordingQueue {
	q := &recordingQueue{TypedRateLimitingInterface: h.ctrl.queue}
	h.ctrl.queue = q
	return q
}

// TestThunderboltFlipWaitsForDesiredAnnotation pins that a gang resolved onto
// the thunderbolt path is not placed until every node it would place a rank on
// lists the model in its desired annotation. Before that, the node's provider
// would give the rank a general interconnect slot while K3SM_MLX_HOSTS names
// the MLX slot, and the rank would refuse to start.
func TestThunderboltFlipWaitsForDesiredAnnotation(t *testing.T) {
	nw, tb := mlxv1alpha1.MLXInterconnectNetwork, mlxv1alpha1.MLXInterconnectThunderbolt
	h := shardedHarness(t, interconnectModel(nw), twoMacs(),
		thunderbolt(netv1alpha1.InterconnectFallbackNetwork, up("mac-a", "seg-0"), up("mac-b", "seg-0")))
	// The resolver's view of a model on the network: both nodes are armed
	// members, and the model is not an interconnect MLXModel.
	for _, n := range []string{"mac-a", "mac-b"} {
		h.setDesired(t, n, desiredListing(t))
	}
	q := h.recordRequeues()
	h.reconcile(t)
	h.markRanks(t, true)
	h.reconcile(t)
	if got := h.gangPath(t); got != nw {
		t.Fatalf("precondition: gang path %q, want network", got)
	}

	// The flip: the gang restarts from the older spec, then places afresh.
	h.setPath(t, tb)
	h.reconcile(t)
	if n := len(h.rankPods(t)); n != 0 {
		t.Fatalf("precondition: %d rank pods survived the spec change, want a gang restart", n)
	}
	q.take()
	h.reconcile(t)
	if n := len(h.rankPods(t)); n != 0 {
		t.Fatalf("%d rank pods created before the nodes' desired annotation lists the model, want none", n)
	}
	if got := q.take(); !containsRequeue(got, requeue{key(), placementRetry}) {
		t.Errorf("requeues = %v, want %s after %s", got, key(), placementRetry)
	}
	s := h.status(t)
	placed := condition(t, s, mlx.ConditionShardsPlaced)
	if placed.Status != metav1.ConditionFalse || placed.Reason != mlx.ReasonAwaitingInterconnectSlot ||
		!strings.Contains(placed.Message, "mac-a, mac-b") {
		t.Errorf("ShardsPlaced = %s/%s %q, want False/%s naming mac-a, mac-b",
			placed.Status, placed.Reason, placed.Message, mlx.ReasonAwaitingInterconnectSlot)
	}
	if s.Phase != mlxv1alpha1.MLXModelPhasePending {
		t.Errorf("phase = %s, want Pending", s.Phase)
	}

	// One node caught up is not enough: the gang is all or nothing.
	h.setDesired(t, "mac-a", desiredListing(t, model()))
	h.reconcile(t)
	if n := len(h.rankPods(t)); n != 0 {
		t.Fatalf("%d rank pods created while mac-b's desired annotation lacks the model, want none", n)
	}
	if placed := condition(t, h.status(t), mlx.ConditionShardsPlaced); !strings.Contains(placed.Message, "(mac-b)") {
		t.Errorf("ShardsPlaced message %q, want it to name only mac-b", placed.Message)
	}

	// The resolver publishes the model on both nodes: the gang is placed.
	h.setDesired(t, "mac-b", desiredListing(t, model()))
	h.reconcile(t)
	if got := h.gangPath(t); got != tb {
		t.Fatalf("gang path %q once the annotation lists the model, want thunderbolt", got)
	}
}

func containsRequeue(got []requeue, want requeue) bool {
	for _, r := range got {
		if r == want {
			return true
		}
	}
	return false
}
