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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/mlx/topology"
)

// mutableTopology is a fake Topology a test can re-cable between reconciles.
type mutableTopology struct {
	mu sync.Mutex
	g  topology.Graph
}

func (m *mutableTopology) Graph(context.Context) (topology.Graph, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.g, nil
}

func (m *mutableTopology) set(g topology.Graph) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.g = g
}

// shardedHarness wires a controller over a sharded model, the given nodes and
// a re-cablable topology.
func shardedHarness(t *testing.T, m *mlxv1alpha1.MLXModel, nodes []corev1.Node, g topology.Graph) (*harness, *mutableTopology) {
	t.Helper()
	topo := &mutableTopology{g: g}
	h := newHarness(t, m, func(c *Config) { c.Topology = topo })
	for i := range nodes {
		if _, err := h.kube.CoreV1().Nodes().Create(context.Background(), &nodes[i], metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed node: %v", err)
		}
	}
	return h, topo
}

func shardedModel(ranks int32, backend mlxv1alpha1.MLXDistributedBackend) *mlxv1alpha1.MLXModel {
	return model(func(m *mlxv1alpha1.MLXModel) {
		m.Spec.Memory = resource.MustParse("48Gi")
		m.Spec.Distributed = &mlxv1alpha1.MLXDistributed{Ranks: ranks, Backend: backend}
	})
}

// rankPods reads back the rank Pods, sorted by name.
func (h *harness) rankPods(t *testing.T) []corev1.Pod {
	t.Helper()
	pods, err := h.ctrl.rankPods(context.Background(), model())
	if err != nil {
		t.Fatalf("list rank pods: %v", err)
	}
	return pods
}

// markRanks sets every rank Pod Running and Ready, standing in for the kubelet.
func (h *harness) markRanks(t *testing.T, ready bool) {
	t.Helper()
	for _, pod := range h.rankPods(t) {
		pod.Status.Phase = corev1.PodRunning
		pod.Status.PodIP = "10.42.0.9"
		cs := corev1.ConditionFalse
		if ready {
			cs = corev1.ConditionTrue
		}
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: cs}}
		if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("update pod status: %v", err)
		}
	}
}

// condition returns a status condition or fails.
func condition(t *testing.T, s mlxv1alpha1.MLXModelStatus, typ string) metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(s.Conditions, typ)
	if c == nil {
		t.Fatalf("no %s condition in %+v", typ, s.Conditions)
	}
	return *c
}

func twoMacs() []corev1.Node {
	return []corev1.Node{gpuNode("mac-a", "64Gi", false), gpuNode("mac-b", "64Gi", false)}
}

// TestShardedReconcilePlacesRankPods: a placeable two-rank ring becomes two
// owned rank Pods bound to their nodes, the Services with rank 0 behind the
// ClusterIP one, NO StatefulSet, and ShardsPlaced=True while Ready waits for
// every rank.
func TestShardedReconcilePlacesRankPods(t *testing.T) {
	h, _ := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(),
		cable(topology.Graph{}, "mac-a", "mac-b", false))
	h.reconcile(t)

	if h.statefulSet(t) != nil {
		t.Error("a StatefulSet was applied for a sharded model")
	}
	pods := h.rankPods(t)
	if len(pods) != 2 {
		t.Fatalf("%d rank pods, want 2", len(pods))
	}
	for i, pod := range pods {
		if pod.Name != mlx.RankPodName(testModelName, i) || pod.Spec.NodeName != []string{"mac-a", "mac-b"}[i] {
			t.Errorf("rank %d = %s on %s", i, pod.Name, pod.Spec.NodeName)
		}
		assertOwnedByModel(t, "rank pod", pod.OwnerReferences)
	}
	svc, err := h.kube.CoreV1().Services(testNamespace).Get(context.Background(), mlx.ServiceName(testModelName), metav1.GetOptions{})
	if err != nil || svc.Spec.Selector[mlx.LabelRank] != "0" {
		t.Errorf("ClusterIP Service = %v, %v; want a selector narrowed to rank 0", svc, err)
	}

	s := h.status(t)
	if c := condition(t, s, mlx.ConditionShardsPlaced); c.Status != metav1.ConditionTrue || c.Reason != mlx.ReasonPlaced {
		t.Errorf("ShardsPlaced = %s/%s, want True/Placed", c.Status, c.Reason)
	}
	if c := condition(t, s, mlx.ConditionLinksHealthy); c.Status != metav1.ConditionTrue {
		t.Errorf("LinksHealthy = %s/%s %q, want True", c.Status, c.Reason, c.Message)
	}
	if c := condition(t, s, mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionFalse {
		t.Errorf("Ready = %s before any rank runs", c.Status)
	}
	if s.Phase != mlxv1alpha1.MLXModelPhasePending || s.Endpoint != "" {
		t.Errorf("phase/endpoint = %s/%q, want Pending and no endpoint", s.Phase, s.Endpoint)
	}
}

// TestShardedReadyNeedsEveryRank: Ready is True only when ALL ranks are ready,
// and only then is the endpoint published.
func TestShardedReadyNeedsEveryRank(t *testing.T) {
	h, _ := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(), topology.Graph{})
	h.reconcile(t)

	// Rank 0 ready, rank 1 still not.
	h.markRanks(t, false)
	pod := h.rankPods(t)[0]
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionFalse {
		t.Errorf("Ready = %s with one of two ranks ready, want False", c.Status)
	}

	h.markRanks(t, true)
	h.reconcile(t)
	s := h.status(t)
	if c := condition(t, s, mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "2 of 2 ranks") {
		t.Errorf("Ready = %s %q, want True over 2 of 2 ranks", c.Status, c.Message)
	}
	if s.Phase != mlxv1alpha1.MLXModelPhaseReady || s.Endpoint == "" {
		t.Errorf("phase/endpoint = %s/%q, want Ready and the endpoint", s.Phase, s.Endpoint)
	}
}

// TestShardedGangRestart: losing any rank — deleted, ended, on a NotReady
// node, or rendered from an older spec — deletes the survivors, and the next
// reconcile with no rank left re-places every rank. A partial gang never
// serves.
func TestShardedGangRestart(t *testing.T) {
	cases := []struct {
		name  string
		lose  func(t *testing.T, h *harness)
		cause string
	}{
		{"rank_deleted", func(t *testing.T, h *harness) {
			if err := h.kube.CoreV1().Pods(testNamespace).Delete(context.Background(), mlx.RankPodName(testModelName, 1), metav1.DeleteOptions{}); err != nil {
				t.Fatal(err)
			}
		}, "missing"},
		{"rank_failed", func(t *testing.T, h *harness) {
			pod := h.rankPods(t)[1]
			pod.Status.Phase = corev1.PodFailed
			if _, err := h.kube.CoreV1().Pods(testNamespace).UpdateStatus(context.Background(), &pod, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}, "ended"},
		{"node_not_ready", func(t *testing.T, h *harness) {
			node, err := h.kube.CoreV1().Nodes().Get(context.Background(), "mac-b", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			node.Status.Conditions[0].Status = corev1.ConditionUnknown
			if _, err := h.kube.CoreV1().Nodes().UpdateStatus(context.Background(), node, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}, "NotReady"},
		{"spec_changed", func(t *testing.T, h *harness) {
			raw, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(context.Background(), testModelName, metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			m, _ := toModel(raw)
			m.Spec.Runtime.Args = []string{"--temp", "0"}
			u, _ := toUnstructured(m)
			u.SetResourceVersion(raw.GetResourceVersion())
			if _, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
		}, "older spec"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing),
				append(twoMacs(), gpuNode("mac-c", "64Gi", false)), topology.Graph{})
			h.reconcile(t)
			h.markRanks(t, true)
			h.reconcile(t)
			if c := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); c.Status != metav1.ConditionTrue {
				t.Fatalf("precondition: Ready = %s", c.Status)
			}
			first := map[string]string{}
			for _, p := range h.rankPods(t) {
				first[p.Name] = string(p.UID) + p.Annotations[mlx.AnnotationSpecHash]
			}

			tc.lose(t, h)
			h.reconcile(t)
			if left := h.rankPods(t); len(left) != 0 {
				t.Errorf("%d rank pods survived the gang restart, want 0", len(left))
			}
			s := h.status(t)
			c := condition(t, s, mlxv1alpha1.MLXModelConditionReady)
			if c.Status != metav1.ConditionFalse || !strings.Contains(c.Message, "gang restart") || !strings.Contains(c.Message, tc.cause) {
				t.Errorf("Ready during restart = %s %q, want False naming a gang restart (%s)", c.Status, c.Message, tc.cause)
			}
			if s.Endpoint != "" {
				t.Errorf("endpoint %q published during a gang restart", s.Endpoint)
			}

			h.reconcile(t)
			again := h.rankPods(t)
			if len(again) != 2 {
				t.Fatalf("%d rank pods after re-placement, want 2", len(again))
			}
			for _, p := range again {
				if first[p.Name] == string(p.UID)+p.Annotations[mlx.AnnotationSpecHash] && tc.name == "spec_changed" {
					t.Errorf("rank pod %s was not re-rendered from the new spec", p.Name)
				}
				if p.Spec.NodeName == "mac-b" && tc.name == "node_not_ready" {
					t.Errorf("rank pod %s was re-placed onto the NotReady node", p.Name)
				}
			}
		})
	}
}

// TestShardedRefusalsAreStatuses: a cluster that cannot hold the gang, or a
// spec the sharded engine refuses, is a status with no rank Pod and no
// single-node fallback.
func TestShardedRefusalsAreStatuses(t *testing.T) {
	cases := []struct {
		name       string
		model      *mlxv1alpha1.MLXModel
		nodes      []corev1.Node
		wantReason string
		wantMsg    string
		wantPhase  mlxv1alpha1.MLXModelPhase
	}{
		{"no_rdma_clique_for_jaccl", shardedModel(2, mlxv1alpha1.MLXDistributedBackendJACCL), twoMacs(),
			mlx.ReasonNoDirectLinkTopology, "no rdma clique of 2", mlxv1alpha1.MLXModelPhasePending},
		{"one_gpu_node", shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs()[:1],
			mlx.ReasonNoDirectLinkTopology, "found 1", mlxv1alpha1.MLXModelPhasePending},
		{"share_does_not_fit", shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing),
			[]corev1.Node{gpuNode("mac-a", "8Gi", false), gpuNode("mac-b", "8Gi", false)},
			mlx.ReasonInsufficientMemory, "0 of 2 candidate nodes", mlxv1alpha1.MLXModelPhasePending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := shardedHarness(t, tc.model, tc.nodes, topology.Graph{})
			h.reconcile(t)
			if n := len(h.rankPods(t)); n != 0 || h.statefulSet(t) != nil {
				t.Errorf("objects created for an unplaceable model: %d rank pods, statefulset %v", n, h.statefulSet(t) != nil)
			}
			s := h.status(t)
			c := condition(t, s, mlx.ConditionShardsPlaced)
			if c.Status != metav1.ConditionFalse || c.Reason != tc.wantReason || !strings.Contains(c.Message, tc.wantMsg) {
				t.Errorf("ShardsPlaced = %s/%s %q, want False/%s containing %q", c.Status, c.Reason, c.Message, tc.wantReason, tc.wantMsg)
			}
			if r := condition(t, s, mlxv1alpha1.MLXModelConditionReady); r.Reason != tc.wantReason {
				t.Errorf("Ready reason = %s, want %s", r.Reason, tc.wantReason)
			}
			if s.Phase != tc.wantPhase {
				t.Errorf("phase = %s, want %s", s.Phase, tc.wantPhase)
			}
		})
	}

	t.Run("gpu_held_by_another_model", func(t *testing.T) {
		h, _ := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(), topology.Graph{})
		other := gpuPod("elsewhere", "other-model-0", "mac-b", 1)
		if _, err := h.kube.CoreV1().Pods(other.Namespace).Create(context.Background(), &other, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed pod: %v", err)
		}
		h.reconcile(t)
		if n := len(h.rankPods(t)); n != 0 {
			t.Errorf("%d rank pods created onto a held GPU", n)
		}
		s := h.status(t)
		c := condition(t, s, mlx.ConditionShardsPlaced)
		if c.Status != metav1.ConditionFalse || c.Reason != mlx.ReasonInsufficientGPU || !strings.Contains(c.Message, "(mac-b)") {
			t.Errorf("ShardsPlaced = %s/%s %q, want False/%s naming mac-b", c.Status, c.Reason, c.Message, mlx.ReasonInsufficientGPU)
		}
		if s.Phase != mlxv1alpha1.MLXModelPhasePending {
			t.Errorf("phase = %s, want Pending", s.Phase)
		}
	})

	t.Run("two_replicas_is_an_invalid_spec", func(t *testing.T) {
		m := shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing)
		m.Spec.Replicas = ptr.To(int32(2))
		h, _ := shardedHarness(t, m, twoMacs(), topology.Graph{})
		h.reconcile(t)
		if r := condition(t, h.status(t), mlxv1alpha1.MLXModelConditionReady); r.Reason != ReasonInvalidSpec {
			t.Errorf("Ready reason = %s, want %s", r.Reason, ReasonInvalidSpec)
		}
		if len(h.rankPods(t)) != 0 {
			t.Error("rank pods created for an invalid spec")
		}
	})
}

// TestShardedLinksHealthy: a placed link going down flips LinksHealthy to
// LinkDegraded naming the link, while a ring gang keeps serving.
func TestShardedLinksHealthy(t *testing.T) {
	h, topo := shardedHarness(t, shardedModel(2, mlxv1alpha1.MLXDistributedBackendRing), twoMacs(),
		cable(topology.Graph{}, "mac-a", "mac-b", false))
	h.reconcile(t)
	h.markRanks(t, true)
	h.reconcile(t)
	if c := condition(t, h.status(t), mlx.ConditionLinksHealthy); c.Status != metav1.ConditionTrue || !strings.Contains(c.Message, "all 1 placed") {
		t.Fatalf("LinksHealthy = %s %q, want True over 1 link", c.Status, c.Message)
	}

	topo.set(topology.Graph{})
	h.reconcile(t)
	s := h.status(t)
	c := condition(t, s, mlx.ConditionLinksHealthy)
	if c.Status != metav1.ConditionFalse || c.Reason != mlx.ReasonLinkDegraded || !strings.Contains(c.Message, "mac-a/mac-b") || !strings.Contains(c.Message, "ring keeps serving") {
		t.Errorf("LinksHealthy = %s/%s %q, want False/LinkDegraded naming mac-a/mac-b", c.Status, c.Reason, c.Message)
	}
	if r := condition(t, s, mlxv1alpha1.MLXModelConditionReady); r.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %s; a ring gang keeps serving over the mesh", r.Status)
	}
	if len(h.rankPods(t)) != 2 {
		t.Error("a degraded link restarted the gang")
	}
}

// TestShardedReplacesTheSingleNodeShape: a model that switches to sharded
// loses its StatefulSet; switching back loses its rank Pods.
func TestShardedReplacesTheSingleNodeShape(t *testing.T) {
	h, _ := shardedHarness(t, model(), twoMacs(), topology.Graph{})
	h.reconcile(t)
	if h.statefulSet(t) == nil {
		t.Fatal("precondition: no StatefulSet for the single-node model")
	}

	raw, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(context.Background(), testModelName, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	m, _ := toModel(raw)
	m.Spec.Memory = resource.MustParse("48Gi")
	m.Spec.Distributed = &mlxv1alpha1.MLXDistributed{Ranks: 2}
	u, _ := toUnstructured(m)
	if _, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	if h.statefulSet(t) != nil {
		t.Error("the single-node StatefulSet survived the switch to sharded")
	}
	if len(h.rankPods(t)) != 2 {
		t.Errorf("%d rank pods after the switch, want 2", len(h.rankPods(t)))
	}

	raw, _ = h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Get(context.Background(), testModelName, metav1.GetOptions{})
	m, _ = toModel(raw)
	m.Spec.Distributed = nil
	u, _ = toUnstructured(m)
	if _, err := h.dyn.Resource(mlxModelResource).Namespace(testNamespace).Update(context.Background(), u, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	h.reconcile(t)
	if len(h.rankPods(t)) != 0 {
		t.Error("rank pods survived the switch back to single-node")
	}
	if h.statefulSet(t) == nil {
		t.Error("no StatefulSet after the switch back")
	}
}

// TestDirectLinkTopologyReadsResolvedStatus: the production Topology lists the
// DirectLink objects and builds the graph from their up ports; a cluster
// without the CRD has an empty graph.
func TestDirectLinkTopologyReadsResolvedStatus(t *testing.T) {
	gvrs := map[schema.GroupVersionResource]string{directLinkResource: "DirectLinkList"}
	up := netv1alpha1.DirectLinkStateUp
	mk := func(node, iface, peer, peerIface string) *unstructured.Unstructured {
		dl := &netv1alpha1.DirectLink{
			TypeMeta:   metav1.TypeMeta{APIVersion: netv1alpha1.SchemeGroupVersion.String(), Kind: "DirectLink"},
			ObjectMeta: metav1.ObjectMeta{Name: node},
			Spec: netv1alpha1.DirectLinkSpec{SchemaVersion: 1, NodeName: node, Medium: netv1alpha1.MediumThunderbolt,
				Ports: []netv1alpha1.DirectLinkPort{{Iface: iface, DomainUUID: node + iface, SpeedGbps: 40}}},
			Status: netv1alpha1.DirectLinkStatus{Ports: []netv1alpha1.DirectLinkPortStatus{
				{Iface: iface, PeerNodeName: peer, PeerIface: peerIface, State: up}}},
		}
		obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(dl)
		if err != nil {
			t.Fatal(err)
		}
		return &unstructured.Unstructured{Object: obj}
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrs,
		mk("mac-a", "en2", "mac-b", "en1"), mk("mac-b", "en1", "mac-a", "en2"))
	g, err := directLinkTopology{dyn: dyn}.Graph(context.Background())
	if err != nil {
		t.Fatalf("Graph() error = %v", err)
	}
	if e, ok := g.Edge("mac-a", "mac-b"); !ok || e.LocalIface != "en2" || e.PeerIface != "en1" || e.SpeedGbps != 40 {
		t.Errorf("edge mac-a->mac-b = %+v, %v", e, ok)
	}
}
