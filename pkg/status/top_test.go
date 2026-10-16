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

package status

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var topNow = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

const apiServiceAvailable = `{"status":{"conditions":[{"type":"Available","status":"True","reason":"Passed"}]}}`

func topNode(name string, cpu, mem string, controlPlane bool) corev1.Node {
	n := corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{}}}
	if controlPlane {
		n.Labels[controlPlaneNodeLabel] = ""
	}
	n.Status.Allocatable = corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(cpu),
		corev1.ResourceMemory: resource.MustParse(mem),
	}
	return n
}

func topPod(ns, name, node string, phase corev1.PodPhase) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	p.Spec.NodeName = node
	p.Status.Phase = phase
	return p
}

// topKube is a cluster of two nodes and four running pods, with metrics for
// node a and for three of the pods.
func topKube() fakeKube {
	return fakeKube{
		nodes: []corev1.Node{topNode("b", "4", "4Gi", false), topNode("a", "8", "16Gi", true)},
		pods: []corev1.Pod{
			topPod("default", "small-cpu-big-mem", "a", corev1.PodRunning),
			topPod("default", "big-cpu", "a", corev1.PodRunning),
			topPod("tools", "mid", "b", corev1.PodRunning),
			topPod("tools", "unsampled", "b", corev1.PodRunning),
			topPod("tools", "done", "b", corev1.PodFailed),
		},
		raw: map[string][]byte{
			metricsAPIServicePath: []byte(apiServiceAvailable),
			nodeMetricsPath:       []byte(`{"items":[{"metadata":{"name":"a"},"timestamp":"2026-10-16T11:59:45Z","usage":{"cpu":"2","memory":"4Gi"}}]}`),
			podMetricsPath: []byte(`{"items":[
				{"metadata":{"namespace":"default","name":"small-cpu-big-mem"},"timestamp":"2026-10-16T11:59:45Z","containers":[{"usage":{"cpu":"10m","memory":"900Mi"}}]},
				{"metadata":{"namespace":"default","name":"big-cpu"},"timestamp":"2026-10-16T11:59:45Z","containers":[{"usage":{"cpu":"500m","memory":"100Mi"}}]},
				{"metadata":{"namespace":"tools","name":"mid"},"timestamp":"2026-10-16T11:59:45Z","containers":[{"usage":{"cpu":"50m","memory":"300Mi"}}]}
			]}`),
		},
	}
}

func collectTop(k Kube, o TopOptions) TopReport {
	c := &TopCollector{Kube: k, Now: func() time.Time { return topNow }}
	return c.Collect(context.Background(), o)
}

func podNames(r TopReport) string {
	var names []string
	for _, p := range r.Pods {
		names = append(names, p.Name)
	}
	return strings.Join(names, ",")
}

// TestTopPodOrder pins the pod table's order: sampled pods by the chosen
// resource then the other, then unsampled pods; terminated pods never.
func TestTopPodOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		o    TopOptions
		want string
	}{
		{"cpu by default", TopOptions{}, "big-cpu,mid,small-cpu-big-mem,unsampled"},
		{"cpu", TopOptions{Sort: TopSortCPU}, "big-cpu,mid,small-cpu-big-mem,unsampled"},
		{"memory", TopOptions{Sort: TopSortMemory}, "small-cpu-big-mem,mid,big-cpu,unsampled"},
		{"namespace", TopOptions{Namespace: "tools"}, "mid,unsampled"},
		{"limit", TopOptions{Limit: 2}, "big-cpu,mid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := collectTop(topKube(), tc.o)
			if got := podNames(r); got != tc.want {
				t.Errorf("pods = %s, want %s", got, tc.want)
			}
		})
	}
	t.Run("limit keeps the total", func(t *testing.T) {
		t.Parallel()
		r := collectTop(topKube(), TopOptions{Limit: 2})
		if r.PodsTotal != 4 {
			t.Errorf("podsTotal = %d, want 4", r.PodsTotal)
		}
		if !strings.Contains(RenderTop(r, Style{}), "pods: 2 of 4 in all namespaces, by cpu\n") {
			t.Errorf("the pod header does not say the table was cut:\n%s", RenderTop(r, Style{}))
		}
	})
	t.Run("namespace leaves the node table whole", func(t *testing.T) {
		t.Parallel()
		r := collectTop(topKube(), TopOptions{Namespace: "tools"})
		if len(r.Nodes) != 2 || r.Nodes[0].Pods != 2 || r.Nodes[1].Pods != 2 {
			t.Errorf("nodes = %+v, want both nodes with their cluster-wide pod counts (2, 2)", r.Nodes)
		}
		if !strings.Contains(RenderTop(r, Style{}), "pods: 2 in namespace tools, by cpu\n") {
			t.Errorf("the pod header does not name the namespace:\n%s", RenderTop(r, Style{}))
		}
	})
}

// TestTopMissingSample: a node metrics-server has not sampled is a row that
// says so, with null usage in the JSON, not zero usage.
func TestTopMissingSample(t *testing.T) {
	t.Parallel()
	r := collectTop(topKube(), TopOptions{})
	if r.Nodes[0].Name != "a" || r.Nodes[1].Name != "b" {
		t.Fatalf("nodes not sorted by name: %+v", r.Nodes)
	}
	a, b := r.Nodes[0], r.Nodes[1]
	if !a.Sampled || *a.CPU.Percent != 25 || *a.Memory.Percent != 25 || *a.SampleAgeSeconds != 15 || a.Role != "server" {
		t.Errorf("node a = %+v, want sampled, 25%% cpu and memory, 15s old, server", a)
	}
	if b.Sampled || b.CPU.UsedMillicores != nil || b.SampleAgeSeconds != nil || b.Role != "agent" {
		t.Errorf("node b = %+v, want an unsampled agent with null usage", b)
	}
	screen := RenderTop(r, Style{})
	if !strings.Contains(screen, "\nb     agent   no metrics yet") {
		t.Errorf("the unsampled node does not say so:\n%s", screen)
	}
}

// TestTopUnavailableHeader pins the header line for every way the metrics API
// can be missing, and that the tables are still filled from the core API.
func TestTopUnavailableHeader(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		edit   func(*fakeKube)
		header string
	}{
		{"Available False", func(k *fakeKube) {
			k.raw[metricsAPIServicePath] = []byte(`{"status":{"conditions":[{"type":"Available","status":"False","reason":"FailedDiscoveryCheck","message":"failing or missing response from https://10.43.0.9:443"}]}}`)
		}, "metrics: unavailable (FailedDiscoveryCheck: failing or missing response from https://10.43.0.9:443); showing nodes and pods without usage"},
		{"no condition", func(k *fakeKube) {
			k.raw[metricsAPIServicePath] = []byte(`{"status":{}}`)
		}, "metrics: unavailable (NoCondition: the APIService v1beta1.metrics.k8s.io reports no Available condition yet); showing nodes and pods without usage"},
		{"forbidden", func(k *fakeKube) {
			k.rawErr = map[string]error{metricsAPIServicePath: errors.New("forbidden")}
		}, "metrics: unavailable (Unreadable: read the APIService v1beta1.metrics.k8s.io: forbidden); showing nodes and pods without usage"},
		{"metrics read fails", func(k *fakeKube) {
			k.rawErr = map[string]error{podMetricsPath: errors.New("the server is currently unable to handle the request")}
		}, "metrics: unavailable (ReadFailed: read /apis/metrics.k8s.io/v1beta1/pods: the server is currently unable to handle the request); showing nodes and pods without usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			k := topKube()
			tc.edit(&k)
			r := collectTop(k, TopOptions{})
			if r.Metrics.Available {
				t.Fatal("metrics reported available")
			}
			screen := RenderTop(r, Style{})
			if first, _, _ := strings.Cut(screen, "\n"); first != tc.header {
				t.Errorf("header = %q\nwant     %q", first, tc.header)
			}
			if len(r.Nodes) != 2 || r.PodsTotal != 4 {
				t.Errorf("tables not filled from the core API: %d nodes, %d pods", len(r.Nodes), r.PodsTotal)
			}
			for _, n := range r.Nodes {
				if n.Sampled {
					t.Errorf("node %s carries usage the header says is unavailable", n.Name)
				}
			}
			if !strings.Contains(screen, "\na     server  -/8000m  -     -/16384Mi  -     2     -\n") {
				t.Errorf("node row does not show allocatable without usage:\n%s", screen)
			}
		})
	}
}

// TestTopFailedReadIsNotRetriedEarly: a failed metrics read waits out the same
// interval as a good one, so a broken metrics API is not hammered every frame.
func TestTopFailedReadIsNotRetriedEarly(t *testing.T) {
	t.Parallel()
	calls := 0
	k := &hookKube{fakeKube: topKube(), onRaw: func(path string) error {
		if path == nodeMetricsPath {
			calls++
			return errors.New("timeout")
		}
		return nil
	}}
	now := topNow
	c := &TopCollector{Kube: k, Now: func() time.Time { return now }}
	for range 3 {
		c.Collect(context.Background(), TopOptions{})
		now = now.Add(2 * time.Second)
	}
	if calls != 1 {
		t.Errorf("node metrics reads over 0, 2, 4 s = %d, want 1", calls)
	}
}

// hookKube lets a test fail or count individual raw reads.
type hookKube struct {
	fakeKube
	onRaw func(path string) error
}

func (k *hookKube) RawGet(ctx context.Context, path string) ([]byte, error) {
	if err := k.onRaw(path); err != nil {
		return nil, err
	}
	return k.fakeKube.RawGet(ctx, path)
}

// TestTopJSONShape pins the keys a consumer reads, including the nulls of an
// unsampled row.
func TestTopJSONShape(t *testing.T) {
	t.Parallel()
	r := collectTop(topKube(), TopOptions{Namespace: "tools", Limit: 1})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schemaVersion", "timestamp", "metrics", "sort", "namespace", "limit", "nodes", "podsTotal", "pods"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing key %q in %s", key, b)
		}
	}
	nodeB := got["nodes"].([]any)[1].(map[string]any)
	if nodeB["sampleAgeSeconds"] != nil || nodeB["cpu"].(map[string]any)["usedMillicores"] != nil {
		t.Errorf("an unsampled node's usage is not null: %v", nodeB)
	}
	pod := got["pods"].([]any)[0].(map[string]any)
	for key, want := range map[string]any{"namespace": "tools", "name": "mid", "node": "b", "sampled": true, "cpuMillicores": 50.0, "memoryBytes": 314572800.0, "restarts": 0.0} {
		if pod[key] != want {
			t.Errorf("pod %s = %v, want %v", key, pod[key], want)
		}
	}
}
