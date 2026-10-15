//go:build e2e

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

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// msControlPlaneLabel is the role label each server sets on its own Node and
	// the add-on pins to.
	msControlPlaneLabel = "node-role.kubernetes.io/control-plane"
	// msNodesEnv names the nodes whose metrics must be served, comma-separated.
	// Unset: every Ready node.
	msNodesEnv = "K3SM_METRICS_NODES"
	// msScrapeWindow bounds the wait for two scrape cycles per node; the add-on
	// scrapes every 15s and computes CPU as a rate over two samples.
	msScrapeWindow = 4 * time.Minute
)

// msNodeMetrics is the metrics.k8s.io/v1beta1 NodeMetricsList subset read here.
// k3sm takes no metrics client dependency for one list.
type msNodeMetrics struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Timestamp time.Time         `json:"timestamp"`
		Usage     map[string]string `json:"usage"`
	} `json:"items"`
}

// TestMetricsServerAddonNativeReady is the real-cluster half of the native
// metrics-server add-on: on a multi-node (mesh) cluster the embedded add-on's pod
// is Ready as a native pod (no runtimeClassName) on a server node, the
// v1beta1.metrics.k8s.io APIService is Available, and, after two scrape cycles,
// the NodeMetrics list carries CPU and memory for EACH named Ready node, worker
// included. One read is never enough: metrics-server computes CPU as a rate over
// two samples, so each node must show two distinct sample times before its usage
// is judged.
func TestMetricsServerAddonNativeReady(t *testing.T) {
	c := Up(t)
	ctx := context.Background()

	nodes := msNamedReadyNodes(t, c)

	t.Run("the pod is Ready, native, on a server node", func(t *testing.T) {
		pod := msWaitAddonPodReady(t, c, 5*time.Minute)
		if pod.Spec.RuntimeClassName != nil {
			t.Errorf("pod %s runtimeClassName = %q, want none (native)", pod.Name, *pod.Spec.RuntimeClassName)
		}
		n, err := c.Client.CoreV1().Nodes().Get(ctx, pod.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get node %s: %v", pod.Spec.NodeName, err)
		}
		if n.Labels[msControlPlaneLabel] != "true" {
			t.Errorf("pod %s runs on %s, which does not carry %s=true", pod.Name, n.Name, msControlPlaneLabel)
		}
		t.Logf("metrics-server pod %s Ready on server node %s (pod IP %s)", pod.Name, n.Name, pod.Status.PodIP)
	})

	t.Run("the APIService is Available", func(t *testing.T) {
		deadline := time.Now().Add(3 * time.Minute)
		for {
			ok, detail := msAPIServiceAvailable(ctx, c)
			if ok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("v1beta1.metrics.k8s.io is not Available after 3m: %s", detail)
			}
			time.Sleep(5 * time.Second)
		}
	})

	t.Run("each named node has CPU and memory after two scrape cycles", func(t *testing.T) {
		first := map[string]time.Time{}
		done := map[string]bool{}
		deadline := time.Now().Add(msScrapeWindow)
		for len(done) < len(nodes) {
			if time.Now().After(deadline) {
				var missing []string
				for _, n := range nodes {
					if !done[n] {
						missing = append(missing, n)
					}
				}
				t.Fatalf("after %s, no second scrape with CPU and memory for %v", msScrapeWindow, missing)
			}
			raw, err := c.Client.Discovery().RESTClient().Get().AbsPath("/apis/metrics.k8s.io/v1beta1/nodes").DoRaw(ctx)
			if err != nil {
				t.Logf("list NodeMetrics: %v (retrying)", err)
				time.Sleep(5 * time.Second)
				continue
			}
			var list msNodeMetrics
			if err := json.Unmarshal(raw, &list); err != nil {
				t.Fatalf("decode NodeMetrics: %v\n%s", err, raw)
			}
			for _, it := range list.Items {
				name := it.Metadata.Name
				if done[name] || !slices.Contains(nodes, name) {
					continue
				}
				f, seen := first[name]
				if !seen {
					first[name] = it.Timestamp
					continue
				}
				if !it.Timestamp.After(f) {
					continue
				}
				cpu, cerr := resource.ParseQuantity(it.Usage["cpu"])
				mem, merr := resource.ParseQuantity(it.Usage["memory"])
				if cerr != nil || merr != nil || cpu.IsZero() || mem.IsZero() {
					t.Errorf("node %s second sample at %s: usage %v, want non-zero cpu AND memory", name, it.Timestamp, it.Usage)
				} else {
					t.Logf("node %s: cpu %s memory %s (samples at %s and %s)", name, cpu.String(), mem.String(), f.Format(time.RFC3339), it.Timestamp.Format(time.RFC3339))
				}
				done[name] = true
			}
			time.Sleep(5 * time.Second)
		}
	})
}

// msNamedReadyNodes is the node set the scrape is judged over: $K3SM_METRICS_NODES
// when set (each must exist and be Ready), else every Ready node. A cluster with
// fewer than two nodes is refused: the native add-on exists to scrape a worker.
func msNamedReadyNodes(t *testing.T, c *Cluster) []string {
	t.Helper()
	list, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	ready := map[string]bool{}
	var all []string
	for _, n := range list.Items {
		for _, cond := range n.Status.Conditions {
			if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
				ready[n.Name] = true
				all = append(all, n.Name)
			}
		}
	}
	names := all
	if v := os.Getenv(msNodesEnv); v != "" {
		names = strings.Split(v, ",")
		for _, n := range names {
			if !ready[n] {
				t.Fatalf("%s names %s, which is not a Ready node (Ready: %v)", msNodesEnv, n, all)
			}
		}
	}
	if len(names) < 2 {
		t.Fatalf("%d Ready nodes named (%v); this test needs a server and a worker", len(names), names)
	}
	return names
}

// msWaitAddonPodReady waits for exactly one Ready metrics-server pod in
// kube-system and returns it.
func msWaitAddonPodReady(t *testing.T, c *Cluster, timeout time.Duration) *corev1.Pod {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pods, err := c.Client.CoreV1().Pods("kube-system").List(context.Background(), metav1.ListOptions{LabelSelector: "k8s-app=metrics-server"})
		if err == nil {
			for i := range pods.Items {
				p := &pods.Items[i]
				if p.DeletionTimestamp != nil {
					continue
				}
				for _, cond := range p.Status.Conditions {
					if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
						return p
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Ready metrics-server pod in kube-system after %s (last list err %v)", timeout, err)
		}
		time.Sleep(5 * time.Second)
	}
}

// msAPIServiceAvailable reads the APIService's Available condition raw (k3sm
// takes no kube-aggregator client dependency for one object).
func msAPIServiceAvailable(ctx context.Context, c *Cluster) (bool, string) {
	raw, err := c.Client.Discovery().RESTClient().Get().AbsPath("/apis/apiregistration.k8s.io/v1/apiservices/v1beta1.metrics.k8s.io").DoRaw(ctx)
	if err != nil {
		return false, err.Error()
	}
	var a struct {
		Status struct {
			Conditions []struct {
				Type, Status, Reason, Message string
			} `json:"conditions"`
		} `json:"status"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return false, err.Error()
	}
	for _, cond := range a.Status.Conditions {
		if cond.Type == "Available" {
			return cond.Status == "True", cond.Reason + ": " + cond.Message
		}
	}
	return false, "no Available condition yet"
}
