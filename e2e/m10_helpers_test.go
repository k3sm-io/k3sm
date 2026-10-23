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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Shared fixtures for the M10 criteria (m10_perpodip_test.go,
// m10_events_test.go, m10_crashloop_test.go, m10_job_test.go,
// m10_sidecar_test.go, m10_ingress_test.go).
//
// Every criterion runs in its own namespace, minted per run by m10Namespace
// and deleted by a t.Cleanup registered before the create, so a run leaves
// nothing behind and two runs never meet. Every pod is pinned to ONE node
// (m10Node) by nodeName AND the darwin nodeSelector, and tolerates only the
// provider taint (keyed), never `operator: Exists`: a blanket toleration would
// defeat an operator's cordon or NoExecute taint on another node.
//
// The workloads are /bin/sh scripts over the node's own binaries (sh, sleep,
// nc, dig), so no fixture binary has to be readable by the node's pod user.

// m10Node returns the node the criteria pin their pods to: $K3SM_E2E_NODE, or
// the cluster's only node when it has exactly one. On a multi-node cluster the
// node must be named, because a criterion that picked one itself could land on
// a node the operator has reserved.
func m10Node(t *testing.T, c *Cluster) string {
	t.Helper()
	if name := os.Getenv("K3SM_E2E_NODE"); name != "" {
		if _, err := c.Client.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{}); err != nil {
			t.Fatalf("get node %s ($K3SM_E2E_NODE): %v", name, err)
		}
		return name
	}
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if len(nodes.Items) != 1 {
		t.Fatalf("set K3SM_E2E_NODE: the cluster has %d nodes, so the node under test is ambiguous", len(nodes.Items))
	}
	return nodes.Items[0].Name
}

// m10NodeIP returns the InternalIP of node.
func m10NodeIP(t *testing.T, c *Cluster, node string) string {
	t.Helper()
	n, err := c.Client.CoreV1().Nodes().Get(context.Background(), node, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get node %s: %v", node, err)
	}
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP && a.Address != "" {
			return a.Address
		}
	}
	t.Fatalf("node %s has no InternalIP: %+v", node, n.Status.Addresses)
	return ""
}

// m10Namespace creates a namespace named for the running test plus a random
// suffix and registers its deletion (foreground, waited on, bounded) BEFORE the
// create, so a create that is abandoned by a t.Fatalf still cleans up.
func m10Namespace(t *testing.T, c *Cluster) string {
	t.Helper()
	ns := runSuffix(t)
	t.Cleanup(func() {
		ctx := context.Background()
		policy := metav1.DeletePropagationForeground
		err := c.Client.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{PropagationPolicy: &policy})
		if err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("cleanup: delete namespace %s: %v", ns, err)
			return
		}
		if !pollUntil(3*time.Minute, func() bool {
			_, err := c.Client.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
			return apierrors.IsNotFound(err)
		}) {
			t.Logf("cleanup: namespace %s still terminating after 3m; it is uniquely named, so no rerun can meet it", ns)
		}
	})
	if _, err := c.Client.CoreV1().Namespaces().Create(context.Background(), &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace %s: %v", ns, err)
	}
	return ns
}

// m10PodSpec is the pinned pod spec every M10 criterion builds on: nodeName AND
// the darwin nodeSelector, the keyed provider toleration only, one container
// "c" running script under /bin/sh.
func m10PodSpec(node string, policy corev1.RestartPolicy, script string) corev1.PodSpec {
	return corev1.PodSpec{
		NodeName:      node,
		NodeSelector:  map[string]string{"kubernetes.io/os": "darwin"},
		Tolerations:   []corev1.Toleration{{Key: "k3sm.io/provider", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		RestartPolicy: policy,
		Containers:    []corev1.Container{{Name: "c", Image: "native", Command: []string{"/bin/sh", "-c", script}}},
	}
}

// m10PinnedPod wraps m10PodSpec in a pod named name in ns, labelled app=name.
func m10PinnedPod(ns, name, node string, policy corev1.RestartPolicy, script string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app": name}},
		Spec:       m10PodSpec(node, policy, script),
	}
}

// m10Create creates pod and fails the test on error.
func m10Create(t *testing.T, c *Cluster, pod *corev1.Pod) *corev1.Pod {
	t.Helper()
	got, err := c.Client.CoreV1().Pods(pod.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create pod %s/%s: %v", pod.Namespace, pod.Name, err)
	}
	return got
}

// m10ContainerLogs returns the current logs of one container, or a marked
// error string (never an empty string on error, so a substring assertion on it
// cannot pass by accident).
func m10ContainerLogs(c *Cluster, ns, pod, container string) string {
	body, err := c.Client.CoreV1().Pods(ns).GetLogs(pod, &corev1.PodLogOptions{Container: container}).DoRaw(context.Background())
	if err != nil {
		return fmt.Sprintf("<get logs %s/%s[%s]: %v>", ns, pod, container, err)
	}
	return string(body)
}

// m10Status returns the status entry of the named container, searching the
// regular and the init containers, or nil.
func m10Status(pod *corev1.Pod, name string) *corev1.ContainerStatus {
	for _, list := range [][]corev1.ContainerStatus{pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses} {
		for i := range list {
			if list[i].Name == name {
				return &list[i]
			}
		}
	}
	return nil
}

// m10Line returns the value of the last `key=value` token for key in out (the
// in-pod scripts report their facts that way), or "".
func m10Line(out, key string) string {
	v := ""
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if k, val, ok := strings.Cut(f, "="); ok && k == key {
				v = val
			}
		}
	}
	return v
}
