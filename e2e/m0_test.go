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
	"os/exec"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// procPattern matches the native process the M0 demo pod execs (`tail -f /dev/null`).
const procPattern = "/usr/bin/tail -f /dev/null"

// TestM0 is the M0 capability gate (DESIGN §9 M0; docs/M0-node.md): a kubectl-applied
// Pod runs as a native macOS process on the Virtual Kubelet node, and delete kills it.
func TestM0(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	const ns, name = "default", "hello-native"

	_ = c.Client.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{}) // clean slate
	t.Cleanup(func() { _ = c.Client.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{}) })

	applyHelloNative(t, c)

	pod := c.WaitPodPhase(t, ns, name, corev1.PodRunning, 60*time.Second)
	if len(pod.Status.ContainerStatuses) == 0 || pod.Status.ContainerStatuses[0].State.Running == nil {
		t.Fatalf("container not Running: %+v", pod.Status.ContainerStatuses)
	}
	t.Logf("pod Running on node %q", pod.Spec.NodeName)

	if !processAlive(procPattern) {
		t.Fatalf("expected a native %q process for the pod, found none", procPattern)
	}

	if err := c.Client.CoreV1().Pods(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete pod: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for processAlive(procPattern) {
		if time.Now().After(deadline) {
			t.Fatal("native process still alive 20s after pod delete")
		}
		time.Sleep(time.Second)
	}
}

// applyHelloNative creates the M0 demo pod (mirrors examples/hello-native.yaml): a
// container whose command runs as a native macOS process; the image field is a placeholder.
func applyHelloNative(t *testing.T, c *Cluster) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "hello-native", Namespace: "default"},
		Spec: corev1.PodSpec{
			NodeName:      "k3sm-m0",
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers: []corev1.Container{{
				Name:    "hello",
				Image:   "native",
				Command: []string{"/bin/sh", "-c", "echo 'hello from a k3sm NATIVE pod'; /usr/bin/sw_vers; echo started-ok; exec /usr/bin/tail -f /dev/null"},
			}},
		},
	}
	if _, err := c.Client.CoreV1().Pods("default").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}
}

// processAlive reports whether a process matching pattern exists (pgrep -f, as in
// docs/M0-node.md's `pgrep -fl tail` validation).
func processAlive(pattern string) bool {
	return exec.Command("pgrep", "-f", pattern).Run() == nil
}
