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
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// conformanceNS is the namespace the synthetic conformance pods run in. It is the
// in-pod-reader namespace (rbac.ConformanceNamespace == "default") so the
// in-pod-kubectl SA grant applies under the default Node,RBAC authorizer.
const conformanceNS = "default"

// nativePod builds a one-shot native Pod for the conformance suite: it targets the
// darwin Virtual Kubelet node (nodeSelector os=darwin, satisfying the M1.2
// admission policy), tolerates the provider taint, runs image "native" with the
// given command, and uses RestartPolicyNever — so a clean exit (0) drives the pod
// to Succeeded and a non-zero exit to Failed, which the test asserts as the
// criterion verdict. Callers mutate volumes/env/securityContext/probes as needed.
func nativePod(name string, command ...string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: conformanceNS, Labels: map[string]string{"app": name}},
		Spec: corev1.PodSpec{
			NodeSelector:  map[string]string{"kubernetes.io/os": "darwin"},
			RestartPolicy: corev1.RestartPolicyNever,
			Tolerations:   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
			Containers: []corev1.Container{{
				Name:    "app",
				Image:   "native",
				Command: command,
			}},
		},
	}
}

// shellPod builds a native Pod whose container runs script under the host /bin/sh.
// The conformance self-check pattern: script exits 0 when the assertion holds (pod
// → Succeeded) and non-zero otherwise (pod → Failed), so the test reads only the
// pod phase, not logs.
func shellPod(name, script string) *corev1.Pod {
	return nativePod(name, "/bin/sh", "-c", script)
}

// applyAndWaitPhase deletes any stale pod of the same name, creates pod, registers
// a cleanup delete, and waits for it to reach want. It returns the observed pod.
func applyAndWaitPhase(t *testing.T, c *Cluster, pod *corev1.Pod, want corev1.PodPhase, timeout time.Duration) *corev1.Pod {
	t.Helper()
	ns, name := pod.Namespace, pod.Name
	_ = c.Client.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{})
	waitPodGone(t, c, ns, name, 30*time.Second)
	t.Cleanup(func() { _ = c.Client.CoreV1().Pods(ns).Delete(context.Background(), name, metav1.DeleteOptions{}) })
	if _, err := c.Client.CoreV1().Pods(ns).Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod %s/%s: %v", ns, name, err)
	}
	return c.WaitPodPhase(t, ns, name, want, timeout)
}

// applyAndWaitSucceeded is applyAndWaitPhase for the common Succeeded verdict; on
// failure it dumps the pod logs so the criterion's self-check reason is visible.
func applyAndWaitSucceeded(t *testing.T, c *Cluster, pod *corev1.Pod, timeout time.Duration) {
	t.Helper()
	defer func() {
		if t.Failed() {
			t.Logf("pod %s/%s logs:\n%s", pod.Namespace, pod.Name, podLogs(t, c, pod.Namespace, pod.Name))
		}
	}()
	applyAndWaitPhase(t, c, pod, corev1.PodSucceeded, timeout)
}

// podLogs returns the (non-follow) logs of the pod's first container, "" on error.
func podLogs(t *testing.T, c *Cluster, ns, name string) string {
	t.Helper()
	body, err := c.Client.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{}).DoRaw(context.Background())
	if err != nil {
		return fmt.Sprintf("<get logs %s/%s: %v>", ns, name, err)
	}
	return string(body)
}

// darwinNode returns the name of the darwin Virtual Kubelet node (the one carrying
// kubernetes.io/os=darwin). It fails if none is Ready.
func darwinNode(t *testing.T, c *Cluster) *corev1.Node {
	t.Helper()
	nodes, err := c.Client.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{
		LabelSelector: "kubernetes.io/os=darwin",
	})
	if err != nil {
		t.Fatalf("list darwin nodes: %v", err)
	}
	for i := range nodes.Items {
		return &nodes.Items[i]
	}
	t.Fatalf("no kubernetes.io/os=darwin node found")
	return nil
}

// darwinNodeIP returns the InternalIP of the darwin node — the address a NodePort
// is dialed on (it equals the *:nodePort wildcard listener's reachable address).
func darwinNodeIP(t *testing.T, c *Cluster) string {
	t.Helper()
	n := darwinNode(t, c)
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP && a.Address != "" {
			return a.Address
		}
	}
	t.Fatalf("darwin node %s has no InternalIP: %+v", n.Name, n.Status.Addresses)
	return ""
}

// readyEndpointAddrs returns the addresses currently marked Ready across all
// EndpointSlices of svc — the set the Service proxy load-balances to. A pod that
// fails its readiness probe drops OUT of this set (the M2.2 semantic).
func readyEndpointAddrs(t *testing.T, c *Cluster, ns, svc string) []string {
	t.Helper()
	slices, err := c.Client.DiscoveryV1().EndpointSlices(ns).List(context.Background(), metav1.ListOptions{
		LabelSelector: discoveryv1.LabelServiceName + "=" + svc,
	})
	if err != nil {
		t.Fatalf("list endpointslices for %s/%s: %v", ns, svc, err)
	}
	var addrs []string
	for _, sl := range slices.Items {
		for _, ep := range sl.Endpoints {
			if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
				addrs = append(addrs, ep.Addresses...)
			}
		}
	}
	return addrs
}

// waitEndpointReady blocks until addr is among svc's Ready endpoint addresses, or
// fails at timeout. Used to gate a transition assertion on a known-good start state.
func waitEndpointReady(t *testing.T, c *Cluster, ns, svc, addr string, timeout time.Duration) {
	t.Helper()
	if !pollUntil(timeout, func() bool { return contains(readyEndpointAddrs(t, c, ns, svc), addr) }) {
		t.Fatalf("address %s never became a Ready endpoint of %s/%s within %s", addr, ns, svc, timeout)
	}
}

// waitEndpointNotReady blocks until addr is NO LONGER a Ready endpoint of svc
// (readiness-fail removed it), or fails at timeout.
func waitEndpointNotReady(t *testing.T, c *Cluster, ns, svc, addr string, timeout time.Duration) {
	t.Helper()
	if !pollUntil(timeout, func() bool { return !contains(readyEndpointAddrs(t, c, ns, svc), addr) }) {
		t.Fatalf("address %s still a Ready endpoint of %s/%s after %s (readiness fail did not remove it)", addr, ns, svc, timeout)
	}
}

// httpGetBody dials url (with a short timeout) and returns the response body; ok is
// false on any dial/read/status error, so a caller can poll until reachable.
func httpGetBody(url string) (body string, ok bool) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", false
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || resp.StatusCode != http.StatusOK {
		return string(b), false
	}
	return string(b), true
}

// waitHTTPBody polls GET url until the body equals want (the NodePort/Service is
// reachable and the right backend answered), or fails at timeout.
func waitHTTPBody(t *testing.T, url, want string, timeout time.Duration) {
	t.Helper()
	var last string
	if pollUntil(timeout, func() bool {
		b, ok := httpGetBody(url)
		last = b
		return ok && b == want
	}) {
		return
	}
	t.Fatalf("GET %s never returned %q within %s (last body %q)", url, want, timeout, last)
}

// hostPort joins host and an int port.
func hostPort(host string, port int32) string {
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}

// pollUntil calls cond every second until it returns true or timeout elapses.
func pollUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Second)
	}
}

// contains reports whether s is in xs.
func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
