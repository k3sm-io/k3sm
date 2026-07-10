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

// Package e2e holds k3sm's build-tagged end-to-end acceptance suites — one per
// milestone (m0_test.go, m1_test.go, …). Each drives a real cluster via client-go and
// asserts that milestone's capability gate (DESIGN §9). They are run by the matching
// hack/acceptance/m<n>.sh, which brings up the cluster + node, exports $KUBECONFIG, then
// `go test -tags e2e -run TestM<n> ./e2e/...`. The e2e tag keeps them out of unit builds.
package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Cluster is a handle to the running acceptance cluster.
type Cluster struct {
	Client kubernetes.Interface
}

// Up connects to the cluster the acceptance script brought up (via $KUBECONFIG). Pre-M1
// the script uses the prebuilt spike control plane; from M1 it runs `k3sm server` (the
// embedded control plane from source). The e2e assertions are identical either way.
func Up(t *testing.T) *Cluster {
	t.Helper()
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("e2e: $KUBECONFIG unset — run via hack/acceptance/m<n>.sh, not `go test` directly")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("load kubeconfig %s: %v", kubeconfig, err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("build client: %v", err)
	}
	return &Cluster{Client: cs}
}

// Healthz returns the apiserver /healthz body (e.g. "ok"), proving the control
// plane is serving — the M1.1 exit check.
func (c *Cluster) Healthz(t *testing.T) string {
	t.Helper()
	body, err := c.Client.Discovery().RESTClient().Get().AbsPath("/healthz").DoRaw(context.Background())
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	return string(body)
}

// terminalPhase reports whether a pod phase is a settled end-state the pod will not
// leave (Succeeded/Failed). Waiting for one terminal phase while the pod has already
// reached the other is hopeless, so WaitPodPhase fails fast instead of burning the
// whole timeout (which, summed across the suite, blows the go-test binary timeout and
// panics — truncating every later criterion into a false RED).
func terminalPhase(p corev1.PodPhase) bool {
	return p == corev1.PodSucceeded || p == corev1.PodFailed
}

// podFailureDetail summarizes why a pod is not in the wanted phase: the pod-level
// reason/message plus each container's terminated (exit code + reason) or waiting
// state. This is the diagnostic a criterion prints on failure, since the kubelet-
// proxied logs subresource is not reliably available for a crashed native pod.
func podFailureDetail(pod *corev1.Pod) string {
	if pod == nil {
		return "<no pod>"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "phase=%s", pod.Status.Phase)
	if pod.Status.Reason != "" || pod.Status.Message != "" {
		fmt.Fprintf(&b, " reason=%q message=%q", pod.Status.Reason, pod.Status.Message)
	}
	for _, cs := range pod.Status.ContainerStatuses {
		switch {
		case cs.State.Terminated != nil:
			tm := cs.State.Terminated
			fmt.Fprintf(&b, "; container %q terminated exitCode=%d signal=%d reason=%q message=%q",
				cs.Name, tm.ExitCode, tm.Signal, tm.Reason, tm.Message)
		case cs.State.Waiting != nil:
			fmt.Fprintf(&b, "; container %q waiting reason=%q message=%q",
				cs.Name, cs.State.Waiting.Reason, cs.State.Waiting.Message)
		case cs.State.Running != nil:
			fmt.Fprintf(&b, "; container %q running", cs.Name)
		}
	}
	return b.String()
}

// WaitPodPhase polls until the pod reaches want; it fails FAST if the pod settles
// into a DIFFERENT terminal phase (a Failed pod never becomes Succeeded), and fails
// at the timeout otherwise. Failures carry podFailureDetail (container exit code /
// reason) so a criterion's cause is visible even when the logs subresource errors.
func (c *Cluster) WaitPodPhase(t *testing.T, ns, name string, want corev1.PodPhase, timeout time.Duration) *corev1.Pod {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pod, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			if pod.Status.Phase == want {
				return pod
			}
			// The pod reached the OTHER terminal state; it will never transition to
			// want, so stop now with the failure detail rather than polling to the
			// deadline (and cascading into a whole-binary timeout panic).
			if terminalPhase(pod.Status.Phase) && pod.Status.Phase != want {
				t.Fatalf("pod %s/%s: want phase %s, reached terminal %s — %s",
					ns, name, want, pod.Status.Phase, podFailureDetail(pod))
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				t.Fatalf("pod %s/%s: want phase %s, last get failed: %v", ns, name, want, err)
			}
			t.Fatalf("pod %s/%s: want phase %s, last %s — %s",
				ns, name, want, pod.Status.Phase, podFailureDetail(pod))
		}
		time.Sleep(time.Second)
	}
}
