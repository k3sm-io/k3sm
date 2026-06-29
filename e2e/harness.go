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
	"os"
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

// WaitPodPhase polls until the pod reaches want, or fails the test at the timeout.
func (c *Cluster) WaitPodPhase(t *testing.T, ns, name string, want corev1.PodPhase, timeout time.Duration) *corev1.Pod {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		pod, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil && pod.Status.Phase == want {
			return pod
		}
		if time.Now().After(deadline) {
			last := "<get failed>"
			if err == nil {
				last = string(pod.Status.Phase)
			}
			t.Fatalf("pod %s/%s: want phase %s, last %s (err=%v)", ns, name, want, last, err)
		}
		time.Sleep(time.Second)
	}
}
