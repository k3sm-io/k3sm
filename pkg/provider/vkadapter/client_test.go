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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestPodInformerFilter pins the pod informer's field-selector semantics to
// upstream's: the factory lists with spec.nodeName=<node>, and that selector
// admits exactly the pods bound to the node.
func TestPodInformerFilter(t *testing.T) {
	const node = "k3sm-node-a"

	cases := []struct {
		name     string
		nodeName string
		want     bool
	}{
		{name: "pod bound to our node", nodeName: node, want: true},
		{name: "pod bound to another node", nodeName: "k3sm-node-b", want: false},
		{name: "unscheduled pod", nodeName: "", want: false},
		{name: "node name prefix only", nodeName: "k3sm-node", want: false},
		{name: "node name with suffix", nodeName: node + "-2", want: false},
		{name: "case differs", nodeName: "K3SM-NODE-A", want: false},
	}

	sel, err := fields.ParseSelector(listedFieldSelector(t, node))
	if err != nil {
		t.Fatalf("parse listed field selector: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := corev1.Pod{Spec: corev1.PodSpec{NodeName: tc.nodeName}}
			if got := sel.Matches(fields.Set{"spec.nodeName": pod.Spec.NodeName}); got != tc.want {
				t.Errorf("selector %q matches spec.nodeName=%q = %v, want %v", sel, tc.nodeName, got, tc.want)
			}
		})
	}
}

// TestPodInformerFilterListOptions asserts the exact field selector the filtered
// factory sends, upstream's OneTermEqualSelector("spec.nodeName", node) string.
func TestPodInformerFilterListOptions(t *testing.T) {
	for _, node := range []string{"k3sm-node-a", "node-b", "node.with.dots"} {
		t.Run(node, func(t *testing.T) {
			got := listedFieldSelector(t, node)
			if want := "spec.nodeName=" + node; got != want {
				t.Errorf("listed field selector = %q, want %q", got, want)
			}
		})
	}
}

// listedFieldSelector starts a pod informer from a factory built with
// podInformerFilter(node) over a fake clientset, and returns the field selector
// of its first pod LIST.
func listedFieldSelector(t *testing.T, node string) string {
	t.Helper()
	client := fake.NewClientset()
	listed := make(chan string, 1)
	client.PrependReactor("list", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if la, ok := action.(k8stesting.ListAction); ok {
			select {
			case listed <- la.GetListRestrictions().Fields.String():
			default:
			}
		}
		return false, nil, nil
	})

	stop := make(chan struct{})
	factory := informers.NewSharedInformerFactoryWithOptions(client, 0, podInformerFilter(node))
	factory.Core().V1().Pods().Informer()
	factory.Start(stop)
	// Shutdown waits for the informer goroutines, which exit only once stop closes.
	defer func() {
		close(stop)
		factory.Shutdown()
	}()

	select {
	case s := <-listed:
		return s
	case <-time.After(10 * time.Second):
		t.Fatal("pod informer never listed pods")
		return ""
	}
}

// TestNodeLeaseV1Client pins the lease client to the kube-node-lease namespace.
func TestNodeLeaseV1Client(t *testing.T) {
	client := fake.NewClientset()
	if _, err := nodeLeaseV1Client(client).Get(context.Background(), "n", metav1.GetOptions{}); err == nil {
		t.Fatal("Get on an empty fake = nil error, want not-found")
	}
	var ns string
	for _, a := range client.Actions() {
		ns = a.GetNamespace()
	}
	if ns != corev1.NamespaceNodeLease {
		t.Errorf("lease client namespace = %q, want %q", ns, corev1.NamespaceNodeLease)
	}
}
