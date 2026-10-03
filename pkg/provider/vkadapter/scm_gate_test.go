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
	k8stesting "k8s.io/client-go/testing"
)

// settleAfterReady is how long the gate keeps watching after the node's own
// startup requests (the pod watch and the Lease) have been observed, so an
// informer started alongside them has had time to issue its LIST.
const settleAfterReady = 500 * time.Millisecond

// TestNewNodeStartsNoClusterWideSCMInformers is the gate on the node's request
// shape. A node identity may read a Secret or ConfigMap only by name, for a pod
// bound to it; a cluster-wide LIST or WATCH of secrets, configmaps or services
// from the node assembly is exactly the request that identity must never make.
//
// The node runs over a fake clientset through Ready and one pod create/delete.
// The barrier is deterministic: the test waits for the pod watch and the Lease
// create (the last startup requests), settles, and only then drives the pod.
//
// Two controls keep the assertion honest. The positive one requires the
// spec.nodeName-filtered pod LIST and WATCH to be recorded, so the recorder is
// not hiding list/watch actions. The mutation one issues a secrets LIST through
// the same clientset after the cycle and requires the scan to report exactly
// that one request, so a scan that could never match does not pass vacuously.
//
// Not t.Parallel: it runs a whole node with its own goroutines and timers.
func TestNewNodeStartsNoClusterWideSCMInformers(t *testing.T) {
	const name = "k3sm-gate"
	h := newNodeHarness(t)
	p := newRecordingProvider()
	n, err := NewNode(name, NodeConfig{
		Client:         h.cs,
		Provider:       p,
		HTTPListenAddr: "127.0.0.1:0",
		NumWorkers:     1,
		ConfigureNode:  func(*corev1.Node) {},
	})
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	stop := runNode(t, n)
	waitClosed(t, h.podWatched, "the pod watch")
	waitClosed(t, h.leaseCreated, "the Lease create")
	time.Sleep(settleAfterReady)
	h.cyclePod(t, p, name)
	if err := stop(); err != nil && err != context.Canceled {
		t.Logf("node Run returned %v", err)
	}

	actions := h.cs.Actions()

	t.Run("positive control: the node-filtered pod list and watch are recorded", func(t *testing.T) {
		want := "spec.nodeName=" + name
		var sawList, sawWatch bool
		for _, a := range actions {
			if a.GetResource().Resource != "pods" {
				continue
			}
			switch act := a.(type) {
			case k8stesting.ListAction:
				if got := act.GetListRestrictions().Fields.String(); got == want {
					sawList = true
				} else {
					t.Errorf("pod list with field selector %q, want %q", got, want)
				}
			case k8stesting.WatchAction:
				if got := act.GetWatchRestrictions().Fields.String(); got == want {
					sawWatch = true
				} else {
					t.Errorf("pod watch with field selector %q, want %q", got, want)
				}
			}
		}
		if !sawList || !sawWatch {
			t.Fatalf("pod list recorded=%v, pod watch recorded=%v: the recorder is not seeing list/watch, so the absence below would be vacuous", sawList, sawWatch)
		}
	})

	t.Run("no list or watch on secrets, configmaps or services", func(t *testing.T) {
		for _, a := range scmListWatches(actions) {
			t.Errorf("node issued %s %s (namespace %q): a cluster-wide request a node identity is not granted",
				a.GetVerb(), a.GetResource().Resource, a.GetNamespace())
		}
	})

	t.Run("mutation control: the scan catches a secrets list", func(t *testing.T) {
		before := len(scmListWatches(h.cs.Actions()))
		if _, err := h.cs.CoreV1().Secrets("").List(context.Background(), metav1.ListOptions{}); err != nil {
			t.Fatalf("secrets list: %v", err)
		}
		if got := len(scmListWatches(h.cs.Actions())) - before; got != 1 {
			t.Fatalf("scan reported %d new secrets list/watch after one list, want 1", got)
		}
	})
}
