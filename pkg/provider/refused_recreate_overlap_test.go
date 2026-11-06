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

package provider

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// TestRefusedRecreateBesideCreateKeepsTheAddress pins why a refused re-create never
// releases the /32 of another create of the UID that is in its RPC, with no update out.
// Only Virtual Kubelet and a held pod's claim worker call CreatePod. Virtual Kubelet
// runs one call per pod key (TestPodControllerRunsOneCallPerPodKey in vkadapter) and
// asks GetPod before it creates (createOrUpdatePod, node/pod.go), and a create of the
// UID in its RPC holds a track GetPod answers with. So its next call is UpdatePod. A
// parked pod's retry does not call CreatePod and counts as an update, which is what
// untrackRejectedCreate reads.
func TestRefusedRecreateBesideCreateKeepsTheAddress(t *testing.T) {
	t.Run("a claim worker's create that lands answers GetPod throughout its RPC", func(t *testing.T) {
		testClaimCreateAnswersGetPod(t, nil)
	})
	t.Run("a claim worker's create that is refused answers GetPod until its refusal", func(t *testing.T) {
		testClaimCreateAnswersGetPod(t, podLevelRefusal())
	})
	t.Run("a refusal beside a parked retry leaves the address to the retry", testRefusalBesideParkedRetry)
}

// assertVirtualKubeletUpdates requires GetPod to find the pod, which is what sends
// Virtual Kubelet down UpdatePod instead of CreatePod.
func assertVirtualKubeletUpdates(t *testing.T, r *runtimedRuntime, pod *corev1.Pod, when string) {
	t.Helper()
	got, err := NewVKProvider(r, "n").GetPod(context.Background(), pod.Namespace, pod.Name)
	if err != nil || got == nil {
		t.Fatalf("GetPod %s = %v, %v, want the pod: Virtual Kubelet would create beside the create", when, got, err)
	}
}

// assertAddressKept requires the pod's hold to stand. releasePodNetwork, which every
// release of a /32 goes through, clears it.
func assertAddressKept(t *testing.T, r *runtimedRuntime, id, when string) {
	t.Helper()
	r.mu.Lock()
	_, held := r.held[id]
	r.mu.Unlock()
	if !held {
		t.Errorf("the pod's address was released %s", when)
	}
}

// testClaimCreateAnswersGetPod holds the claim worker's create in its RPC, the one
// create that runs off Virtual Kubelet's queue, and lands it with answer. Fails when a
// track stops answering GetPod while the RPC runs: Virtual Kubelet's create could then
// run inside the worker's, and whichever was refused would release the other's /32.
func testClaimCreateAnswersGetPod(t *testing.T, answer *runtimev1.CreatePodResponse) {
	ctx := context.Background()
	cs := fake.NewClientset(pendingClaim())
	r, f, clk, _ := newClaimProvider(t, cs)
	pod := claimPod(corev1.RestartPolicyAlways)
	id := string(pod.UID)
	if err := r.CreatePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("CreatePod = %v, want the pod held", err)
	}
	held := r.trackByID(id)
	if held == nil {
		t.Fatal("the held create published no track")
	}
	held.restartMu.Lock()
	worker := held.claims
	held.restartMu.Unlock()
	assertVirtualKubeletUpdates(t, r, pod, "with the pod held")

	if _, err := cs.CoreV1().PersistentVolumes().Create(ctx, localPV(t, r), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(claimTestNS).Update(ctx, boundClaim(), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	land := f.holdCreate()
	defer land()
	if answer != nil {
		f.pushCreate(answer)
	}
	stepWhenWaiting(t, clk, claimWaitMaxDelay)
	waitRestart(t, "the worker's create to enter its RPC", func() bool { return f.createCount() == 1 })
	assertVirtualKubeletUpdates(t, r, pod, "with the worker's create in its RPC")
	assertAddressKept(t, r, id, "with the worker's create in its RPC")

	land()
	waitRestart(t, "the worker to return", func() bool {
		select {
		case <-worker.done:
			return true
		default:
			return false
		}
	})
	if answer == nil {
		assertVirtualKubeletUpdates(t, r, pod, "after the worker's create landed")
		assertAddressKept(t, r, id, "after the worker's create landed")
		return
	}
	// The refusal took the track with the worker's only create, so this create is
	// Virtual Kubelet's next, with nothing out beside it.
	if got, err := r.GetPod(ctx, pod.Namespace, pod.Name); !vkadapter.IsNotFound(err) {
		t.Fatalf("GetPod after the worker's refusal = %v, %v, want NotFound", got, err)
	}
	if err := r.CreatePod(ctx, pod.DeepCopy()); err != nil {
		t.Fatalf("the create behind the refusal: %v", err)
	}
	assertAddressKept(t, r, id, "by the refusal in front of the create")
	if !f.hasCreated(id) || r.trackByID(id) == nil {
		t.Errorf("the create behind the refusal: guest %v, track %v, want both", f.hasCreated(id), r.trackByID(id) != nil)
	}
}

// testRefusalBesideParkedRetry forces the order only an overlapping Virtual Kubelet
// could drive, as GetPod answers for a parked pod, because a retry is the other way to
// have a create in its RPC and it reads as an update. Fails when untrackRejectedCreate
// stops reading the retry: the retry lands on a released address, with no track.
func testRefusalBesideParkedRetry(t *testing.T) {
	ctx := context.Background()
	pod := pullPod("refused-beside-retry")
	id := string(pod.UID)
	r, f, _, land := parkedWithHeldRetry(t, pod)
	defer land()
	assertVirtualKubeletUpdates(t, r, pod, "with the parked pod's retry in its RPC")

	f.mu.Lock()
	f.createHold = nil
	f.mu.Unlock()
	f.pushCreate(podLevelRefusal())
	if err := r.CreatePod(ctx, pod.DeepCopy()); err == nil {
		t.Fatal("the re-create succeeded; the test needs it refused")
	}
	assertAddressKept(t, r, id, "by the refusal beside the retry")
	assertTracked(t, r, id, "the retry is still out")

	land()
	waitRestart(t, "the retry to land", func() bool { return f.hasCreated(id) && updatingCount(r, id) == 0 })
	assertAddressKept(t, r, id, "with the retry landed")
	assertTracked(t, r, id, "the retry landed")
	if deleteIsOwed(r, id) {
		t.Error("the refusal is still owed with the guest running")
	}
}
