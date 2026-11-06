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
	"errors"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
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

// heldTeardownNetwork tracks which pods hold an address and parks every Teardown until
// its hold is released, so a test can act while a release is out.
type heldTeardownNetwork struct {
	*recordingNetwork
	hold chan struct{}

	mu        sync.Mutex
	allocated map[string]bool
	setups    int
	teardowns int
}

func (n *heldTeardownNetwork) Setup(ctx context.Context, id string) (string, error) {
	n.mu.Lock()
	n.allocated[id] = true
	n.setups++
	n.mu.Unlock()
	return n.recordingNetwork.Setup(ctx, id)
}

func (n *heldTeardownNetwork) Teardown(id string) error {
	n.mu.Lock()
	n.teardowns++
	n.mu.Unlock()
	<-n.hold
	n.mu.Lock()
	delete(n.allocated, id)
	n.mu.Unlock()
	return nil
}

// state reports the setups and teardowns so far, and whether id holds an address.
func (n *heldTeardownNetwork) state(id string) (setups, teardowns int, allocated bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.setups, n.teardowns, n.allocated[id]
}

// refusedClaimRelease is a claim worker's create that was refused and is parked in the
// release of the pod's address.
type refusedClaimRelease struct {
	r       *runtimedRuntime
	f       *fakeRuntimeServer
	net     *heldTeardownNetwork
	pod     *corev1.Pod
	logs    string
	worker  *claimWait
	finish  func()
	waiting *atomic.Bool
}

// holdRefusedClaimRelease drives a held pod's claim worker into a refused create and
// stops it at Teardown.
func holdRefusedClaimRelease(t *testing.T) *refusedClaimRelease {
	t.Helper()
	ctx := context.Background()
	cs := fake.NewClientset(pendingClaim())
	r, f, clk, _ := newClaimProvider(t, cs)
	hold := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(hold) }) }
	t.Cleanup(finish)
	net := &heldTeardownNetwork{recordingNetwork: &recordingNetwork{}, hold: hold, allocated: map[string]bool{}}
	r.network = net
	waiting := &atomic.Bool{}
	r.fenceWaitHook = func(string) { waiting.Store(true) }

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
	logs := podlogs.BuildPodLogsDirectory(r.logGC.PodLogsDir, pod.Namespace, pod.Name, id)
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := cs.CoreV1().PersistentVolumes().Create(ctx, localPV(t, r), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(claimTestNS).Update(ctx, boundClaim(), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	f.pushCreate(podLevelRefusal())
	stepWhenWaiting(t, clk, claimWaitMaxDelay)
	waitRestart(t, "the refused create to reach Teardown", func() bool {
		_, teardowns, _ := net.state(id)
		return teardowns == 1
	})
	return &refusedClaimRelease{r: r, f: f, net: net, pod: pod, logs: logs, worker: worker, finish: finish, waiting: waiting}
}

// awaitWorker waits for the worker to return, with its release over.
func (x *refusedClaimRelease) awaitWorker(t *testing.T) {
	t.Helper()
	waitRestart(t, "the worker to return", func() bool {
		select {
		case <-x.worker.done:
			return true
		default:
			return false
		}
	})
}

// TestRefusedClaimCreateFencesTheAddressRelease pins that the release of a refused
// create is fenced from the moment its track goes. GetPod answers NotFound from there,
// so Virtual Kubelet's next call is a create, and everything the release frees is keyed
// by the UID. Fails when the fence comes later than the removal: the create allocates
// and lands, and then the release takes the address from under a running guest.
func TestRefusedClaimCreateFencesTheAddressRelease(t *testing.T) {
	t.Run("a create behind the removal waits for the release", testCreateWaitsForRefusalRelease)
	t.Run("a refusal beside a running release leaves it the fence", testRefusalBesideRunningRelease)
}

func testCreateWaitsForRefusalRelease(t *testing.T) {
	ctx := context.Background()
	x := holdRefusedClaimRelease(t)
	r, f, pod := x.r, x.f, x.pod
	id := string(pod.UID)
	if got, err := r.GetPod(ctx, pod.Namespace, pod.Name); !vkadapter.IsNotFound(err) {
		t.Fatalf("GetPod with the release out = %v, %v, want NotFound", got, err)
	}
	if _, err := os.Stat(x.logs); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the log tree with the release out: %v, want it removed inside the fence", err)
	}
	setupsBefore, _, _ := x.net.state(id)

	created := make(chan error, 1)
	go func() { created <- r.CreatePod(ctx, pod.DeepCopy()) }()
	waitRestart(t, "the create behind the refusal to wait or return", func() bool {
		return x.waiting.Load() || len(created) == 1
	})
	if !x.waiting.Load() {
		t.Error("the create behind the refusal ran beside the release, not at its fence")
	}
	if setups, _, _ := x.net.state(id); x.waiting.Load() && setups != setupsBefore {
		t.Errorf("setups with the create at the fence = %d, want %d", setups, setupsBefore)
	}

	x.finish()
	x.awaitWorker(t)
	waitRestart(t, "the create behind the refusal to return", func() bool { return len(created) == 1 })
	if err := <-created; err != nil {
		t.Fatalf("the create behind the refusal: %v", err)
	}
	if !f.hasCreated(id) || r.trackByID(id) == nil {
		t.Errorf("after the refusal's release: guest %v, track %v, want both", f.hasCreated(id), r.trackByID(id) != nil)
	}
	if _, teardowns, allocated := x.net.state(id); !allocated || teardowns != 1 {
		t.Errorf("after the refusal's release: address held %v, teardowns %d, want it held behind one release", allocated, teardowns)
	}
	assertAddressKept(t, r, id, "behind the refusal's release")
}

// testRefusalBesideRunningRelease forces the order only an overlapping Virtual Kubelet
// could drive, by a direct call, because a second release would replace the first's
// fence and end it early. Fails when a refusal publishes over a running release.
func testRefusalBesideRunningRelease(t *testing.T) {
	x := holdRefusedClaimRelease(t)
	r, pod := x.r, x.pod
	id := string(pod.UID)
	r.mu.Lock()
	fence := r.fenceReleasing[id]
	r.mu.Unlock()
	if fence == nil {
		t.Fatal("the refused create's release published no fence")
	}

	// In a goroutine, as a refusal that published a second release parks at Teardown.
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		r.untrackRejectedCreate(pod, &podTrack{pod: pod.DeepCopy()})
	}()
	waitRestart(t, "the second refusal to return or reach Teardown", func() bool {
		_, teardowns, _ := x.net.state(id)
		select {
		case <-returned:
			return true
		default:
			return teardowns == 2
		}
	})
	r.mu.Lock()
	now := r.fenceReleasing[id]
	_, owed := r.deleteOwed[id]
	r.mu.Unlock()
	if now != fence {
		t.Error("the second refusal replaced the running release's fence")
	}
	if !owed {
		t.Error("the second refusal is not owed to the last call out")
	}

	x.finish()
	x.awaitWorker(t)
	waitRestart(t, "the owed refusal to be released", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.fenceReleasing[id] == nil && r.deleteOwed[id] == nil
	})
	if _, teardowns, allocated := x.net.state(id); allocated || teardowns != 2 {
		t.Errorf("address held %v, teardowns %d, want it released by both refusals", allocated, teardowns)
	}
}

// TestCreateRPCHasNoTransportToLoseAGuest pins why neither create path compensates a
// create RPC that returns an error: the provider holds the runtime in process, as the
// server, not over a connection. Its only error return comes before it builds anything
// (refuseBesideUnadoptedHelper, CreatePod in runtimed's pkg/runtime). This stops
// compiling if the field becomes a client, which is when a transport error could hide
// a built guest and both paths would owe a compensating delete.
func TestCreateRPCHasNoTransportToLoseAGuest(t *testing.T) {
	r, f, _, _ := newPullProvider(t)
	var server runtimev1.RuntimeServer = r.rt
	if server != runtimev1.RuntimeServer(f) {
		t.Errorf("the provider's runtime = %T, want the server it was built with", server)
	}
}
