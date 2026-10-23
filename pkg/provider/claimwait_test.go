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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	"k3sm.io/k3sm/pkg/provisioner"
)

const (
	claimTestNS    = "default"
	claimTestClaim = "data-claim"
	claimTestPV    = "pvc-uid-claim"
)

// newClaimProvider wires a fake-clocked provider whose apiserver client is cs.
func newClaimProvider(t *testing.T, cs *fake.Clientset) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock, *record.FakeRecorder) {
	t.Helper()
	f := newFakeRuntimeServer()
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n",
		NodeIP:   "192.168.1.10",
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec,
		Client:   cs,
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	t.Cleanup(func() {
		if tr := r.trackByID(string(claimPod(corev1.RestartPolicyAlways).UID)); tr != nil {
			tr.stopClaimWait()
		}
	})
	return r, f, clk, rec
}

// claimPod mounts the claim claimTestClaim as volume "data". restartPolicy
// Never is the shape that made the bug visible: the pod ran to Succeeded.
func claimPod(policy corev1.RestartPolicy) *corev1.Pod {
	pod := runtimedPod(claimTestNS, "writer")
	pod.Spec.RestartPolicy = policy
	pod.Spec.Volumes = []corev1.Volume{{
		Name:         "data",
		VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: claimTestClaim}},
	}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	return pod
}

func pendingClaim() *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: claimTestNS, Name: claimTestClaim, UID: types.UID("uid-claim")},
		Status:     corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending},
	}
}

func boundClaim() *corev1.PersistentVolumeClaim {
	pvc := pendingClaim()
	pvc.Spec.VolumeName = claimTestPV
	pvc.Status.Phase = corev1.ClaimBound
	return pvc
}

// localPV is the PV the local-path provisioner would create for the claim on
// this provider's runtime root, bound to the claim by UID.
func localPV(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume {
	t.Helper()
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: claimTestPV},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{Local: &corev1.LocalVolumeSource{Path: claimDir(t, r)}},
			ClaimRef:               &corev1.ObjectReference{Namespace: claimTestNS, Name: claimTestClaim, UID: types.UID("uid-claim")},
		},
	}
}

// claimDir is the directory runtimed mounts for the claim on r's root.
func claimDir(t *testing.T, r *runtimedRuntime) string {
	t.Helper()
	dir, err := provisioner.ClassForRoot(r.rootfs).DataDir(claimTestNS, claimTestClaim)
	if err != nil {
		t.Fatalf("DataDir: %v", err)
	}
	return dir
}

// stepWhenWaiting advances the fake clock by d once the claim worker sleeps on
// it, so a step can never land before the worker's timer exists.
func stepWhenWaiting(t *testing.T, clk *testclock.FakeClock, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !clk.HasWaiters() {
		if time.Now().After(deadline) {
			t.Fatal("the claim worker never waited on the clock")
		}
		time.Sleep(time.Millisecond)
	}
	clk.Step(d)
}

// claimGets counts the GETs of the claim the provider made.
func claimGets(cs *fake.Clientset) int {
	n := 0
	for _, a := range cs.Actions() {
		if g, ok := a.(k8stesting.GetAction); ok && a.GetVerb() == "get" && a.GetResource().Resource == "persistentvolumeclaims" && g.GetName() == claimTestClaim {
			n++
		}
	}
	return n
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// assertHeld checks the pod is not started and reports the kubelet's waiting
// surface: Pending, its container Waiting ContainerCreating, no pod IP.
func assertHeld(t *testing.T, r *runtimedRuntime, f *fakeRuntimeServer) {
	t.Helper()
	if n := f.createCount(); n != 0 {
		t.Fatalf("runtimed CreatePod called %d times for a pod whose claim does not resolve; want 0", n)
	}
	st, err := r.GetPodStatus(context.Background(), claimTestNS, "writer")
	if err != nil {
		t.Fatalf("GetPodStatus of a held pod: %v", err)
	}
	if st.Phase != corev1.PodPending {
		t.Fatalf("held pod phase = %s, want Pending", st.Phase)
	}
	if st.PodIP != "" {
		t.Fatalf("held pod has pod IP %q, want none (no sandbox exists)", st.PodIP)
	}
	if len(st.ContainerStatuses) != 1 || st.ContainerStatuses[0].State.Waiting == nil ||
		st.ContainerStatuses[0].State.Waiting.Reason != reasonContainerCreating {
		t.Fatalf("held pod container statuses = %+v, want one Waiting ContainerCreating", st.ContainerStatuses)
	}
}

// TestPodWithUnboundClaimWaits pins that a pod whose claim is still
// Pending is not started and gets the kubelet's FailedMount Event; it is
// re-checked on a back-off rather than a busy loop; and once the claim binds,
// the pod starts, on the directory its bound PV names.
func TestPodWithUnboundClaimWaits(t *testing.T) {
	cs := fake.NewClientset(pendingClaim())
	r, f, clk, rec := newClaimProvider(t, cs)
	pod := claimPod(corev1.RestartPolicyNever)

	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod returned %v; a pod waiting for its claim is held, not failed (virtual-kubelet would mark a restartPolicy Never pod Failed)", err)
	}
	assertHeld(t, r, f)

	want := "Warning FailedMount Unable to attach or mount volumes: unmounted volumes=[data], unattached volumes=[], " +
		"failed to process volumes=[data]: error processing PVC default/data-claim: PVC is not bound"
	if events := recordedEvents(rec.Events); !containsEvent(events, want) {
		t.Fatalf("events = %q, want %q", events, want)
	}

	// No busy loop: with the clock still, the worker reads nothing more.
	gets := claimGets(cs)
	time.Sleep(20 * time.Millisecond)
	if n := claimGets(cs); n != gets {
		t.Fatalf("claim read %d more times with the clock stopped; the re-check must wait on the back-off", n-gets)
	}
	// One step of the back-off re-checks once; the claim is still Pending, so
	// the pod stays held, and the unchanged message is not re-recorded.
	stepWhenWaiting(t, clk, claimWaitInitialDelay)
	waitFor(t, "the re-check", func() bool { return claimGets(cs) == gets+1 })
	waitFor(t, "the worker to sleep again", clk.HasWaiters)
	assertHeld(t, r, f)
	if events := recordedEvents(rec.Events); containsEvent(events, "FailedMount") {
		t.Fatalf("an unchanged FailedMount was re-recorded within the event interval: %q", events)
	}

	// The claim binds to the provisioner's PV.
	if _, err := cs.CoreV1().PersistentVolumes().Create(context.Background(), localPV(t, r), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(claimTestNS).Update(context.Background(), boundClaim(), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	stepWhenWaiting(t, clk, claimWaitMaxDelay)
	waitFor(t, "the held pod to be created", func() bool { return f.createCount() == 1 })
	waitFor(t, "the held track to be replaced", func() bool {
		tr := r.trackByID(string(pod.UID))
		return tr != nil && !tr.claimWaiting()
	})

	box := f.createdBox(string(pod.UID))
	if box == nil {
		t.Fatal("runtimed holds no box for the pod after its claim bound")
	}
	var claim string
	for _, v := range box.GetVolumes() {
		if v.GetName() == "data" {
			claim = v.GetPersistentVolumeClaim().GetClaimName()
		}
	}
	if claim != claimTestClaim {
		t.Fatalf("created box volume data claim = %q, want %q", claim, claimTestClaim)
	}
	// runtimed mounts the claim's directory of its storage class; the pod was
	// started only because that is exactly the bound PV's path.
	pv, err := cs.CoreV1().PersistentVolumes().Get(context.Background(), claimTestPV, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if pv.Spec.Local.Path != claimDir(t, r) {
		t.Fatalf("pod started on %q, but its bound PV names %q", claimDir(t, r), pv.Spec.Local.Path)
	}
	st, err := r.GetPodStatus(context.Background(), claimTestNS, "writer")
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != corev1.PodRunning {
		t.Fatalf("pod phase after its claim bound = %s, want Running", st.Phase)
	}
}

// TestPodWithClaimBoundToUnresolvablePVWaits: a Bound claim is not enough. A PV
// that is missing, not bound back to this claim, has no path, or names a
// directory other than the one this node mounts keeps the pod held, with an
// Event naming the claim and the PV.
func TestPodWithClaimBoundToUnresolvablePVWaits(t *testing.T) {
	cases := []struct {
		name string
		pv   func(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume // nil: no PV object
		want string
	}{
		{
			name: "no path source",
			pv: func(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume {
				pv := localPV(t, r)
				pv.Spec.PersistentVolumeSource = corev1.PersistentVolumeSource{NFS: &corev1.NFSVolumeSource{Server: "nfs.example", Path: "/export"}}
				return pv
			},
			want: "error processing PVC default/data-claim: PV pvc-uid-claim has no local or hostPath source with a path this node can mount",
		},
		{
			name: "empty local path",
			pv: func(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume {
				pv := localPV(t, r)
				pv.Spec.Local.Path = ""
				return pv
			},
			want: "PV pvc-uid-claim has no local or hostPath source with a path this node can mount",
		},
		{
			name: "path is not the claim's directory",
			pv: func(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume {
				pv := localPV(t, r)
				pv.Spec.Local = nil
				pv.Spec.HostPath = &corev1.HostPathVolumeSource{Path: "/srv/elsewhere"}
				return pv
			},
			want: "PV pvc-uid-claim path /srv/elsewhere is not the directory this node mounts for the claim",
		},
		{
			name: "PV missing",
			want: "error processing PVC default/data-claim: failed to fetch PV pvc-uid-claim from API server:",
		},
		{
			name: "PV bound to another claim",
			pv: func(t *testing.T, r *runtimedRuntime) *corev1.PersistentVolume {
				pv := localPV(t, r)
				pv.Spec.ClaimRef.UID = "uid-other"
				return pv
			},
			want: "found PV object pvc-uid-claim but its pv.Spec.ClaimRef.UID uid-other does not point to claim.UID uid-claim",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := fake.NewClientset(boundClaim())
			r, f, clk, rec := newClaimProvider(t, cs)
			if tc.pv != nil {
				if _, err := cs.CoreV1().PersistentVolumes().Create(context.Background(), tc.pv(t, r), metav1.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			pod := claimPod(corev1.RestartPolicyNever)
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			assertHeld(t, r, f)
			events := recordedEvents(rec.Events)
			if !containsEvent(events, "Warning FailedMount Unable to attach or mount volumes:") || !containsEvent(events, tc.want) {
				t.Fatalf("events = %q, want a FailedMount containing %q", events, tc.want)
			}
			// Still held after a re-check.
			gets := claimGets(cs)
			stepWhenWaiting(t, clk, claimWaitInitialDelay)
			waitFor(t, "the re-check", func() bool { return claimGets(cs) > gets })
			waitFor(t, "the worker to sleep again", clk.HasWaiters)
			assertHeld(t, r, f)
		})
	}
}

// TestHeldPodDeleteStopsTheWait: deleting a held pod stops its worker for good;
// a later bind never creates it.
func TestHeldPodDeleteStopsTheWait(t *testing.T) {
	cs := fake.NewClientset(pendingClaim())
	r, f, clk, _ := newClaimProvider(t, cs)
	pod := claimPod(corev1.RestartPolicyAlways)
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	waitFor(t, "the worker to wait", clk.HasWaiters)
	if err := r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if tr := r.trackByID(string(pod.UID)); tr != nil {
		t.Fatal("a deleted held pod is still tracked")
	}
	if _, err := cs.CoreV1().PersistentVolumes().Create(context.Background(), localPV(t, r), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CoreV1().PersistentVolumeClaims(claimTestNS).Update(context.Background(), boundClaim(), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	clk.Step(time.Minute)
	time.Sleep(20 * time.Millisecond)
	if n := f.createCount(); n != 0 {
		t.Fatalf("runtimed CreatePod called %d times after the held pod was deleted; want 0", n)
	}
}

// TestHeldPodMessageNamesEveryUnresolvedClaim pins the multi-volume shape:
// every mounted volume is listed as unmounted, only the failing claims as
// failed to process, and their errors are joined as upstream joins them.
func TestHeldPodMessageNamesEveryUnresolvedClaim(t *testing.T) {
	cs := fake.NewClientset(pendingClaim())
	r, _, _, _ := newClaimProvider(t, cs)
	pod := claimPod(corev1.RestartPolicyAlways)
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{Name: "cache", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		corev1.Volume{Name: "logs", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "absent"}}},
	)
	pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts,
		corev1.VolumeMount{Name: "cache", MountPath: "/cache"}, corev1.VolumeMount{Name: "logs", MountPath: "/logs"})
	got := r.unresolvedClaims(context.Background(), pod)
	wantPrefix := "Unable to attach or mount volumes: unmounted volumes=[cache data logs], unattached volumes=[], failed to process volumes=[data logs]: " +
		"error processing PVC default/data-claim: PVC is not bound; error processing PVC default/absent: failed to fetch PVC from API server:"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("message = %q, want prefix %q", got, wantPrefix)
	}
}
