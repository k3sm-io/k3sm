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

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// restartState snapshots the fake's RestartContainer bookkeeping under its lock.
func (f *fakeRuntimeServer) restartState() (int, restartRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restartCalls, f.lastRestart
}

// waitRestart polls until cond holds or the deadline expires.
func waitRestart(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// settleRestartCalls asserts the fake's RestartContainer count stays at want
// over a short settle window (catches a double-scheduled re-exec whose second
// timer would fire on the same clock step).
func settleRestartCalls(t *testing.T, f *fakeRuntimeServer, want int) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got, _ := f.restartState(); got != want {
			t.Fatalf("RestartContainer calls = %d, want %d (double-restart)", got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// newRestartFake is newRuntimedFake with an injected fake clock so the
// CrashLoopBackOff waits are stepped, never slept.
func newRestartFake(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock) {
	t.Helper()
	r, f := newRuntimedFake(t)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	return r, f, clk
}

// sidecarJobPod is a Job-shaped pod (restartPolicy: Never) with a native
// sidecar: an initContainer carrying restartPolicy: Always (KEP-753) plus one
// regular (main) container.
func sidecarJobPod() *corev1.Pod {
	always := corev1.ContainerRestartPolicyAlways
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "job-pod", UID: types.UID("uid-job-pod")},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			InitContainers: []corev1.Container{
				{Name: "proxy", Image: "registry/proxy:latest", Command: []string{"/proxy"}, RestartPolicy: &always},
			},
			Containers: []corev1.Container{
				{Name: "main", Image: "registry/main:latest", Command: []string{"/main"}},
			},
		},
	}
}

// rtRunning renders a running runtime container status.
func rtRunning(name string) *runtimev1.ContainerStatus {
	return &runtimev1.ContainerStatus{
		Name: name, Ready: true, Started: true, StartedSet: true,
		State: &runtimev1.ContainerState{
			Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(time.Unix(5000, 0))},
		},
	}
}

// rtTerminated renders a terminated runtime container status. restarts is
// runtimed's restart_count at the time of the exit (the single count
// authority); finishedAt disambiguates termination identities.
func rtTerminated(name string, exit, restarts int32, finishedAt time.Time) *runtimev1.ContainerStatus {
	return &runtimev1.ContainerStatus{
		Name: name, RestartCount: restarts,
		State: &runtimev1.ContainerState{
			Terminated: &runtimev1.ContainerStateTerminated{
				ExitCode:   exit,
				Reason:     "Error",
				FinishedAt: timestamppb.New(finishedAt),
			},
		},
	}
}

// TestNativeSidecarStaysRunning is the M10.2-a1 provider-side sidecar
// criterion: translate marks an init container with restartPolicy: Always as a
// native sidecar on the proto (ALWAYS; regular containers stay UNSPECIFIED); a
// running sidecar surfaces in status.initContainerStatuses with started=true;
// and when the sidecar EXITS in a restartPolicy:Never pod the effective-policy
// resolver still decides restart (sidecar → Always regardless of pod policy):
// the provider schedules the re-exec via RestartContainer, synthesizes the
// CrashLoopBackOff waiting overlay while it is pending, and the pod phase
// stays Running throughout.
func TestNativeSidecarStaysRunning(t *testing.T) {
	r, f, clk := newRestartFake(t)
	pod := sidecarJobPod()
	ctx := context.Background()

	t.Run("translate marks the init sidecar ALWAYS, regular UNSPECIFIED", func(t *testing.T) {
		box, err := r.buildBox(ctx, pod, "10.1.1.2")
		if err != nil {
			t.Fatalf("buildBox: %v", err)
		}
		if got := box.GetInitContainers()[0].GetRestartPolicy(); got != runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_ALWAYS {
			t.Errorf("init sidecar restart_policy = %v, want ALWAYS", got)
		}
		if got := box.GetContainers()[0].GetRestartPolicy(); got != runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_UNSPECIFIED {
			t.Errorf("regular container restart_policy = %v, want UNSPECIFIED", got)
		}
	})

	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID("uid-job-pod")
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}

	t.Run("running sidecar surfaces in initContainerStatuses started=true", func(t *testing.T) {
		rs := &runtimev1.PodStatus{
			PodId:                 "uid-job-pod",
			Phase:                 runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp:                 "10.1.1.2",
			InitContainerStatuses: []*runtimev1.ContainerStatus{rtRunning("proxy")},
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtRunning("main")},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
		if st.Phase != corev1.PodRunning {
			t.Fatalf("phase = %s, want Running", st.Phase)
		}
		if len(st.InitContainerStatuses) != 1 {
			t.Fatalf("initContainerStatuses = %d entries, want 1", len(st.InitContainerStatuses))
		}
		sc := st.InitContainerStatuses[0]
		if sc.State.Running == nil {
			t.Errorf("sidecar state = %+v, want Running", sc.State)
		}
		if sc.Started == nil || !*sc.Started {
			t.Errorf("sidecar Started = %v, want true", sc.Started)
		}
	})

	t.Run("sidecar exit in a Never pod restarts with CrashLoopBackOff overlay", func(t *testing.T) {
		rs := &runtimev1.PodStatus{
			PodId:                 "uid-job-pod",
			Phase:                 runtimev1.PodPhase_POD_PHASE_RUNNING, // mains-only phase: main still runs
			PodIp:                 "10.1.1.2",
			InitContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("proxy", 1, 2, time.Unix(6000, 0))},
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtRunning("main")},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)

		if st.Phase != corev1.PodRunning {
			t.Fatalf("phase while sidecar restart pending = %s, want Running", st.Phase)
		}
		sc := st.InitContainerStatuses[0]
		if sc.State.Waiting == nil || sc.State.Waiting.Reason != reasonCrashLoopBackOff {
			t.Fatalf("sidecar state = %+v, want Waiting{CrashLoopBackOff}", sc.State)
		}
		if !strings.Contains(sc.State.Waiting.Message, "back-off 10s") {
			t.Errorf("waiting message = %q, want the 10s base back-off", sc.State.Waiting.Message)
		}
		if lt := sc.LastTerminationState.Terminated; lt == nil || lt.ExitCode != 1 {
			t.Errorf("lastState = %+v, want terminated exit 1 (the prior exit)", sc.LastTerminationState)
		}
		// runtimed's restart_count is the single count authority — surfaced
		// verbatim, never provider-bumped.
		if sc.RestartCount != 2 {
			t.Errorf("restartCount = %d, want 2 (runtimed's count, verbatim)", sc.RestartCount)
		}

		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })
		_, rec := f.restartState()
		if rec.podID != "uid-job-pod" || rec.container != "proxy" {
			t.Errorf("RestartContainer(%q, %q), want (uid-job-pod, proxy)", rec.podID, rec.container)
		}
	})
}

// TestJobBackoffAndCompletionAccounting is the M10.2-a1 Job criterion, scoped
// HONESTLY to the provider terminal-phase contract (B74): what the provider
// owes the real kube-controller-manager Job controller per pod — Never +
// exit≠0 → phase Failed, terminal, no restart; OnFailure + exit≠0 →
// restart-in-place (RestartContainer; phase stays Running; runtimed's
// restart_count surfaced verbatim); all mains exit 0 → Succeeded; a
// sidecar-bearing Job pod is terminal on its MAINS. The controller-side
// composition (a live Job's completions/backoffLimit accounting against the
// real KCM) is the e2e stub TestM10_JobCompletion (e2e/m10_test.go).
func TestJobBackoffAndCompletionAccounting(t *testing.T) {
	newTracked := func(t *testing.T, pod *corev1.Pod) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock, *podTrack) {
		t.Helper()
		r, f, clk := newRestartFake(t)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		tr := r.trackByID(string(pod.UID))
		if tr == nil {
			t.Fatal("pod not tracked")
		}
		return r, f, clk, tr
	}

	t.Run("Never + main exit nonzero is terminal Failed, no restart", func(t *testing.T) {
		pod := runtimedPod("default", "job-never")
		pod.Spec.RestartPolicy = corev1.RestartPolicyNever
		r, f, clk, tr := newTracked(t, pod)

		rs := &runtimev1.PodStatus{
			PodId:             string(pod.UID),
			Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
			ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 1, 0, time.Unix(6000, 0))},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
		if st.Phase != corev1.PodFailed {
			t.Fatalf("phase = %s, want Failed (terminal)", st.Phase)
		}
		if st.ContainerStatuses[0].State.Terminated == nil {
			t.Errorf("state = %+v, want terminated pass-through (no CrashLoopBackOff overlay)", st.ContainerStatuses[0].State)
		}
		if clk.HasWaiters() {
			t.Error("a re-exec timer was armed for a Never pod")
		}
		settleRestartCalls(t, f, 0)
	})

	t.Run("OnFailure + main exit nonzero restarts in place, phase stays Running", func(t *testing.T) {
		pod := runtimedPod("default", "job-onfailure")
		pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
		r, f, clk, tr := newTracked(t, pod)

		rs := &runtimev1.PodStatus{
			PodId:             string(pod.UID),
			Phase:             runtimev1.PodPhase_POD_PHASE_FAILED, // runtimed's mains-only view; the provider holds Running
			ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 2, 3, time.Unix(6000, 0))},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
		if st.Phase != corev1.PodRunning {
			t.Fatalf("phase while restart pending = %s, want Running (never phase-flip without the re-exec)", st.Phase)
		}
		cs := st.ContainerStatuses[0]
		if cs.State.Waiting == nil || cs.State.Waiting.Reason != reasonCrashLoopBackOff {
			t.Fatalf("state = %+v, want Waiting{CrashLoopBackOff}", cs.State)
		}
		if cs.RestartCount != 3 {
			t.Errorf("restartCount = %d, want 3 (runtimed's count, verbatim)", cs.RestartCount)
		}
		if lt := cs.LastTerminationState.Terminated; lt == nil || lt.ExitCode != 2 {
			t.Errorf("lastState = %+v, want terminated exit 2", cs.LastTerminationState)
		}

		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })
		_, rec := f.restartState()
		if rec.container != "c0" {
			t.Errorf("restarted container = %q, want c0", rec.container)
		}
	})

	t.Run("all mains exit 0 is Succeeded, no restart", func(t *testing.T) {
		for _, policy := range []corev1.RestartPolicy{corev1.RestartPolicyNever, corev1.RestartPolicyOnFailure} {
			t.Run(string(policy), func(t *testing.T) {
				pod := runtimedPod("default", "job-done-"+strings.ToLower(string(policy)))
				pod.Spec.RestartPolicy = policy
				r, f, clk, tr := newTracked(t, pod)

				rs := &runtimev1.PodStatus{
					PodId:             string(pod.UID),
					Phase:             runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
					ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 0, 0, time.Unix(6000, 0))},
				}
				st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
				if st.Phase != corev1.PodSucceeded {
					t.Fatalf("phase = %s, want Succeeded", st.Phase)
				}
				if clk.HasWaiters() {
					t.Error("a re-exec timer was armed for a completed pod")
				}
				settleRestartCalls(t, f, 0)
			})
		}
	})

	t.Run("sidecar-bearing Job pod is terminal on its mains", func(t *testing.T) {
		pod := sidecarJobPod()
		r, f, clk, tr := newTracked(t, pod)

		// runtimed's mains-only phase: the main failed (Never pod ⇒ terminal);
		// the sidecar still shows running while runtimed tears it down.
		rs := &runtimev1.PodStatus{
			PodId:                 string(pod.UID),
			Phase:                 runtimev1.PodPhase_POD_PHASE_FAILED,
			InitContainerStatuses: []*runtimev1.ContainerStatus{rtRunning("proxy")},
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtTerminated("main", 1, 0, time.Unix(6000, 0))},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
		if st.Phase != corev1.PodFailed {
			t.Fatalf("phase = %s, want Failed (terminal on mains despite the running sidecar)", st.Phase)
		}
		if clk.HasWaiters() {
			t.Error("a re-exec timer was armed on a terminal pod")
		}
		settleRestartCalls(t, f, 0)
	})
}

// TestRestartTriggerIdempotent pins the B26 BINDING idempotency contract: the
// trigger is keyed on the termination identity (container name +
// restart_count + exit + finish instant) inside the podTrack, so a
// stream+backstop double-delivery of the SAME terminated status schedules
// exactly ONE RestartContainer — while a genuinely NEW termination (the
// post-re-exec exit, restart_count bumped by runtimed) schedules the next one,
// with the CrashLoopBackOff delay doubled.
func TestRestartTriggerIdempotent(t *testing.T) {
	pod := runtimedPod("default", "crashy")
	pod.Spec.RestartPolicy = corev1.RestartPolicyOnFailure
	r, f, clk := newRestartFake(t)
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID(string(pod.UID))
	if tr == nil {
		t.Fatal("pod not tracked")
	}

	exit1 := &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 1, 0, time.Unix(6000, 0))},
	}
	// Double delivery: once from the stream, once from the backstop resync.
	r.buildStatus(pod.DeepCopy(), tr, exit1, nil)
	r.buildStatus(pod.DeepCopy(), tr, exit1, nil)

	waitRestart(t, "backoff timer armed", clk.HasWaiters)
	clk.Step(400 * time.Second) // fires ANY armed timer, even a wrongly-doubled 20s one
	waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n >= 1 })
	settleRestartCalls(t, f, 1) // exactly one — never a double restart

	// Wait for the in-flight re-exec to fully settle (runRestart clears pending
	// AFTER the RPC returns) so the deliveries below exercise the terminationKey
	// latch, not the transient pending flag.
	waitRestart(t, "first re-exec settled", func() bool {
		tr.restartMu.Lock()
		defer tr.restartMu.Unlock()
		cr := tr.restarts["c0"]
		return cr != nil && !cr.pending
	})

	// A STALE re-delivery of the already-handled termination stays latched.
	r.buildStatus(pod.DeepCopy(), tr, exit1, nil)
	if clk.HasWaiters() {
		t.Error("a stale re-delivery re-armed the re-exec timer")
	}
	settleRestartCalls(t, f, 1)

	// The NEXT termination (restart_count bumped by runtimed's re-exec) is a
	// fresh identity: it schedules again, with the backoff advanced to 20s.
	exit2 := &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 1, 1, time.Unix(6500, 0))},
	}
	st := r.buildStatus(pod.DeepCopy(), tr, exit2, nil)
	if w := st.ContainerStatuses[0].State.Waiting; w == nil || !strings.Contains(w.Message, "back-off 20s") {
		t.Errorf("second crash overlay = %+v, want a doubled 20s back-off", st.ContainerStatuses[0].State)
	}
	waitRestart(t, "second backoff timer armed", clk.HasWaiters)
	clk.Step(21 * time.Second)
	waitRestart(t, "second RestartContainer call", func() bool { n, _ := f.restartState(); return n == 2 })
	settleRestartCalls(t, f, 2)
}
