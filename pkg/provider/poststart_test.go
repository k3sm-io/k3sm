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
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// --- postStart fidelity fakes -------------------------------------------------

// hookRuntime is the in-memory RuntimeServer for the postStart gate: it records
// every exec-hook invocation, can HOLD a hook mid-flight (so the pending window is
// observable rather than raced), records a hook whose stream context was CANCELLED,
// and scripts the hook's exit code. Everything else is the shared fake — no live
// runtimed, no privilege, no network (the standards' "fake at seams" rule).
type hookRuntime struct {
	*fakeRuntimeServer

	hmu      sync.Mutex
	execs    []string // container name per exec-hook invocation, in order
	canceled int      // hooks that returned because their context was cancelled
	exit     int32    // scripted hook exit code (0 = the hook succeeded)
	release  chan struct{}
}

// Exec runs (or holds) one lifecycle exec hook. A nil release channel returns at
// once; otherwise the hook blocks until the test releases it — or until its context
// is cancelled, which is what a pod deletion must do to an in-flight hook.
func (h *hookRuntime) Exec(stream grpc.BidiStreamingServer[runtimev1.ExecRequest, runtimev1.ExecResponse]) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	h.hmu.Lock()
	h.execs = append(h.execs, req.GetContainer())
	release, exit := h.release, h.exit
	h.hmu.Unlock()

	if release != nil {
		select {
		case <-release:
		case <-stream.Context().Done():
			h.hmu.Lock()
			h.canceled++
			h.hmu.Unlock()
			return stream.Context().Err()
		}
	}
	return stream.Send(&runtimev1.ExecResponse{Exit: &runtimev1.ExecResult{ExitCode: exit}})
}

func (h *hookRuntime) execCount() int {
	h.hmu.Lock()
	defer h.hmu.Unlock()
	return len(h.execs)
}

func (h *hookRuntime) canceledCount() int {
	h.hmu.Lock()
	defer h.hmu.Unlock()
	return h.canceled
}

// newHookFake wires a provider over the hook runtime with a FakeRecorder, so the
// Warning event a failed hook must record is observable.
func newHookFake(t *testing.T) (*runtimedRuntime, *hookRuntime, *record.FakeRecorder) {
	t.Helper()
	r, f, rec, _ := newHookFakeLogged(t)
	return r, f, rec
}

// newHookFakeLogged is newHookFake with the provider's node log captured, so the
// lines the terminal postStart arm writes are countable.
func newHookFakeLogged(t *testing.T) (*runtimedRuntime, *hookRuntime, *record.FakeRecorder, *captureHandler) {
	t.Helper()
	f := &hookRuntime{fakeRuntimeServer: newFakeRuntimeServer()}
	rec := record.NewFakeRecorder(32)
	logs := newCaptureHandler()
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
	}, nil, slog.New(logs))
	return r, f, rec, logs
}

// postStartPod is a single-container ("c0" — the name the shared fake's status
// renderer reports) pod whose container carries an exec postStart hook.
func postStartPod(name string, policy corev1.RestartPolicy) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			RestartPolicy: policy,
			Containers: []corev1.Container{{
				Name:    "c0",
				Image:   "web",
				Command: []string{"/web"},
				Lifecycle: &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
					Exec: &corev1.ExecAction{Command: []string{"/bin/poststart"}},
				}},
			}},
		},
	}
}

// hookStatus returns the pod status the provider publishes (the same assembly
// every publish path uses).
func hookStatus(t *testing.T, r *runtimedRuntime, pod *corev1.Pod) *corev1.PodStatus {
	t.Helper()
	st, err := r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	return st
}

// containerReady reports the published Ready flag of the named container.
func containerReady(st *corev1.PodStatus, name string) bool {
	for i := range st.ContainerStatuses {
		if st.ContainerStatuses[i].Name == name {
			return st.ContainerStatuses[i].Ready
		}
	}
	return false
}

// waitCond polls cond until it holds or the deadline expires.
func waitCond(t *testing.T, what string, cond func() bool) {
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

// --- TestPostStartFidelity ---------------------------------------------------

// TestPostStartFidelity is the B39 gate: the provider must serve postStart hooks
// with the upstream kubelet's semantics, not B10's fire-and-forget dispatch. The
// contract is the one stated on the API type itself (k8s.io/api core/v1 types.go,
// Lifecycle / Lifecycle.PostStart — "management of the container blocks until the
// action is complete"; "If the handler fails, the container is terminated and
// restarted according to its restart policy"), which the kubelet implements by
// running the hook synchronously inside startContainer.
//
// Four rows, one per semantic, each red on a plausible-wrong implementation:
//
//  1. READY-GATING — a container whose hook has not returned must not publish
//     Ready, and the pod must not publish Ready/ContainersReady. Red on B10's
//     dispatch-only hook, which publishes the runtime's Ready verbatim.
//  2. restartPolicy: Never — a failed hook kills the container, which stays
//     Terminated: one StopContainer, no restart, the pod Failed, the failure on
//     the pod's Events. Red on a log-and-continue implementation (a Ready pod, no
//     event) and on a hold-NotReady-only one (the process still running).
//  3. RE-RUN ON RESTART — the hook fires on every container START. Red on a
//     once-per-pod implementation (exec count stuck at 1 across a restart).
//  4. CANCELABLE LIFETIME — a hook still running at pod deletion is cancelled with
//     the pod and never blocks teardown. Red on B10's context.Background() + 2m
//     cap, under which the hook outlives the pod by up to two minutes.
//
// TIER: unit. All four are provable at the provider↔runtime seam with the package's
// existing fakes — no live runtimed, no privilege, no network, no wall-clock sleep
// beyond bounded polling.
//
// CEILING (row 2, stated so the gate cannot be mistaken for more than it proves):
// the stop is observed at the runtime seam (the fake re-renders the container
// Terminated once StopContainer succeeds); that runtimed's verb really kills one
// process group and leaves it dead is runtimed's own gate. The arms where the stop
// cannot happen (a vm backend, a runtimed without the verb) are
// TestPostStartKillFollowsRestartPolicy's rows, not this one's.
func TestPostStartFidelity(t *testing.T) {
	ctx := context.Background()

	t.Run("a container is not Ready until its postStart hook completes", func(t *testing.T) {
		r, f, _ := newHookFake(t)
		f.release = make(chan struct{}, 1) // hold the hook mid-flight
		pod := postStartPod("gate", corev1.RestartPolicyAlways)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
		waitCond(t, "the postStart hook to be dispatched", func() bool { return f.execCount() == 1 })

		// The RUNTIME reports the container running and Ready — so a Ready=false
		// here can only come from the provider's postStart gate, never from the
		// runtime status passing through.
		rs, err := f.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: string(pod.UID)})
		if err != nil || !rs.GetStatus().GetContainerStatuses()[0].GetReady() {
			t.Fatalf("precondition: the runtime must report c0 ready (err=%v, status=%v)", err, rs.GetStatus())
		}

		st := hookStatus(t, r, pod)
		if containerReady(st, "c0") {
			t.Error("c0 published Ready while its postStart hook is still running")
		}
		if s := st.ContainerStatuses[0].Started; s == nil || *s {
			t.Errorf("c0 Started = %v, want false while the postStart hook runs", s)
		}
		if got := condStatus(st, corev1.ContainersReady); got != corev1.ConditionFalse {
			t.Errorf("ContainersReady = %s, want False while a postStart hook runs", got)
		}
		if got := condStatus(st, corev1.PodReady); got != corev1.ConditionFalse {
			t.Errorf("PodReady = %s, want False while a postStart hook runs", got)
		}

		f.release <- struct{}{} // the hook returns 0
		waitCond(t, "the readiness gate to lift once the hook completes", func() bool {
			return containerReady(hookStatus(t, r, pod), "c0")
		})
		st = hookStatus(t, r, pod)
		if got := condStatus(st, corev1.PodReady); got != corev1.ConditionTrue {
			t.Errorf("PodReady = %s after the hook completed, want True", got)
		}
		if got := condStatus(st, corev1.ContainersReady); got != corev1.ConditionTrue {
			t.Errorf("ContainersReady = %s after the hook completed, want True", got)
		}
	})

	t.Run("restartPolicy Never: a failed hook kills the container, which stays Terminated", func(t *testing.T) {
		r, f, rec := newHookFake(t)
		f.exit = 7 // the hook fails
		pod := postStartPod("never", corev1.RestartPolicyNever)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

		// The failure reaches the pod's Events with the kubelet's reason, and
		// WITHOUT the handler's output (Events are namespace-readable).
		ev := nextLifecycleEvent(rec.Events, 3*time.Second)
		if !strings.HasPrefix(ev, "Warning "+reasonFailedPostStartHook+" ") || !strings.Contains(ev, "c0") {
			t.Errorf("event = %q, want a Warning %s naming container c0", ev, reasonFailedPostStartHook)
		}

		// The container never becomes Ready on this start, and the pod is not Ready:
		// a failed postStart is a failed container start, not an advisory warning.
		waitCond(t, "the failed hook to hold c0 NotReady", func() bool {
			return !containerReady(hookStatus(t, r, pod), "c0")
		})
		st := hookStatus(t, r, pod)
		if got := condStatus(st, corev1.PodReady); got != corev1.ConditionFalse {
			t.Errorf("PodReady = %s after a failed postStart, want False", got)
		}
		// ...and it STAYS NotReady: the verdict is latched for the container start,
		// not a one-tick blip that the next publish clears.
		if containerReady(hookStatus(t, r, pod), "c0") {
			t.Error("c0 became Ready on a later publish after its postStart hook failed")
		}
		// Never restarts nothing — the failed hook must not drive a re-exec.
		settleRestartCalls(t, f.fakeRuntimeServer, 0)
		if n := f.execCount(); n != 1 {
			t.Errorf("postStart hook ran %d times under restartPolicy Never, want 1 (no restart, no re-run)", n)
		}
		// ...but it is KILLED: one terminal stop, and the container stays down.
		waitCond(t, "the terminal stop", func() bool { n, _ := f.stopState(); return n >= 1 })
		if n, _ := f.stopState(); n != 1 {
			t.Errorf("StopContainer calls = %d, want 1 (upstream kills a container whose postStart hook failed)", n)
		}
		st = hookStatus(t, r, pod)
		if term := st.ContainerStatuses[0].State.Terminated; term == nil {
			t.Errorf("c0 state = %+v, want Terminated after the postStart kill", st.ContainerStatuses[0].State)
		}
		if st.Phase != corev1.PodFailed {
			t.Errorf("phase = %s, want Failed (Never, the only container killed)", st.Phase)
		}
	})

	t.Run("the hook re-runs on every container start, not once per pod", func(t *testing.T) {
		r, f, _ := newHookFake(t)
		f.release = make(chan struct{}, 1)
		pod := postStartPod("rerun", corev1.RestartPolicyAlways)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

		waitCond(t, "the first postStart hook", func() bool { return f.execCount() == 1 })
		f.release <- struct{}{}
		waitCond(t, "the first hook's gate to lift", func() bool {
			return containerReady(hookStatus(t, r, pod), "c0")
		})

		// Restart the container through the single restart authority — the same
		// path a committed liveness failure and a CrashLoopBackOff re-exec take.
		if err := r.restartForLiveness(ctx, string(pod.UID), "c0"); err != nil {
			t.Fatalf("restartForLiveness: %v", err)
		}
		waitCond(t, "the container re-exec", func() bool {
			n, _ := f.restartState()
			return n == 1
		})
		waitCond(t, "the postStart hook to re-run on the restarted container", func() bool {
			return f.execCount() == 2
		})

		// The re-dispatched hook gates readiness exactly like the first one.
		st := hookStatus(t, r, pod)
		if containerReady(st, "c0") {
			t.Error("c0 published Ready while its RE-RUN postStart hook is still running")
		}
		f.release <- struct{}{}
	})

	t.Run("a hook still running at pod deletion is cancelled and never blocks teardown", func(t *testing.T) {
		r, f, _ := newHookFake(t)
		f.release = make(chan struct{}) // never fed: the hook hangs forever
		pod := postStartPod("cancel", corev1.RestartPolicyAlways)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		waitCond(t, "the postStart hook to be dispatched", func() bool { return f.execCount() == 1 })

		done := make(chan error, 1)
		go func() { done <- r.DeletePod(ctx, pod) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("DeletePod blocked on a hung postStart hook")
		}

		// The hook's context died WITH the pod: it neither outlives teardown nor
		// waits out a fixed cap.
		waitCond(t, "the in-flight hook to be cancelled by the pod deletion", func() bool {
			return f.canceledCount() == 1
		})
	})
}

// --- TestPostStartKillFollowsRestartPolicy ------------------------------------

// countLogs counts captured records whose message is msg.
func countLogs(h *captureHandler, msg string) int {
	n := 0
	for _, rec := range h.captured() {
		if rec.message == msg {
			n++
		}
	}
	return n
}

// pendingEvents returns every event recorded so far, without waiting.
func pendingEvents(ch <-chan string) []string {
	var out []string
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

// hasKilling reports whether any of evs is a Normal Killing event.
func hasKilling(evs []string) bool {
	for _, ev := range evs {
		if strings.HasPrefix(ev, corev1.EventTypeNormal+" "+reasonKilling+" ") {
			return true
		}
	}
	return false
}

// TestPostStartKillFollowsRestartPolicy is the provider half of the terminal
// postStart kill: a container whose postStart hook fails is KILLED and then
// handled by its restart policy (k8s.io/api core/v1 Lifecycle.PostStart), which
// the kubelet implements as killContainer → CRI StopContainer. Under Never that
// is the new StopContainer verb and the container stays Terminated; under
// OnFailure/Always it stays RestartContainer through the single restart
// authority. Where the stop cannot happen, the honest subset stands and the two
// Unimplemented channels stay apart: a runtimed that predates the verb
// (transport) gets one upgrade line per process; a backend that cannot stop one
// container (embedded, the vm shape) gets none. A re-attached pod is stopped
// like any other (TestAdoptedPodRestartsInPlace).
//
// Red on main: the fake runtime serves no StopContainer and the Never arm never
// stops anything.
func TestPostStartKillFollowsRestartPolicy(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		policy corev1.RestartPolicy
	}{
		{"OnFailure restarts, never stops", corev1.RestartPolicyOnFailure},
		{"Always restarts, never stops", corev1.RestartPolicyAlways},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, f, _ := newHookFake(t)
			f.exit = 7
			pod := postStartPod("restart-"+strings.ToLower(string(tc.policy)), tc.policy)
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
			waitCond(t, "the postStart re-exec", func() bool { n, _ := f.restartState(); return n >= 1 })
			settleRestartCalls(t, f.fakeRuntimeServer, 1)
			if n, _ := f.stopState(); n != 0 {
				t.Errorf("StopContainer calls = %d under %s, want 0 (the kill is a re-exec)", n, tc.policy)
			}
		})
	}

	t.Run("Never stops the container, which stays Terminated", func(t *testing.T) {
		r, f, rec := newHookFake(t)
		f.exit = 7
		pod := postStartPod("never-stop", corev1.RestartPolicyNever)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

		if ev := nextLifecycleEvent(rec.Events, 3*time.Second); !strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reasonFailedPostStartHook+" ") {
			t.Fatalf("first event = %q, want the Warning %s", ev, reasonFailedPostStartHook)
		}
		want := corev1.EventTypeNormal + " " + reasonKilling + " " + msgKillingPostStart
		if ev := nextLifecycleEvent(rec.Events, 3*time.Second); ev != want {
			t.Fatalf("second event = %q, want %q (recorded after the stop)", ev, want)
		}
		n, last := f.stopState()
		if n != 1 {
			t.Errorf("StopContainer calls = %d, want 1", n)
		}
		if last.podID != string(pod.UID) || last.container != "c0" || last.grace != 0 || last.reason != reasonFailedPostStartHook {
			t.Errorf("StopContainer args = %+v, want pod %s, c0, grace 0 (the PodBox grace), reason %s", last, pod.UID, reasonFailedPostStartHook)
		}
		settleRestartCalls(t, f.fakeRuntimeServer, 0)

		st := hookStatus(t, r, pod)
		cs := st.ContainerStatuses[0]
		if cs.State.Terminated == nil || cs.State.Terminated.Reason != "Error" || cs.State.Terminated.ExitCode != 137 {
			t.Errorf("c0 state = %+v, want Terminated{137, Error} (runtimed's reason passed through)", cs.State)
		}
		if cs.Ready {
			t.Error("c0 Ready after the postStart kill")
		}
		if st.Phase != corev1.PodFailed {
			t.Errorf("phase = %s, want Failed", st.Phase)
		}
		settleRestartCalls(t, f.fakeRuntimeServer, 0)
	})

	// heldSubset asserts the honest subset: the container is still running, held
	// NotReady, never Terminated, never restarted, and no Killing event exists.
	heldSubset := func(t *testing.T, r *runtimedRuntime, f *hookRuntime, rec *record.FakeRecorder, pod *corev1.Pod) {
		t.Helper()
		st := hookStatus(t, r, pod)
		cs := st.ContainerStatuses[0]
		if cs.State.Running == nil || cs.State.Terminated != nil {
			t.Errorf("c0 state = %+v, want Running (never reported Terminated while it runs)", cs.State)
		}
		if cs.Ready {
			t.Error("c0 Ready after a failed postStart hook")
		}
		if st.Phase != corev1.PodRunning {
			t.Errorf("phase = %s, want Running", st.Phase)
		}
		settleRestartCalls(t, f.fakeRuntimeServer, 0)
		if hasKilling(pendingEvents(rec.Events)) {
			t.Error("a Killing event was recorded for a container that was not stopped")
		}
	}

	t.Run("Never against a runtimed without the verb: honest subset, one upgrade line per process", func(t *testing.T) {
		r, f, rec, logs := newHookFakeLogged(t)
		f.exit = 7
		f.setStopErr(status.Error(codes.Unimplemented, "unknown method StopContainer"))
		pods := []*corev1.Pod{postStartPod("old-a", corev1.RestartPolicyNever), postStartPod("old-b", corev1.RestartPolicyNever)}
		for _, pod := range pods {
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
		}
		waitCond(t, "both pods held NotReady", func() bool { return countLogs(logs, logPostStartHeld) == 2 })
		if n, _ := f.stopState(); n != 2 {
			t.Errorf("StopContainer calls = %d, want 2 (one attempt per pod)", n)
		}
		if n := countLogs(logs, logStopVerbMissing); n != 1 {
			t.Errorf("upgrade lines = %d across two pods, want exactly 1 per process", n)
		}
		for _, pod := range pods {
			heldSubset(t, r, f, rec, pod)
		}
	})

	t.Run("Never on a backend that cannot stop one container: honest subset, no upgrade line", func(t *testing.T) {
		r, f, rec, logs := newHookFakeLogged(t)
		f.exit = 7
		f.setStopResp(&runtimev1.StopContainerResponse{
			Error:         &rpcstatus.Status{Code: int32(codes.Unimplemented), Message: "vm pods have no per-container stop"},
			FailureReason: runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED,
		})
		pod := postStartPod("vm-like", corev1.RestartPolicyNever)
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })
		waitCond(t, "the container held NotReady", func() bool { return countLogs(logs, logPostStartHeld) == 1 })
		if n, _ := f.stopState(); n != 1 {
			t.Errorf("StopContainer calls = %d, want 1", n)
		}
		if n := countLogs(logs, logStopVerbMissing); n != 0 {
			t.Errorf("upgrade lines = %d, want 0 (a backend ceiling is not closed by an upgrade)", n)
		}
		heldSubset(t, r, f, rec, pod)
	})
}
