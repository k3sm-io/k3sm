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
	"strings"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// ---------------------------------------------------------------------------
// The StartContainer seam (R17): a FIFO of outcomes plus an optional hold, so
// the retry worker's two observable windows — sleeping (ImagePullBackOff) and
// attempting (ErrImagePull) — are stepped deterministically instead of raced.
// ---------------------------------------------------------------------------

// startOutcome is one queued StartContainer answer: a transport error, or a
// response whose waiting entry carries the typed failure_reason runtimed would
// have recorded. An exhausted FIFO answers success, which is what makes "the
// pull finally worked" the default tail of every sequence.
type startOutcome struct {
	err  error
	resp *runtimev1.StartContainerResponse
}

// startRecord captures the arguments of a StartContainer RPC.
type startRecord struct {
	podID     string
	container string
}

// StartContainer serves the queued outcomes in order, recording every call. It
// blocks on the hold channel (when armed) AFTER recording the call, so a test
// can observe the provider inside its attempt window.
func (f *fakeRuntimeServer) StartContainer(_ context.Context, req *runtimev1.StartContainerRequest) (*runtimev1.StartContainerResponse, error) {
	f.mu.Lock()
	f.startCalls++
	f.lastStart = startRecord{podID: req.GetPodId(), container: req.GetContainer()}
	var out startOutcome
	if len(f.startFIFO) > 0 {
		out, f.startFIFO = f.startFIFO[0], f.startFIFO[1:]
	}
	hold := f.startHold
	f.mu.Unlock()
	if hold != nil {
		<-hold
	}
	switch {
	case out.err != nil:
		return nil, out.err
	case out.resp != nil:
		return out.resp, nil
	default:
		return &runtimev1.StartContainerResponse{Status: &runtimev1.ContainerStatus{Name: req.GetContainer()}}, nil
	}
}

// pushStart queues one StartContainer outcome.
func (f *fakeRuntimeServer) pushStart(out startOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startFIFO = append(f.startFIFO, out)
}

// holdStart makes every subsequent StartContainer block until the returned
// release func runs.
func (f *fakeRuntimeServer) holdStart() func() {
	hold := make(chan struct{})
	f.mu.Lock()
	f.startHold = hold
	f.mu.Unlock()
	var released bool
	return func() {
		f.mu.Lock()
		f.startHold = nil
		f.mu.Unlock()
		if !released {
			released = true
			close(hold)
		}
	}
}

// startState snapshots the fake's StartContainer bookkeeping under its lock.
func (f *fakeRuntimeServer) startState() (int, startRecord) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCalls, f.lastStart
}

// forget drops a pod from the fake WITHOUT telling the provider, reproducing the
// window in which the provider tracks a pod the runtime does not know yet (the
// CreatePod call window).
func (f *fakeRuntimeServer) forget(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.created, id)
}

// startFailure builds the StartContainerResponse runtimed returns when the retry
// attempt failed again: the container stays Waiting, carrying the typed reason
// and the bounded message.
func startFailureResp(container string, fr runtimev1.FailureReason, message string) *runtimev1.StartContainerResponse {
	return &runtimev1.StartContainerResponse{
		Status: &runtimev1.ContainerStatus{
			Name: container,
			State: &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{
				Message:       message,
				FailureReason: fr,
			}},
		},
		Error:         &rpcstatus.Status{Code: int32(codes.Unavailable), Message: message},
		FailureReason: fr,
	}
}

// rtWaiting renders the runtime container status of a container that could not
// be started: Waiting with a typed failure_reason and a bounded message, exactly
// the shape runtimed's partial-start contract records.
func rtWaiting(name, image string, fr runtimev1.FailureReason, message string) *runtimev1.ContainerStatus {
	return &runtimev1.ContainerStatus{
		Name:  name,
		Image: image,
		State: &runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{
			Message:       message,
			FailureReason: fr,
		}},
	}
}

// pendingStatus is the pod status runtimed reports for a partially started pod:
// PENDING, carrying the given container statuses.
func pendingStatus(pod *corev1.Pod, cs ...*runtimev1.ContainerStatus) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_PENDING,
		ContainerStatuses: cs,
	}
}

// pullPod is a single-container pod whose image is the one the tests fail.
const pullImage = "registry.example/web:1"

func pullPod(name string) *corev1.Pod {
	pod := crashPod(name, corev1.RestartPolicyAlways)
	pod.Spec.Containers[0].Image = pullImage
	return pod
}

// waitingOf returns the named main container's waiting state, or nil.
func waitingOf(st *corev1.PodStatus, name string) *corev1.ContainerStateWaiting {
	for i := range st.ContainerStatuses {
		if st.ContainerStatuses[i].Name == name {
			return st.ContainerStatuses[i].State.Waiting
		}
	}
	return nil
}

// pullEntries snapshots the track's live pull schedules under the lock.
func pullEntries(t *podTrack) []string {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	out := make([]string, 0, len(t.pulls))
	for ref := range t.pulls {
		out = append(out, ref)
	}
	return out
}

// recordedEvents returns every event recorded so far, without waiting.
func recordedEvents(ch <-chan string) []string {
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

func containsEvent(events []string, substr string) bool {
	for _, ev := range events {
		if strings.Contains(ev, substr) {
			return true
		}
	}
	return false
}

// TestPullFailureWaitingStates is the B119 NAMED GATE: the kubelet's image
// pull-failure surface, end to end through the provider.
//
// It is one test with two groups, because the feature has two halves that must
// agree: a PURE translation of runtimed's typed failure_reason into the
// kubelet's waiting vocabulary (the "sync" group), and the provider-owned RETRY
// SCHEDULE that decides when ErrImagePull reads ImagePullBackOff instead and
// when a new StartContainer attempt is made (the "async" group, driven on the
// fake clock so nothing sleeps).
//
// Non-vacuity: before this change the provider passed runtimed's waiting reason
// through verbatim (runtimed leaves it EMPTY for a typed failure), had no
// ImagePullBackOff surface, no retry, no ContainerCreating synthesis, and
// derivePhase reported Running for a pod with one running and one waiting
// container. Every assertion below fails against that provider.
func TestPullFailureWaitingStates(t *testing.T) {
	t.Run("sync: runtimed's typed failure becomes the kubelet's waiting reason", func(t *testing.T) {
		t.Run("the failure_reason table", func(t *testing.T) {
			tests := []struct {
				name       string
				fr         runtimev1.FailureReason
				rtReason   string
				wantReason string
			}{
				{"invalid reference is terminal", runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME, "", reasonInvalidImageName},
				{"policy Never with the image absent", runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL, "", reasonErrImageNeverPull},
				{"the run spec could not be built", runtimev1.FailureReason_FAILURE_REASON_CONTAINER_CONFIG, "", reasonCreateContainerConfigError},
				{"the pull itself failed", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "", reasonErrImagePull},
				{"the credential could not be resolved", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL, "", reasonErrImagePull},
				{"no platform matched", runtimev1.FailureReason_FAILURE_REASON_IMAGE_NO_PLATFORM_MATCH, "", reasonErrImagePull},
				{"the signature was rejected", runtimev1.FailureReason_FAILURE_REASON_SIGNATURE_REJECTED, "", reasonErrImagePull},
				{"a non-failure wait passes runtimed's reason through", runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED, reasonPodInitializing, reasonPodInitializing},
				// The proto's forward-compat rule: a value this build does not
				// know is an image/container start failure (apis
				// ContainerStateWaiting.failure_reason).
				{"an unknown value reads as a pull failure", runtimev1.FailureReason(9999), "", reasonErrImagePull},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					const msg = "pull registry.example/web:1: unexpected status 401 Unauthorized"
					got := toContainerState(&runtimev1.ContainerState{Waiting: &runtimev1.ContainerStateWaiting{
						Reason:        tt.rtReason,
						Message:       msg,
						FailureReason: tt.fr,
					}})
					if got.Waiting == nil {
						t.Fatalf("state = %+v, want a Waiting state", got)
					}
					if got.Waiting.Reason != tt.wantReason {
						t.Errorf("waiting reason = %q, want %q", got.Waiting.Reason, tt.wantReason)
					}
					if got.Waiting.Message != msg {
						t.Errorf("waiting message = %q, want runtimed's message verbatim", got.Waiting.Message)
					}
				})
			}
		})

		t.Run("a waiting container holds the pod Pending even beside a running one", func(t *testing.T) {
			pod := &corev1.Pod{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyAlways}}
			cs := []corev1.ContainerStatus{
				{Name: "up", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
				{Name: "stuck", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reasonErrImagePull}}},
			}
			if got := derivePhase(pod, runtimev1.PodPhase_POD_PHASE_PENDING, cs); got != corev1.PodPending {
				t.Errorf("derivePhase(runtime PENDING) = %s, want Pending", got)
			}
			// Even when the runtime already calls the pod RUNNING, the kubelet's
			// getPhase checks waiting BEFORE running.
			if got := derivePhase(pod, runtimev1.PodPhase_POD_PHASE_RUNNING, cs); got != corev1.PodPending {
				t.Errorf("derivePhase(runtime RUNNING) = %s, want Pending (waiting is checked first)", got)
			}
			// A waiting container that carries a last termination is a restart, not
			// a start that never happened: it does not hold the pod Pending.
			cs[1].LastTerminationState = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 1}}
			cs[1].State.Waiting.Reason = reasonCrashLoopBackOff
			if got := derivePhase(pod, runtimev1.PodPhase_POD_PHASE_RUNNING, cs); got != corev1.PodRunning {
				t.Errorf("derivePhase with a crash-looping sibling = %s, want Running", got)
			}
		})

		t.Run("a tracked pod the runtime does not know yet is ContainerCreating, never NotFound", func(t *testing.T) {
			r, f := newRuntimedFake(t)
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "creating", UID: types.UID("uid-creating")},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{Name: "init0", Image: pullImage, Command: []string{"/init"}}},
					Containers:     []corev1.Container{{Name: "c0", Image: pullImage, Command: []string{"/web"}}},
				},
			}
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			// Reproduce the CreatePod call window: tracked here, unknown there.
			f.forget(string(pod.UID))

			st, err := r.GetPodStatus(context.Background(), "default", "creating")
			if err != nil {
				t.Fatalf("GetPodStatus during the create window: %v, want a synthesized status", err)
			}
			if st.Phase != corev1.PodPending {
				t.Errorf("phase = %s, want Pending", st.Phase)
			}
			if len(st.InitContainerStatuses) != 1 || st.InitContainerStatuses[0].State.Waiting == nil ||
				st.InitContainerStatuses[0].State.Waiting.Reason != reasonContainerCreating {
				t.Errorf("init container status = %+v, want Waiting{ContainerCreating}", st.InitContainerStatuses)
			}
			if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonPodInitializing {
				t.Errorf("main container status = %+v, want Waiting{PodInitializing} (an init container is declared)", st.ContainerStatuses)
			}

			// With no init containers the mains read ContainerCreating.
			plain := runtimedPod("default", "plain")
			if err := r.CreatePod(context.Background(), plain); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			f.forget(string(plain.UID))
			st, err = r.GetPodStatus(context.Background(), "default", "plain")
			if err != nil {
				t.Fatalf("GetPodStatus during the create window: %v", err)
			}
			if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonContainerCreating {
				t.Errorf("main container status = %+v, want Waiting{ContainerCreating}", st.ContainerStatuses)
			}

			// A pod the PROVIDER does not track is still NotFound.
			if _, err := r.GetPodStatus(context.Background(), "default", "nope"); err == nil {
				t.Error("an untracked pod must still be NotFound")
			}
		})

		t.Run("the native routes never reach the reference parser", func(t *testing.T) {
			r, _ := newRuntimedFake(t)
			for _, tc := range []struct {
				name  string
				image string
				want  bool
			}{
				{"the native sentinel", runtimed.NativeImage, true},
				{"an absolute host path", "/usr/local/bin/app", true},
				{"a registry reference", pullImage, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					pod := runtimedPod("default", "native")
					pod.Spec.Containers[0].Image = tc.image
					if tc.image == runtimed.NativeImage || strings.HasPrefix(tc.image, "/") {
						// The host-binary route is the no-command shape.
						pod.Spec.Containers[0].Command = nil
					}
					box, err := r.buildBox(context.Background(), pod, "192.168.1.10")
					if err != nil {
						t.Fatalf("buildBox: %v", err)
					}
					if got := isHostBinaryRoute(box.GetContainers()[0]); got != tc.want {
						t.Fatalf("isHostBinaryRoute(%q) = %v, want %v", tc.image, got, tc.want)
					}
					if !tc.want {
						return
					}
					// A host-binary route is resolved without a pull, so runtimed
					// never parses it as a reference and no InvalidImageName wait can
					// be produced for it. Pin the consequence at this seam: the class
					// of a non-failure wait is "no schedule".
					if got := pullClassFor(runtimev1.FailureReason_FAILURE_REASON_UNSPECIFIED); got != pullClassNone {
						t.Errorf("pullClassFor(UNSPECIFIED) = %v, want no schedule", got)
					}
				})
			}
		})
	})

	t.Run("async: the provider owns the retry schedule", func(t *testing.T) {
		t.Run("ErrImagePull and ImagePullBackOff alternate, restartCount stays 0", func(t *testing.T) {
			pod := pullPod("alternate")
			r, f, clk, tr, rec := newCrashFake(t, pod)
			const msg = "pull registry.example/web:1: connection refused"
			failing := func() *runtimev1.PodStatus {
				return pendingStatus(pod, rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, msg))
			}

			// 1. The attempt that failed reads ErrImagePull with runtimed's message.
			st := r.buildStatus(pod.DeepCopy(), tr, failing(), nil)
			w := waitingOf(&st, "c0")
			if w == nil || w.Reason != reasonErrImagePull || w.Message != msg {
				t.Fatalf("first observation = %+v, want Waiting{ErrImagePull} with runtimed's message", w)
			}
			if st.Phase != corev1.PodPending {
				t.Errorf("phase = %s, want Pending while a container waits", st.Phase)
			}
			if st.ContainerStatuses[0].RestartCount != 0 {
				t.Errorf("restartCount = %d, want 0 (a pull failure is not a restart)", st.ContainerStatuses[0].RestartCount)
			}

			// 2. Once the worker is sleeping out its back-off the surface flips.
			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
			st = r.buildStatus(pod.DeepCopy(), tr, failing(), nil)
			w = waitingOf(&st, "c0")
			if w == nil || w.Reason != reasonImagePullBackOff {
				t.Fatalf("during the back-off = %+v, want Waiting{ImagePullBackOff}", w)
			}
			if want := msgBackOffPullingImage(pullImage); w.Message != want {
				t.Errorf("back-off message = %q, want %q", w.Message, want)
			}

			// 3. Inside the attempt window the surface reads ErrImagePull again.
			release := f.holdStart()
			f.pushStart(startOutcome{resp: startFailureResp("c0", runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, msg)})
			clk.Step(11 * time.Second)
			waitRestart(t, "the StartContainer retry", func() bool { n, _ := f.startState(); return n == 1 })
			st = r.buildStatus(pod.DeepCopy(), tr, failing(), nil)
			w = waitingOf(&st, "c0")
			if w == nil || w.Reason != reasonErrImagePull {
				t.Fatalf("inside the attempt window = %+v, want Waiting{ErrImagePull}", w)
			}
			_, rec2 := f.startState()
			if rec2.container != "c0" || rec2.podID != string(pod.UID) {
				t.Errorf("StartContainer called for %+v, want this pod's c0", rec2)
			}

			// 4. The failed attempt re-arms the schedule at the doubled delay.
			release()
			waitRestart(t, "the schedule to re-arm", clk.HasWaiters)
			st = r.buildStatus(pod.DeepCopy(), tr, failing(), nil)
			if w := waitingOf(&st, "c0"); w == nil || w.Reason != reasonImagePullBackOff {
				t.Fatalf("after the failed retry = %+v, want Waiting{ImagePullBackOff}", w)
			}
			if calls, _ := f.restartState(); calls != 0 {
				t.Errorf("RestartContainer called %d times, want 0 — a never-started container is never restarted", calls)
			}
			if st.ContainerStatuses[0].RestartCount != 0 {
				t.Errorf("restartCount = %d, want 0 throughout the alternation", st.ContainerStatuses[0].RestartCount)
			}

			events := recordedEvents(rec.Events)
			if !containsEvent(events, "Failed to pull image") {
				t.Errorf("events = %v, want a Failed event naming the pull", events)
			}
			if !containsEvent(events, "Back-off pulling image") {
				t.Errorf("events = %v, want a BackOff event", events)
			}

			// 5. A successful attempt drops the schedule.
			clk.Step(21 * time.Second)
			waitRestart(t, "the successful StartContainer", func() bool { n, _ := f.startState(); return n == 2 })
			waitRestart(t, "the schedule to be dropped", func() bool { return len(pullEntries(tr)) == 0 })
		})

		t.Run("a transport failure keeps retrying under the same schedule", func(t *testing.T) {
			pod := pullPod("transport")
			r, f, clk, tr, _ := newCrashFake(t, pod)
			f.pushStart(startOutcome{err: errors.New("runtimed unavailable")})
			r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)

			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
			clk.Step(11 * time.Second)
			waitRestart(t, "the first attempt", func() bool { n, _ := f.startState(); return n == 1 })
			waitRestart(t, "the retry to re-arm after the transport error", clk.HasWaiters)
			clk.Step(21 * time.Second)
			waitRestart(t, "the retried attempt", func() bool { n, _ := f.startState(); return n >= 2 })
		})

		t.Run("policy Never gets no exponential worker, only the resync re-attempt", func(t *testing.T) {
			pod := pullPod("never")
			r, f, clk, tr, rec := newCrashFake(t, pod)
			const msg = "image registry.example/web:1 is not present and pull policy is Never"
			never := func() *runtimev1.PodStatus {
				return pendingStatus(pod, rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_NEVER_PULL, msg))
			}

			st := r.buildStatus(pod.DeepCopy(), tr, never(), nil)
			if w := waitingOf(&st, "c0"); w == nil || w.Reason != reasonErrImageNeverPull {
				t.Fatalf("waiting = %+v, want Waiting{ErrImageNeverPull}", w)
			}
			if clk.HasWaiters() {
				t.Error("an exponential back-off timer was armed for a Never failure; it has no backoff upstream")
			}
			if n, _ := f.startState(); n != 0 {
				t.Errorf("StartContainer called %d times on the first evaluation, want 0", n)
			}
			if !containsEvent(recordedEvents(rec.Events), "is not present with pull policy of Never") {
				t.Error("want an ErrImageNeverPull event on the evaluation")
			}

			// One re-attempt per backstop resync, no exponential growth.
			clk.Step(resyncInterval)
			r.buildStatus(pod.DeepCopy(), tr, never(), nil)
			waitRestart(t, "the resync-cadence re-attempt", func() bool { n, _ := f.startState(); return n == 1 })
			if clk.HasWaiters() {
				t.Error("the resync re-attempt armed a back-off timer; it must not")
			}
		})

		t.Run("DeletePod cancels the worker", func(t *testing.T) {
			pod := pullPod("deleted")
			r, f, clk, tr, _ := newCrashFake(t, pod)
			r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)
			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)

			if err := r.DeletePod(context.Background(), pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			clk.Step(600 * time.Second)
			settleStartCalls(t, f, 0)
		})

		t.Run("an idempotent CreatePod cancels the replaced track's worker", func(t *testing.T) {
			pod := pullPod("replaced")
			r, f, clk, oldTrack, _ := newCrashFake(t, pod)
			r.buildStatus(pod.DeepCopy(), oldTrack, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)
			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)

			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("idempotent CreatePod: %v", err)
			}
			newTrack := r.trackByID(string(pod.UID))
			if newTrack == nil || newTrack == oldTrack {
				t.Fatal("setup: CreatePod did not replace the track, so the race is not exercised")
			}
			clk.Step(600 * time.Second)
			settleStartCalls(t, f, 0)
			if got := pullEntries(newTrack); len(got) != 0 {
				t.Errorf("the replaced track's worker wrote %v into the successor's bookkeeping, want none", got)
			}
		})

		t.Run("UpdatePod with a changed image drops the schedule", func(t *testing.T) {
			pod := pullPod("updated")
			r, _, _, tr, _ := newCrashFake(t, pod)
			r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)
			if got := pullEntries(tr); len(got) != 1 || got[0] != pullImage {
				t.Fatalf("pull schedules = %v, want one for %q", got, pullImage)
			}

			fixed := pod.DeepCopy()
			fixed.Spec.Containers[0].Image = "registry.example/web:2"
			// The fake serves no UpdatePod, so the RPC fails; the re-keying happens
			// before it, which is the point — a spec change must not wait on the
			// runtime to answer.
			_ = r.UpdatePod(context.Background(), fixed)
			if got := pullEntries(tr); len(got) != 0 {
				t.Errorf("pull schedules after the image change = %v, want none (the old reference is gone)", got)
			}
		})
	})
}

// settleStartCalls asserts the fake's StartContainer count stays at want over a
// short settle window (catches a worker that outlived its pod).
func settleStartCalls(t *testing.T, f *fakeRuntimeServer, want int) {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got, _ := f.startState(); got != want {
			t.Fatalf("StartContainer calls = %d, want %d", got, want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
