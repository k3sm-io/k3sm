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
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

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
func (f *fakeRuntimeServer) StartContainer(ctx context.Context, req *runtimev1.StartContainerRequest) (*runtimev1.StartContainerResponse, error) {
	f.mu.Lock()
	f.startCalls++
	f.lastStart = startRecord{podID: req.GetPodId(), container: req.GetContainer()}
	var out startOutcome
	if len(f.startFIFO) > 0 {
		out, f.startFIFO = f.startFIFO[0], f.startFIFO[1:]
	}
	hold := f.startHold
	f.mu.Unlock()
	// The hold honours the CALLER's context, which is what makes "this attempt
	// belongs to the pod" observable: a tracked worker's ctx dies with the pod,
	// a goroutine rooted at context.Background never does.
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			f.mu.Lock()
			f.startCancels++
			f.mu.Unlock()
			return nil, ctx.Err()
		}
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

// startCancelCount is the number of held StartContainer calls that ended by
// context cancellation.
func (f *fakeRuntimeServer) startCancelCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startCancels
}

// createCount is the number of CreatePod RPCs the fake has served.
func (f *fakeRuntimeServer) createCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createCalls
}

// deleteCount is the number of DeletePod RPCs the fake has been ENTERED with —
// incremented before the optional hold, so a test can observe the provider
// parked inside the call.
func (f *fakeRuntimeServer) deleteCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleteCalls
}

// pushCreate queues one CreatePod refusal; an exhausted FIFO answers success.
func (f *fakeRuntimeServer) pushCreate(resp *runtimev1.CreatePodResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createFIFO = append(f.createFIFO, resp)
}

// holdDelete parks every subsequent DeletePod inside the RPC until the returned
// release func runs.
func (f *fakeRuntimeServer) holdDelete() func() {
	hold := make(chan struct{})
	f.mu.Lock()
	f.deleteHold = hold
	f.mu.Unlock()
	var released bool
	return func() {
		f.mu.Lock()
		f.deleteHold = nil
		f.mu.Unlock()
		if !released {
			released = true
			close(hold)
		}
	}
}

// createRefusal is the CreatePodResponse runtimed returns when the whole create
// failed — the vm shape, where no guest exists to hold a per-container waiting
// state, so the typed reason rides the response itself.
func createRefusal(fr runtimev1.FailureReason, message string) *runtimev1.CreatePodResponse {
	return &runtimev1.CreatePodResponse{
		Error:         &rpcstatus.Status{Code: int32(codes.FailedPrecondition), Message: message},
		FailureReason: fr,
	}
}

// newPullProvider wires a fake-clocked, recorder-backed provider WITHOUT
// creating a pod, so a test can arm the CreatePod FIFO before the create it is
// about to assert on (newCrashFake creates eagerly).
func newPullProvider(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock, *record.FakeRecorder) {
	t.Helper()
	f := newFakeRuntimeServer()
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n",
		NodeIP:   "192.168.1.10",
		Root:     t.TempDir(),
		Recorder: rec,
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	return r, f, clk, rec
}

// rtRunningPulled is a running container status carrying the image-pull outcome
// runtimed stamps for the most recent start attempt.
func rtRunningPulled(name, image string, pulled bool, d time.Duration) *runtimev1.ContainerStatus {
	cs := rtRunning(name)
	cs.Image = image
	cs.ImagePull = &runtimev1.ImagePullOutcome{Pulled: pulled, Duration: durationpb.New(d)}
	return cs
}

// runningStatusOf is the pod status of a pod whose containers are all up.
func runningStatusOf(pod *corev1.Pod, cs ...*runtimev1.ContainerStatus) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_RUNNING,
		ContainerStatuses: cs,
	}
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

		// A host-binary route is resolved without a pull: runtimed never parses it
		// as a reference (that exemption is pinned on the runtime side by
		// runtimed's TestHostBinaryRoutesNeverReachTheReferenceParser), so nothing
		// on this side may treat it as an image being fetched. This drives both
		// routes all the way to a published status and asserts the whole
		// pull surface stays silent for them.
		t.Run("the native routes never reach the reference parser", func(t *testing.T) {
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
					pod := runtimedPod("default", "native-"+strings.NewReplacer("/", "-", " ", "-").Replace(tc.image))
					pod.Spec.Containers[0].Image = tc.image
					if tc.image == runtimed.NativeImage || strings.HasPrefix(tc.image, "/") {
						// The host-binary route is the no-command shape.
						pod.Spec.Containers[0].Command = nil
					}
					r, _, _, tr, rec := newCrashFake(t, pod)
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
					st := r.buildStatus(pod.DeepCopy(), tr, runningStatusOf(pod, rtRunning("c0")), nil)
					if w := waitingOf(&st, "c0"); w != nil {
						t.Errorf("waiting = %+v, want none — a host binary is resolved in place", w)
					}
					if got := pullEntries(tr); len(got) != 0 {
						t.Errorf("pull schedules = %v, want none for a route that is never pulled", got)
					}
					if events := recordedEvents(rec.Events); containsEvent(events, "Pulling image") {
						t.Errorf("events = %v, want no Pulling event for a host-binary route", events)
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

		t.Run("the delete cancels the worker BEFORE the runtimed DeletePod RPC", func(t *testing.T) {
			pod := pullPod("delete-order")
			r, f, clk, tr, _ := newCrashFake(t, pod)
			r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)
			waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)

			// Park the provider inside the DeletePod RPC and assert what it had
			// ALREADY done: the sleeping worker is cancelled, so firing its timer
			// now reaches the runtime with nothing. Cancelling after the RPC — the
			// previous order — leaves a StartContainer racing a pod runtimed is
			// tearing down; runtimed refuses it, but the two sides must close the
			// window together rather than leaning on one another.
			release := f.holdDelete()
			done := make(chan error, 1)
			go func() { done <- r.DeletePod(context.Background(), pod) }()
			waitRestart(t, "the DeletePod RPC to be entered", func() bool { return f.deleteCount() == 1 })

			clk.Step(600 * time.Second)
			settleStartCalls(t, f, 0)
			release()
			if err := <-done; err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
		})

		t.Run("an image change re-keys through the tracked machinery, never a bare goroutine", func(t *testing.T) {
			pod := pullPod("updated")
			r, f, clk, tr, _ := newCrashFake(t, pod)
			// InvalidImageName earns no exponential worker, so the only attempt in
			// this test is the one the re-key files — nothing else can produce it.
			r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
				rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME, "parse ref: invalid tag")), nil)
			if got := pullEntries(tr); len(got) != 1 || got[0] != pullImage {
				t.Fatalf("pull schedules = %v, want one for %q", got, pullImage)
			}

			release := f.holdStart()
			defer release()
			fixed := pod.DeepCopy()
			fixed.Spec.Containers[0].Image = "registry.example/web:2"
			// The fake serves no UpdatePod, so the RPC fails; the re-keying happens
			// before it, which is the point — a spec change must not wait on the
			// runtime to answer.
			_ = r.UpdatePod(context.Background(), fixed)
			waitRestart(t, "the re-keyed attempt", func() bool { n, _ := f.startState(); return n == 1 })
			if got := pullEntries(tr); len(got) != 1 || got[0] != "registry.example/web:2" {
				t.Fatalf("pull schedules after the image change = %v, want one for the NEW reference", got)
			}

			// The attempt lives in t.pulls, so the pod's own delete reaches it. A
			// goroutine rooted at context.Background never learns the pod is gone
			// and would still be talking to runtimed after this returns.
			if err := r.DeletePod(context.Background(), pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			waitRestart(t, "the in-flight attempt to be cancelled by the delete",
				func() bool { return f.startCancelCount() == 1 })
			release()
			clk.Step(600 * time.Second)
			settleStartCalls(t, f, 1)
			if got := pullEntries(tr); len(got) != 0 {
				t.Errorf("pull schedules after the delete = %v, want none", got)
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

// TestPullProgressEvents pins the kubelet's pull-PROGRESS events on the runtimed
// path — the pair `kubectl describe pod` shows for every image a container
// starts behind, and the pair whose absence made a slow start indistinguishable
// from a hung one.
//
// Non-vacuity: before this change the runtimed path emitted Pulling nowhere and
// Pulled nowhere (only the HostProcess path had a Pulled emitter, for its
// already-present host binaries), so every assertion below fails against it.
// The Pulled message shape is not derivable from the status alone either: it is
// read from runtimed's typed image_pull outcome, which is why the wire carries
// one.
func TestPullProgressEvents(t *testing.T) {
	t.Run("CreatePod announces Pulling, and the first outcome announces Pulled", func(t *testing.T) {
		pod := pullPod("pulling")
		r, _, _, tr, rec := newCrashFake(t, pod)

		events := recordedEvents(rec.Events)
		if !containsEvent(events, msgPullingImage(pullImage)) {
			t.Fatalf("events = %v, want %q at the create attempt", events, msgPullingImage(pullImage))
		}
		if containsEvent(events, "Successfully pulled") {
			t.Errorf("events = %v, want no Pulled before any outcome is reported", events)
		}

		running := runningStatusOf(pod, rtRunningPulled("c0", pullImage, true, 1500*time.Millisecond))
		r.buildStatus(pod.DeepCopy(), tr, running, nil)
		events = recordedEvents(rec.Events)
		want := `Successfully pulled image "` + pullImage + `" in 1.5s`
		if !containsEvent(events, want) {
			t.Errorf("events = %v, want one containing %q", events, want)
		}
		if !containsEvent(events, "including waiting") {
			t.Errorf("events = %v, want the kubelet's two-duration Pulled message", events)
		}

		// Once per attempt: re-observing the same outcome says nothing more.
		r.buildStatus(pod.DeepCopy(), tr, running, nil)
		if events := recordedEvents(rec.Events); containsEvent(events, "Successfully pulled") {
			t.Errorf("events = %v, want Pulled exactly once per attempt", events)
		}
	})

	t.Run("an image already on the machine gets the local-hit message", func(t *testing.T) {
		pod := pullPod("present")
		r, _, _, tr, rec := newCrashFake(t, pod)
		_ = recordedEvents(rec.Events)

		r.buildStatus(pod.DeepCopy(), tr,
			runningStatusOf(pod, rtRunningPulled("c0", pullImage, false, 3*time.Millisecond)), nil)
		events := recordedEvents(rec.Events)
		if !containsEvent(events, msgImageAlreadyPresent(pullImage)) {
			t.Errorf("events = %v, want %q", events, msgImageAlreadyPresent(pullImage))
		}
		if containsEvent(events, "Successfully pulled") {
			t.Errorf("events = %v, want no registry-fetch phrasing for a local hit", events)
		}
	})

	t.Run("a retry attempt announces its own Pulling", func(t *testing.T) {
		pod := pullPod("retry-pulling")
		r, f, clk, tr, rec := newCrashFake(t, pod)
		r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
			rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL, "boom")), nil)
		_ = recordedEvents(rec.Events)

		waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "the StartContainer retry", func() bool { n, _ := f.startState(); return n == 1 })
		waitRestart(t, "the retry's Pulling event", func() bool {
			return containsEvent(recordedEvents(rec.Events), msgPullingImage(pullImage))
		})
	})

	t.Run("an unparseable reference reports the kubelet's InspectFailed message", func(t *testing.T) {
		pod := pullPod("badref")
		r, _, _, tr, rec := newCrashFake(t, pod)
		_ = recordedEvents(rec.Events)

		const bounded = "parse reference: invalid tag"
		r.buildStatus(pod.DeepCopy(), tr, pendingStatus(pod,
			rtWaiting("c0", pullImage, runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME, bounded)), nil)
		want := `Failed to apply default image tag "` + pullImage + `": ` + bounded
		if events := recordedEvents(rec.Events); !containsEvent(events, want) {
			t.Errorf("events = %v, want the kubelet's applyDefaultImageTag message %q", events, want)
		}
	})
}

// TestParkedCreateForAnUnresolvableImage is the vm half of the pull-failure
// surface: a pod whose CreatePod fails WHOLESALE for a container-class image
// reason, because no guest exists to hold a per-container waiting state.
//
// Non-vacuity: before this change the provider returned that refusal as an
// error, which lands the pod ProviderFailed — a terminal phase for a condition
// upstream reports as a retryable ImagePullBackOff, and one that makes a
// ReplicaSet churn new Pods against a registry that is merely down. Every
// assertion in the first group fails against that provider, and the second
// group pins the pod-level reasons that must KEEP failing the create.
func TestParkedCreateForAnUnresolvableImage(t *testing.T) {
	t.Run("a container-class refusal parks the pod instead of failing it", func(t *testing.T) {
		pod := pullPod("parked")
		r, f, clk, rec := newPullProvider(t)
		f.pushCreate(createRefusal(runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			`container c0: pull image "`+pullImage+`": unexpected status 500 Internal Server Error`))

		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod = %v, want the pod parked rather than failed", err)
		}
		tr := r.trackByID(string(pod.UID))
		if tr == nil {
			t.Fatal("the refused pod is not tracked, so nothing can retry it")
		}

		st, err := r.GetPodStatus(context.Background(), "default", "parked")
		if err != nil {
			t.Fatalf("GetPodStatus on a parked pod: %v", err)
		}
		if st.Phase != corev1.PodPending {
			t.Errorf("phase = %s, want Pending", st.Phase)
		}
		if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonErrImagePull {
			t.Fatalf("waiting = %+v, want Waiting{ErrImagePull}", w)
		}
		events := recordedEvents(rec.Events)
		if !containsEvent(events, "Failed to pull image") {
			t.Errorf("events = %v, want the same Failed event the started-pod path emits", events)
		}
		if !containsEvent(events, msgPullingImage(pullImage)) {
			t.Errorf("events = %v, want a Pulling event for the create attempt", events)
		}

		// The same alternation, on the same schedule primitive.
		waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
		st, err = r.GetPodStatus(context.Background(), "default", "parked")
		if err != nil {
			t.Fatalf("GetPodStatus during the back-off: %v", err)
		}
		if w := waitingOf(st, "c0"); w == nil || w.Reason != reasonImagePullBackOff {
			t.Fatalf("during the back-off = %+v, want Waiting{ImagePullBackOff}", w)
		}

		// The retry verb is CreatePod: runtimed holds nothing to start.
		clk.Step(11 * time.Second)
		waitRestart(t, "the CreatePod retry", func() bool { return f.createCount() == 2 })
		if n, _ := f.startState(); n != 0 {
			t.Errorf("StartContainer called %d times, want 0 for a pod runtimed never created", n)
		}

		// The FIFO is exhausted, so the retry succeeded: the pod proceeds exactly
		// like a normal create.
		waitRestart(t, "the park to clear", func() bool { return len(pullEntries(tr)) == 0 })
		st, err = r.GetPodStatus(context.Background(), "default", "parked")
		if err != nil {
			t.Fatalf("GetPodStatus after the successful retry: %v", err)
		}
		if st.Phase != corev1.PodRunning {
			t.Errorf("phase = %s, want Running once the retry created the pod", st.Phase)
		}
	})

	t.Run("a pod-level refusal still fails the create", func(t *testing.T) {
		pod := pullPod("podlevel")
		r, f, _, _ := newPullProvider(t)
		f.pushCreate(createRefusal(runtimev1.FailureReason_FAILURE_REASON_SANDBOX_SETUP,
			"create vm for pod: guest did not come up"))

		if err := r.CreatePod(context.Background(), pod); err == nil {
			t.Fatal("CreatePod = nil, want an error — a pod-level failure is not an image the node can retry")
		}
		if tr := r.trackByID(string(pod.UID)); tr != nil && tr.parkedFailure() != nil {
			t.Error("a pod-level failure parked the pod; only container-class image failures park")
		}
	})
}
