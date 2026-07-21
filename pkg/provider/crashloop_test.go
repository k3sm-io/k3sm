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
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// rtTerminatedFull renders a terminated runtime container status carrying the
// FULL termination detail kubectl surfaces (startedAt as well as finishedAt), so
// the lastState.terminated assertions below are non-vacuous.
func rtTerminatedFull(name string, exit, restarts int32, startedAt, finishedAt time.Time) *runtimev1.ContainerStatus {
	cs := rtTerminated(name, exit, restarts, finishedAt)
	cs.State.GetTerminated().StartedAt = timestamppb.New(startedAt)
	return cs
}

// crashPod is a single-container pod under the given pod-level restart policy.
func crashPod(name string, policy corev1.RestartPolicy) *corev1.Pod {
	pod := runtimedPod("default", name)
	pod.Spec.RestartPolicy = policy
	return pod
}

// newCrashFake wires a restart-capable fake provider with a fake clock AND a
// FakeRecorder, then creates pod and returns its track.
func newCrashFake(t *testing.T, pod *corev1.Pod) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock, *podTrack, *record.FakeRecorder) {
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
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID(string(pod.UID))
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	return r, f, clk, tr, rec
}

// TestRestartOnExitCrashLoopSurface is the B26 NAMED GATE: the exit-driven
// re-exec and the CrashLoopBackOff surface a crash-looping pod must present to
// `kubectl get`/`kubectl describe`, end to end through the provider's single
// restart authority.
//
// It pins, in one place, every behaviour B26 exists to deliver:
//
//  1. an EXIT (not a probe) drives a re-exec through the RestartContainer RPC;
//  2. the container surfaces Waiting{Reason: CrashLoopBackOff} with upstream's
//     "back-off %s restarting failed container=..." message;
//  3. lastState.terminated is preserved VERBATIM (exitCode/reason/startedAt/
//     finishedAt) while the container waits;
//  4. the pod PHASE stays Running for the whole restart window — and stays
//     Running on the raw translation alone (derivePhase honors the restart
//     policy), not only while the overlay happens to be pending;
//  5. the restart window spans exit-observed → container-observed-RUNNING, so a
//     status observed after the RPC returned but before the container is up does
//     NOT flap the pod to Failed;
//  6. a FAILED RestartContainer RPC is RETRIED under the advanced backoff rather
//     than abandoning the container forever;
//  7. a LIVENESS-driven restart flows through the SAME bookkeeping and the SAME
//     per-container backoff (one restart authority, one backoff);
//  8. a Warning BackOff Event is recorded for every throttled attempt;
//  9. a native sidecar (init container with restartPolicy: Always, KEP-753)
//     restarts independently of the pod-level policy.
func TestRestartOnExitCrashLoopSurface(t *testing.T) {
	const (
		startedAtUnix  = 5000
		finishedAtUnix = 6000
	)
	startedAt, finishedAt := time.Unix(startedAtUnix, 0), time.Unix(finishedAtUnix, 0)

	// crashStatus is the runtime status of a pod whose only main container just
	// exited non-zero. runtimed's mains-only phase is FAILED; the provider must
	// hold the published phase at Running because the pod policy restarts it.
	crashStatus := func(pod *corev1.Pod, exit, restarts int32) *runtimev1.PodStatus {
		return &runtimev1.PodStatus{
			PodId:             string(pod.UID),
			Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
			ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminatedFull("c0", exit, restarts, startedAt, finishedAt)},
		}
	}
	runningStatus := func(pod *corev1.Pod, restarts int32) *runtimev1.PodStatus {
		cs := rtRunning("c0")
		cs.RestartCount = restarts
		return &runtimev1.PodStatus{
			PodId:             string(pod.UID),
			Phase:             runtimev1.PodPhase_POD_PHASE_RUNNING,
			ContainerStatuses: []*runtimev1.ContainerStatus{cs},
		}
	}

	t.Run("exit drives the re-exec and the CrashLoopBackOff surface", func(t *testing.T) {
		pod := crashPod("crash-surface", corev1.RestartPolicyAlways)
		r, f, clk, tr, _ := newCrashFake(t, pod)

		st := r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 3, 0), nil)

		if st.Phase != corev1.PodRunning {
			t.Fatalf("phase = %s, want Running (a restarting pod is Running, never terminal)", st.Phase)
		}
		cs := st.ContainerStatuses[0]
		if cs.State.Waiting == nil || cs.State.Waiting.Reason != reasonCrashLoopBackOff {
			t.Fatalf("state = %+v, want Waiting{CrashLoopBackOff}", cs.State)
		}
		wantMsg := fmt.Sprintf("back-off 10s restarting failed container=c0 pod=%s_%s(%s)", pod.Name, pod.Namespace, pod.UID)
		if cs.State.Waiting.Message != wantMsg {
			t.Errorf("waiting message = %q, want %q (upstream's phrasing)", cs.State.Waiting.Message, wantMsg)
		}
		lt := cs.LastTerminationState.Terminated
		if lt == nil {
			t.Fatalf("lastState = %+v, want the triggering termination preserved", cs.LastTerminationState)
		}
		if lt.ExitCode != 3 || lt.Reason != "Error" {
			t.Errorf("lastState.terminated = exit %d reason %q, want exit 3 reason Error", lt.ExitCode, lt.Reason)
		}
		if !lt.StartedAt.Time.Equal(startedAt) || !lt.FinishedAt.Time.Equal(finishedAt) {
			t.Errorf("lastState.terminated started/finished = %v/%v, want %v/%v",
				lt.StartedAt.Time, lt.FinishedAt.Time, startedAt, finishedAt)
		}
		if cs.Ready {
			t.Error("a crash-looping container must not be Ready")
		}

		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })
		_, rec := f.restartState()
		if rec.podID != string(pod.UID) || rec.container != "c0" {
			t.Errorf("RestartContainer(%q, %q), want (%s, c0)", rec.podID, rec.container, pod.UID)
		}
	})

	t.Run("phase stays Running from the translation alone (derivePhase honors the policy)", func(t *testing.T) {
		// No track, no overlay: this is the RAW translation. A restartable
		// termination must not render PodFailed even before any bookkeeping exists,
		// and a running main must beat a failed sibling.
		for _, tc := range []struct {
			name   string
			policy corev1.RestartPolicy
			rs     *runtimev1.PodStatus
			want   corev1.PodPhase
		}{
			{"Always + failed main is Running", corev1.RestartPolicyAlways, nil, corev1.PodRunning},
			{"OnFailure + failed main is Running", corev1.RestartPolicyOnFailure, nil, corev1.PodRunning},
			{"Never + failed main is Failed", corev1.RestartPolicyNever, nil, corev1.PodFailed},
		} {
			t.Run(tc.name, func(t *testing.T) {
				pod := crashPod("raw-"+strings.ToLower(string(tc.policy)), tc.policy)
				st := toPodStatus(pod, crashStatus(pod, 1, 0), "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
				if st.Phase != tc.want {
					t.Errorf("phase = %s, want %s", st.Phase, tc.want)
				}
			})
		}

		t.Run("a running main beats a failed sibling under Never", func(t *testing.T) {
			pod := crashPod("mixed", corev1.RestartPolicyNever)
			pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "c1", Image: "registry/x:latest"})
			rs := &runtimev1.PodStatus{
				PodId: string(pod.UID),
				Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
				ContainerStatuses: []*runtimev1.ContainerStatus{
					rtTerminatedFull("c0", 1, 0, startedAt, finishedAt),
					rtRunning("c1"),
				},
			}
			st := toPodStatus(pod, rs, "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
			if st.Phase != corev1.PodRunning {
				t.Errorf("phase = %s, want Running (upstream never reports Failed while a container runs)", st.Phase)
			}
		})
	})

	t.Run("the restart window spans exit until the container is observed running", func(t *testing.T) {
		pod := crashPod("window", corev1.RestartPolicyAlways)
		r, f, clk, tr, _ := newCrashFake(t, pod)

		r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 0), nil)
		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })
		waitRestart(t, "the re-exec RPC to settle", func() bool {
			tr.restartMu.Lock()
			defer tr.restartMu.Unlock()
			cr := tr.restarts["c0"]
			return cr != nil && !cr.attempt
		})

		// The RPC returned, but the container has NOT been observed running yet:
		// a status delivered in this window (runtimed's pre-swap snapshot, or the
		// 10s backstop resync) must NOT drop the CrashLoopBackOff surface or flap
		// the phase.
		st := r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 0), nil)
		if st.Phase != corev1.PodRunning {
			t.Errorf("phase in the post-RPC window = %s, want Running (no Running->Failed->Running flap)", st.Phase)
		}
		if w := st.ContainerStatuses[0].State.Waiting; w == nil || w.Reason != reasonCrashLoopBackOff {
			t.Errorf("state in the post-RPC window = %+v, want Waiting{CrashLoopBackOff} held", st.ContainerStatuses[0].State)
		}

		// Observing the container RUNNING (restart_count bumped by runtimed) closes
		// the window: the surface reverts to the runtime's own state.
		st = r.buildStatus(pod.DeepCopy(), tr, runningStatus(pod, 1), nil)
		if st.ContainerStatuses[0].State.Running == nil {
			t.Errorf("state after the container came up = %+v, want Running", st.ContainerStatuses[0].State)
		}
		tr.restartMu.Lock()
		inFlight := tr.restarts["c0"].restartInFlight()
		tr.restartMu.Unlock()
		if inFlight {
			t.Error("the restart window stayed open after the container was observed running")
		}
	})

	t.Run("a failed re-exec RPC is retried under the backoff", func(t *testing.T) {
		pod := crashPod("retry", corev1.RestartPolicyAlways)
		r, f, clk, tr, _ := newCrashFake(t, pod)
		f.setRestartErr(errors.New("runtimed unavailable"))

		r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 0), nil)
		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "the first (failing) RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })

		// Upstream's CrashLoopBackOff is an UNBOUNDED retry loop. The failed RPC did
		// not bump runtimed's restart_count, so the terminationKey is unchanged and
		// no status observation can re-arm the schedule — the worker itself must.
		// The failure advances the SHARED schedule, so the surfaced back-off grows.
		delayIs := func(d time.Duration) func() bool {
			return func() bool {
				tr.restartMu.Lock()
				defer tr.restartMu.Unlock()
				cr := tr.restarts["c0"]
				return cr != nil && cr.delay == d
			}
		}
		waitRestart(t, "the retry rescheduled at the doubled back-off", delayIs(20*time.Second))
		st := r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 0), nil)
		if w := st.ContainerStatuses[0].State.Waiting; w == nil || !strings.Contains(w.Message, "back-off 20s") {
			t.Errorf("retry overlay = %+v, want the doubled 20s back-off", st.ContainerStatuses[0].State)
		}

		waitRestart(t, "the retry timer armed", clk.HasWaiters)
		clk.Step(21 * time.Second)
		waitRestart(t, "the retried RestartContainer call", func() bool { n, _ := f.restartState(); return n >= 2 })

		// Once the RPC succeeds the loop stops.
		f.setRestartErr(nil)
		clk.Step(60 * time.Second)
		waitRestart(t, "the successful RestartContainer call", func() bool {
			tr.restartMu.Lock()
			defer tr.restartMu.Unlock()
			cr := tr.restarts["c0"]
			return cr != nil && !cr.attempt
		})
	})

	t.Run("a liveness restart shares the bookkeeping and the backoff", func(t *testing.T) {
		pod := crashPod("liveness", corev1.RestartPolicyAlways)
		pod.Spec.Containers[0].LivenessProbe = &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstrFromInt(8080)}},
		}
		r, f, _, tr, _ := newCrashFake(t, pod)

		// The prober's restart seam is the ONE injection point; drive it directly
		// (a real probe loop would call exactly this).
		r.mu.Lock()
		pr := r.probers[string(pod.UID)]
		r.mu.Unlock()
		if pr == nil {
			t.Fatal("no prober started for a pod with a liveness probe")
		}
		if pr.restartFunc == nil {
			t.Fatal("prober restart seam is not wired")
		}
		if err := pr.restartFunc(context.Background(), string(pod.UID), "c0"); err != nil {
			t.Fatalf("liveness restart: %v", err)
		}
		waitRestart(t, "the liveness RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })

		// It must have gone through the SHARED containerRestart bookkeeping, not
		// around it: the per-container entry exists and the shared backoff advanced.
		tr.restartMu.Lock()
		cr := tr.restarts["c0"]
		tr.restartMu.Unlock()
		if cr == nil {
			t.Fatal("the liveness restart bypassed the containerRestart bookkeeping (no entry)")
		}
		waitRestart(t, "the liveness re-exec to settle", func() bool {
			tr.restartMu.Lock()
			defer tr.restartMu.Unlock()
			return !cr.attempt
		})

		// A subsequent EXIT-driven restart must continue the SAME schedule (20s),
		// proving there is exactly one backoff per container across both triggers.
		st := r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 1), nil)
		if w := st.ContainerStatuses[0].State.Waiting; w == nil || !strings.Contains(w.Message, "back-off 20s") {
			t.Errorf("exit-after-liveness overlay = %+v, want the SHARED schedule advanced to 20s", st.ContainerStatuses[0].State)
		}
	})

	// The other half of the BackOff contract: a liveness kill on a container that
	// is NOT already looping is immediate (kubelet parity), so nothing backed off.
	// Upstream surfaces that as Unhealthy + Killing and reserves BackOff for
	// genuine throttling — emitting it here would fire an operator's
	// `reason=BackOff` alert on a single probe blip against a healthy container,
	// and the overlay would render the self-contradicting "back-off 0s".
	t.Run("an immediate liveness restart is neither a BackOff event nor a CrashLoopBackOff", func(t *testing.T) {
		pod := crashPod("liveness-immediate", corev1.RestartPolicyAlways)
		r, f, _, tr, rec := newCrashFake(t, pod)

		if err := r.restartForLiveness(context.Background(), string(pod.UID), "c0"); err != nil {
			t.Fatalf("liveness restart: %v", err)
		}
		waitRestart(t, "the liveness RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })

		tr.restartMu.Lock()
		cr := tr.restarts["c0"]
		delay, inFlight := cr.delay, cr.restartInFlight()
		tr.restartMu.Unlock()
		if delay != 0 {
			t.Fatalf("liveness delay = %s, want 0 (an idle container's kill is immediate)", delay)
		}
		if !inFlight {
			t.Fatal("the restart window must be open across the swap")
		}

		// The container is restarting, so it reads not-Ready — but it is NOT in a
		// crash loop and must not be rendered as one.
		st := &corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "c0", Ready: true,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		}
		r.applyRestartOverlay(pod, tr, st)
		got := st.ContainerStatuses[0]
		if w := got.State.Waiting; w != nil && w.Reason == reasonCrashLoopBackOff {
			t.Errorf("state = %+v, want no CrashLoopBackOff (nothing backed off)", got.State)
		}
		if w := got.State.Waiting; w != nil && strings.Contains(w.Message, "back-off 0s") {
			t.Errorf("rendered %q — a zero back-off must never be reported as one", w.Message)
		}
		if got.Ready {
			t.Error("a container being restarted must not be Ready")
		}

		select {
		case ev := <-rec.Events:
			t.Errorf("recorded %q, want NO BackOff event for an un-throttled liveness restart", ev)
		case <-time.After(100 * time.Millisecond):
		}
	})

	t.Run("a Warning BackOff event is recorded for the throttled re-exec", func(t *testing.T) {
		pod := crashPod("backoff-event", corev1.RestartPolicyAlways)
		r, f, clk, tr, rec := newCrashFake(t, pod)

		r.buildStatus(pod.DeepCopy(), tr, crashStatus(pod, 1, 0), nil)
		waitRestart(t, "backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })

		got := drainEvents(t, rec.Events, 1, 3*time.Second)
		want := fmt.Sprintf("Warning BackOff Back-off restarting failed container c0 in pod %s_%s(%s)",
			pod.Name, pod.Namespace, pod.UID)
		if got[0] != want {
			t.Errorf("event = %q, want %q", got[0], want)
		}
	})

	t.Run("a native sidecar restarts under its container-level Always in a Never pod", func(t *testing.T) {
		pod := sidecarJobPod()
		r, f, clk, tr, _ := newCrashFake(t, pod)

		rs := &runtimev1.PodStatus{
			PodId:                 string(pod.UID),
			Phase:                 runtimev1.PodPhase_POD_PHASE_RUNNING,
			InitContainerStatuses: []*runtimev1.ContainerStatus{rtTerminatedFull("proxy", 1, 0, startedAt, finishedAt)},
			ContainerStatuses:     []*runtimev1.ContainerStatus{rtRunning("main")},
		}
		st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)

		if st.Phase != corev1.PodRunning {
			t.Fatalf("phase = %s, want Running", st.Phase)
		}
		sc := st.InitContainerStatuses[0]
		if sc.State.Waiting == nil || sc.State.Waiting.Reason != reasonCrashLoopBackOff {
			t.Fatalf("sidecar state = %+v, want Waiting{CrashLoopBackOff}", sc.State)
		}
		if lt := sc.LastTerminationState.Terminated; lt == nil || lt.ExitCode != 1 {
			t.Errorf("sidecar lastState = %+v, want terminated exit 1", sc.LastTerminationState)
		}
		// The MAIN container is untouched: the sidecar's container-level policy is
		// independent of the pod-level Never.
		if st.ContainerStatuses[0].State.Running == nil {
			t.Errorf("main state = %+v, want Running (unaffected by the sidecar restart)", st.ContainerStatuses[0].State)
		}

		waitRestart(t, "the sidecar backoff timer armed", clk.HasWaiters)
		clk.Step(11 * time.Second)
		waitRestart(t, "the sidecar RestartContainer call", func() bool { n, _ := f.restartState(); return n == 1 })
		_, got := f.restartState()
		if got.container != "proxy" {
			t.Errorf("restarted container = %q, want proxy (the sidecar, not the main)", got.container)
		}
	})

	// PodInitialized is DERIVED, not stamped True unconditionally. Every
	// controller reads this condition on every pod with init containers, so the
	// gate proves the derivation end to end through toPodStatus — not just the
	// crash-looping sidecar that motivated it, but each arm of the rule, so a
	// regression that over-corrects (holding a legitimately-initialized pod at
	// False, wedging its controller) is caught here too.
	t.Run("PodInitialized is derived from the init-container statuses", func(t *testing.T) {
		startedSidecar := func() *runtimev1.ContainerStatus {
			cs := rtRunning("proxy")
			cs.Started, cs.StartedSet = true, true
			return cs
		}
		// A plain (non-sidecar) init container: same pod shape, no container-level
		// restartPolicy, so it satisfies Initialized only by exiting 0.
		plainInitPod := func() *corev1.Pod {
			pod := sidecarJobPod()
			pod.Spec.InitContainers[0].RestartPolicy = nil
			return pod
		}

		for _, tc := range []struct {
			name   string
			pod    *corev1.Pod
			initCS []*runtimev1.ContainerStatus
			want   corev1.ConditionStatus
		}{
			{
				name:   "a sidecar crash-looping before it ever started is NOT initialized",
				pod:    sidecarJobPod(),
				initCS: []*runtimev1.ContainerStatus{rtTerminatedFull("proxy", 1, 2, startedAt, finishedAt)},
				want:   corev1.ConditionFalse,
			},
			{
				name:   "a STARTED sidecar initializes the pod (it never terminates first)",
				pod:    sidecarJobPod(),
				initCS: []*runtimev1.ContainerStatus{startedSidecar()},
				want:   corev1.ConditionTrue,
			},
			{
				name:   "a declared init container with no status yet is NOT initialized",
				pod:    sidecarJobPod(),
				initCS: nil,
				want:   corev1.ConditionFalse,
			},
			{
				name:   "a plain init container that exited 0 initializes the pod",
				pod:    plainInitPod(),
				initCS: []*runtimev1.ContainerStatus{rtTerminatedFull("proxy", 0, 0, startedAt, finishedAt)},
				want:   corev1.ConditionTrue,
			},
			{
				name:   "a plain init container that FAILED does NOT initialize the pod",
				pod:    plainInitPod(),
				initCS: []*runtimev1.ContainerStatus{rtTerminatedFull("proxy", 1, 0, startedAt, finishedAt)},
				want:   corev1.ConditionFalse,
			},
			{
				name:   "a pod with no init containers is initialized",
				pod:    crashPod("no-init", corev1.RestartPolicyAlways),
				initCS: nil,
				want:   corev1.ConditionTrue,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rs := &runtimev1.PodStatus{
					PodId:                 string(tc.pod.UID),
					Phase:                 runtimev1.PodPhase_POD_PHASE_PENDING,
					InitContainerStatuses: tc.initCS,
				}
				st := toPodStatus(tc.pod, rs, "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
				c := findPodCondition(st.Conditions, corev1.PodInitialized)
				if c == nil {
					t.Fatal("no PodInitialized condition")
				}
				if c.Status != tc.want {
					t.Errorf("PodInitialized = %s, want %s", c.Status, tc.want)
				}
				if tc.want == corev1.ConditionFalse && c.Reason != "ContainersNotInitialized" {
					t.Errorf("reason = %q, want ContainersNotInitialized (what kubectl describe prints)", c.Reason)
				}
			})
		}
	})
}

// intstrFromInt is a local helper keeping the probe spec above readable.
func intstrFromInt(port int32) intstr.IntOrString { return intstr.FromInt32(port) }

// TestContainerRestartStateMachine is the table-driven proof of the collapsed
// restart bookkeeping (B26): `restarting` (the OBSERVABLE window the status
// overlay renders) and `attempt` (the internal single-worker claim) are written
// only by the four methods on containerRestart, and they advance independently.
// Before B26 a single `pending` flag conflated the two, so the window closed the
// instant the RPC returned.
func TestContainerRestartStateMachine(t *testing.T) {
	tests := []struct {
		name            string
		drive           func(cr *containerRestart, cancel context.CancelFunc)
		wantInFlight    bool
		wantAttempt     bool
		wantCancelled   bool
		wantHasLastTerm bool
	}{
		{
			name:  "a fresh entry is idle",
			drive: func(*containerRestart, context.CancelFunc) {},
		},
		{
			name:         "beginAttempt opens the window and claims the worker",
			drive:        func(cr *containerRestart, cancel context.CancelFunc) { cr.beginAttempt(cancel) },
			wantInFlight: true,
			wantAttempt:  true,
		},
		{
			name: "endAttempt releases the worker but HOLDS the window",
			drive: func(cr *containerRestart, cancel context.CancelFunc) {
				gen, _ := cr.beginAttempt(cancel)
				cr.hasLastTerm = true
				cr.endAttempt(gen)
			},
			wantInFlight:    true, // the surface survives until the container is up
			wantHasLastTerm: true,
		},
		{
			name: "observeRunning closes the window and drops the stale termination",
			drive: func(cr *containerRestart, cancel context.CancelFunc) {
				gen, _ := cr.beginAttempt(cancel)
				cr.hasLastTerm = true
				cr.endAttempt(gen)
				cr.observeRunning()
			},
		},
		{
			name: "abort cancels the worker and closes the window",
			drive: func(cr *containerRestart, cancel context.CancelFunc) {
				cr.beginAttempt(cancel)
				cr.abort()
			},
			wantCancelled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cancelled := false
			cr := &containerRestart{backoff: newCrashLoopBackoff(nil)}
			tt.drive(cr, func() { cancelled = true })

			if got := cr.restartInFlight(); got != tt.wantInFlight {
				t.Errorf("restartInFlight() = %v, want %v", got, tt.wantInFlight)
			}
			if cr.attempt != tt.wantAttempt {
				t.Errorf("attempt = %v, want %v", cr.attempt, tt.wantAttempt)
			}
			if cr.hasLastTerm != tt.wantHasLastTerm {
				t.Errorf("hasLastTerm = %v, want %v", cr.hasLastTerm, tt.wantHasLastTerm)
			}
			if cancelled != tt.wantCancelled {
				t.Errorf("worker cancelled = %v, want %v", cancelled, tt.wantCancelled)
			}
		})
	}

	t.Run("beginAttempt refuses a second worker", func(t *testing.T) {
		cr := &containerRestart{backoff: newCrashLoopBackoff(nil)}
		if _, ok := cr.beginAttempt(func() {}); !ok {
			t.Fatal("the first beginAttempt must claim the slot")
		}
		if _, ok := cr.beginAttempt(func() {}); ok {
			t.Error("a second beginAttempt claimed the slot — two workers could race one container")
		}
	})

	t.Run("abort actually invokes the cancel func", func(t *testing.T) {
		cancelled := false
		cr := &containerRestart{backoff: newCrashLoopBackoff(nil)}
		cr.beginAttempt(func() { cancelled = true })
		cr.abort()
		if !cancelled {
			t.Error("abort did not cancel the in-flight worker")
		}
		if cr.restartInFlight() || cr.attempt {
			t.Error("abort left the entry non-idle")
		}
	})

	// The claim is releasable ONLY by its holder. Worker A is aborted mid-RPC
	// (cancelRestarts on an idempotent CreatePod, or the terminal gate), a fresh
	// status starts worker B, and only THEN does A's blocked RestartContainer
	// return and run its deferred release. If that release landed, B's container
	// would read `attempt == false` while B is still running, and
	// scheduleRestartLocked — which gates solely on `attempt` — would start a
	// THIRD worker: two concurrent RestartContainer RPCs and two backoff.Next()
	// advances against one schedule.
	t.Run("a stale worker cannot release its successor's claim", func(t *testing.T) {
		cr := &containerRestart{backoff: newCrashLoopBackoff(nil)}
		genA, ok := cr.beginAttempt(func() {})
		if !ok {
			t.Fatal("setup: worker A must claim the slot")
		}
		cr.abort() // the track was replaced / the pod went terminal

		genB, ok := cr.beginAttempt(func() {})
		if !ok {
			t.Fatal("setup: worker B must claim the freed slot")
		}
		if genA == genB {
			t.Fatal("the successor reused the aborted claim's generation")
		}

		cr.endAttempt(genA) // worker A's RPC finally returns
		if !cr.attempt {
			t.Error("the stale worker released its successor's claim — a second worker could now be scheduled")
		}
		if !cr.holdsAttempt(genB) {
			t.Error("worker B no longer holds the claim it was granted")
		}

		cr.endAttempt(genB) // the real holder releases
		if cr.attempt {
			t.Error("the claim holder's release was ignored")
		}
	})

	// An aborted claim that was never superseded is also not releasable: abort
	// already cleared it, so a late release must not resurrect any state.
	t.Run("an aborted worker's release is a no-op", func(t *testing.T) {
		cr := &containerRestart{backoff: newCrashLoopBackoff(nil)}
		gen, _ := cr.beginAttempt(func() {})
		cr.abort()
		cr.endAttempt(gen)
		if cr.attempt || cr.restartInFlight() {
			t.Error("a late release reopened an aborted claim")
		}
	})
}

// TestCreatePodReplaceIsolatesTheOldRestartWorker proves a replaced track's
// worker cannot reach its successor's bookkeeping. An idempotent CreatePod for
// the same pod.UID installs a NEW podTrack (runtimed.go) and cancels the old
// one's workers — but a worker blocked inside RestartContainer at that instant
// still has to unwind. Because the worker is handed the track and entry it was
// STARTED against (never a podID it re-resolves), and releases its claim only by
// generation, that unwinding touches nothing live: no RPC fires against the
// successor and its bookkeeping stays pristine.
func TestCreatePodReplaceIsolatesTheOldRestartWorker(t *testing.T) {
	pod := crashPod("replaced", corev1.RestartPolicyAlways)
	r, f, clk, oldTrack, _ := newCrashFake(t, pod)

	r.buildStatus(pod.DeepCopy(), oldTrack, &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 1, 0, time.Unix(6000, 0))},
	}, nil)
	waitRestart(t, "backoff timer armed", clk.HasWaiters)

	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("idempotent CreatePod: %v", err)
	}
	newTrack := r.trackByID(string(pod.UID))
	if newTrack == nil {
		t.Fatal("pod not tracked after the replacing CreatePod")
	}
	if newTrack == oldTrack {
		t.Fatal("setup: CreatePod did not replace the track, so the race is not exercised")
	}

	clk.Step(600 * time.Second) // long past every back-off step
	settleRestartCalls(t, f, 0)

	newTrack.restartMu.Lock()
	n := len(newTrack.restarts)
	newTrack.restartMu.Unlock()
	if n != 0 {
		t.Errorf("the replaced track's worker wrote %d entries into the successor's bookkeeping, want 0", n)
	}
}

// TestDeletePodCancelsRestartWorker proves the re-exec worker never outlives its
// pod: a container waiting out its back-off when the pod is deleted must not
// issue a RestartContainer RPC against a pod runtimed has already torn down.
func TestDeletePodCancelsRestartWorker(t *testing.T) {
	pod := crashPod("deleted", corev1.RestartPolicyAlways)
	r, f, clk, tr, _ := newCrashFake(t, pod)

	r.buildStatus(pod.DeepCopy(), tr, &runtimev1.PodStatus{
		PodId:             string(pod.UID),
		Phase:             runtimev1.PodPhase_POD_PHASE_FAILED,
		ContainerStatuses: []*runtimev1.ContainerStatus{rtTerminated("c0", 1, 0, time.Unix(6000, 0))},
	}, nil)
	waitRestart(t, "backoff timer armed", clk.HasWaiters)

	if err := r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	clk.Step(600 * time.Second) // long past every back-off step
	settleRestartCalls(t, f, 0)
}
