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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

func TestActiveDeadlineExceeded(t *testing.T) {
	now := time.Unix(10000, 0)
	five := int64(5)
	at := func(d time.Duration) *metav1.Time { m := metav1.NewTime(now.Add(-d)); return &m }
	cases := []struct {
		name     string
		deadline *int64
		start    *metav1.Time
		want     bool
	}{
		{"no deadline is never exceeded", nil, at(time.Hour), false},
		{"no start time is never exceeded", &five, nil, false},
		{"before the deadline", &five, at(4 * time.Second), false},
		{"at the deadline", &five, at(5 * time.Second), true},
		{"past the deadline", &five, at(time.Minute), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := activeDeadlineExceeded(c.deadline, c.start, now); got != c.want {
				t.Errorf("activeDeadlineExceeded = %v, want %v", got, c.want)
			}
		})
	}
}

// TestPodPastActiveDeadlineFailsDeadlineExceeded pins the kubelet's
// activeDeadlineSeconds enforcement on the resync: a pod past its deadline,
// running or parked on an image failure, is stopped once and reported Failed
// with reason DeadlineExceeded (persisted, one Event, no DisruptionTarget), keeps
// its address until its DeletePod, and is never created again.
func TestPodPastActiveDeadlineFailsDeadlineExceeded(t *testing.T) {
	ptr := func(v int64) *int64 { return &v }
	cases := []struct {
		name     string
		deadline *int64
		parked   bool
		nilStart bool
		// backdate, when set, moves the track's start that far before the
		// provider clock after CreatePod.
		backdate time.Duration
		step     time.Duration
		// update, when set, is the deadline an UpdatePod installs after a first
		// resync that must leave the pod alone.
		update     *int64
		wantFailed bool
	}{
		// Every step clears or misses its deadline by minutes: the track's start
		// is the wall clock when CreatePod runs, which on a loaded host can be
		// well after the fake clock was set.
		{name: "a running pod past its deadline", deadline: ptr(60), step: 20 * time.Minute, wantFailed: true},
		// The parked pod's start is back-dated instead: a step past the pull
		// back-off would fire a create re-attempt before the resync.
		{name: "a pod parked on an image failure past its deadline", deadline: ptr(60), parked: true, backdate: 20 * time.Minute, step: time.Second, wantFailed: true},
		{name: "a pod with no deadline", step: time.Hour},
		{name: "a pod whose deadline is not yet reached", deadline: ptr(3600), step: 10 * time.Minute},
		{name: "a pod with no start time", deadline: ptr(60), nilStart: true, step: time.Hour},
		{name: "an update that shortens the deadline is honoured", deadline: ptr(3600), step: 20 * time.Minute, update: ptr(60), wantFailed: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			pod := pullPod("deadline")
			pod.Spec.ActiveDeadlineSeconds = c.deadline
			id := string(pod.UID)
			r, e, _, rec := newBlockedCreateProvider(t)
			// The track's start time is the wall clock's; the provider clock
			// starts there so a step moves the pod's age.
			clk := testclock.NewFakeClock(time.Now())
			r.clk = clk
			cs := fake.NewClientset()
			r.client = cs
			if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
				t.Fatalf("apiserver create: %v", err)
			}
			if c.parked {
				e.pushCreate(imageRefusal())
			}
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tr := r.trackByID(id)
			if tr == nil {
				t.Fatal("pod not tracked after CreatePod")
			}
			if c.parked {
				if tr.parkedFailure() == nil {
					t.Fatal("the image-refused pod is not parked")
				}
				waitFor(t, "the back-off worker to sleep", clk.HasWaiters)
				// The runtime holds nothing for a parked pod: its stop is not-found.
				e.mu.Lock()
				e.deleteFIFO = append(e.deleteFIFO, status.Error(codes.NotFound, "pod not found"))
				e.mu.Unlock()
			}
			if c.nilStart {
				r.mu.Lock()
				tr.startTime = metav1.Time{}
				r.mu.Unlock()
			}
			if c.backdate > 0 {
				r.mu.Lock()
				tr.startTime = metav1.NewTime(clk.Now().Add(-c.backdate))
				r.mu.Unlock()
			}
			_ = recordedEvents(rec.Events)
			creates := e.createCalls()

			clk.Step(c.step)
			r.resync(ctx)
			waitDeadlineStops(r)
			waitDeadlineStops(r)
			if c.update != nil {
				if st := tr.evictedStatus(); st != nil {
					t.Fatalf("failed before the update: %s/%s", st.Phase, st.Reason)
				}
				updated := pod.DeepCopy()
				updated.Spec.ActiveDeadlineSeconds = c.update
				// The fake runtime serves no UpdatePod, so the RPC's error is
				// expected: the tracked spec is replaced before the call.
				_ = r.UpdatePod(ctx, updated)
				r.resync(ctx)
				waitDeadlineStops(r)
				waitDeadlineStops(r)
				waitDeadlineStops(r)
			}

			st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			events := recordedEvents(rec.Events)
			if !c.wantFailed {
				if st.Phase == corev1.PodFailed || tr.evictedStatus() != nil {
					t.Fatalf("status = %s/%s, want the pod untouched", st.Phase, st.Reason)
				}
				if n := e.deleteCount(); n != 0 {
					t.Errorf("runtime DeletePod calls = %d, want 0", n)
				}
				if n := countEvents(events, reasonDeadlineExceeded); n != 0 {
					t.Errorf("DeadlineExceeded events = %d, want 0", n)
				}
				return
			}

			if st.Phase != corev1.PodFailed || st.Reason != reasonDeadlineExceeded || st.Message != msgDeadlineExceeded {
				t.Fatalf("status = %s/%s %q, want Failed/%s %q", st.Phase, st.Reason, st.Message, reasonDeadlineExceeded, msgDeadlineExceeded)
			}
			if dt := findPodCondition(st.Conditions, corev1.DisruptionTarget); dt != nil {
				t.Errorf("DisruptionTarget = %+v, want none: a deadline failure is not a disruption", dt)
			}
			if n := e.deleteCount(); n != 1 {
				t.Errorf("runtime DeletePod calls = %d, want 1", n)
			}
			live, err := cs.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("apiserver get: %v", err)
			}
			if !isDeadlineExceededPod(live) || isEvictedPod(live) {
				t.Errorf("apiserver status = %s/%s, want Failed/%s persisted", live.Status.Phase, live.Status.Reason, reasonDeadlineExceeded)
			}
			if n := countEvents(events, "Warning "+reasonDeadlineExceeded); n != 1 {
				t.Errorf("Warning DeadlineExceeded events = %d (%v), want 1", n, events)
			}
			if !addressHeld(r, id) {
				t.Error("the failed pod's address was released before its DeletePod")
			}
			if c.parked && tr.parkedFailure() != nil {
				t.Error("the failed pod is still parked")
			}

			// Later resyncs, and a long wait past any pull back-off, do nothing more.
			clk.Step(maxPullBackoffForTest)
			r.resync(ctx)
			waitDeadlineStops(r)
			waitDeadlineStops(r)
			waitNoAttempt(t, tr)
			if n := e.deleteCount(); n != 1 {
				t.Errorf("runtime DeletePod calls after a later resync = %d, want 1", n)
			}
			if n := countEvents(recordedEvents(rec.Events), reasonDeadlineExceeded); n != 0 {
				t.Errorf("DeadlineExceeded events on a later resync = %d, want 0", n)
			}

			// A later create, of the stale object or the persisted Failed one, is refused.
			for _, again := range []*corev1.Pod{pod, live} {
				if err := r.CreatePod(ctx, again); err != nil {
					t.Fatalf("CreatePod of the failed pod: %v", err)
				}
			}
			if n := e.createCalls(); n != creates {
				t.Errorf("runtime CreatePod calls = %d, want %d: a deadline-failed pod is never created again", n, creates)
			}
			if e.hasCreated(id) {
				t.Error("the runtime holds the deadline-failed pod")
			}

			if err := r.DeletePod(ctx, live); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			waitRestart(t, "the address release", func() bool { return !addressHeld(r, id) })
			waitRestart(t, "the track to go", func() bool { return r.trackByID(id) == nil })
		})
	}
}

// TestActiveDeadlinePersistRetried pins the durable Failed status: an apiserver
// write that fails when the pod is stopped is retried on later resyncs until it
// lands, with no second stop and no second Event.
func TestActiveDeadlinePersistRetried(t *testing.T) {
	ctx := context.Background()
	pod := pullPod("deadline-persist")
	deadline := int64(600)
	pod.Spec.ActiveDeadlineSeconds = &deadline
	id := string(pod.UID)
	r, e, _, rec := newBlockedCreateProvider(t)
	clk := testclock.NewFakeClock(time.Now())
	r.clk = clk
	cs := fake.NewClientset()
	r.client = cs
	if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("apiserver create: %v", err)
	}
	// The stop runs off the tick on the provider's lifetime, not the tick's
	// context, so the first write is made the only attempt.
	saved := persistEvictedBackoff
	persistEvictedBackoff = wait.Backoff{Steps: 1}
	t.Cleanup(func() { persistEvictedBackoff = saved })
	// The status write fails for the first resync's whole attempt window: the
	// failure ends that resync's context, so its backoff stops at once.
	var failing atomic.Bool
	failing.Store(true)
	var writes atomic.Int32
	firstCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.PrependReactor("update", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "status" {
			return false, nil, nil
		}
		writes.Add(1)
		if failing.Load() {
			cancel()
			return true, nil, errors.New("apiserver unavailable")
		}
		return false, nil, nil
	})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID(id)
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	_ = recordedEvents(rec.Events)

	clk.Step(time.Duration(deadline)*time.Second + 10*time.Minute)
	r.resync(firstCtx)
	waitDeadlineStops(r)
	if st := tr.evictedStatus(); st == nil || st.Reason != reasonDeadlineExceeded {
		t.Fatalf("track status = %v, want Failed/%s", st, reasonDeadlineExceeded)
	}
	if tr.unpersistedStatus() == nil {
		t.Fatal("a failed status write left no debt for the next resync")
	}
	live, err := cs.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("apiserver get: %v", err)
	}
	if isDeadlineExceededPod(live) {
		t.Fatal("the status reached the apiserver through a failing write")
	}

	failing.Store(false)
	clk.Step(10 * time.Second)
	r.resync(ctx)
	waitDeadlineStops(r)
	live, err = cs.CoreV1().Pods(pod.Namespace).Get(ctx, pod.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("apiserver get: %v", err)
	}
	if !isDeadlineExceededPod(live) {
		t.Fatalf("apiserver status = %s/%s, want Failed/%s persisted by a later resync", live.Status.Phase, live.Status.Reason, reasonDeadlineExceeded)
	}
	if tr.unpersistedStatus() != nil {
		t.Error("the debt outlived a successful write")
	}
	n := writes.Load()
	clk.Step(10 * time.Second)
	r.resync(ctx)
	waitDeadlineStops(r)
	if got := writes.Load(); got != n {
		t.Errorf("status writes after the debt was paid = %d, want %d", got, n)
	}
	if got := e.deleteCount(); got != 1 {
		t.Errorf("runtime DeletePod calls = %d, want 1", got)
	}
	if got := countEvents(recordedEvents(rec.Events), "Warning "+reasonDeadlineExceeded); got != 1 {
		t.Errorf("Warning DeadlineExceeded events = %d, want 1", got)
	}
}

// TestActiveDeadlinePersistRetriedOncePerTick pins the tick's retry: with the
// apiserver down, a resync with two owed pods makes exactly one status write
// attempt per pod, with no back-off, so the owed pods cannot stall the tick.
func TestActiveDeadlinePersistRetriedOncePerTick(t *testing.T) {
	ctx := context.Background()
	r, _, _, _ := newBlockedCreateProvider(t)
	r.clk = testclock.NewFakeClock(time.Now())
	cs := fake.NewClientset()
	r.client = cs
	// A back-off on the tick would show as more than one attempt per pod.
	saved := persistEvictedBackoff
	persistEvictedBackoff = wait.Backoff{Steps: 4, Duration: time.Millisecond}
	t.Cleanup(func() { persistEvictedBackoff = saved })
	var mu sync.Mutex
	writes := map[string]int{}
	cs.PrependReactor("update", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "status" {
			return false, nil, nil
		}
		ua, ok := a.(k8stesting.UpdateAction)
		if !ok {
			return true, nil, errors.New("unexpected action")
		}
		mu.Lock()
		writes[ua.GetObject().(*corev1.Pod).Name]++
		mu.Unlock()
		return true, nil, errors.New("apiserver unavailable")
	})
	names := []string{"deadline-owed-a", "deadline-owed-b"}
	for _, name := range names {
		pod := pullPod(name)
		if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
			t.Fatalf("apiserver create: %v", err)
		}
		if err := r.CreatePod(ctx, pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		tr := r.trackByID(string(pod.UID))
		if tr == nil {
			t.Fatalf("pod %s not tracked after CreatePod", name)
		}
		st := failedPodStatus(pod.Status, reasonDeadlineExceeded, msgDeadlineExceeded, metav1.NewTime(r.clk.Now()))
		tr.restartMu.Lock()
		tr.unpersisted = st
		tr.restartMu.Unlock()
	}
	r.enforceActiveDeadlines(ctx)
	waitDeadlineStops(r)
	mu.Lock()
	defer mu.Unlock()
	for _, name := range names {
		if got := writes[name]; got != 1 {
			t.Errorf("status write attempts for %s on one tick = %d, want 1", name, got)
		}
	}
}

// TestActiveDeadlineCountsFromTheEarlierStart pins restart safety: a daemon that
// restarts after a deadline stop but before the Failed status was written is
// handed the pod Running with its first life's status.startTime, and CreatePod
// stamps a fresh wall-clock start. The deadline counts from the earlier time, so
// the pod is failed on the first resync, not after a second full deadline.
func TestActiveDeadlineCountsFromTheEarlierStart(t *testing.T) {
	ctx := context.Background()
	pod := pullPod("deadline-restart")
	deadline := int64(600)
	pod.Spec.ActiveDeadlineSeconds = &deadline
	first := metav1.NewTime(time.Now().Add(-time.Hour))
	pod.Status.Phase = corev1.PodRunning
	pod.Status.StartTime = &first
	id := string(pod.UID)
	r, e, _, _ := newBlockedCreateProvider(t)
	clk := testclock.NewFakeClock(time.Now())
	r.clk = clk
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID(id)
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	r.resync(ctx)
	waitDeadlineStops(r)
	if st := tr.evictedStatus(); st == nil || st.Reason != reasonDeadlineExceeded {
		t.Fatalf("track status = %v, want Failed/%s on the first resync", st, reasonDeadlineExceeded)
	}
	if n := e.deleteCount(); n != 1 {
		t.Errorf("runtime DeletePod calls = %d, want 1", n)
	}
}

// TestActiveDeadlineFencesALateParkedCreate pins the fence on a parked pod's
// retry: a create still in flight when the pod is failed past its deadline lands
// after the terminal mark, so it is deleted again (commitParkedCreate answers
// commitDeleted) and no guest stays up, while the address and the Failed status
// stay for the pod's DeletePod.
func TestActiveDeadlineFencesALateParkedCreate(t *testing.T) {
	ctx := context.Background()
	pod := probePullPod("deadline-late-create")
	deadline := int64(60)
	pod.Spec.ActiveDeadlineSeconds = &deadline
	id := string(pod.UID)
	r, f, clk, release := parkedWithHeldRetry(t, pod)
	defer release()
	tr := r.trackByID(id)
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	r.mu.Lock()
	tr.startTime = metav1.NewTime(clk.Now().Add(-20 * time.Minute))
	r.mu.Unlock()

	r.resync(ctx)
	waitDeadlineStops(r)
	if st := tr.evictedStatus(); st == nil || st.Reason != reasonDeadlineExceeded {
		t.Fatalf("track status = %v, want Failed/%s", st, reasonDeadlineExceeded)
	}
	stops := len(f.deleteRecords())

	release()
	waitRestart(t, "the compensating delete", func() bool { return len(f.deleteRecords()) == stops+1 })
	if got := f.deleteRecords(); got[stops] != id {
		t.Errorf("the compensating delete named %q, want the pod's id %q", got[stops], id)
	}
	if f.hasCreated(id) {
		t.Error("the runtime still holds the pod: the late create brought up a guest behind a Failed status")
	}
	if !addressHeld(r, id) {
		t.Error("the failed pod's address was released before its DeletePod")
	}
	st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if st.Phase != corev1.PodFailed || st.Reason != reasonDeadlineExceeded {
		t.Errorf("status after the late create = %s/%s, want Failed/%s", st.Phase, st.Reason, reasonDeadlineExceeded)
	}
}

// waitBounded polls cond until it holds, failing the test after 30 s.
func waitBounded(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitDeadlineStops waits for every active-deadline stop a resync started off
// the tick to finish.
func waitDeadlineStops(r *runtimedRuntime) { r.deadlineStops.Wait() }

// heldStopRuntime holds the runtime stop of one pod id open until hold is
// closed, signalling entered when that stop arrives.
type heldStopRuntime struct {
	*fakeRuntimeServer
	holdID  string
	hold    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (h *heldStopRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	if req.GetPodId() == h.holdID {
		h.once.Do(func() { close(h.entered) })
		<-h.hold
	}
	return h.fakeRuntimeServer.DeletePod(ctx, req)
}

// TestResyncNotBlockedByDeadlineStop pins the deadline stop off the tick: a
// stop held open in the runtime does not hold the resync, the held pod does not
// read Failed before its stop succeeds, a second due pod is stopped meanwhile, an
// unrelated pod's status is still published, each failed pod gets one Event, and
// shutdown waits for the stop still in flight.
func TestResyncNotBlockedByDeadlineStop(t *testing.T) {
	ctx := context.Background()
	deadline := int64(60)
	a, b, c := pullPod("deadline-a"), pullPod("deadline-b"), pullPod("deadline-c")
	a.Spec.ActiveDeadlineSeconds = &deadline
	b.Spec.ActiveDeadlineSeconds = &deadline
	f := newFakeRuntimeServer()
	h := &heldStopRuntime{fakeRuntimeServer: f, holdID: string(a.UID), hold: make(chan struct{}), entered: make(chan struct{})}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(h, RuntimedConfig{
		NodeName: "n",
		NodeIP:   testNodeIP,
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec,
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), testNodeIP, nil),
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Now())
	r.clk = clk
	var released atomic.Bool
	releaseA := func() {
		if released.CompareAndSwap(false, true) {
			close(h.hold)
		}
	}
	// Cleanups run last-in first-out: the held stop is released before the
	// provider is shut down, so a failed assertion does not leak the stop.
	t.Cleanup(r.shutdown)
	t.Cleanup(releaseA)
	var pubMu sync.Mutex
	published := map[string]*corev1.Pod{}
	r.notify = func(p *corev1.Pod) {
		pubMu.Lock()
		published[p.Name] = p
		pubMu.Unlock()
	}
	for _, p := range []*corev1.Pod{a, b, c} {
		if err := r.CreatePod(ctx, p); err != nil {
			t.Fatalf("CreatePod %s: %v", p.Name, err)
		}
	}
	_ = recordedEvents(rec.Events)

	// Drop the creates' own publications, so the unrelated pod's check below
	// reads only what the resync published.
	pubMu.Lock()
	clear(published)
	pubMu.Unlock()
	clk.Step(20 * time.Minute)
	done := make(chan struct{})
	go func() {
		r.resync(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("resync is held by a pod's deadline stop")
	}
	select {
	case <-h.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("pod A's stop never reached the runtime")
	}
	st, err := r.GetPodStatus(ctx, a.Namespace, a.Name)
	if err != nil {
		t.Fatalf("GetPodStatus A: %v", err)
	}
	if st.Phase == corev1.PodFailed || st.Reason == reasonDeadlineExceeded {
		t.Fatalf("A status = %s/%s while its stop is held, want not Failed until the stop succeeds", st.Phase, st.Reason)
	}
	waitBounded(t, "pod B's stop while A's is held", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, id := range f.deleteIDs {
			if id == string(b.UID) {
				return true
			}
		}
		return false
	})
	pubMu.Lock()
	pc := published[c.Name]
	pubMu.Unlock()
	if pc == nil || pc.Status.Phase == corev1.PodFailed {
		t.Fatalf("the unrelated pod's status was not published by the resync: %v", pc)
	}

	shut := make(chan struct{})
	go func() {
		r.shutdown()
		close(shut)
	}()
	// Wait until shutdown has ended the lifetime, so the window below measures
	// its wait on the stop, not a shutdown that has not started yet.
	waitBounded(t, "shutdown to close the provider's lifetime", func() bool {
		select {
		case <-r.lifetime:
			return true
		default:
			return false
		}
	})
	select {
	case <-shut:
		t.Fatal("shutdown returned with a deadline stop in flight")
	case <-time.After(250 * time.Millisecond):
	}
	releaseA()
	select {
	case <-shut:
	case <-time.After(30 * time.Second):
		t.Fatal("shutdown did not return after the stop finished")
	}
	events := recordedEvents(rec.Events)
	if n := countEvents(events, "Warning "+reasonDeadlineExceeded); n != 2 {
		t.Errorf("Warning DeadlineExceeded events = %d (%v), want one per failed pod", n, events)
	}
	for _, p := range []*corev1.Pod{a, b} {
		if st := r.trackByID(string(p.UID)).evictedStatus(); st == nil || st.Reason != reasonDeadlineExceeded {
			t.Errorf("%s track status = %v, want Failed/%s", p.Name, st, reasonDeadlineExceeded)
		}
	}
}

// TestActiveDeadlineStopDropsStatusOfADeletedPod pins a deadline stop that
// returns after the pod's DeletePod began: the pod is the delete's now, so the
// stop records no owed status, writes none and publishes none.
func TestActiveDeadlineStopDropsStatusOfADeletedPod(t *testing.T) {
	ctx := context.Background()
	deadline := int64(60)
	pod := pullPod("deadline-deleted")
	pod.Spec.ActiveDeadlineSeconds = &deadline
	f := newFakeRuntimeServer()
	h := &heldStopRuntime{fakeRuntimeServer: f, holdID: string(pod.UID), hold: make(chan struct{}), entered: make(chan struct{})}
	r := newRuntimedWith(h, RuntimedConfig{
		NodeName: "n",
		NodeIP:   testNodeIP,
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: record.NewFakeRecorder(64),
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), testNodeIP, nil),
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Now())
	r.clk = clk
	cs := fake.NewClientset()
	r.client = cs
	if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("apiserver create: %v", err)
	}
	var writes atomic.Int32
	cs.PrependReactor("update", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		writes.Add(1)
		return false, nil, nil
	})
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(h.hold)
		}
	}
	t.Cleanup(r.shutdown)
	t.Cleanup(release)
	var deleted atomic.Bool
	var late atomic.Int32
	r.notify = func(p *corev1.Pod) {
		if p.Name == pod.Name && deleted.Load() {
			late.Add(1)
		}
	}
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	tr := r.trackByID(string(pod.UID))
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}

	clk.Step(20 * time.Minute)
	r.resync(ctx)
	select {
	case <-h.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the deadline stop never reached the runtime")
	}
	writes.Store(0)
	delDone := make(chan error, 1)
	go func() { delDone <- r.DeletePod(ctx, pod) }()
	waitBounded(t, "DeletePod to mark the track deleting", func() bool {
		d, _ := tr.deleteProgress()
		return d
	})
	deleted.Store(true)
	release()
	select {
	case err := <-delDone:
		if err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("DeletePod did not return after the stop was released")
	}
	waitDeadlineStops(r)
	if n := late.Load(); n != 0 {
		t.Errorf("status callbacks for the deleted pod after its DeletePod = %d, want 0", n)
	}
	if n := writes.Load(); n != 0 {
		t.Errorf("status writes for the deleted pod = %d, want 0", n)
	}
	if st := tr.unpersistedStatus(); st != nil {
		t.Errorf("the deleted pod still owes a status: %v", st)
	}
}

// finishedRuntime reports every pod the fake runtime holds as finished on its
// own: phase phase, its one container c0 terminated with exit.
type finishedRuntime struct {
	*fakeRuntimeServer
	phase runtimev1.PodPhase
	exit  int32
}

func (f *finishedRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	resp, err := f.fakeRuntimeServer.GetPodStatus(ctx, req)
	if err != nil || resp.GetStatus() == nil {
		return resp, err
	}
	reason := "Completed"
	if f.exit != 0 {
		reason = "Error"
	}
	resp.Status.Phase = f.phase
	resp.Status.ContainerStatuses = []*runtimev1.ContainerStatus{{
		Name: "c0", Image: "web",
		State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
			ExitCode:   f.exit,
			Reason:     reason,
			StartedAt:  timestamppb.New(f.started),
			FinishedAt: timestamppb.New(f.started.Add(time.Second)),
		}},
	}}
	return resp, nil
}

// TestActiveDeadlineLeavesAFinishedPodAlone pins the kubelet's terminal-phase
// guard: a restartPolicy Never pod that finished on its own inside its deadline
// is not active, so the deadline passing later neither stops it nor replaces its
// own Succeeded or Failed status with DeadlineExceeded.
func TestActiveDeadlineLeavesAFinishedPodAlone(t *testing.T) {
	cases := []struct {
		name  string
		phase runtimev1.PodPhase
		exit  int32
		want  corev1.PodPhase
	}{
		{"a pod that succeeded", runtimev1.PodPhase_POD_PHASE_SUCCEEDED, 0, corev1.PodSucceeded},
		{"a pod that failed on its own", runtimev1.PodPhase_POD_PHASE_FAILED, 1, corev1.PodFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			pod := crashPod("deadline-finished", corev1.RestartPolicyNever)
			deadline := int64(10)
			pod.Spec.ActiveDeadlineSeconds = &deadline
			id := string(pod.UID)
			f := &finishedRuntime{fakeRuntimeServer: newFakeRuntimeServer(), phase: c.phase, exit: c.exit}
			rec := record.NewFakeRecorder(64)
			r := newRuntimedWith(f, RuntimedConfig{
				NodeName: "n",
				NodeIP:   testNodeIP,
				Root:     t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: rec,
			}, nil, nil)
			clk := testclock.NewFakeClock(time.Now())
			r.clk = clk
			cs := fake.NewClientset()
			r.client = cs
			if _, err := cs.CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{}); err != nil {
				t.Fatalf("apiserver create: %v", err)
			}
			var writes atomic.Int32
			cs.PrependReactor("update", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
				if a.GetSubresource() == "status" {
					writes.Add(1)
				}
				return false, nil, nil
			})
			if err := r.CreatePod(ctx, pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			tr := r.trackByID(id)
			if tr == nil {
				t.Fatal("pod not tracked after CreatePod")
			}
			_ = recordedEvents(rec.Events)

			// Past the 10 s deadline by minutes: the track's start is the wall
			// clock when CreatePod ran, which on a loaded host trails the fake
			// clock's start.
			clk.Step(20 * time.Minute)
			r.resync(ctx)
			waitDeadlineStops(r)

			if n := f.deleteCount(); n != 0 {
				t.Errorf("runtime DeletePod calls = %d, want 0: a finished pod is not stopped", n)
			}
			if n := countEvents(recordedEvents(rec.Events), reasonDeadlineExceeded); n != 0 {
				t.Errorf("DeadlineExceeded events = %d, want 0", n)
			}
			if n := writes.Load(); n != 0 {
				t.Errorf("apiserver status writes = %d, want 0", n)
			}
			if st := tr.evictedStatus(); st != nil {
				t.Errorf("track marked terminal %s/%s, want no mark", st.Phase, st.Reason)
			}
			st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			if st.Phase != c.want || st.Reason == reasonDeadlineExceeded {
				t.Errorf("status = %s/%s, want %s, not %s", st.Phase, st.Reason, c.want, reasonDeadlineExceeded)
			}
		})
	}
}

// deadlineStopHarness is a provider over rt with a fake clock, a recorder, and a
// log of every status the resync published for one pod.
type deadlineStopHarness struct {
	r   *runtimedRuntime
	clk *testclock.FakeClock
	rec *record.FakeRecorder
	pod *corev1.Pod

	mu        sync.Mutex
	published []corev1.PodStatus
}

func newDeadlineStopHarness(t *testing.T, rt runtimev1.RuntimeServer, name string) *deadlineStopHarness {
	t.Helper()
	deadline := int64(60)
	pod := pullPod(name)
	pod.Spec.ActiveDeadlineSeconds = &deadline
	h := &deadlineStopHarness{rec: record.NewFakeRecorder(64), pod: pod}
	h.r = newRuntimedWith(rt, RuntimedConfig{
		NodeName: "n",
		NodeIP:   testNodeIP,
		Root:     t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: h.rec,
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), testNodeIP, nil),
	}, nil, nil)
	h.clk = testclock.NewFakeClock(time.Now())
	h.r.clk = h.clk
	h.r.notify = func(p *corev1.Pod) {
		if p.Name != name {
			return
		}
		h.mu.Lock()
		h.published = append(h.published, *p.Status.DeepCopy())
		h.mu.Unlock()
	}
	if err := h.r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	return h
}

// failedPublications counts the published statuses that report the pod Failed.
func (h *deadlineStopHarness) failedPublications() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, st := range h.published {
		if st.Phase == corev1.PodFailed {
			n++
		}
	}
	return n
}

// assertNotFailed checks every status surface (GetPodStatus, GetPods, the
// resync's publications) reports the pod as anything but Failed.
func (h *deadlineStopHarness) assertNotFailed(t *testing.T, when string) {
	t.Helper()
	ctx := context.Background()
	st, err := h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus %s: %v", when, err)
	}
	if st.Phase == corev1.PodFailed || st.Reason == reasonDeadlineExceeded {
		t.Errorf("GetPodStatus %s = %s/%s, want not Failed", when, st.Phase, st.Reason)
	}
	pods, err := h.r.GetPods(ctx)
	if err != nil {
		t.Fatalf("GetPods %s: %v", when, err)
	}
	for _, p := range pods {
		if p.Name == h.pod.Name && (p.Status.Phase == corev1.PodFailed || p.Status.Reason == reasonDeadlineExceeded) {
			t.Errorf("GetPods %s = %s/%s, want not Failed", when, p.Status.Phase, p.Status.Reason)
		}
	}
	if n := h.failedPublications(); n != 0 {
		t.Errorf("Failed publications %s = %d, want 0", when, n)
	}
}

// assertDeadlineFailed checks the pod reads Failed/DeadlineExceeded with exactly
// one Warning Event over the whole test.
func (h *deadlineStopHarness) assertDeadlineFailed(t *testing.T, events []string) {
	t.Helper()
	st, err := h.r.GetPodStatus(context.Background(), h.pod.Namespace, h.pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if st.Phase != corev1.PodFailed || st.Reason != reasonDeadlineExceeded {
		t.Errorf("status after the stop = %s/%s, want Failed/%s", st.Phase, st.Reason, reasonDeadlineExceeded)
	}
	if n := countEvents(events, "Warning "+reasonDeadlineExceeded); n != 1 {
		t.Errorf("Warning DeadlineExceeded events = %d (%v), want 1", n, events)
	}
}

// TestDeadlineStopFailureNeverPublishesFailedThenRunning pins the two-stage
// deadline mark: a pod past its deadline reads Failed/DeadlineExceeded only once
// its runtime stop has succeeded. While the stop is held no status surface says
// Failed and a later tick starts no second stop; a stop that fails publishes
// nothing, so no reader ever sees Failed and then Running again, and the next
// tick retries it.
func TestDeadlineStopFailureNeverPublishesFailedThenRunning(t *testing.T) {
	t.Run("a held stop", func(t *testing.T) {
		ctx := context.Background()
		f := newFakeRuntimeServer()
		hs := &heldStopRuntime{fakeRuntimeServer: f, hold: make(chan struct{}), entered: make(chan struct{})}
		h := newDeadlineStopHarness(t, hs, "deadline-held")
		hs.holdID = string(h.pod.UID)
		var released atomic.Bool
		release := func() {
			if released.CompareAndSwap(false, true) {
				close(hs.hold)
			}
		}
		t.Cleanup(h.r.shutdown)
		t.Cleanup(release)
		var events []string
		events = append(events, recordedEvents(h.rec.Events)...)

		h.clk.Step(20 * time.Minute)
		h.r.resync(ctx)
		select {
		case <-hs.entered:
		case <-time.After(30 * time.Second):
			t.Fatal("the deadline stop never reached the runtime")
		}
		h.assertNotFailed(t, "while the stop is held")

		h.clk.Step(10 * time.Second)
		h.r.resync(ctx)
		h.assertNotFailed(t, "on a second tick while the stop is held")

		release()
		waitDeadlineStops(h.r)
		if n := f.deleteCount(); n != 1 {
			t.Errorf("runtime DeletePod calls = %d, want 1: a tick during the stop started a second one", n)
		}
		events = append(events, recordedEvents(h.rec.Events)...)
		h.assertDeadlineFailed(t, events)
	})

	t.Run("a stop that fails once", func(t *testing.T) {
		ctx := context.Background()
		f := newFakeRuntimeServer()
		f.deleteFIFO = append(f.deleteFIFO, status.Error(codes.Unavailable, "runtime unavailable"))
		// The failing stop is held inside the RPC, so the tick's own publication
		// runs while it is in flight; the closed channel holds no later call.
		hold := make(chan struct{})
		f.deleteHold = hold
		var released atomic.Bool
		release := func() {
			if released.CompareAndSwap(false, true) {
				close(hold)
			}
		}
		h := newDeadlineStopHarness(t, f, "deadline-fails-once")
		t.Cleanup(h.r.shutdown)
		t.Cleanup(release)
		var events []string
		events = append(events, recordedEvents(h.rec.Events)...)

		h.clk.Step(20 * time.Minute)
		h.r.resync(ctx)
		waitBounded(t, "the deadline stop to reach the runtime", func() bool { return f.deleteCount() == 1 })
		h.assertNotFailed(t, "while the failing stop is in flight")
		release()
		waitDeadlineStops(h.r)
		h.assertNotFailed(t, "after the stop failed")
		events = append(events, recordedEvents(h.rec.Events)...)
		if n := countEvents(events, reasonDeadlineExceeded); n != 0 {
			t.Errorf("DeadlineExceeded events after the failed stop = %d, want 0", n)
		}

		h.clk.Step(10 * time.Second)
		h.r.resync(ctx)
		waitDeadlineStops(h.r)
		if n := f.deleteCount(); n != 2 {
			t.Errorf("runtime DeletePod calls = %d, want 2: the next tick retries the failed stop", n)
		}
		events = append(events, recordedEvents(h.rec.Events)...)
		h.assertDeadlineFailed(t, events)
	})
}

// TestDeadlineStopFencesThePodWhileItRuns pins the fences of a deadline stop in
// flight: while the runtime stop is held the pod reads live (not Failed), yet a
// repeat CreatePod starts no second runtime create, an UpdatePod makes no runtime
// update, a container exit the teardown produces schedules no restart of a
// restartPolicy Always pod, and the pod is not an eviction candidate.
func TestDeadlineStopFencesThePodWhileItRuns(t *testing.T) {
	ctx := context.Background()
	f := newFakeRuntimeServer()
	hs := &heldStopRuntime{fakeRuntimeServer: f, hold: make(chan struct{}), entered: make(chan struct{})}
	h := newDeadlineStopHarness(t, hs, "deadline-fenced")
	id := string(h.pod.UID)
	hs.holdID = id
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(hs.hold)
		}
	}
	t.Cleanup(h.r.shutdown)
	t.Cleanup(release)
	tr := h.r.trackByID(id)
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	if h.pod.Spec.RestartPolicy != corev1.RestartPolicyAlways {
		t.Fatalf("restartPolicy = %s, want Always", h.pod.Spec.RestartPolicy)
	}

	h.clk.Step(20 * time.Minute)
	h.r.resync(ctx)
	select {
	case <-hs.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the deadline stop never reached the runtime")
	}
	h.assertNotFailed(t, "while the stop is held")

	creates := f.createCount()
	if err := h.r.CreatePod(ctx, h.pod.DeepCopy()); err != nil {
		t.Fatalf("repeat CreatePod: %v", err)
	}
	if n := f.createCount(); n != creates {
		t.Errorf("runtime CreatePod calls = %d, want %d: a repeat create during the stop started a second one", n, creates)
	}

	updated := h.pod.DeepCopy()
	updated.Labels = map[string]string{"edited": "true"}
	if err := h.r.UpdatePod(ctx, updated); err != nil {
		t.Errorf("UpdatePod: %v (a runtime update was attempted for a pod being stopped)", err)
	}
	if n := f.updateCount(); n != 0 {
		t.Errorf("runtime UpdatePod calls = %d, want 0: a pod being stopped was updated", n)
	}

	h.r.buildStatus(h.pod.DeepCopy(), tr, exitStatus(id, 143, "Error", 0, h.clk.Now()), nil)
	if restartScheduled(tr, "c0") {
		t.Error("an exit observed during the deadline stop scheduled a restart")
	}

	for _, c := range h.r.evictionCandidates(ctx) {
		if c.pod.UID == h.pod.UID {
			t.Error("a pod whose deadline stop is in flight is an eviction candidate")
		}
	}

	release()
	waitDeadlineStops(h.r)
	if n := f.deleteCount(); n != 1 {
		t.Errorf("runtime DeletePod calls = %d, want 1", n)
	}
	if got, _ := f.restartState(); got != 0 {
		t.Errorf("RestartContainer calls = %d, want 0", got)
	}
	if st := tr.evictedStatus(); st == nil || st.Reason != reasonDeadlineExceeded {
		t.Errorf("track status = %v, want Failed/%s once the stop succeeded", st, reasonDeadlineExceeded)
	}
}

// TestDeadlineStopKeepsTheLastLiveStatusWhileTheRuntimeForgetsThePod pins the
// status of a pod whose deadline stop is in flight once the runtime has
// forgotten it: the runtime drops the pod as its DeletePod begins (the base
// fake deletes its record before waiting on deleteHold), and the pod must go on
// reading its last live status (Running, no container Waiting) on every
// surface, never the synthesized creating status (Pending, ContainerCreating),
// until the stop succeeds and it reads Failed/DeadlineExceeded.
func TestDeadlineStopKeepsTheLastLiveStatusWhileTheRuntimeForgetsThePod(t *testing.T) {
	ctx := context.Background()
	f := newFakeRuntimeServer()
	hold := make(chan struct{})
	f.deleteHold = hold
	var released atomic.Bool
	release := func() {
		if released.CompareAndSwap(false, true) {
			close(hold)
		}
	}
	h := newDeadlineStopHarness(t, f, "deadline-forgotten")
	t.Cleanup(h.r.shutdown)
	t.Cleanup(release)
	var events []string
	events = append(events, recordedEvents(h.rec.Events)...)

	assertLive := func(t *testing.T, surface string, st corev1.PodStatus) {
		t.Helper()
		if st.Phase != corev1.PodRunning {
			t.Errorf("%s phase = %s, want %s", surface, st.Phase, corev1.PodRunning)
		}
		for _, cs := range st.ContainerStatuses {
			if cs.State.Waiting != nil {
				t.Errorf("%s container %s Waiting (%s), want not Waiting", surface, cs.Name, cs.State.Waiting.Reason)
			}
		}
	}
	st, err := h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus before the deadline: %v", err)
	}
	assertLive(t, "GetPodStatus before the deadline", *st)

	h.mu.Lock()
	h.published = nil
	h.mu.Unlock()
	h.clk.Step(20 * time.Minute)
	h.r.resync(ctx)
	waitBounded(t, "the deadline stop to reach the runtime", func() bool { return f.deleteCount() == 1 })
	f.mu.Lock()
	_, known := f.created[string(h.pod.UID)]
	f.mu.Unlock()
	if known {
		t.Fatal("the fake runtime still knows the pod inside its held DeletePod")
	}

	// A second tick while the stop is held publishes from the runtime's NotFound.
	h.clk.Step(10 * time.Second)
	h.r.resync(ctx)
	st, err = h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus while the stop is held: %v", err)
	}
	assertLive(t, "GetPodStatus while the stop is held", *st)
	pods, err := h.r.GetPods(ctx)
	if err != nil {
		t.Fatalf("GetPods while the stop is held: %v", err)
	}
	for _, p := range pods {
		if p.Name == h.pod.Name {
			assertLive(t, "GetPods while the stop is held", p.Status)
		}
	}
	h.mu.Lock()
	published := append([]corev1.PodStatus(nil), h.published...)
	h.mu.Unlock()
	if len(published) == 0 {
		t.Fatal("no status published while the stop is held")
	}
	for i, p := range published {
		assertLive(t, fmt.Sprintf("publication %d while the stop is held", i), p)
	}

	release()
	waitDeadlineStops(h.r)
	events = append(events, recordedEvents(h.rec.Events)...)
	h.assertDeadlineFailed(t, events)
}

// hungStopRuntime hangs the first runtime stop of one pod id until its context
// is done and then returns the context's error, as a wedged runtime would; it
// records each stop's grace. Later stops reach the fake runtime.
type hungStopRuntime struct {
	*fakeRuntimeServer
	hangID  string
	entered chan struct{}

	mu     sync.Mutex
	hung   bool
	graces []int64
}

func (h *hungStopRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	h.mu.Lock()
	h.graces = append(h.graces, req.GetGracePeriodSeconds())
	hang := req.GetPodId() == h.hangID && !h.hung
	if hang {
		h.hung = true
	}
	h.mu.Unlock()
	if hang {
		close(h.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return h.fakeRuntimeServer.DeletePod(ctx, req)
}

func (h *hungStopRuntime) stopGraces() []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int64(nil), h.graces...)
}

// TestDeadlineStopTimesOutAndIsRetried pins the bound on one deadline stop: a
// runtime stop that hangs returns once the pod's grace plus deadlineStopSlack
// has passed, the pod's stopping mark (and with it its fence) is released, no
// surface reads Failed, and the next tick starts a second stop.
func TestDeadlineStopTimesOutAndIsRetried(t *testing.T) {
	saved := deadlineStopSlack
	deadlineStopSlack = 100 * time.Millisecond
	t.Cleanup(func() { deadlineStopSlack = saved })

	ctx := context.Background()
	f := newFakeRuntimeServer()
	hs := &hungStopRuntime{fakeRuntimeServer: f, entered: make(chan struct{})}
	h := newDeadlineStopHarness(t, hs, "deadline-hung")
	id := string(h.pod.UID)
	hs.hangID = id
	t.Cleanup(h.r.shutdown)
	tr := h.r.trackByID(id)
	if tr == nil {
		t.Fatal("pod not tracked after CreatePod")
	}
	grace := int64(1)
	h.r.mu.Lock()
	tr.pod.Spec.TerminationGracePeriodSeconds = &grace
	h.r.mu.Unlock()
	bound := time.Duration(floorGrace(grace))*time.Second + deadlineStopSlack

	began := time.Now()
	h.clk.Step(20 * time.Minute)
	h.r.resync(ctx)
	select {
	case <-hs.entered:
	case <-time.After(30 * time.Second):
		t.Fatal("the deadline stop never reached the runtime")
	}
	if !tr.isStopping() {
		t.Error("the pod is not stopping while its stop hangs")
	}
	stopped := make(chan struct{})
	go func() {
		waitDeadlineStops(h.r)
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(bound + 10*time.Second):
		t.Fatalf("the hung deadline stop did not return within %v: it fences the pod until shutdown", bound+10*time.Second)
	}
	if elapsed := time.Since(began); elapsed < bound {
		t.Errorf("the stop returned after %v, before its bound %v", elapsed, bound)
	}
	if tr.isStopping() {
		t.Error("the pod is still stopping after its stop timed out")
	}
	h.assertNotFailed(t, "after the stop timed out")
	if events := recordedEvents(h.rec.Events); countEvents(events, reasonDeadlineExceeded) != 0 {
		t.Errorf("DeadlineExceeded events after the timed-out stop = %v, want none", events)
	}

	h.clk.Step(10 * time.Second)
	h.r.resync(ctx)
	waitDeadlineStops(h.r)
	if got := hs.stopGraces(); len(got) != 2 || got[0] != floorGrace(grace) || got[1] != floorGrace(grace) {
		t.Errorf("runtime stop graces = %v, want two stops of %d s: the next tick retries the timed-out stop", got, floorGrace(grace))
	}
}

// forgettingStopRuntime fails the first runtime stop of one pod id after
// forgetting the pod, as runtimed does: the daemon drops the pod as its
// DeletePod begins, so the pod reads NotFound even though the stop then
// failed. With hang the stop hangs until its context is done (the per-stop
// timeout); otherwise it returns Unavailable. Later stops reach the fake
// runtime, which answers a stop of a forgotten pod with success.
type forgettingStopRuntime struct {
	*fakeRuntimeServer
	failID string
	hang   bool

	mu     sync.Mutex
	failed bool
	stops  int
}

func (f *forgettingStopRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.mu.Lock()
	f.stops++
	fail := req.GetPodId() == f.failID && !f.failed
	if fail {
		f.failed = true
	}
	f.mu.Unlock()
	if !fail {
		return f.fakeRuntimeServer.DeletePod(ctx, req)
	}
	f.fakeRuntimeServer.mu.Lock()
	delete(f.fakeRuntimeServer.created, req.GetPodId())
	f.fakeRuntimeServer.mu.Unlock()
	if f.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return nil, status.Error(codes.Unavailable, "runtime unavailable")
}

func (f *forgettingStopRuntime) stopCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops
}

// TestFailedDeadlineStopKeepsTheLiveStatusUntilTheRetry pins the status of a
// pod whose deadline stop failed after the runtime had already forgotten it:
// between the failure and the next tick's retry every surface (GetPodStatus,
// GetPods, a tick's publication) goes on reading the pod's last live status,
// Running with no container Waiting, never the synthesized creating status;
// and the Failed/DeadlineExceeded status the retry publishes is built from
// that live status, so no container in it is Waiting and each carries the
// start time it was running from.
func TestFailedDeadlineStopKeepsTheLiveStatusUntilTheRetry(t *testing.T) {
	saved := deadlineStopSlack
	deadlineStopSlack = 100 * time.Millisecond
	t.Cleanup(func() { deadlineStopSlack = saved })

	for _, c := range []struct {
		name string
		hang bool
	}{
		{name: "the stop fails Unavailable"},
		{name: "the stop hangs until its timeout", hang: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			fs := &forgettingStopRuntime{fakeRuntimeServer: newFakeRuntimeServer(), hang: c.hang}
			h := newDeadlineStopHarness(t, fs, "deadline-forgotten-failed")
			id := string(h.pod.UID)
			fs.failID = id
			t.Cleanup(h.r.shutdown)
			tr := h.r.trackByID(id)
			if tr == nil {
				t.Fatal("pod not tracked after CreatePod")
			}
			grace := int64(1)
			h.r.mu.Lock()
			tr.pod.Spec.TerminationGracePeriodSeconds = &grace
			h.r.mu.Unlock()

			noWaiting := func(t *testing.T, surface string, st corev1.PodStatus) {
				t.Helper()
				for _, cs := range st.ContainerStatuses {
					if cs.State.Waiting != nil {
						t.Errorf("%s container %s Waiting (%s), want not Waiting", surface, cs.Name, cs.State.Waiting.Reason)
					}
				}
			}
			assertLive := func(t *testing.T, surface string, st corev1.PodStatus) {
				t.Helper()
				if st.Phase != corev1.PodRunning {
					t.Errorf("%s phase = %s, want %s", surface, st.Phase, corev1.PodRunning)
				}
				noWaiting(t, surface, st)
			}
			st, err := h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus before the deadline: %v", err)
			}
			assertLive(t, "GetPodStatus before the deadline", *st)

			// The first tick starts the stop; the runtime forgets the pod and the
			// stop fails (or times out). Nothing is Failed yet.
			h.clk.Step(20 * time.Minute)
			h.r.resync(ctx)
			waitDeadlineStops(h.r)
			if n := fs.stopCount(); n != 1 {
				t.Fatalf("runtime stops after the first tick = %d, want 1", n)
			}
			if tr.isStopping() {
				t.Fatal("the pod is still stopping after its stop failed: the fence was not released")
			}
			fs.fakeRuntimeServer.mu.Lock()
			_, known := fs.fakeRuntimeServer.created[id]
			fs.fakeRuntimeServer.mu.Unlock()
			if known {
				t.Fatal("the fake runtime still knows the pod after its failed stop")
			}

			// Between the failure and the retry.
			st, err = h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus after the failed stop: %v", err)
			}
			assertLive(t, "GetPodStatus after the failed stop", *st)
			pods, err := h.r.GetPods(ctx)
			if err != nil {
				t.Fatalf("GetPods after the failed stop: %v", err)
			}
			for _, p := range pods {
				if p.Name == h.pod.Name {
					assertLive(t, "GetPods after the failed stop", p.Status)
				}
			}
			// A tick that publishes without retrying: the tracked spec's deadline
			// is lifted for this one tick (the pointer is swapped, as UpdatePod
			// does, and restored after).
			h.mu.Lock()
			h.published = nil
			h.mu.Unlock()
			h.r.mu.Lock()
			withDeadline := tr.pod
			lifted := withDeadline.DeepCopy()
			lifted.Spec.ActiveDeadlineSeconds = nil
			tr.pod = lifted
			h.r.mu.Unlock()
			h.r.resync(ctx)
			h.r.mu.Lock()
			tr.pod = withDeadline
			h.r.mu.Unlock()
			if n := fs.stopCount(); n != 1 {
				t.Fatalf("runtime stops after the publishing tick = %d, want 1", n)
			}
			h.mu.Lock()
			published := append([]corev1.PodStatus(nil), h.published...)
			h.published = nil
			h.mu.Unlock()
			if len(published) == 0 {
				t.Fatal("no status published between the failure and the retry")
			}
			for i, p := range published {
				assertLive(t, fmt.Sprintf("publication %d after the failed stop", i), p)
			}

			// The retry.
			h.clk.Step(10 * time.Second)
			h.r.resync(ctx)
			waitDeadlineStops(h.r)
			if n := fs.stopCount(); n != 2 {
				t.Errorf("runtime stops after the retry tick = %d, want 2", n)
			}
			h.r.resync(ctx)
			st, err = h.r.GetPodStatus(ctx, h.pod.Namespace, h.pod.Name)
			if err != nil {
				t.Fatalf("GetPodStatus after the retry: %v", err)
			}
			if st.Phase != corev1.PodFailed || st.Reason != reasonDeadlineExceeded {
				t.Fatalf("status after the retry = %s/%s, want Failed/%s", st.Phase, st.Reason, reasonDeadlineExceeded)
			}
			h.mu.Lock()
			published = append([]corev1.PodStatus(nil), h.published...)
			h.mu.Unlock()
			failed := 0
			for i, p := range append(published, *st) {
				surface := fmt.Sprintf("publication %d from the retry", i)
				if i == len(published) {
					surface = "GetPodStatus after the retry"
				}
				if p.Phase != corev1.PodFailed {
					assertLive(t, surface, p)
					continue
				}
				failed++
				noWaiting(t, surface, p)
				for _, cs := range p.ContainerStatuses {
					if term := cs.State.Terminated; term != nil && term.StartedAt.IsZero() {
						t.Errorf("%s container %s terminated with no start time: built from a not-running status", surface, cs.Name)
					}
				}
			}
			if failed == 0 {
				t.Error("the retry published no Failed status")
			}
		})
	}
}
