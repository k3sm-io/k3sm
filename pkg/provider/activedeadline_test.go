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
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	testclock "k8s.io/utils/clock/testing"
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
