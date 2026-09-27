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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// attachRuntime is the fake in-process runtime of the re-attachment gate: the
// provider-test RuntimeServer, plus the podAttacher verbs, with every attach,
// the reap and every create written to ONE ordered log so the startup ordering
// is an assertion rather than an inference.
type attachRuntime struct {
	*fakeRuntimeServer

	amu      sync.Mutex
	seq      []string
	results  map[string]attachResult         // pod id -> what AttachPod answers
	attached map[string]*runtimev1.PodStatus // pod id -> the status of an attached pod
	boxes    map[string]*runtimev1.PodBox    // pod id -> the box AttachPod was given
	instance map[string]int32                // pod id -> c0's instance number at the last create
}

type attachResult struct {
	status *runtimev1.PodStatus
	err    error
}

func newAttachRuntime() *attachRuntime {
	return &attachRuntime{
		fakeRuntimeServer: newFakeRuntimeServer(),
		results:           map[string]attachResult{},
		attached:          map[string]*runtimev1.PodStatus{},
		boxes:             map[string]*runtimev1.PodBox{},
		instance:          map[string]int32{},
	}
}

func (a *attachRuntime) log(entry string) {
	a.amu.Lock()
	defer a.amu.Unlock()
	a.seq = append(a.seq, entry)
}

func (a *attachRuntime) sequence() []string {
	a.amu.Lock()
	defer a.amu.Unlock()
	return slices.Clone(a.seq)
}

func (a *attachRuntime) AttachPod(_ context.Context, box *runtimev1.PodBox) (*runtimev1.PodStatus, error) {
	id := box.GetPodId()
	a.log("attach:" + id)
	a.amu.Lock()
	defer a.amu.Unlock()
	a.boxes[id] = box
	res, ok := a.results[id]
	if !ok {
		return nil, fmt.Errorf("attach pod %s: %w", id, runtimed.ErrNothingToAttach)
	}
	if res.err != nil {
		return nil, res.err
	}
	a.attached[id] = res.status
	return res.status, nil
}

func (a *attachRuntime) ReapOrphanedPods() error {
	a.log("reap")
	return nil
}

// CreatePod records the create and, like runtimed, numbers the new instance of
// c0 one past the highest log file already in its log directory, which is what
// makes a recreate that keeps the log tree a restartCount+1.
func (a *attachRuntime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	id := req.GetPod().GetPodId()
	a.log("create:" + id)
	n := int32(0)
	if entries, err := os.ReadDir(filepath.Join(req.GetPod().GetLogDirectory(), "c0")); err == nil {
		for _, e := range entries {
			var i int32
			if _, err := fmt.Sscanf(e.Name(), "%d.log", &i); err == nil && i+1 > n {
				n = i + 1
			}
		}
	}
	a.amu.Lock()
	a.instance[id] = n
	a.amu.Unlock()
	resp, err := a.fakeRuntimeServer.CreatePod(ctx, req)
	if resp.GetStatus() != nil {
		resp.Status.ContainerStatuses[0].RestartCount = n
	}
	return resp, err
}

// DeletePod records the delete and forgets an attached pod only when the
// underlying fake accepted it: a queued deleteFIFO error leaves the pod running
// as it was, as a failed runtimed delete does.
func (a *attachRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	a.log("delete:" + req.GetPodId())
	resp, err := a.fakeRuntimeServer.DeletePod(ctx, req)
	if err != nil {
		return resp, err
	}
	a.amu.Lock()
	delete(a.attached, req.GetPodId())
	a.amu.Unlock()
	return resp, nil
}

// GetPodStatus answers an attached pod from the status its attach returned, and
// every other pod from the underlying fake with the instance CreatePod chose.
func (a *attachRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	a.amu.Lock()
	st, ok := a.attached[req.GetPodId()]
	n := a.instance[req.GetPodId()]
	a.amu.Unlock()
	if ok {
		return &runtimev1.GetPodStatusResponse{Status: st}, nil
	}
	resp, err := a.fakeRuntimeServer.GetPodStatus(ctx, req)
	if resp.GetStatus() != nil {
		resp.Status.ContainerStatuses[0].RestartCount = n
	}
	return resp, err
}

// exitAttached makes the named containers of an attached pod (its first one
// when none is named) report the exit an adopted process gets: terminated,
// status unknown.
func (a *attachRuntime) exitAttached(id string, names ...string) {
	a.amu.Lock()
	defer a.amu.Unlock()
	st := proto.Clone(a.attached[id]).(*runtimev1.PodStatus)
	if len(names) == 0 {
		names = []string{st.ContainerStatuses[0].GetName()}
	}
	for _, cs := range st.ContainerStatuses {
		if slices.Contains(names, cs.GetName()) {
			cs.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
				ExitCode: -1, Reason: runtimed.ExitStatusUnknownReason, FinishedAt: timestamppb.Now(),
			}}
		}
	}
	a.attached[id] = st
}

// attachTestPod is a pod bound to the node in the given phase, publishing ip.
func attachTestPod(name string, phase corev1.PodPhase, ip string, started time.Time) corev1.Pod {
	st := metav1.NewTime(started)
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			NodeName:      "n",
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{Name: "c0", Image: "registry/web:latest", Command: []string{"/web"}},
				{Name: "c1", Image: "registry/web:latest", Command: []string{"/side"}},
			},
		},
		Status: corev1.PodStatus{Phase: phase, PodIP: ip, StartTime: &st},
	}
}

// TestStartAttachesLiveNodePods is the provider half of pod re-attachment after
// a node-daemon restart. A running pod whose processes survived is ATTACHED, not
// created: it keeps its address and its restart counts, its status carries the
// two facts the restart cost it (the k3sm.io/log-stream-lost condition, and a
// container that died while the daemon was down reported ExitStatusUnknown with
// exit code -1), and one PodReattached Event says so. A pod runtimed cannot
// attach to falls back to the create path with its address released. And the
// ORDER is the one the startup reap demands: every attach, then the reap, then
// any create.
func TestStartAttachesLiveNodePods(t *testing.T) {
	t.Run("attach, then reap, then create", func(t *testing.T) {
		started := time.Unix(1_700_000_000, 0)
		web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
		gone := attachTestPod("gone", corev1.PodRunning, "100.64.0.8", started)
		pending := attachTestPod("pending", corev1.PodPending, "", started)

		rt := newAttachRuntime()
		lost := &runtimev1.PodCondition{
			Type:    runtimed.LogStreamLostConditionType,
			Status:  runtimev1.ConditionStatus_CONDITION_STATUS_TRUE,
			Reason:  "RuntimeRestarted",
			Message: "earlier output from this container may be missing",
		}
		rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
			PodId: "uid-web",
			Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp: "100.64.0.7",
			ContainerStatuses: []*runtimev1.ContainerStatus{
				{
					Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, RestartCount: 2,
					State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}},
				},
				{
					Name: "c1", Image: "registry/web:latest", RestartCount: 1,
					State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
						ExitCode: -1, Reason: runtimed.ExitStatusUnknownReason, FinishedAt: timestamppb.New(started),
					}},
				},
			},
			Conditions: []*runtimev1.PodCondition{lost},
		}}

		ipam := newFakeIPAM(t, "100.64.0.0/24")
		rec := record.NewFakeRecorder(64)
		r := newRuntimedWith(rt, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
			Network:  NewPodNetAdapter(ipam, "192.168.1.10", nil),
			Recorder: rec,
		}, nil, nil)
		r.podSource = &fakePodSource{listed: []corev1.Pod{web, gone, pending}}
		ctx := context.Background()

		r.adoptNodePods(ctx, rt)

		// The startup sequence attached the two running pods (never the pending
		// one), reaped, and created nothing itself.
		if got, want := rt.sequence(), []string{"attach:uid-web", "attach:uid-gone", "reap"}; !slices.Equal(got, want) {
			t.Fatalf("startup sequence = %v, want %v", got, want)
		}
		if got := rt.boxes["uid-web"].GetPodIp(); got != "100.64.0.7" {
			t.Errorf("attach box pod_ip = %q, want the pod's published 100.64.0.7", got)
		}

		// The attached pod keeps its address on the pod network; the refused pod's
		// re-reservation was released for the create to allocate afresh.
		ipam.mu.Lock()
		webIP, webBound := ipam.byPod["uid-web"]
		_, goneBound := ipam.byPod["uid-gone"]
		ipam.mu.Unlock()
		if !webBound || webIP.String() != "100.64.0.7" {
			t.Errorf("uid-web bound = %v %v, want 100.64.0.7 re-reserved", webBound, webIP)
		}
		if goneBound {
			t.Error("uid-gone still holds its address after its attach was refused")
		}

		// Virtual Kubelet's first sync, which can only start after NewRuntimed has
		// returned: a pod GetPod knows is left alone, any other is created.
		for _, p := range []corev1.Pod{web, gone, pending} {
			if known, _ := r.GetPod(ctx, p.Namespace, p.Name); known != nil {
				continue
			}
			if err := r.CreatePod(ctx, p.DeepCopy()); err != nil {
				t.Fatalf("CreatePod %s: %v", p.Name, err)
			}
		}
		want := []string{"attach:uid-web", "attach:uid-gone", "reap", "create:uid-gone", "create:uid-pending"}
		if got := rt.sequence(); !slices.Equal(got, want) {
			t.Fatalf("sequence = %v, want %v (every attach, then the reap, then the creates; the attached pod never created)", got, want)
		}

		st, err := r.GetPodStatus(ctx, "default", "web")
		if err != nil {
			t.Fatalf("GetPodStatus web: %v", err)
		}
		if st.Phase != corev1.PodRunning || st.PodIP != "100.64.0.7" {
			t.Errorf("web phase/podIP = %s/%s, want Running/100.64.0.7", st.Phase, st.PodIP)
		}
		if st.StartTime == nil || !st.StartTime.Time.Equal(started) {
			t.Errorf("web StartTime = %v, want the pod's first-life %v", st.StartTime, started)
		}
		byName := map[string]corev1.ContainerStatus{}
		for _, cs := range st.ContainerStatuses {
			byName[cs.Name] = cs
		}
		if got := byName["c0"].RestartCount; got != 2 {
			t.Errorf("c0 restartCount = %d, want 2 (unchanged by the attach)", got)
		}
		if got := byName["c1"].RestartCount; got != 1 {
			t.Errorf("c1 restartCount = %d, want 1 (unchanged by the attach)", got)
		}
		term := byName["c1"].State.Terminated
		if term == nil || term.Reason != "ExitStatusUnknown" || term.ExitCode != -1 {
			t.Errorf("c1 terminated = %+v, want reason ExitStatusUnknown, exit code -1", term)
		}
		cond := findPodCondition(st.Conditions, corev1.PodConditionType(runtimed.LogStreamLostConditionType))
		if cond == nil || cond.Status != corev1.ConditionTrue || cond.Reason != "RuntimeRestarted" {
			t.Errorf("log-stream-lost condition = %+v, want True/RuntimeRestarted", cond)
		}
		if n := countConditions(st.Conditions, runtimed.LogStreamLostConditionType); n != 1 {
			t.Errorf("log-stream-lost appears %d times, want once", n)
		}
		rt.fakeRuntimeServer.mu.Lock()
		restarts := rt.fakeRuntimeServer.restartCalls
		rt.fakeRuntimeServer.mu.Unlock()
		if restarts != 0 {
			t.Errorf("RestartContainer called %d times by the attach, want 0", restarts)
		}

		// A second status read must not record the Event again.
		if _, err := r.GetPodStatus(ctx, "default", "web"); err != nil {
			t.Fatalf("GetPodStatus web (again): %v", err)
		}
		if n := drainReason(rec, reasonPodReattached); n != 1 {
			t.Errorf("PodReattached events = %d, want exactly 1", n)
		}
	})

	t.Run("an exit due a restart recreates the attached pod", func(t *testing.T) {
		started := time.Unix(1_700_000_000, 0)
		web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
		web.Spec.RestartPolicy = corev1.RestartPolicyAlways
		web.Spec.Containers = web.Spec.Containers[:1]

		rt := newAttachRuntime()
		rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
			PodId: "uid-web",
			Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp: "100.64.0.7",
			ContainerStatuses: []*runtimev1.ContainerStatus{{
				Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, RestartCount: 2,
				State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}},
			}},
		}}
		rec := record.NewFakeRecorder(64)
		r := newRuntimedWith(rt, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
			Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), "192.168.1.10", nil),
			Recorder: rec,
		}, nil, nil)
		r.podSource = &fakePodSource{listed: []corev1.Pod{web}}
		ctx := context.Background()
		r.adoptNodePods(ctx, rt)

		// The three instances the pod's first life wrote, as runtimed names them.
		logDir := filepath.Join(rt.boxes["uid-web"].GetLogDirectory(), "c0")
		for i := range 3 {
			if err := os.WriteFile(filepath.Join(logDir, fmt.Sprintf("%d.log", i)), []byte("x\n"), 0o644); err != nil {
				t.Fatalf("stage log: %v", err)
			}
		}

		rt.exitAttached("uid-web")
		// Two observations of the same exit (the stream and the backstop).
		for range 2 {
			if _, err := r.GetPodStatus(ctx, "default", "web"); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for !slices.Contains(rt.sequence(), "create:uid-web") && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got, want := rt.sequence(), []string{"attach:uid-web", "reap", "delete:uid-web", "create:uid-web"}; !slices.Equal(got, want) {
			t.Fatalf("sequence = %v, want %v (one delete, one create)", got, want)
		}
		rt.fakeRuntimeServer.mu.Lock()
		restarts := rt.fakeRuntimeServer.restartCalls
		rt.fakeRuntimeServer.mu.Unlock()
		if restarts != 0 {
			t.Errorf("RestartContainer called %d times on an attached pod, want 0 (runtimed refuses it)", restarts)
		}
		if _, err := os.Stat(filepath.Join(logDir, "2.log")); err != nil {
			t.Errorf("the recreate removed the previous instance's log: %v", err)
		}
		st, err := r.GetPodStatus(ctx, "default", "web")
		if err != nil {
			t.Fatalf("GetPodStatus after recreate: %v", err)
		}
		if st.Phase != corev1.PodRunning || len(st.ContainerStatuses) == 0 || st.ContainerStatuses[0].RestartCount != 3 {
			t.Errorf("after recreate phase=%s statuses=%+v, want Running with restartCount 3", st.Phase, st.ContainerStatuses)
		}
		if n := drainReason(rec, reasonPodRecreatedAfterReattach); n != 1 {
			t.Errorf("PodRecreatedAfterReattach events = %d, want exactly 1", n)
		}
		if tr := r.trackByID("uid-web"); tr == nil || tr.adopted {
			t.Errorf("after recreate the pod must be tracked as a created pod, got %+v", tr)
		}
	})

	t.Run("an unlisted node attaches nothing and still reaps", func(t *testing.T) {
		rt := newAttachRuntime()
		r := newRuntimedWith(rt, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir()}, nil, nil)
		r.podSource = &fakePodSource{listErr: errors.New("apiserver unreachable")}
		r.adoptNodePods(context.Background(), rt)
		if got, want := rt.sequence(), []string{"reap"}; !slices.Equal(got, want) {
			t.Fatalf("sequence = %v, want %v", got, want)
		}
	})
}

// adoptTwoContainerWeb attaches a two-container restartPolicy: Always pod whose
// containers both run, and returns the provider, the fake runtime and the
// recorder.
func adoptTwoContainerWeb(t *testing.T) (*runtimedRuntime, *attachRuntime, *record.FakeRecorder) {
	t.Helper()
	started := time.Unix(1_700_000_000, 0)
	web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
	web.Spec.RestartPolicy = corev1.RestartPolicyAlways
	running := &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}}
	rt := newAttachRuntime()
	rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
		PodId: "uid-web",
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "100.64.0.7",
		ContainerStatuses: []*runtimev1.ContainerStatus{
			{Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, RestartCount: 2, State: running},
			{Name: "c1", Image: "registry/web:latest", ContainerId: "cid1", Ready: true, RestartCount: 1, State: running},
		},
	}}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(rt, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), "192.168.1.10", nil),
		Recorder: rec,
	}, nil, nil)
	r.podSource = &fakePodSource{listed: []corev1.Pod{web}}
	r.adoptNodePods(context.Background(), rt)
	if tr := r.trackByID("uid-web"); tr == nil || !tr.adopted {
		t.Fatalf("uid-web was not re-attached: %+v", tr)
	}
	return r, rt, rec
}

// waitFor polls cond for up to five seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// countSeq counts entry in the fake runtime's ordered log.
func countSeq(rt *attachRuntime, entry string) int {
	n := 0
	for _, e := range rt.sequence() {
		if e == entry {
			n++
		}
	}
	return n
}

// drainReasonEvents empties the fake recorder and returns the events carrying reason.
func drainReasonEvents(rec *record.FakeRecorder, reason string) []string {
	var out []string
	for {
		select {
		case e := <-rec.Events:
			if strings.Contains(e, " "+reason+" ") {
				out = append(out, e)
			}
		default:
			return out
		}
	}
}

// TestAdoptedPodRestartsRecreate pins that every restart trigger on a
// re-attached pod converges on the one-shot whole-pod recreate, never on
// RestartContainer (which runtimed refuses there), that the recreate's Event
// names every container due a restart, and that a failed runtime delete does
// not latch the pod out of every later retry.
func TestAdoptedPodRestartsRecreate(t *testing.T) {
	restartCalls := func(rt *attachRuntime) int {
		rt.fakeRuntimeServer.mu.Lock()
		defer rt.fakeRuntimeServer.mu.Unlock()
		return rt.fakeRuntimeServer.restartCalls
	}

	for _, tc := range []struct {
		name   string
		exited []string
		want   string
	}{
		{name: "one of two containers exits", exited: []string{"c1"}, want: "container c1 is due a restart"},
		{name: "both containers exit", exited: []string{"c0", "c1"}, want: "containers c0, c1 are due a restart"},
	} {
		t.Run("an exit recreates the whole pod once: "+tc.name, func(t *testing.T) {
			r, rt, rec := adoptTwoContainerWeb(t)
			ctx := context.Background()
			rt.exitAttached("uid-web", tc.exited...)
			for range 2 { // the stream and the backstop
				if _, err := r.GetPodStatus(ctx, "default", "web"); err != nil {
					t.Fatalf("GetPodStatus: %v", err)
				}
			}
			waitFor(t, "the recreate's create", func() bool { return countSeq(rt, "create:uid-web") == 1 })
			if got, want := rt.sequence(), []string{"attach:uid-web", "reap", "delete:uid-web", "create:uid-web"}; !slices.Equal(got, want) {
				t.Fatalf("sequence = %v, want %v (one delete of the whole pod, one create)", got, want)
			}
			if n := restartCalls(rt); n != 0 {
				t.Errorf("RestartContainer called %d times on an attached pod, want 0", n)
			}
			evs := drainReasonEvents(rec, reasonPodRecreatedAfterReattach)
			if len(evs) != 1 {
				t.Fatalf("PodRecreatedAfterReattach events = %v, want exactly 1", evs)
			}
			if !strings.Contains(evs[0], tc.want) {
				t.Errorf("event %q does not name the containers due a restart (want %q)", evs[0], tc.want)
			}
		})
	}

	t.Run("a failed runtime delete clears the latch and the next exit retries", func(t *testing.T) {
		r, rt, rec := adoptTwoContainerWeb(t)
		ctx := context.Background()
		rt.fakeRuntimeServer.mu.Lock()
		rt.fakeRuntimeServer.deleteFIFO = []error{errors.New("runtimed unavailable")}
		rt.fakeRuntimeServer.mu.Unlock()
		tr := r.trackByID("uid-web")
		rt.exitAttached("uid-web", "c0")
		if _, err := r.GetPodStatus(ctx, "default", "web"); err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
		waitFor(t, "the failed delete to release the recreate latch", func() bool {
			tr.restartMu.Lock()
			defer tr.restartMu.Unlock()
			return countSeq(rt, "delete:uid-web") == 1 && !tr.recreating
		})
		if n := countSeq(rt, "create:uid-web"); n != 0 {
			t.Fatalf("created %d times after a failed delete, want 0", n)
		}
		failed := drainReasonEvents(rec, reasonPodRecreateAfterReattachFailed)
		if len(failed) != 1 || !strings.Contains(failed[0], "runtimed unavailable") {
			t.Errorf("PodRecreateAfterReattachFailed events = %v, want exactly 1 naming the error", failed)
		}

		// The pod is still running as it was and its exit is observed again.
		if _, err := r.GetPodStatus(ctx, "default", "web"); err != nil {
			t.Fatalf("GetPodStatus (retry): %v", err)
		}
		waitFor(t, "the retried recreate's create", func() bool { return countSeq(rt, "create:uid-web") == 1 })
		want := []string{"attach:uid-web", "reap", "delete:uid-web", "delete:uid-web", "create:uid-web"}
		if got := rt.sequence(); !slices.Equal(got, want) {
			t.Fatalf("sequence = %v, want %v", got, want)
		}
		if n := len(drainReasonEvents(rec, reasonPodRecreateAfterReattachFailed)); n != 0 {
			t.Errorf("a successful retry recorded %d more PodRecreateAfterReattachFailed events, want 0", n)
		}
		if n := restartCalls(rt); n != 0 {
			t.Errorf("RestartContainer called %d times on an attached pod, want 0", n)
		}
	})

	t.Run("a committed liveness failure recreates the pod, never RestartContainer", func(t *testing.T) {
		r, rt, rec := adoptTwoContainerWeb(t)
		// The prober's restartFunc seam, twice: a probe that keeps failing
		// while the recreate is in flight must not start a second one.
		for range 2 {
			if err := r.restartForLiveness(context.Background(), "uid-web", "c0"); err != nil {
				t.Fatalf("restartForLiveness: %v", err)
			}
		}
		waitFor(t, "the recreate's create", func() bool { return countSeq(rt, "create:uid-web") == 1 })
		if got, want := rt.sequence(), []string{"attach:uid-web", "reap", "delete:uid-web", "create:uid-web"}; !slices.Equal(got, want) {
			t.Fatalf("sequence = %v, want %v", got, want)
		}
		if n := restartCalls(rt); n != 0 {
			t.Errorf("RestartContainer called %d times for a liveness failure on an attached pod, want 0", n)
		}
		evs := drainReasonEvents(rec, reasonPodRecreatedAfterReattach)
		if len(evs) != 1 || !strings.Contains(evs[0], "container c0 is due a restart") {
			t.Errorf("PodRecreatedAfterReattach events = %v, want exactly 1 naming c0", evs)
		}
	})
}

// countConditions counts the conditions of type t.
func countConditions(conds []corev1.PodCondition, t string) int {
	n := 0
	for _, c := range conds {
		if string(c.Type) == t {
			n++
		}
	}
	return n
}

// drainReason empties the fake recorder and counts the events carrying reason.
func drainReason(rec *record.FakeRecorder, reason string) int {
	n := 0
	for {
		select {
		case e := <-rec.Events:
			if strings.Contains(e, " "+reason+" ") {
				n++
			}
		default:
			return n
		}
	}
}
