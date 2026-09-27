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
	testclock "k8s.io/utils/clock/testing"

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

// CreatePod records the create.
func (a *attachRuntime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	a.log("create:" + req.GetPod().GetPodId())
	return a.fakeRuntimeServer.CreatePod(ctx, req)
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
// every other pod from the underlying fake.
func (a *attachRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	a.amu.Lock()
	st, ok := a.attached[req.GetPodId()]
	a.amu.Unlock()
	if ok {
		return &runtimev1.GetPodStatusResponse{Status: st}, nil
	}
	return a.fakeRuntimeServer.GetPodStatus(ctx, req)
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

// RestartContainer, StartContainer and StopContainer write the per-container
// verb to the ordered log, so "one restart of c1 and nothing else" is one
// sequence assertion. The underlying fake keeps its own tallies.
func (a *attachRuntime) RestartContainer(ctx context.Context, req *runtimev1.RestartContainerRequest) (*runtimev1.RestartContainerResponse, error) {
	a.log("restart:" + req.GetPodId() + "/" + req.GetContainer())
	return a.fakeRuntimeServer.RestartContainer(ctx, req)
}

func (a *attachRuntime) StartContainer(ctx context.Context, req *runtimev1.StartContainerRequest) (*runtimev1.StartContainerResponse, error) {
	a.log("start:" + req.GetPodId() + "/" + req.GetContainer())
	return a.fakeRuntimeServer.StartContainer(ctx, req)
}

// StopContainer answers an attached pod itself (the underlying fake renders
// only the pods it created): the stopped container reports Terminated.
func (a *attachRuntime) StopContainer(_ context.Context, req *runtimev1.StopContainerRequest) (*runtimev1.StopContainerResponse, error) {
	a.log("stop:" + req.GetPodId() + "/" + req.GetContainer())
	a.exitAttached(req.GetPodId(), req.GetContainer())
	return &runtimev1.StopContainerResponse{Status: &runtimev1.ContainerStatus{Name: req.GetContainer()}}, nil
}

// adoptWeb attaches a two-container pod under policy whose c0 runs and whose c1
// is in c1State (running when nil), on a fake clock so the CrashLoopBackOff
// wait is stepped, never slept.
func adoptWeb(t *testing.T, policy corev1.RestartPolicy, c1State *runtimev1.ContainerState) (*runtimedRuntime, *attachRuntime, *record.FakeRecorder, *testclock.FakeClock) {
	t.Helper()
	started := time.Unix(1_700_000_000, 0)
	web := attachTestPod("web", corev1.PodRunning, "100.64.0.7", started)
	web.Spec.RestartPolicy = policy
	running := &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(started)}}
	if c1State == nil {
		c1State = running
	}
	rt := newAttachRuntime()
	rt.results["uid-web"] = attachResult{status: &runtimev1.PodStatus{
		PodId: "uid-web",
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "100.64.0.7",
		ContainerStatuses: []*runtimev1.ContainerStatus{
			{Name: "c0", Image: "registry/web:latest", ContainerId: "cid0", Ready: true, RestartCount: 2, State: running},
			{Name: "c1", Image: "registry/web:latest", ContainerId: "cid1", Ready: true, RestartCount: 1, State: c1State},
		},
	}}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(rt, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), "192.168.1.10", nil),
		Recorder: rec,
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	r.podSource = &fakePodSource{listed: []corev1.Pod{web}}
	r.adoptNodePods(context.Background(), rt)
	if r.trackByID("uid-web") == nil {
		t.Fatal("uid-web was not re-attached")
	}
	return r, rt, rec, clk
}

// awaitSeq polls cond for up to five seconds and, on timeout, fails naming the
// runtime calls made so far, which is what says which path was taken instead.
func awaitSeq(t *testing.T, rt *attachRuntime, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s; runtime calls = %v", what, rt.sequence())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAdoptedPodRestartsInPlace is the provider half of restarting one
// container of a re-attached pod in place. The kubelet restarts only the
// container that exited, and the runtime now can too on an attached pod (it
// compiles the pod's sandbox profile at attach and verifies it against the
// spawn record), so every restart trigger on a re-attached pod takes the
// ordinary per-container path: an observed exit and a committed liveness
// failure are one RestartContainer of that container, a failed postStart hook
// under Never is one StopContainer, and a container that died while the daemon
// was down (it has no process under this daemon, and the runtime refuses
// RestartContainer on it) is one StartContainer. The sibling is never touched,
// nothing is deleted or created, and no recreate Event is recorded.
//
// Red on main: every trigger recreated the whole pod (delete, then create).
func TestAdoptedPodRestartsInPlace(t *testing.T) {
	const recreateReason = "PodRecreatedAfterReattach"
	unknownExit := &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
		ExitCode: -1, Reason: runtimed.ExitStatusUnknownReason, FinishedAt: timestamppb.New(time.Unix(1_700_000_100, 0)),
	}}

	for _, tc := range []struct {
		name    string
		policy  corev1.RestartPolicy
		c1State *runtimev1.ContainerState
		trigger func(t *testing.T, r *runtimedRuntime, rt *attachRuntime, clk *testclock.FakeClock)
		want    string
	}{
		{
			name:   "an exit with a restart due restarts that container only",
			policy: corev1.RestartPolicyAlways,
			trigger: func(t *testing.T, r *runtimedRuntime, rt *attachRuntime, clk *testclock.FakeClock) {
				rt.exitAttached("uid-web", "c1")
				for range 2 { // the stream and the backstop deliver the same exit
					if _, err := r.GetPodStatus(context.Background(), "default", "web"); err != nil {
						t.Fatalf("GetPodStatus: %v", err)
					}
				}
				awaitSeq(t, rt, "the backoff timer", clk.HasWaiters)
				clk.Step(crashLoopBaseDelay)
			},
			want: "restart:uid-web/c1",
		},
		{
			name:   "a committed liveness failure restarts that container only",
			policy: corev1.RestartPolicyAlways,
			trigger: func(t *testing.T, r *runtimedRuntime, _ *attachRuntime, _ *testclock.FakeClock) {
				for range 2 { // a probe that keeps failing while the restart is in flight
					if err := r.restartForLiveness(context.Background(), "uid-web", "c1"); err != nil {
						t.Fatalf("restartForLiveness: %v", err)
					}
				}
			},
			want: "restart:uid-web/c1",
		},
		{
			name:   "a failed postStart hook under Never stops that container only",
			policy: corev1.RestartPolicyNever,
			trigger: func(t *testing.T, r *runtimedRuntime, _ *attachRuntime, _ *testclock.FakeClock) {
				tr := r.trackByID("uid-web")
				r.failPostStart(context.Background(), tr, tr.pod, "uid-web", "default/web", "c1", errors.New("hook exited 7"))
			},
			want: "stop:uid-web/c1",
		},
		{
			name:    "a container that died while the daemon was down is started, not restarted",
			policy:  corev1.RestartPolicyAlways,
			c1State: unknownExit,
			trigger: func(t *testing.T, r *runtimedRuntime, rt *attachRuntime, clk *testclock.FakeClock) {
				if _, err := r.GetPodStatus(context.Background(), "default", "web"); err != nil {
					t.Fatalf("GetPodStatus: %v", err)
				}
				awaitSeq(t, rt, "the backoff timer", clk.HasWaiters)
				clk.Step(crashLoopBaseDelay)
			},
			want: "start:uid-web/c1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, rt, rec, clk := adoptWeb(t, tc.policy, tc.c1State)
			tc.trigger(t, r, rt, clk)
			awaitSeq(t, rt, tc.want, func() bool { return countSeq(rt, tc.want) == 1 })
			time.Sleep(100 * time.Millisecond) // let a second (wrong) action surface
			if got, want := rt.sequence(), []string{"attach:uid-web", "reap", tc.want}; !slices.Equal(got, want) {
				t.Fatalf("sequence = %v, want %v (one verb on c1; no delete, no create, c0 untouched)", got, want)
			}
			if n := drainReason(rec, recreateReason); n != 0 {
				t.Errorf("%s events = %d, want 0", recreateReason, n)
			}
			if r.trackByID("uid-web") == nil {
				t.Fatal("the pod is no longer tracked")
			}
			st, err := r.GetPodStatus(context.Background(), "default", "web")
			if err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			for _, cs := range st.ContainerStatuses {
				if cs.Name == "c0" && (cs.State.Running == nil || cs.RestartCount != 2) {
					t.Errorf("sibling c0 = %+v, want still Running at restartCount 2", cs)
				}
			}
		})
	}
}
