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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// lcEvent is one Event object as the apiserver holds it: the involved object's
// UID and fieldPath, the Event's type, reason and message, and its count.
type lcEvent struct {
	uid, fieldPath, eventtype, reason, message string
	count                                      int
}

// usClock is a wall clock that steps in whole microseconds and is read more than
// once per step, as the macOS clock is: every 3 reads it advances 1µs. It is
// what lets two Events recorded back to back carry the same timestamp.
type usClock struct {
	mu    sync.Mutex
	base  time.Time
	reads int64
}

func (c *usClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	return c.base.Add(time.Duration(c.reads/3) * time.Microsecond)
}

// lcRecorder is a record.EventRecorder that stores Events the way the node's
// client-go recorder and the apiserver do, which record.FakeRecorder does not:
//
//   - the Event is named "<object name>.<hex UnixNano>" from the recorder's
//     clock (record.makeEvent), here the coarse usClock;
//   - the correlator keys an Event by source, involved object (fieldPath
//     included), type, reason and message; a key seen before PATCHES the Event
//     filed under that key's name (count and message), a new key CREATES one;
//   - a Create whose name already exists is refused (AlreadyExists) and
//     dropped, while the correlator keeps the key filed under that name.
//
// So two Events stamped in one clock step reproduce the live failure: the
// second is dropped, and its next occurrence is patched onto the first.
type lcRecorder struct {
	clock *usClock

	mu    sync.Mutex
	objs  map[string]*lcEvent // Event name -> the stored Event
	order []string            // names in creation order
	keys  map[string]string   // correlator key -> Event name
}

var _ record.EventRecorder = (*lcRecorder)(nil)

func newLCRecorder(clock *usClock) *lcRecorder {
	return &lcRecorder{clock: clock, objs: map[string]*lcEvent{}, keys: map[string]string{}}
}

func (c *lcRecorder) Event(obj runtime.Object, eventtype, reason, message string) {
	e := lcEvent{eventtype: eventtype, reason: reason, message: message, count: 1}
	var objName string
	switch o := obj.(type) {
	case *corev1.ObjectReference:
		e.uid, e.fieldPath, objName = string(o.UID), o.FieldPath, o.Name
	case *corev1.Pod:
		e.uid, objName = string(o.UID), o.Name
	}
	name := fmt.Sprintf("%s.%x", objName, c.clock.Now().UnixNano())
	key := strings.Join([]string{e.uid, e.fieldPath, eventtype, reason, message}, "\x00")
	c.mu.Lock()
	defer c.mu.Unlock()
	if filed, ok := c.keys[key]; ok {
		if o := c.objs[filed]; o != nil {
			o.message = message
			o.count++
		}
		return
	}
	c.keys[key] = name
	if _, exists := c.objs[name]; exists {
		return // AlreadyExists: the apiserver refuses it, the key stays filed
	}
	c.objs[name] = &e
	c.order = append(c.order, name)
}

func (c *lcRecorder) Eventf(obj runtime.Object, eventtype, reason, format string, args ...any) {
	c.Event(obj, eventtype, reason, fmt.Sprintf(format, args...))
}

func (c *lcRecorder) AnnotatedEventf(obj runtime.Object, _ map[string]string, eventtype, reason, format string, args ...any) {
	c.Event(obj, eventtype, reason, fmt.Sprintf(format, args...))
}

// snapshot returns the stored Events in creation order.
func (c *lcRecorder) snapshot() []lcEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]lcEvent, 0, len(c.order))
	for _, n := range c.order {
		out = append(out, *c.objs[n])
	}
	return out
}

// count is the number of occurrences (the sum of the stored counts) of Events
// with reason whose fieldPath names container.
func (c *lcRecorder) count(reason, container string) int {
	n := 0
	for _, e := range c.snapshot() {
		if e.reason == reason && e.fieldPath == "spec.containers{"+container+"}" {
			n += e.count
		}
	}
	return n
}

// lcContainer is one container of the lifecycle fake: its restart count, the
// start instant of its current instance, and whether that instance exited.
type lcContainer struct {
	restarts   int32
	startedAt  time.Time
	exited     bool
	finishedAt time.Time
}

// instanceFake is a runtime that runs one pod's containers the way runtimed
// reports them: every start gets a fresh container ID (runtimed derives it from
// the start), RestartContainer bumps restart_count and starts a new instance,
// and CreatePod of a pod it already holds is idempotent.
type instanceFake struct {
	runtimev1.UnimplementedRuntimeServer

	mu       sync.Mutex
	podID    string
	created  bool
	clock    time.Time
	ctrs     map[string]*lcContainer
	order    []string
	restarts int
}

func newInstanceFake(names ...string) *instanceFake {
	return &instanceFake{clock: time.Unix(5000, 0), ctrs: map[string]*lcContainer{}, order: names}
}

// tickLocked advances the fake's start clock, so every start has its own instant.
func (f *instanceFake) tickLocked() time.Time {
	f.clock = f.clock.Add(time.Second)
	return f.clock
}

func (f *instanceFake) statusLocked() *runtimev1.PodStatus {
	st := &runtimev1.PodStatus{PodId: f.podID, Phase: runtimev1.PodPhase_POD_PHASE_RUNNING, PodIp: "10.0.0.5"}
	for _, name := range f.order {
		c := f.ctrs[name]
		cs := &runtimev1.ContainerStatus{
			Name:         name,
			Image:        runtimed.NativeImage,
			RestartCount: c.restarts,
			ContainerId:  fmt.Sprintf("%s-%d-%d", name, c.restarts, c.startedAt.UnixNano()),
		}
		if c.exited {
			cs.State = &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
				ExitCode: 1, Reason: "Error",
				StartedAt: timestamppb.New(c.startedAt), FinishedAt: timestamppb.New(c.finishedAt),
			}}
		} else {
			cs.Ready, cs.Started, cs.StartedSet = true, true, true
			cs.State = &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(c.startedAt)}}
		}
		st.ContainerStatuses = append(st.ContainerStatuses, cs)
	}
	return st
}

func (f *instanceFake) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.created {
		f.created, f.podID = true, req.GetPod().GetPodId()
		for _, name := range f.order {
			f.ctrs[name] = &lcContainer{startedAt: f.tickLocked()}
		}
	}
	return &runtimev1.CreatePodResponse{Status: f.statusLocked()}, nil
}

func (f *instanceFake) GetPodStatus(_ context.Context, _ *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.created {
		return &runtimev1.GetPodStatusResponse{Error: &rpcstatus.Status{Code: int32(codes.NotFound), Message: "not found"}}, nil
	}
	return &runtimev1.GetPodStatusResponse{Status: f.statusLocked()}, nil
}

func (f *instanceFake) RestartContainer(_ context.Context, req *runtimev1.RestartContainerRequest) (*runtimev1.RestartContainerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.ctrs[req.GetContainer()]
	c.restarts++
	c.startedAt, c.exited = f.tickLocked(), false
	f.restarts++
	return &runtimev1.RestartContainerResponse{Status: &runtimev1.ContainerStatus{Name: req.GetContainer()}}, nil
}

func (f *instanceFake) DeletePod(_ context.Context, _ *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = false
	return &runtimev1.DeletePodResponse{}, nil
}

// crash makes the named container's current instance exit 1.
func (f *instanceFake) crash(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.ctrs[name]
	c.exited, c.finishedAt = true, f.tickLocked()
}

func (f *instanceFake) restartCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.restarts
}

func (f *instanceFake) status() *runtimev1.PodStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusLocked()
}

// TestRuntimedPathEmitsContainerLifecycleEvents is the B762 gate: a pod on the
// runtimed path records the kubelet's container lifecycle Events, each against
// the Pod with the container's fieldPath, exactly once per container instance:
//
//   - a two-container start records Pulled ("already present" for the native
//     image), Created and Started once per container, in that order;
//   - an idempotent CreatePod replay, repeated GetPodStatus and GetPods resyncs,
//     the stream's emit of the same status and a stale status from before a
//     re-exec record nothing more;
//   - a crashing container re-exec'd twice records three Pulled/Created/Started
//     sets;
//   - DeletePod records one Killing per container still running and none for a
//     container whose instance has exited, and a repeated DeletePod none again.
//
// The recorder stores Events the way client-go and the apiserver do, on a
// clock with microsecond steps (lcRecorder, usClock), so a re-exec's occurrences
// are counts on one Event, as with the kubelet, and two Events stamped in one
// step collide by name the way they did on a macOS node.
//
// Fails-before: the runtimed path recorded none of these Events. Removing the
// instance latch reds the resync counts; removing the eventSpacer's wait reds
// it with the live failure, a Created Event carrying "Started container
// crasher" and no Started for the re-execs.
func TestRuntimedPathEmitsContainerLifecycleEvents(t *testing.T) {
	ctx := context.Background()
	pod := runtimedPod("default", "events")
	pod.Spec.RestartPolicy = corev1.RestartPolicyAlways
	pod.Spec.Containers = []corev1.Container{
		{Name: "steady", Image: runtimed.NativeImage, Command: []string{"/bin/sh", "-c", "sleep 1000"}},
		{Name: "crasher", Image: runtimed.NativeImage, Command: []string{"/bin/sh", "-c", "exit 1"}},
	}
	f := newInstanceFake("steady", "crasher")
	wall := &usClock{base: time.Unix(20000, 0)}
	rec := newLCRecorder(wall)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(), Recorder: rec,
	}, nil, nil)
	// The provider's spacer reads the same coarse clock the recorder stamps with.
	spacer, ok := r.recorder.(*EventSpacer)
	if !ok {
		t.Fatalf("the provider's recorder is %T, want the *EventSpacer over the configured one", r.recorder)
	}
	spacer.now = wall.Now
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	r.mu.Lock()
	r.notify = func(*corev1.Pod) {}
	r.mu.Unlock()

	// resync drives every status path a running node takes, several times.
	resync := func() {
		t.Helper()
		for range 3 {
			if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			if _, err := r.GetPods(ctx); err != nil {
				t.Fatalf("GetPods: %v", err)
			}
			r.emit(f.status())
		}
	}
	// want checks the counts and messages. A phase before the last only logs
	// its failure and lets the test go on, so a red run shows every symptom.
	want := func(phase string, counts map[string]map[string]int) {
		t.Helper()
		for container, byReason := range counts {
			for reason, n := range byReason {
				if got := rec.count(reason, container); got != n {
					t.Errorf("%s: %d %s Event(s) for container %s, want %d", phase, got, reason, container, n)
				}
			}
		}
		// Each stored Event's message is its own reason's: the live failure was a
		// Created Event carrying "Started container crasher".
		for _, e := range rec.snapshot() {
			name := strings.TrimSuffix(strings.TrimPrefix(e.fieldPath, "spec.containers{"), "}")
			var wantMsg string
			switch e.reason {
			case reasonCreated:
				wantMsg = msgCreatedContainer(name)
			case reasonStarted:
				wantMsg = msgStartedContainer(name)
			case reasonPulled:
				wantMsg = msgImageAlreadyPresent(runtimed.NativeImage)
			default:
				continue
			}
			if e.message != wantMsg {
				t.Errorf("%s: a %s Event for %s carries %q, want %q", phase, e.reason, name, e.message, wantMsg)
			}
		}
		if t.Failed() {
			t.Logf("Events after %s:", phase)
			for _, e := range rec.snapshot() {
				t.Logf("  %s %s %s (x%d): %s", e.eventtype, e.reason, e.fieldPath, e.count, e.message)
			}
		}
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}

	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	// Not fatal on timeout: an Event lost to a name collision must surface as
	// the count and message assertions below, which say what went wrong.
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if rec.count(reasonStarted, "steady") > 0 && rec.count(reasonStarted, "crasher") > 0 {
			break
		}
	}
	start := map[string]map[string]int{
		"steady":  {reasonPulled: 1, reasonCreated: 1, reasonStarted: 1, reasonKilling: 0},
		"crasher": {reasonPulled: 1, reasonCreated: 1, reasonStarted: 1, reasonKilling: 0},
	}
	want("pod start", start)

	// Order and content per container, as the kubelet records them.
	for _, name := range []string{"steady", "crasher"} {
		var got []string
		for _, e := range rec.snapshot() {
			if e.fieldPath == "spec.containers{"+name+"}" {
				if e.uid != string(pod.UID) {
					t.Errorf("Event %s for %s involves uid %q, want the pod's %q", e.reason, name, e.uid, pod.UID)
				}
				got = append(got, e.eventtype+" "+e.reason+" "+e.message)
			}
		}
		wantSeq := []string{
			"Normal Pulled " + msgImageAlreadyPresent(runtimed.NativeImage),
			"Normal Created " + msgCreatedContainer(name),
			"Normal Started " + msgStartedContainer(name),
		}
		if strings.Join(got, "\n") != strings.Join(wantSeq, "\n") {
			t.Errorf("Events for %s =\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(wantSeq, "\n"))
		}
	}

	// A replayed CreatePod and every resync path: nothing new.
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("replayed CreatePod: %v", err)
	}
	time.Sleep(20 * time.Millisecond) // the replay's async dispatch
	resync()
	want("replay and resyncs", start)

	// The crasher exits and is re-exec'd twice; each new instance records its set.
	stale := f.status()
	for i := 1; i <= 2; i++ {
		f.crash("crasher")
		resync()
		waitFor("the back-off timer", clk.HasWaiters)
		clk.Step(10 * time.Minute)
		waitFor("the re-exec", func() bool { return f.restartCalls() == i })
		// Bounded, not fatal: a lost Started must surface as the assertions below.
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			if rec.count(reasonStarted, "crasher") == 1+i {
				break
			}
		}
		resync()
	}
	// A status read before the re-execs, delivered late, is not a new instance.
	r.emit(stale)
	if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	afterCrash := map[string]map[string]int{
		"steady":  {reasonPulled: 1, reasonCreated: 1, reasonStarted: 1, reasonKilling: 0},
		"crasher": {reasonPulled: 3, reasonCreated: 3, reasonStarted: 3, reasonKilling: 0},
	}
	want("two re-execs", afterCrash)

	// The crasher's third instance exits; then the pod is deleted.
	f.crash("crasher")
	if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if err := r.DeletePod(ctx, pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	if err := r.DeletePod(ctx, pod); err != nil {
		t.Fatalf("repeated DeletePod: %v", err)
	}
	afterCrash["steady"][reasonKilling] = 1
	want("delete", afterCrash)
	for _, e := range rec.snapshot() {
		if e.reason == reasonKilling && (e.eventtype != corev1.EventTypeNormal || e.message != msgStoppingContainer("steady")) {
			t.Errorf("Killing Event = %s %q, want Normal %q", e.eventtype, e.message, msgStoppingContainer("steady"))
		}
	}
}
