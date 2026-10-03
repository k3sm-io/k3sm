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
	"slices"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"

	netv1 "k3sm.io/apis/net/v1"
	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ephemeralUpdateRuntime is the fake runtimed with a programmable UpdatePod: it
// records every box it is sent and answers the queued response (success with the
// stored status when none is queued).
type ephemeralUpdateRuntime struct {
	*fakeRuntimeServer

	umu     sync.Mutex
	boxes   []*runtimev1.PodBox
	answers []*runtimev1.UpdatePodResponse
}

func (f *ephemeralUpdateRuntime) UpdatePod(_ context.Context, req *runtimev1.UpdatePodRequest) (*runtimev1.UpdatePodResponse, error) {
	f.umu.Lock()
	f.boxes = append(f.boxes, req.GetPod())
	var resp *runtimev1.UpdatePodResponse
	if len(f.answers) > 0 {
		resp, f.answers = f.answers[0], f.answers[1:]
	}
	f.umu.Unlock()
	if resp != nil {
		return resp, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return &runtimev1.UpdatePodResponse{Status: f.statusLocked(req.GetPod().GetPodId())}, nil
}

func (f *ephemeralUpdateRuntime) answer(resp *runtimev1.UpdatePodResponse) {
	f.umu.Lock()
	defer f.umu.Unlock()
	f.answers = append(f.answers, resp)
}

func (f *ephemeralUpdateRuntime) lastBox() *runtimev1.PodBox {
	f.umu.Lock()
	defer f.umu.Unlock()
	if len(f.boxes) == 0 {
		return nil
	}
	return f.boxes[len(f.boxes)-1]
}

// updateRefusal is an UpdatePodResponse refusing the update for reason.
func updateRefusal(code codes.Code, reason runtimev1.FailureReason, message string) *runtimev1.UpdatePodResponse {
	return &runtimev1.UpdatePodResponse{
		Error:         &rpcstatus.Status{Code: int32(code), Message: message},
		FailureReason: reason,
	}
}

// debugContainer is the ephemeral container `kubectl debug --image=native`
// appends.
func debugContainer(name, target string) corev1.EphemeralContainer {
	return corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:       name,
			Image:      "native",
			Command:    []string{"/bin/sh"},
			Args:       []string{"-c", "echo hi"},
			WorkingDir: "/tmp",
			Stdin:      true,
			TTY:        true,
			Env:        []corev1.EnvVar{{Name: "DEBUG", Value: "1"}},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "data", MountPath: "/data", ReadOnly: true},
			},
			ImagePullPolicy: corev1.PullIfNotPresent,
		},
		TargetContainerName: target,
	}
}

func ephemeralStatusByName(st *corev1.PodStatus, name string) *corev1.ContainerStatus {
	for i := range st.EphemeralContainerStatuses {
		if st.EphemeralContainerStatuses[i].Name == name {
			return &st.EphemeralContainerStatuses[i]
		}
	}
	return nil
}

// TestToPodBoxMapsEphemeralContainers is the provider gate for `kubectl debug`:
// the pod's ephemeral containers reach runtimed through the same translation as
// every other container, the two shapes this node refuses are reported on the
// container with the kubelet's CreateContainerConfigError, the runtime's
// ephemeral statuses are published, and none of it can decide the pod's phase,
// readiness or restarts, or fail the pod.
//
// Non-vacuity: before this change toPodBox never read spec.ephemeralContainers
// and toPodStatus never wrote ephemeralContainerStatuses, so `kubectl debug`
// was a silent no-op that waited forever; and UpdatePod returned every runtimed
// refusal to virtual-kubelet, which marks the pod ProviderFailed.
func TestToPodBoxMapsEphemeralContainers(t *testing.T) {
	t.Run("the box carries the ephemeral containers runtimed is asked to start", func(t *testing.T) {
		pod := runtimedPod("default", "dbg")
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{
			debugContainer("dbg", ""),
			debugContainer("tgt", "c0"),
		}
		box, err := toPodBox(pod, "10.0.0.5", "192.168.1.10", "/var/lib/k3sm/pods/uid-dbg", "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		ecs := box.GetEphemeralContainers()
		if len(ecs) != 1 || ecs[0].GetName() != "dbg" {
			t.Fatalf("ephemeral containers = %v, want exactly dbg (tgt sets targetContainerName and is never sent)", ecs)
		}
		dbg := ecs[0]
		if dbg.GetImage() != "native" || !slices.Equal(dbg.GetCommand(), []string{"/bin/sh"}) ||
			!slices.Equal(dbg.GetArgs(), []string{"-c", "echo hi"}) || dbg.GetWorkingDir() != "/tmp" ||
			!dbg.GetStdin() || !dbg.GetTty() ||
			dbg.GetImagePullPolicy() != runtimev1.ImagePullPolicy_IMAGE_PULL_POLICY_IF_NOT_PRESENT {
			t.Errorf("dbg = %v, want the spec's image, argv, workdir, stdin/tty and pull policy", dbg)
		}
		if vm := dbg.GetVolumeMounts(); len(vm) != 1 || vm[0].GetName() != "data" || vm[0].GetMountPath() != "/data" || !vm[0].GetReadOnly() {
			t.Errorf("dbg volume mounts = %v, want data at /data read-only", vm)
		}
		if dbg.GetRestartPolicy() != runtimev1.ContainerRestartPolicy_CONTAINER_RESTART_POLICY_UNSPECIFIED || len(dbg.GetPorts()) != 0 {
			t.Errorf("dbg carries a restart policy or ports the proto forbids on an ephemeral container: %v", dbg)
		}
		// The infra env every container of the pod gets (the bind-discipline
		// /32) lands on the debug container too, after its own.
		names := func(c *runtimev1.Container) []string {
			var out []string
			for _, e := range c.GetEnv() {
				out = append(out, e.GetName())
			}
			return out
		}
		for _, n := range names(box.GetContainers()[0]) {
			if !slices.Contains(names(dbg), n) {
				t.Errorf("dbg env lacks the pod-wide %s the regular container carries; dbg env = %v", n, names(dbg))
			}
		}
		if !slices.Contains(names(dbg), "DEBUG") {
			t.Errorf("dbg env = %v, want its own DEBUG", names(dbg))
		}
	})

	t.Run("a vm pod's ephemeral containers are never sent", func(t *testing.T) {
		pod := runtimedPod("default", "vmdbg")
		vm := "vm"
		pod.Spec.RuntimeClassName = &vm
		pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{debugContainer("dbg", "")}
		box, err := toPodBox(pod, "10.0.0.5", "10.0.0.5", "/var/lib/k3sm/pods/uid-vmdbg", "", netv1.DNSConfig{}, nil)
		if err != nil {
			t.Fatalf("toPodBox: %v", err)
		}
		if ecs := box.GetEphemeralContainers(); len(ecs) != 0 {
			t.Errorf("ephemeral containers = %v, want none: a vm pod cannot start one, and runtimed keeps no record of a refused append", ecs)
		}
	})

	running := func(pod *corev1.Pod, ephemeral ...*runtimev1.ContainerStatus) *runtimev1.PodStatus {
		return &runtimev1.PodStatus{
			PodId: string(pod.UID),
			Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			ContainerStatuses: []*runtimev1.ContainerStatus{{
				Name: "c0", Image: "registry/web:latest", Ready: true,
				State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(time.Unix(5000, 0))}},
			}},
			EphemeralContainerStatuses: ephemeral,
		}
	}
	terminated := func(name string, exit int32, reason string) *runtimev1.ContainerStatus {
		return &runtimev1.ContainerStatus{
			Name: name, Image: "native",
			State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{ExitCode: exit, Reason: reason}},
		}
	}
	vm := "vm"

	statusRows := []struct {
		name      string
		vm        bool
		ephemeral []corev1.EphemeralContainer
		reported  []*runtimev1.ContainerStatus
		// wantWaiting maps an ephemeral container to its expected
		// CreateContainerConfigError message; an empty message means Waiting
		// ContainerCreating (neither reported nor refused). wantExit maps a
		// reported terminated container to its exit code.
		wantWaiting map[string]string
		wantExit    map[string]int32
	}{
		{
			name:        "targetContainerName is refused with the stated message",
			ephemeral:   []corev1.EphemeralContainer{debugContainer("tgt", "c0")},
			wantWaiting: map[string]string{"tgt": msgEphemeralTargetUnsupported},
		},
		{
			name:        "a vm pod's ephemeral container is refused with runtimed's message",
			vm:          true,
			ephemeral:   []corev1.EphemeralContainer{debugContainer("dbg", "")},
			wantWaiting: map[string]string{"dbg": msgEphemeralOnVM},
		},
		{
			name:      "a reported ephemeral status round-trips",
			ephemeral: []corev1.EphemeralContainer{debugContainer("dbg", "")},
			reported:  []*runtimev1.ContainerStatus{terminated("dbg", 0, "Completed")},
			wantExit:  map[string]int32{"dbg": 0},
		},
		{
			name:      "a reported status wins over the derived one for its name",
			vm:        true,
			ephemeral: []corev1.EphemeralContainer{debugContainer("dbg", ""), debugContainer("dbg2", "")},
			reported:  []*runtimev1.ContainerStatus{terminated("dbg", 137, "ContainerStatusUnknown")},
			wantExit:  map[string]int32{"dbg": 137},
			wantWaiting: map[string]string{
				"dbg2": msgEphemeralOnVM,
			},
		},
		{
			name:        "an entry neither reported nor refused reads ContainerCreating",
			ephemeral:   []corev1.EphemeralContainer{debugContainer("dbg", ""), debugContainer("late", "")},
			reported:    []*runtimev1.ContainerStatus{terminated("dbg", 0, "Completed")},
			wantExit:    map[string]int32{"dbg": 0},
			wantWaiting: map[string]string{"late": ""},
		},
		{
			name:        "a native debug container and a refused one side by side",
			ephemeral:   []corev1.EphemeralContainer{debugContainer("dbg", ""), debugContainer("tgt", "c0")},
			reported:    []*runtimev1.ContainerStatus{terminated("dbg", 0, "Completed")},
			wantExit:    map[string]int32{"dbg": 0},
			wantWaiting: map[string]string{"tgt": msgEphemeralTargetUnsupported},
		},
	}
	for _, tt := range statusRows {
		t.Run("status: "+tt.name, func(t *testing.T) {
			pod := runtimedPod("default", "dbg")
			if tt.vm {
				pod.Spec.RuntimeClassName = &vm
			}
			pod.Spec.EphemeralContainers = tt.ephemeral
			st := toPodStatus(pod, running(pod, tt.reported...), "192.168.1.10", metav1.Now(), nil, transportReady)
			if got, want := len(st.EphemeralContainerStatuses), len(tt.wantWaiting)+len(tt.wantExit); got != want {
				t.Fatalf("ephemeral statuses = %d (%v), want %d", got, st.EphemeralContainerStatuses, want)
			}
			for name, msg := range tt.wantWaiting {
				cs := ephemeralStatusByName(st, name)
				if cs == nil || cs.State.Waiting == nil {
					t.Fatalf("%s: status = %+v, want Waiting", name, cs)
				}
				wantReason := reasonCreateContainerConfigError
				if msg == "" {
					wantReason = reasonContainerCreating
				}
				if cs.State.Waiting.Reason != wantReason || cs.State.Waiting.Message != msg {
					t.Errorf("%s: waiting = %+v, want {%s, %q}", name, cs.State.Waiting, wantReason, msg)
				}
				if cs.Ready || cs.Started == nil || *cs.Started {
					t.Errorf("%s: ready=%v started=%v, want a container that never started", name, cs.Ready, cs.Started)
				}
			}
			for name, exit := range tt.wantExit {
				cs := ephemeralStatusByName(st, name)
				if cs == nil || cs.State.Terminated == nil || cs.State.Terminated.ExitCode != exit {
					t.Errorf("%s: status = %+v, want Terminated exit %d as reported", name, cs, exit)
				}
			}
			if len(st.ContainerStatuses) != 1 || st.ContainerStatuses[0].Name != "c0" {
				t.Errorf("container statuses = %v, want only c0: an ephemeral status must not leak into them", st.ContainerStatuses)
			}
		})
	}

	// An ephemeral container's exit must not decide anything about the pod: the
	// phase, ContainersReady and Ready stay the mains' verdict, and the restart
	// authority never sees it, under either restart policy.
	for _, policy := range []corev1.RestartPolicy{corev1.RestartPolicyNever, corev1.RestartPolicyAlways} {
		t.Run("an ephemeral exit never feeds phase, readiness or restarts under "+string(policy), func(t *testing.T) {
			pod := crashPod("never-"+string(policy), policy)
			pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{debugContainer("dbg", "")}
			r, f, _, tr, _ := newCrashFake(t, pod)
			rs := running(pod, terminated("dbg", 1, "Error"))
			st := r.buildStatus(pod.DeepCopy(), tr, rs, nil)
			if st.Phase != corev1.PodRunning {
				t.Errorf("phase = %s, want Running", st.Phase)
			}
			for _, ct := range []corev1.PodConditionType{corev1.ContainersReady, corev1.PodReady} {
				if c := findPodCondition(st.Conditions, ct); c == nil || c.Status != corev1.ConditionTrue {
					t.Errorf("%s = %+v, want True: a debug container's exit is not the pod's readiness", ct, c)
				}
			}
			if cs := ephemeralStatusByName(&st, "dbg"); cs == nil || cs.State.Terminated == nil || cs.State.Terminated.ExitCode != 1 {
				t.Errorf("dbg = %+v, want its Terminated exit 1 published", cs)
			}
			tr.restartMu.Lock()
			pending := len(tr.restarts)
			tr.restartMu.Unlock()
			if pending != 0 {
				t.Errorf("restart bookkeeping = %d entries, want none for an ephemeral exit", pending)
			}
			if n, _ := f.restartState(); n != 0 {
				t.Errorf("RestartContainer called %d times, want 0", n)
			}
		})
	}

	// The UpdatePod contract: the append reaches runtimed; a refusal of the
	// append is the debug container's, never the pod's; the pod's status is
	// pushed at once; the Warning Event is recorded once per container.
	newUpdateProvider := func(t *testing.T) (*runtimedRuntime, *ephemeralUpdateRuntime, *record.FakeRecorder, chan *corev1.Pod) {
		t.Helper()
		f := &ephemeralUpdateRuntime{fakeRuntimeServer: newFakeRuntimeServer()}
		rec := record.NewFakeRecorder(64)
		r := newRuntimedWith(f, RuntimedConfig{
			NodeName: "n", NodeIP: "192.168.1.10",
			Root: t.TempDir(), PodLogsDir: t.TempDir(),
			Recorder: rec,
		}, nil, nil)
		pushed := make(chan *corev1.Pod, 16)
		r.mu.Lock()
		r.notify = func(p *corev1.Pod) { pushed <- p }
		r.mu.Unlock()
		return r, f, rec, pushed
	}
	waitPushed := func(t *testing.T, pushed chan *corev1.Pod, cond func(*corev1.Pod) bool) *corev1.Pod {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case p := <-pushed:
				if cond(p) {
					return p
				}
			case <-deadline:
				t.Fatal("no status push satisfied the condition")
				return nil
			}
		}
	}
	appendDebug := func(pod *corev1.Pod, ecs ...corev1.EphemeralContainer) *corev1.Pod {
		next := pod.DeepCopy()
		next.Spec.EphemeralContainers = append(next.Spec.EphemeralContainers, ecs...)
		return next
	}

	t.Run("update: a vm pod's append is derived, never sent, and later updates still apply", func(t *testing.T) {
		r, f, rec, pushed := newUpdateProvider(t)
		pod := crashPod("vmdbg", corev1.RestartPolicyNever)
		pod.Spec.RuntimeClassName = &vm
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		next := appendDebug(pod, debugContainer("dbg", ""))
		if err := r.UpdatePod(context.Background(), next); err != nil {
			t.Fatalf("UpdatePod = %v, want nil: an error marks the pod ProviderFailed (Failed under restartPolicy Never)", err)
		}
		if got := f.lastBox().GetEphemeralContainers(); len(got) != 0 {
			t.Errorf("box sent = %v, want no ephemeral container for a vm pod", got)
		}
		p := waitPushed(t, pushed, func(p *corev1.Pod) bool { return ephemeralStatusByName(&p.Status, "dbg") != nil })
		if cs := ephemeralStatusByName(&p.Status, "dbg"); cs.State.Waiting == nil || cs.State.Waiting.Message != msgEphemeralOnVM ||
			cs.State.Waiting.Reason != reasonCreateContainerConfigError {
			t.Errorf("pushed dbg = %+v, want Waiting CreateContainerConfigError %q", cs, msgEphemeralOnVM)
		}
		if p.Status.Phase != corev1.PodRunning {
			t.Errorf("pushed phase = %s, want Running", p.Status.Phase)
		}

		// A later label change on the debugged pod reaches runtimed and applies.
		relabeled := next.DeepCopy()
		relabeled.Labels = map[string]string{"touched": "yes"}
		if err := r.UpdatePod(context.Background(), relabeled); err != nil {
			t.Fatalf("UpdatePod (labels) = %v, want nil", err)
		}
		if got := f.lastBox(); got.GetLabels()["touched"] != "yes" || len(got.GetEphemeralContainers()) != 0 {
			t.Errorf("label update box = labels %v, ephemeral %v; want the new label and no ephemeral entry", got.GetLabels(), got.GetEphemeralContainers())
		}
		// Several status polls: the status path records no Event.
		for range 3 {
			st, err := r.GetPodStatus(context.Background(), "default", "vmdbg")
			if err != nil {
				t.Fatalf("GetPodStatus: %v", err)
			}
			if cs := ephemeralStatusByName(st, "dbg"); cs == nil || cs.State.Waiting == nil || cs.State.Waiting.Message != msgEphemeralOnVM {
				t.Errorf("polled dbg = %+v, want the derived vm refusal", cs)
			}
		}
		if n := countEvents(recordedEvents(rec.Events), msgEphemeralOnVM); n != 1 {
			t.Errorf("Warning Events carrying the vm refusal = %d, want exactly 1", n)
		}
	})

	t.Run("update: UNSUPPORTED is swallowed only on a pod that lists ephemeral containers", func(t *testing.T) {
		r, f, _, _ := newUpdateProvider(t)
		pod := crashPod("unsup", corev1.RestartPolicyAlways)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		relabeled := pod.DeepCopy()
		relabeled.Labels = map[string]string{"touched": "yes"}
		f.answer(updateRefusal(codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED, "unsupported"))
		if err := r.UpdatePod(context.Background(), relabeled); err == nil {
			t.Error("UpdatePod = nil, want an UNSUPPORTED on a pod with no ephemeral container returned")
		}
		debugged := appendDebug(relabeled, debugContainer("dbg", ""))
		if err := r.UpdatePod(context.Background(), debugged); err != nil {
			t.Fatalf("UpdatePod (append): %v", err)
		}
		again := debugged.DeepCopy()
		again.Labels["touched"] = "twice"
		f.answer(updateRefusal(codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_UNSUPPORTED, "unsupported"))
		if err := r.UpdatePod(context.Background(), again); err != nil {
			t.Errorf("UpdatePod = %v, want nil: UNSUPPORTED on a pod that lists ephemeral containers is the append backstop", err)
		}
	})

	t.Run("update: an underived refusal of the append reads ContainerCreating and carries an Event", func(t *testing.T) {
		r, f, rec, pushed := newUpdateProvider(t)
		pod := crashPod("refused", corev1.RestartPolicyNever)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		const why = "pod uid-refused has terminated; an ephemeral container cannot be added"
		f.answer(updateRefusal(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE, why))
		if err := r.UpdatePod(context.Background(), appendDebug(pod, debugContainer("dbg", ""))); err != nil {
			t.Fatalf("UpdatePod = %v, want nil for a refusal that concerns only the append", err)
		}
		p := waitPushed(t, pushed, func(p *corev1.Pod) bool { return ephemeralStatusByName(&p.Status, "dbg") != nil })
		if cs := ephemeralStatusByName(&p.Status, "dbg"); cs.State.Waiting == nil || cs.State.Waiting.Reason != reasonContainerCreating {
			t.Errorf("pushed dbg = %+v, want Waiting ContainerCreating", cs)
		}
		if n := countEvents(recordedEvents(rec.Events), why); n != 1 {
			t.Errorf("Warning Events carrying runtimed's refusal = %d, want 1", n)
		}
	})

	t.Run("update: targetContainerName is not forwarded and is reported once", func(t *testing.T) {
		r, f, rec, pushed := newUpdateProvider(t)
		pod := crashPod("tgt", corev1.RestartPolicyAlways)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		next := appendDebug(pod, debugContainer("tgt", "c0"))
		if err := r.UpdatePod(context.Background(), next); err != nil {
			t.Fatalf("UpdatePod: %v", err)
		}
		if got := f.lastBox().GetEphemeralContainers(); len(got) != 0 {
			t.Errorf("box sent = %v, want no ephemeral container (tgt names a target)", got)
		}
		p := waitPushed(t, pushed, func(p *corev1.Pod) bool { return ephemeralStatusByName(&p.Status, "tgt") != nil })
		if cs := ephemeralStatusByName(&p.Status, "tgt"); cs.State.Waiting == nil || cs.State.Waiting.Message != msgEphemeralTargetUnsupported {
			t.Errorf("pushed tgt = %+v, want Waiting %q", cs, msgEphemeralTargetUnsupported)
		}
		// A second append of a different container is a new UpdatePod; the
		// already-reported tgt must not be reported again.
		again := appendDebug(next, debugContainer("dbg", ""))
		if err := r.UpdatePod(context.Background(), again); err != nil {
			t.Fatalf("UpdatePod (second append): %v", err)
		}
		if got := f.lastBox().GetEphemeralContainers(); len(got) != 1 || got[0].GetName() != "dbg" {
			t.Errorf("box sent = %v, want only dbg", got)
		}
		if n := countEvents(recordedEvents(rec.Events), msgEphemeralTargetUnsupported); n != 1 {
			t.Errorf("Warning Events carrying the target refusal = %d, want exactly 1", n)
		}
	})

	t.Run("update: a refusal of anything but the append still fails the update", func(t *testing.T) {
		r, f, _, _ := newUpdateProvider(t)
		pod := crashPod("immutable", corev1.RestartPolicyAlways)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		changed := pod.DeepCopy()
		changed.Spec.Containers[0].Command = []string{"/other"}
		f.answer(updateRefusal(codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE, "container set is not updatable in place"))
		if err := r.UpdatePod(context.Background(), changed); err == nil {
			t.Error("UpdatePod = nil, want the NOT_UPDATABLE refusal returned for a non-ephemeral change")
		}
	})
}
