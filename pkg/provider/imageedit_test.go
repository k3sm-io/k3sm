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
	"strings"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

const (
	imageEditReason = "ImageEditNotApplied"
	imageA          = "registry.example/web:a"
	imageB          = "registry.example/web:b"
	imageC          = "registry.example/web:c"
)

// inPlaceRuntime answers the way runtimed does for a pod it holds. UpdatePod
// applies labels and annotations only (runtimed/pkg/runtime/server.go), so every
// status keeps reporting the image the container was created from, with the
// image_pull outcome stamped at creation. StartContainer on a container that has
// a process is refused: Unimplemented for a vm pod (startcontainer.go), and
// NOT_UPDATABLE for a native one.
type inPlaceRuntime struct {
	*fakeRuntimeServer

	imu     sync.Mutex
	vm      bool
	initial map[string]string // init container name -> image at create
	main    map[string]string // main container name -> image at create
	updates int
}

func (f *inPlaceRuntime) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	resp, err := f.fakeRuntimeServer.CreatePod(ctx, req)
	if err != nil || resp.GetError().GetCode() != 0 {
		return resp, err
	}
	f.imu.Lock()
	defer f.imu.Unlock()
	f.initial, f.main = map[string]string{}, map[string]string{}
	for _, c := range req.GetPod().GetInitContainers() {
		f.initial[c.GetName()] = c.GetImage()
	}
	for _, c := range req.GetPod().GetContainers() {
		f.main[c.GetName()] = c.GetImage()
	}
	return &runtimev1.CreatePodResponse{Status: f.status(req.GetPod().GetPodId())}, nil
}

func (f *inPlaceRuntime) status(id string) *runtimev1.PodStatus {
	entry := func(name, image string) *runtimev1.ContainerStatus {
		cs := rtRunning(name)
		cs.Image = image
		cs.ImagePull = &runtimev1.ImagePullOutcome{Pulled: true, Duration: durationpb.New(time.Second)}
		return cs
	}
	st := &runtimev1.PodStatus{PodId: id, Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}
	for name, image := range f.initial {
		st.InitContainerStatuses = append(st.InitContainerStatuses, entry(name, image))
	}
	for name, image := range f.main {
		st.ContainerStatuses = append(st.ContainerStatuses, entry(name, image))
	}
	return st
}

func (f *inPlaceRuntime) UpdatePod(_ context.Context, req *runtimev1.UpdatePodRequest) (*runtimev1.UpdatePodResponse, error) {
	f.imu.Lock()
	defer f.imu.Unlock()
	f.updates++
	return &runtimev1.UpdatePodResponse{Status: f.status(req.GetPod().GetPodId())}, nil
}

func (f *inPlaceRuntime) GetPodStatus(ctx context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	f.imu.Lock()
	defer f.imu.Unlock()
	if f.main == nil {
		return f.fakeRuntimeServer.GetPodStatus(ctx, req)
	}
	return &runtimev1.GetPodStatusResponse{Status: f.status(req.GetPodId())}, nil
}

func (f *inPlaceRuntime) StartContainer(ctx context.Context, req *runtimev1.StartContainerRequest) (*runtimev1.StartContainerResponse, error) {
	if _, err := f.fakeRuntimeServer.StartContainer(ctx, req); err != nil {
		return nil, err
	}
	f.imu.Lock()
	defer f.imu.Unlock()
	code, reason := codes.FailedPrecondition, runtimev1.FailureReason_FAILURE_REASON_NOT_UPDATABLE
	if f.vm {
		code, reason = codes.Unimplemented, runtimev1.FailureReason_FAILURE_REASON_INTERNAL
	}
	return &runtimev1.StartContainerResponse{
		Error:         &rpcstatus.Status{Code: int32(code), Message: "refused"},
		FailureReason: reason,
	}, nil
}

func (f *inPlaceRuntime) updateTally() int {
	f.imu.Lock()
	defer f.imu.Unlock()
	return f.updates
}

// imageEditProvider wires a provider to an inPlaceRuntime.
func imageEditProvider(t *testing.T, vm bool) (*runtimedRuntime, *inPlaceRuntime, *record.FakeRecorder) {
	t.Helper()
	f := &inPlaceRuntime{fakeRuntimeServer: newFakeRuntimeServer(), vm: vm}
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10",
		Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec,
	}, nil, nil)
	return r, f, rec
}

// imageEditPod is a pod with two mains and one init container on imageA; vm
// selects the vm RuntimeClass.
func imageEditPod(name string, vm bool) *corev1.Pod {
	pod := crashPod(name, corev1.RestartPolicyAlways)
	pod.Spec.Containers[0].Image = imageA
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "c1", Image: imageA, Command: []string{"/app"}})
	pod.Spec.InitContainers = []corev1.Container{{Name: "i0", Image: imageA, Command: []string{"/app"}}}
	if vm {
		class := "vm"
		pod.Spec.RuntimeClassName = &class
	}
	return pod
}

// withImage returns a copy of pod with the named container on image.
func withImage(pod *corev1.Pod, container, image string) *corev1.Pod {
	out := pod.DeepCopy()
	for _, cs := range [][]corev1.Container{out.Spec.InitContainers, out.Spec.Containers} {
		for i := range cs {
			if cs[i].Name == container {
				cs[i].Image = image
			}
		}
	}
	return out
}

// mustUpdate applies an edit: the update is never an error, because an error
// marks the running pod ProviderFailed, and Failed outright under
// restartPolicy Never.
func mustUpdate(t *testing.T, r *runtimedRuntime, pod *corev1.Pod) {
	t.Helper()
	if err := r.UpdatePod(context.Background(), pod); err != nil {
		t.Fatalf("UpdatePod = %v, want nil: an error fails a pod that is running", err)
	}
}

// eventsWith drains rec and returns the events containing substr.
func eventsWith(rec *record.FakeRecorder, substr string) (matched, all []string) {
	for {
		select {
		case e := <-rec.Events:
			all = append(all, e)
			if strings.Contains(e, substr) {
				matched = append(matched, e)
			}
		default:
			return matched, all
		}
	}
}

// reportedImage reads a container's status image through the provider's own
// status path, the one kubectl sees.
func reportedImage(t *testing.T, r *runtimedRuntime, pod *corev1.Pod, container string) string {
	t.Helper()
	st, err := r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	for _, css := range [][]corev1.ContainerStatus{st.InitContainerStatuses, st.ContainerStatuses} {
		for _, cs := range css {
			if cs.Name == container {
				return cs.Image
			}
		}
	}
	t.Fatalf("status has no container %s", container)
	return ""
}

// TestRunningVMPodImageEditIsNotSilent pins what an in-place image edit does on
// a vm pod the runtime holds. The guest cannot take a new image in place, so the
// edit is reported as a Warning naming the container and both images, and the
// container status keeps naming what runs.
//
// Non-vacuity: the provider forwarded the edit to UpdatePod, runtimed answered
// OK having applied only labels and annotations, and virtual-kubelet recorded
// its own "updated successfully". Nothing named the edit that did not happen,
// and the Pulling and Pulled events that followed claimed the new image had been
// fetched.
func TestRunningVMPodImageEditIsNotSilent(t *testing.T) {
	t.Run("the edit is warned once, and the status keeps naming what runs", func(t *testing.T) {
		r, f, rec := imageEditProvider(t, true)
		pod := imageEditPod("running", true)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		tr := r.trackByID(string(pod.UID))
		eventsWith(rec, imageEditReason)

		edited := withImage(pod, "c0", imageB)
		mustUpdate(t, r, edited)
		if n := f.updateTally(); n != 1 {
			t.Errorf("UpdatePod RPCs = %d, want 1: labels in the same edit still apply", n)
		}
		warnings, all := eventsWith(rec, imageEditReason)
		if len(warnings) != 1 {
			t.Fatalf("%s events = %v, want exactly 1 (all events: %v)", imageEditReason, warnings, all)
		}
		for _, want := range []string{corev1.EventTypeWarning, `"c0"`, imageA, imageB} {
			if !strings.Contains(warnings[0], want) {
				t.Errorf("event %q does not name %q", warnings[0], want)
			}
		}
		if got := reportedImage(t, r, edited, "c0"); got != imageA {
			t.Errorf("containerStatuses[c0].image = %q, want %q, the image that runs", got, imageA)
		}
		if got, err := r.GetPod(context.Background(), edited.Namespace, edited.Name); err != nil || got.Spec.Containers[0].Image != imageB {
			t.Errorf("GetPod image = %v (err %v), want the edited spec: anything else has virtual-kubelet send the update again", got, err)
		}

		// The attempt the edit would have started is synchronous to observe: a
		// filed schedule is what runs the false Pulling and Pulled.
		tr.restartMu.Lock()
		schedule, window := tr.pulls[imageB], tr.pulling["c0"]
		tr.restartMu.Unlock()
		if schedule != nil || (window != nil && window.image == imageB) {
			t.Errorf("pull schedule = %+v, open attempt = %+v, want neither for %s: a running guest fetches nothing for the edit", schedule, window, imageB)
		}
		_, after := eventsWith(rec, imageEditReason)
		for _, e := range append(all, after...) {
			if strings.Contains(e, imageB) && (strings.Contains(e, reasonPulling) || strings.Contains(e, reasonPulled)) {
				t.Errorf("event %q claims a pull of the edited image", e)
			}
		}

		// A later update that does not touch the image does not repeat it.
		relabeled := edited.DeepCopy()
		relabeled.Labels = map[string]string{"touched": "yes"}
		mustUpdate(t, r, relabeled)
		if again, _ := eventsWith(rec, imageEditReason); len(again) != 0 {
			t.Errorf("a label update repeated the warning: %v", again)
		}
	})

	t.Run("only the edited container is named, init containers included", func(t *testing.T) {
		for _, container := range []string{"c1", "i0"} {
			r, _, rec := imageEditProvider(t, true)
			pod := imageEditPod("one-of-"+container, true)
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			eventsWith(rec, imageEditReason)
			mustUpdate(t, r, withImage(pod, container, imageB))
			warnings, _ := eventsWith(rec, imageEditReason)
			if len(warnings) != 1 || !strings.Contains(warnings[0], `"`+container+`"`) {
				t.Errorf("edit of %s: events = %v, want one naming only it", container, warnings)
			}
		}
	})

	t.Run("the old image is the one running, not the one last named", func(t *testing.T) {
		r, _, rec := imageEditProvider(t, true)
		pod := imageEditPod("two-edits", true)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		eventsWith(rec, imageEditReason)
		first := withImage(pod, "c0", imageB)
		mustUpdate(t, r, first)
		eventsWith(rec, imageEditReason)
		second := withImage(first, "c0", imageC)
		mustUpdate(t, r, second)
		warnings, _ := eventsWith(rec, imageEditReason)
		if len(warnings) != 1 || !strings.Contains(warnings[0], imageA) || !strings.Contains(warnings[0], imageC) || strings.Contains(warnings[0], imageB) {
			t.Errorf("events = %v, want one naming %s and %s and not %s", warnings, imageA, imageC, imageB)
		}

		// Editing back to what runs leaves nothing to warn about.
		mustUpdate(t, r, withImage(second, "c0", imageA))
		if back, _ := eventsWith(rec, imageEditReason); len(back) != 0 {
			t.Errorf("an edit back to the running image warned: %v", back)
		}
	})

	t.Run("a parked vm pod takes the edit at its retry and is not warned", func(t *testing.T) {
		r, f, rec := imageEditProvider(t, true)
		pod := imageEditPod("parked", true)
		f.pushCreate(createRefusal(runtimev1.FailureReason_FAILURE_REASON_INVALID_IMAGE_NAME,
			`container c0: parse image "`+imageA+`": invalid reference format`))
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod = %v, want the pod parked", err)
		}
		tr := r.trackByID(string(pod.UID))
		if tr == nil || tr.parkedFailure() == nil {
			t.Fatal("setup: the pod is not parked, so the update path under test is not reached")
		}
		edited := pod.DeepCopy()
		edited.Spec.InitContainers[0].Image = imageB
		edited.Spec.Containers[0].Image = imageB
		edited.Spec.Containers[1].Image = imageB
		mustUpdate(t, r, edited)
		waitRestart(t, "the retry's CreatePod", func() bool { return f.createCount() == 2 })
		waitRestart(t, "the park to clear", func() bool { return tr.parkedFailure() == nil })
		if got := f.createdBox(string(pod.UID)).GetContainers()[0].GetImage(); got != imageB {
			t.Errorf("the retry created image %q, want the edited %q", got, imageB)
		}
		if warnings, _ := eventsWith(rec, imageEditReason); len(warnings) != 0 {
			t.Errorf("a parked pod's edit, which applies, was warned: %v", warnings)
		}
	})

	t.Run("a native pod keeps its path", func(t *testing.T) {
		r, f, rec := imageEditProvider(t, false)
		pod := imageEditPod("native", false)
		if err := r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		edited := withImage(pod, "c0", imageB)
		mustUpdate(t, r, edited)
		waitRestart(t, "the re-keyed attempt", func() bool {
			f.fakeRuntimeServer.mu.Lock()
			defer f.fakeRuntimeServer.mu.Unlock()
			return f.startCalls == 1
		})
		if got := reportedImage(t, r, edited, "c0"); got != imageA {
			t.Errorf("containerStatuses[c0].image = %q, want %q, the image that runs", got, imageA)
		}
		if warnings, _ := eventsWith(rec, imageEditReason); len(warnings) != 0 {
			t.Errorf("native events = %v, want none: this path is not changed here", warnings)
		}
	})
}
