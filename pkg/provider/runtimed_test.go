package provider

import (
	"context"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// fakeRuntimeServer is an in-memory runtimev1.RuntimeServer for provider tests:
// it records created pods and renders a Running status, with no real Seatbelt,
// image pull, or process spawn. It lets the runtimedRuntime translation +
// watch/backstop wiring be tested at the seam without privilege (the standards'
// "fake at seams" rule); the real confinement is an e2e concern.
type fakeRuntimeServer struct {
	runtimev1.UnimplementedRuntimeServer

	mu      sync.Mutex
	created map[string]*runtimev1.PodBox
	started time.Time
}

func newFakeRuntimeServer() *fakeRuntimeServer {
	return &fakeRuntimeServer{created: map[string]*runtimev1.PodBox{}, started: time.Unix(5000, 0)}
}

func (f *fakeRuntimeServer) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	box := req.GetPod()
	f.created[box.GetPodId()] = box
	return &runtimev1.CreatePodResponse{Status: f.statusLocked(box.GetPodId())}, nil
}

func (f *fakeRuntimeServer) DeletePod(_ context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.created, req.GetPodId())
	return &runtimev1.DeletePodResponse{}, nil
}

func (f *fakeRuntimeServer) GetPodStatus(_ context.Context, req *runtimev1.GetPodStatusRequest) (*runtimev1.GetPodStatusResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.created[req.GetPodId()]; !ok {
		return &runtimev1.GetPodStatusResponse{
			Error: &rpcstatus.Status{Code: int32(codes.NotFound), Message: "not found"},
		}, nil
	}
	return &runtimev1.GetPodStatusResponse{Status: f.statusLocked(req.GetPodId())}, nil
}

// WatchPodStatus emits the current snapshot for every tracked pod, then blocks
// until the stream context ends (the fake never pushes further transitions).
func (f *fakeRuntimeServer) WatchPodStatus(_ *runtimev1.WatchPodStatusRequest, stream grpc.ServerStreamingServer[runtimev1.PodStatusEvent]) error {
	f.mu.Lock()
	var evs []*runtimev1.PodStatusEvent
	for id := range f.created {
		evs = append(evs, &runtimev1.PodStatusEvent{
			Type:   runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_ADDED,
			Status: f.statusLocked(id),
		})
	}
	f.mu.Unlock()
	for _, ev := range evs {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// statusLocked renders a Running status whose StartTime regenerates each call
// (mimicking runtimed's lossy renderer) so the provider's STABLE-StartTime
// handling is actually exercised.
func (f *fakeRuntimeServer) statusLocked(id string) *runtimev1.PodStatus {
	return &runtimev1.PodStatus{
		PodId: id,
		Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
		PodIp: "10.0.0.5",
		// Deliberately "now" each call — the provider must NOT surface this.
		StartTime: timestamppb.New(time.Now()),
		ContainerStatuses: []*runtimev1.ContainerStatus{{
			Name:  "c0",
			Image: "web",
			Ready: true,
			State: &runtimev1.ContainerState{
				Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(f.started)},
			},
		}},
	}
}

func newRuntimedFake(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer) {
	t.Helper()
	f := newFakeRuntimeServer()
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir()}, nil)
	return r, f
}

func runtimedPod(ns, name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID("uid-" + name)},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c0", Image: "registry/web:latest", Command: []string{"/web"}}},
		},
	}
}

// TestRuntimedCreateRunning is the unit-level proof of M1.3: a pod handed to the
// runtimed-backed provider comes back Running with the gate-filling PodBox sent
// to the runtime.
func TestRuntimedCreateRunning(t *testing.T) {
	r, f := newRuntimedFake(t)
	pod := runtimedPod("default", "web")
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	st, err := r.GetPodStatus(context.Background(), "default", "web")
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if st.Phase != corev1.PodRunning {
		t.Fatalf("phase = %s, want Running", st.Phase)
	}
	if st.HostIP != "192.168.1.10" {
		t.Errorf("HostIP = %q, want the node IP", st.HostIP)
	}

	box := f.created["uid-web"]
	if box.GetSandboxProfile() == nil || box.GetSignaturePolicy() == runtimev1.SignaturePolicy_SIGNATURE_POLICY_UNSPECIFIED {
		t.Error("PodBox sent to runtime did not fill the fail-closed gate")
	}
}

// TestRuntimedStableStartTime verifies the StartTime is stable across snapshots
// even though the fake regenerates it every call.
func TestRuntimedStableStartTime(t *testing.T) {
	r, _ := newRuntimedFake(t)
	pod := runtimedPod("default", "web")
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	st1, _ := r.GetPodStatus(context.Background(), "default", "web")
	time.Sleep(10 * time.Millisecond)
	st2, _ := r.GetPodStatus(context.Background(), "default", "web")
	if st1.StartTime == nil || st2.StartTime == nil {
		t.Fatal("StartTime must be set")
	}
	if !st1.StartTime.Equal(st2.StartTime) {
		t.Errorf("StartTime changed between snapshots: %v vs %v (must be stable)", st1.StartTime, st2.StartTime)
	}
}

// TestRuntimedGetPodNotFound confirms an unknown pod surfaces NotFound.
func TestRuntimedGetPodNotFound(t *testing.T) {
	r, _ := newRuntimedFake(t)
	if _, err := r.GetPodStatus(context.Background(), "default", "nope"); err == nil {
		t.Fatal("want error for unknown pod")
	}
}

// TestRuntimedWatchFires verifies Watch drives the callback off the runtime
// stream (the snapshot emitted on subscribe).
func TestRuntimedWatchFires(t *testing.T) {
	r, _ := newRuntimedFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := r.CreatePod(ctx, runtimedPod("default", "web")); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	got := make(chan *corev1.Pod, 8)
	r.Watch(ctx, func(p *corev1.Pod) { got <- p })

	select {
	case p := <-got:
		if p.Name != "web" {
			t.Fatalf("watch delivered pod %q, want web", p.Name)
		}
		if p.Status.Phase != corev1.PodRunning {
			t.Fatalf("watched pod phase = %s, want Running", p.Status.Phase)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watch callback did not fire within 3s")
	}
}

// TestRuntimedDeleteForgets confirms DeletePod is idempotent and forgets the pod.
func TestRuntimedDeleteForgets(t *testing.T) {
	r, _ := newRuntimedFake(t)
	pod := runtimedPod("default", "web")
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	if err := r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod #1: %v", err)
	}
	if err := r.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod #2 (idempotent): %v", err)
	}
	if _, err := r.GetPodStatus(context.Background(), "default", "web"); err == nil {
		t.Fatal("want NotFound after delete")
	}
}
