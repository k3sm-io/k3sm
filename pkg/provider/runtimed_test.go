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
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// fakeRuntimeServer is an in-memory runtimev1.RuntimeServer for provider tests:
// it records created pods and renders a Running status, with no real Seatbelt,
// image pull, or process spawn. It lets the runtimedRuntime translation +
// watch/backstop wiring be tested at the seam without privilege (the standards'
// "fake at seams" rule); the real confinement is an e2e concern.
type fakeRuntimeServer struct {
	runtimev1.UnimplementedRuntimeServer

	mu        sync.Mutex
	created   map[string]*runtimev1.PodBox
	started   time.Time
	footprint map[string]uint64 // pod id -> working-set bytes (M2.3 metrics)
	lastGrace int64             // grace_period_seconds of the last DeletePod (M2.3)
	gotSA     string            // ServiceAccount bound on the last CreatePod ctx (M2.4)
}

func newFakeRuntimeServer() *fakeRuntimeServer {
	return &fakeRuntimeServer{created: map[string]*runtimev1.PodBox{}, footprint: map[string]uint64{}, started: time.Unix(5000, 0)}
}

// PodMetrics satisfies the provider's podMetricsSource so StatsSummary is testable
// without a real proc_pid_rusage sampler. A pod with no recorded footprint reports
// ok=false (no sampler — the unlimited-pod case).
func (f *fakeRuntimeServer) PodMetrics(podID string) (runtimed.PodMetrics, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ws, ok := f.footprint[podID]
	if !ok {
		return runtimed.PodMetrics{}, false
	}
	return runtimed.PodMetrics{PodID: podID, WorkingSetBytes: ws, Timestamp: time.Unix(6000, 0)}, true
}

func (f *fakeRuntimeServer) CreatePod(ctx context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	box := req.GetPod()
	f.created[box.GetPodId()] = box
	// Record the ServiceAccount the provider bound to the ctx so the M2.4
	// per-pod SA-token binding is observable at the runtime seam.
	f.gotSA = serviceAccountFromContext(ctx)
	return &runtimev1.CreatePodResponse{Status: f.statusLocked(box.GetPodId())}, nil
}

func (f *fakeRuntimeServer) DeletePod(_ context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastGrace = req.GetGracePeriodSeconds()
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
	r := newRuntimedWith(f, RuntimedConfig{NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir()}, nil, nil)
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

// TestRuntimedStatsSummaryFootprint is the M2.3-a1 proof that GetStatsSummary
// reports the runtimed working-set footprint: a fake PodMetrics value flows into
// the Summary API the kubelet serves (kubectl top reads it).
func TestRuntimedStatsSummaryFootprint(t *testing.T) {
	r, f := newRuntimedFake(t)
	pod := runtimedPod("default", "web")
	if err := r.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	f.mu.Lock()
	f.footprint["uid-web"] = 256 << 20 // 256 MiB
	f.mu.Unlock()

	summary, err := r.StatsSummary(context.Background())
	if err != nil {
		t.Fatalf("StatsSummary: %v", err)
	}
	if summary.Node.NodeName != "n" {
		t.Errorf("node name = %q, want n", summary.Node.NodeName)
	}
	if len(summary.Pods) != 1 {
		t.Fatalf("want 1 pod stat, got %d", len(summary.Pods))
	}
	ps := summary.Pods[0]
	if ps.PodRef.Name != "web" || ps.PodRef.Namespace != "default" {
		t.Errorf("podRef = %+v, want web/default", ps.PodRef)
	}
	if ps.Memory == nil || ps.Memory.WorkingSetBytes == nil || *ps.Memory.WorkingSetBytes != 256<<20 {
		t.Fatalf("pod memory working set = %v, want %d", ps.Memory, 256<<20)
	}
	// The pod-level footprint is attributed to the first container so a
	// container-summing consumer (metrics-server) gets the right total.
	if len(ps.Containers) != 1 || ps.Containers[0].Memory == nil || *ps.Containers[0].Memory.WorkingSetBytes != 256<<20 {
		t.Errorf("container memory not attributed to first container: %+v", ps.Containers)
	}
}

// TestRuntimedStatsSummaryUnsampled confirms a pod without a footprint (no memory
// limit ⇒ no sampler) is omitted from the summary rather than reported as zero.
func TestRuntimedStatsSummaryUnsampled(t *testing.T) {
	r, _ := newRuntimedFake(t)
	if err := r.CreatePod(context.Background(), runtimedPod("default", "web")); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	summary, err := r.StatsSummary(context.Background())
	if err != nil {
		t.Fatalf("StatsSummary: %v", err)
	}
	if len(summary.Pods) != 0 {
		t.Errorf("want no pod stats for an unsampled pod, got %d", len(summary.Pods))
	}
}

// TestRuntimedDeleteGrace is the M2.3-a1 proof for the SIGTERM→SIGKILL grace: the
// pod's terminationGracePeriodSeconds is passed through to runtimed, and the k8s
// 30s default is applied when unset (runtimed treats 0 as immediate-kill).
func TestRuntimedDeleteGrace(t *testing.T) {
	tests := []struct {
		name      string
		grace     *int64
		wantGrace int64
	}{
		{"unset defaults to 30", nil, 30},
		{"explicit 10 passed through", ptr(int64(10)), 10},
		{"explicit 0 passed through (immediate)", ptr(int64(0)), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, f := newRuntimedFake(t)
			pod := runtimedPod("default", "web")
			pod.Spec.TerminationGracePeriodSeconds = tt.grace
			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod: %v", err)
			}
			if err := r.DeletePod(context.Background(), pod); err != nil {
				t.Fatalf("DeletePod: %v", err)
			}
			f.mu.Lock()
			got := f.lastGrace
			f.mu.Unlock()
			if got != tt.wantGrace {
				t.Errorf("DeletePod grace = %d, want %d", got, tt.wantGrace)
			}
		})
	}
}
