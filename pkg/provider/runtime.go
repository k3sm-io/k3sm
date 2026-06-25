package provider

import (
	"context"
	"io"

	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	corev1 "k8s.io/api/core/v1"
)

// Runtime is the consumer-side seam between the Virtual Kubelet provider and a
// pod-execution backend. The provider (the VK adapter) drives the pod lifecycle
// and renders Node/Pod status; the Runtime turns a corev1.Pod into running work
// on this Mac and reports its status back.
//
// Two implementations satisfy it: HostProcess (the M0 native-process runtime,
// no isolation) and runtimedRuntime (the M1 in-process runtimed image runtime —
// OCI pull → clonefile → ad-hoc-sign → Seatbelt confine). Defining the interface
// here, at the consumer, keeps the provider decoupled from either backend and
// lets the server pick one behind a flag.
//
// CreatePod must be idempotent on (namespace, name); DeletePod must tolerate
// repeated calls (the pod may already be gone). GetPodStatus returns an
// errdefs.NotFound error for an unknown pod so callers can distinguish "gone".
type Runtime interface {
	// CreatePod starts every container of pod and begins tracking its status.
	CreatePod(ctx context.Context, pod *corev1.Pod) error
	// UpdatePod applies an in-place spec change (best-effort; may be a no-op).
	UpdatePod(ctx context.Context, pod *corev1.Pod) error
	// DeletePod stops the pod's processes and forgets it.
	DeletePod(ctx context.Context, pod *corev1.Pod) error
	// GetPodStatus returns the current status of the named pod.
	GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error)
	// GetPods returns the pods this runtime is tracking.
	GetPods(ctx context.Context) ([]*corev1.Pod, error)
	// GetContainerLogs returns a container's combined stdout/stderr.
	GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (io.ReadCloser, error)
	// Watch delivers a full corev1.Pod (with .Status) on every status change for
	// the lifetime of ctx. The implementation runs cb OUTSIDE any held lock (the
	// VK re-entrancy rule) and resyncs the current state when its underlying
	// stream breaks, so a missed event is always recovered.
	Watch(ctx context.Context, cb func(*corev1.Pod))
}
