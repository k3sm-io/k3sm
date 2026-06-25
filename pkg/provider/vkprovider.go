package provider

import (
	"context"
	"io"

	dto "github.com/prometheus/client_model/go"
	"github.com/virtual-kubelet/virtual-kubelet/errdefs"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	"github.com/virtual-kubelet/virtual-kubelet/node/nodeutil"
	corev1 "k8s.io/api/core/v1"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"
)

// VKProvider adapts any Runtime into the full Virtual Kubelet provider contract
// (nodeutil.Provider). It is the single seam the VK node talks to, so swapping
// the pod-execution backend (HostProcess vs runtimed) is a one-line choice at
// startup with no change to the node wiring.
//
// The lifecycle/logs methods delegate straight to the Runtime; NotifyPods wires
// the Runtime's status watch to the VK callback. RunInContainer and the stats
// methods are runtime-specific and reported as not-implemented here unless the
// Runtime also exposes them (HostProcess implements its own GetContainerLogs and
// stats directly when used unwrapped — see the M0 node path).
type VKProvider struct {
	rt       Runtime
	nodeName string
}

// NewVKProvider returns a VKProvider over rt. nodeName is reported in the stats
// summary.
func NewVKProvider(rt Runtime, nodeName string) *VKProvider {
	return &VKProvider{rt: rt, nodeName: nodeName}
}

// Compile-time check that the adapter satisfies the full VK provider contract.
var _ nodeutil.Provider = (*VKProvider)(nil)

// CreatePod delegates to the Runtime.
func (v *VKProvider) CreatePod(ctx context.Context, pod *corev1.Pod) error {
	return v.rt.CreatePod(ctx, pod)
}

// UpdatePod delegates to the Runtime.
func (v *VKProvider) UpdatePod(ctx context.Context, pod *corev1.Pod) error {
	return v.rt.UpdatePod(ctx, pod)
}

// DeletePod delegates to the Runtime.
func (v *VKProvider) DeletePod(ctx context.Context, pod *corev1.Pod) error {
	return v.rt.DeletePod(ctx, pod)
}

// GetPod returns the named pod from the Runtime, NotFound if it is unknown.
func (v *VKProvider) GetPod(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	pods, err := v.rt.GetPods(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range pods {
		if p.Namespace == namespace && p.Name == name {
			return p, nil
		}
	}
	return nil, errdefs.NotFoundf("pod %q not found", namespace+"/"+name)
}

// GetPodStatus delegates to the Runtime.
func (v *VKProvider) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	return v.rt.GetPodStatus(ctx, namespace, name)
}

// GetPods delegates to the Runtime.
func (v *VKProvider) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	return v.rt.GetPods(ctx)
}

// NotifyPods wires the Runtime's status watch to the VK status callback.
func (v *VKProvider) NotifyPods(ctx context.Context, cb func(*corev1.Pod)) {
	v.rt.Watch(ctx, cb)
}

// GetContainerLogs delegates to the Runtime.
func (v *VKProvider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts api.ContainerLogOpts) (io.ReadCloser, error) {
	return v.rt.GetContainerLogs(ctx, namespace, podName, containerName, opts)
}

// RunInContainer is not implemented for M1 (exec lands with the M2 daemon
// split); kubectl logs is the supported diagnostic path.
func (v *VKProvider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach api.AttachIO) error {
	return errdefs.NotFound("exec is not implemented in M1")
}

// AttachToContainer is not implemented for M1.
func (v *VKProvider) AttachToContainer(ctx context.Context, namespace, podName, containerName string, attach api.AttachIO) error {
	return errdefs.NotFound("attach is not implemented in M1")
}

// PortForward is not implemented for M1.
func (v *VKProvider) PortForward(ctx context.Context, namespace, podName string, port int32, stream io.ReadWriteCloser) error {
	return errdefs.NotFound("port-forward is not implemented in M1")
}

// GetStatsSummary returns an empty node stats summary (the Summary API lands in
// M2 with runtimed's proc_pid_rusage metrics).
func (v *VKProvider) GetStatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	return &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: v.nodeName}}, nil
}

// GetMetricsResource returns no custom metrics in M1.
func (v *VKProvider) GetMetricsResource(ctx context.Context) ([]*dto.MetricFamily, error) {
	return nil, nil
}
