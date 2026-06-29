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

// RunInContainer serves `kubectl exec`, delegating to the backing Runtime's
// StreamingRuntime capability (the runtimed runtime drives the runtime/v1 Exec
// RPC). A Runtime without it (HostProcess) reports NotFound (M2.5).
func (v *VKProvider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach api.AttachIO) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return errdefs.NotFound("exec is not supported by this runtime")
	}
	return s.RunInContainer(ctx, namespace, podName, containerName, cmd, attach)
}

// AttachToContainer serves `kubectl attach`, delegating to the StreamingRuntime
// capability; NotFound when the backing Runtime lacks it (M2.5).
func (v *VKProvider) AttachToContainer(ctx context.Context, namespace, podName, containerName string, attach api.AttachIO) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return errdefs.NotFound("attach is not supported by this runtime")
	}
	return s.AttachToContainer(ctx, namespace, podName, containerName, attach)
}

// PortForward serves `kubectl port-forward`, delegating to the StreamingRuntime
// capability; NotFound when the backing Runtime lacks it (M2.5).
func (v *VKProvider) PortForward(ctx context.Context, namespace, podName string, port int32, stream io.ReadWriteCloser) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return errdefs.NotFound("port-forward is not supported by this runtime")
	}
	return s.PortForward(ctx, namespace, podName, port, stream)
}

// GetStatsSummary returns the kubelet Summary API snapshot kubectl top reads.
// When the backing Runtime implements StatsSource (the runtimed runtime does, via
// runtimed's proc_pid_rusage footprint), it produces real per-pod memory stats;
// otherwise (HostProcess) the node-only summary is returned.
func (v *VKProvider) GetStatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error) {
	if s, ok := v.rt.(StatsSource); ok {
		return s.StatsSummary(ctx)
	}
	return &statsv1alpha1.Summary{Node: statsv1alpha1.NodeStats{NodeName: v.nodeName}}, nil
}

// GetMetricsResource returns no custom metrics in M1.
func (v *VKProvider) GetMetricsResource(ctx context.Context) ([]*dto.MetricFamily, error) {
	return nil, nil
}
