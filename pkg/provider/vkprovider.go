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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// VKProvider adapts any Runtime into the full Virtual Kubelet provider contract
// (vkadapter.Provider). It is the single seam the VK node talks to, so swapping
// the pod-execution backend (HostProcess vs runtimed) is a one-line choice at
// startup with no change to the node wiring.
//
// The lifecycle/logs methods delegate straight to the Runtime; NotifyPods wires
// the Runtime's status watch to the VK callback. RunInContainer and the stats
// methods are runtime-specific and reported as not-implemented here unless the
// Runtime also exposes them (HostProcess implements its own GetContainerLogs and
// stats directly when used unwrapped — see the hostprocess node path).
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
var _ vkadapter.Provider = (*VKProvider)(nil)

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
	return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+name)
}

// GetPodStatus delegates to the Runtime.
func (v *VKProvider) GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error) {
	return v.rt.GetPodStatus(ctx, namespace, name)
}

// GetPods delegates to the Runtime.
func (v *VKProvider) GetPods(ctx context.Context) ([]*corev1.Pod, error) {
	return v.rt.GetPods(ctx)
}

// RuntimeHealthy reports whether the backing Runtime can currently serve pods,
// delegating to its optional HealthReporter capability. A Runtime without that
// capability is reported HEALTHY: the absence of a health surface is not evidence
// of ill health, and letting it read as unhealthy would make every such node
// NotReady for a question it was never able to answer.
func (v *VKProvider) RuntimeHealthy(ctx context.Context) bool {
	h, ok := v.rt.(HealthReporter)
	if !ok {
		return true
	}
	return h.Healthy(ctx)
}

// ServableRuntime returns the in-process runtimed runtime the backing Runtime
// drives, comma-ok, delegating to its optional ControlSocketSource capability. A
// Runtime without that capability reports false and the node binds no runtimed
// control socket — the correct answer for the HostProcess runtime, which has no
// runtime/v1 services to serve.
func (v *VKProvider) ServableRuntime() (*runtimed.Runtime, bool) {
	s, ok := v.rt.(ControlSocketSource)
	if !ok {
		return nil, false
	}
	return s.ServableRuntime()
}

// NotifyPods wires the Runtime's status watch to the VK status callback.
func (v *VKProvider) NotifyPods(ctx context.Context, cb func(*corev1.Pod)) {
	v.rt.Watch(ctx, cb)
}

// GetContainerLogs satisfies the VK provider contract by converting VK's
// flattened option struct into the kubelet's own *corev1.PodLogOptions and
// delegating to the Runtime.
//
// It exists for INTERFACE COMPLIANCE, not because anything should route through
// it: the node registers the kubelet's real /containerLogs handler
// (pkg/provider/podlogs) on a more specific mux pattern than VK's catch-all, so
// a `kubectl logs` request reaches the Runtime with its options intact. This
// path is what a caller holding a bare vkadapter.Provider gets, and it is lossy
// in the one way VK's struct is lossy — see toPodLogOptions.
func (v *VKProvider) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts vkadapter.ContainerLogOpts) (io.ReadCloser, error) {
	return v.rt.GetContainerLogs(ctx, namespace, podName, containerName, toPodLogOptions(opts))
}

// toPodLogOptions converts VK's ContainerLogOpts to the kubelet's PodLogOptions.
//
// Tail and LimitBytes are plain ints in VK's struct, so zero and unset are the
// same value there and cannot be told apart here: both are mapped to UNSET
// ("show everything"), because the alternative — mapping 0 to "show nothing" —
// would make an ordinary `kubectl logs` that never asked for a tail return an
// empty stream. The node's own handler does not go through this function and so
// does not pay that cost.
func toPodLogOptions(opts vkadapter.ContainerLogOpts) *corev1.PodLogOptions {
	out := &corev1.PodLogOptions{
		Follow:     opts.Follow,
		Previous:   opts.Previous,
		Timestamps: opts.Timestamps,
	}
	if opts.Tail > 0 {
		tail := int64(opts.Tail)
		out.TailLines = &tail
	}
	if opts.LimitBytes > 0 {
		limit := int64(opts.LimitBytes)
		out.LimitBytes = &limit
	}
	if opts.SinceSeconds > 0 {
		since := int64(opts.SinceSeconds)
		out.SinceSeconds = &since
	}
	if !opts.SinceTime.IsZero() {
		t := metav1.NewTime(opts.SinceTime)
		out.SinceTime = &t
	}
	return out
}

// ContainerLogBackend returns the backing Runtime's kubelet /containerLogs
// backend, comma-ok. false means this Runtime keeps no CRI log tree, and the node
// registers no /containerLogs route of its own.
func (v *VKProvider) ContainerLogBackend() (podlogs.Backend, bool) {
	s, ok := v.rt.(ContainerLogSource)
	if !ok {
		return nil, false
	}
	return s, true
}

// StartLogMaintenance starts container-log rotation and the log garbage
// collector on the backing Runtime, if it keeps a CRI log tree. A Runtime without
// one has nothing to rotate and nothing to collect, so this is a no-op rather
// than an error.
func (v *VKProvider) StartLogMaintenance(ctx context.Context) {
	if s, ok := v.rt.(ContainerLogSource); ok {
		s.StartLogMaintenance(ctx)
	}
}

// RunInContainer serves `kubectl exec`, delegating to the backing Runtime's
// StreamingRuntime capability (the runtimed runtime drives the runtime/v1 Exec
// RPC). A Runtime without it (HostProcess) reports NotFound.
func (v *VKProvider) RunInContainer(ctx context.Context, namespace, podName, containerName string, cmd []string, attach vkadapter.AttachIO) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return vkadapter.NotFound("exec is not supported by this runtime")
	}
	return s.RunInContainer(ctx, namespace, podName, containerName, cmd, attach)
}

// AttachToContainer serves `kubectl attach`, delegating to the StreamingRuntime
// capability; NotFound when the backing Runtime lacks it.
func (v *VKProvider) AttachToContainer(ctx context.Context, namespace, podName, containerName string, attach vkadapter.AttachIO) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return vkadapter.NotFound("attach is not supported by this runtime")
	}
	return s.AttachToContainer(ctx, namespace, podName, containerName, attach)
}

// PortForward serves `kubectl port-forward`, delegating to the StreamingRuntime
// capability; NotFound when the backing Runtime lacks it.
func (v *VKProvider) PortForward(ctx context.Context, namespace, podName string, port int32, stream io.ReadWriteCloser) error {
	s, ok := v.rt.(StreamingRuntime)
	if !ok {
		return vkadapter.NotFound("port-forward is not supported by this runtime")
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

// GetMetricsResource serves the VK /metrics/resource endpoint — the kubelet
// resource-metrics scrape target an operator-installed metrics-server reads to
// populate metrics.k8s.io (`kubectl top`, HPA-on-CPU).
//
// It transcodes the SAME Summary snapshot GetStatsSummary serves, so the two
// endpoints can never disagree about the node. A Runtime with no StatsSource has
// nothing to report and serves an empty scrape target, which is the honest shape
// for an unimplemented metering surface.
//
// The CPU/memory pair is emitted JOINTLY or not at all — see buildResourceMetrics
// for why a memory-only endpoint would be a regression on serving nothing.
func (v *VKProvider) GetMetricsResource(ctx context.Context) ([]*dto.MetricFamily, error) {
	s, ok := v.rt.(StatsSource)
	if !ok {
		return nil, nil
	}
	summary, err := s.StatsSummary(ctx)
	if err != nil {
		return nil, err
	}
	return buildResourceMetrics(summary), nil
}
