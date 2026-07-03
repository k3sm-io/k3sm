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

	corev1 "k8s.io/api/core/v1"
	statsv1alpha1 "k8s.io/kubelet/pkg/apis/stats/v1alpha1"

	"k3sm.io/k3sm/pkg/provider/vkadapter"
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
	GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts vkadapter.ContainerLogOpts) (io.ReadCloser, error)
	// Watch delivers a full corev1.Pod (with .Status) on every status change for
	// the lifetime of ctx. The implementation runs cb OUTSIDE any held lock (the
	// VK re-entrancy rule) and resyncs the current state when its underlying
	// stream breaks, so a missed event is always recovered.
	Watch(ctx context.Context, cb func(*corev1.Pod))
}

// StatsSource is an OPTIONAL Runtime capability: a Runtime that can report a
// kubelet Summary API snapshot (the source kubectl top reads). VKProvider's
// GetStatsSummary uses it via a type assertion when the backing Runtime
// implements it — the runtimed runtime does (it surfaces runtimed's
// proc_pid_rusage footprint); HostProcess does not, and keeps its empty summary.
// Defining it here (consumer-side) keeps the core Runtime interface small.
type StatsSource interface {
	// StatsSummary returns the node + per-pod stats (memory working set) for the
	// pods this runtime tracks.
	StatsSummary(ctx context.Context) (*statsv1alpha1.Summary, error)
}

// StreamingRuntime is an OPTIONAL Runtime capability: a Runtime that serves the
// container streaming verbs — exec, attach, and port-forward — by wiring the VK
// AttachIO/byte stream to the runtime/v1 Exec/Attach/PortForward RPCs (M2.5).
// VKProvider delegates to it via a type assertion, returning NotFound when the
// backing Runtime lacks it. The runtimed runtime implements it; HostProcess (the
// M0 native-process runtime) does not — it has no confined exec channel.
// Defining it here (consumer-side) keeps the core Runtime interface small, the
// same pattern as StatsSource.
type StreamingRuntime interface {
	// RunInContainer runs cmd in a container, streaming stdio/resize over attach
	// and returning the command's exit status (`kubectl exec`).
	RunInContainer(ctx context.Context, namespace, podName, container string, cmd []string, attach vkadapter.AttachIO) error
	// AttachToContainer attaches to a running container's stdio (`kubectl attach`).
	AttachToContainer(ctx context.Context, namespace, podName, container string, attach vkadapter.AttachIO) error
	// PortForward proxies a byte stream to a pod TCP port (`kubectl port-forward`).
	PortForward(ctx context.Context, namespace, podName string, port int32, stream io.ReadWriteCloser) error
}
