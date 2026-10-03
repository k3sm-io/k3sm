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
	"errors"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// Pod re-attachment after a node-daemon restart.
//
// A native pod's processes are session leaders that outlive the daemon that
// spawned them, so a `launchctl kickstart -k` leaves them running. The node's
// answer, like the kubelet's, is to read the pods bound to it from the apiserver
// (the spec source of truth; runtimed persists none) and ask the runtime to
// ATTACH to each pod's live processes instead of creating it again. A pod the
// runtime cannot attach to is created afresh by the normal create path.
//
// ORDERING (binding, and why it lives in the constructor): every attach runs
// BEFORE runtimed's startup pod reap, because the reap kills every recorded
// process group no registered pod owns, and an attach is what registers one.
// The reap runs before any create, because Virtual Kubelet — the only caller of
// CreatePod — is started with the provider NewRuntimed returns, so nothing can
// create a pod until adoptNodePods has returned. Creates are therefore never
// issued from here: a pod left unattached is left untracked, and Virtual
// Kubelet's first sync finds it unknown to GetPod and calls CreatePod, exactly
// as for a pod scheduled to this node a moment ago. Issuing those creates here
// instead would hold node registration (and the node lease) behind every image
// pull of every fallback pod.

// podAttacher is the slice of the concrete in-process runtime the startup
// sequence needs: the attach verb and the startup reap that must follow it. It
// is declared here, at the consumer, because neither is a Runtime service RPC —
// AttachPod exists only on *runtimed.Runtime, for the node that shares its
// process — and a test drives the sequence through a fake.
type podAttacher interface {
	// AttachPod re-attaches to the live processes of the pod box describes,
	// returning the pod's status. Every refusal wraps runtimed.ErrNothingToAttach.
	AttachPod(ctx context.Context, box *runtimev1.PodBox) (*runtimev1.PodStatus, error)
	// ReapOrphanedPods kills every recorded pod process group no registered pod
	// owns. Exactly once per runtime; always nil by contract.
	ReapOrphanedPods() error
}

var _ podAttacher = (*runtimed.Runtime)(nil)

// podNetReattacher is the optional pod-network capability an attach needs:
// re-reserving the address a surviving pod is already bound to, and re-ensuring
// its lo0 alias, without allocating a new one. *PodNetAdapter implements it. A
// network without it cannot keep a surviving pod's address from being handed
// to another pod, so such a node attaches nothing.
type podNetReattacher interface {
	Reattach(ctx context.Context, podID, ip string) error
}

// attachListTimeout bounds the startup list of this node's pods. A list that
// does not answer in time attaches nothing: the reap then treats every
// surviving pod as it did before re-attachment existed, and the pods are
// created again.
const attachListTimeout = orphanAPITimeout

// adoptNodePods is the startup sequence: attach every running native pod bound
// to this node, then run the runtime's startup reap. It never fails the node:
// an unreachable apiserver, a pod that cannot be attached and a reap fault all
// degrade to the create-everything behavior.
func (r *runtimedRuntime) adoptNodePods(ctx context.Context, a podAttacher) {
	attached, left := 0, 0
	pods := r.listPodsToAttach(ctx)
	for i := range pods {
		if r.attachPod(ctx, a, &pods[i]) {
			attached++
		} else {
			left++
		}
	}
	// See NewRuntimed for why the reap's error is logged and never propagated.
	if err := a.ReapOrphanedPods(); err != nil {
		r.log.Error("startup pod reap reported an error (degraded, node continues)", "err", err)
	}
	if attached+left > 0 {
		r.log.Info("startup pod re-attachment complete", "attached", attached, "left_for_create", left)
	}
}

// listPodsToAttach returns the pods bound to this node that an attach may
// apply to: in the Running phase, not being deleted, and native (a vm pod's
// helper never survives its daemon). A node without an apiserver client, or a
// list that fails, yields none.
func (r *runtimedRuntime) listPodsToAttach(ctx context.Context) []corev1.Pod {
	if r.podSource == nil {
		return nil
	}
	listCtx, cancel := context.WithTimeout(ctx, attachListTimeout)
	listed, err := r.podSource.listNodePods(listCtx, r.nodeName)
	cancel()
	if err != nil {
		r.log.Warn("startup pod re-attachment skipped: cannot list this node's pods; surviving pod processes will be reaped and the pods created again", "err", err)
		return nil
	}
	var out []corev1.Pod
	for i := range listed {
		p := &listed[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		if backend, err := podSandboxBackend(p); err != nil || backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
			continue
		}
		out = append(out, *p)
	}
	return out
}

// attachPod re-attaches one pod and reports whether it did. On success the pod
// is tracked exactly as a created one is, with four differences that are the
// point: its restart counts are runtimed's attached counts, never bumped here;
// its postStart hooks are not run again (they ran in the pod's first life); a
// container the attach reported Terminated is restarted through StartContainer
// rather than RestartContainer (diedWhileDown); and one Warning PodReattached
// Event says what the restart cost the pod. Every restart trigger then takes
// the ordinary per-container path: runtimed compiled the pod's sandbox profile
// at the attach, so one container restarts or stops in place.
//
// The pod's address comes from its published status.podIP and is RE-RESERVED
// through the pod network (podnet's ReattachPod: that exact address, and an
// idempotent lo0 alias ensure) rather than set up anew — a fresh Setup would
// allocate a different address for a pod whose processes are bound to the old
// one. The reservation precedes the attach so a concurrent create can never be
// handed the address, and it is released if the attach is refused, because the
// reap that follows kills the processes bound to it.
func (r *runtimedRuntime) attachPod(ctx context.Context, a podAttacher, pod *corev1.Pod) bool {
	id := string(pod.UID)
	podIP, ok := r.reattachPodIP(ctx, pod)
	if !ok {
		return false
	}
	ctx = withPodIdentity(ctx, pod)
	// Registered before the first read (buildBox resolves env) and before
	// the first refresh tick, or both would be refused as unreferenced. A
	// failed attach leaves it registered: the pod still exists on this node,
	// and its create or delete takes the registration from here.
	r.refs.RegisterPod(pod)
	box, err := r.buildBox(ctx, pod, podIP)
	if err != nil {
		r.log.Warn("startup re-attachment: cannot translate the pod; it will be created again", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		r.releasePodNetwork(pod)
		return false
	}
	rs, err := a.AttachPod(ctx, box)
	if err != nil {
		if errors.Is(err, runtimed.ErrNothingToAttach) {
			r.log.Info("startup re-attachment: no live processes to attach; the pod will be created again", "namespace", pod.Namespace, "name", pod.Name, "reason", err)
		} else {
			r.log.Warn("startup re-attachment failed; the pod will be created again", "namespace", pod.Namespace, "name", pod.Name, "err", err)
		}
		r.releasePodNetwork(pod)
		return false
	}

	start := metav1.Now()
	if pod.Status.StartTime != nil {
		// The pod's StartTime is the one it was published with in its first life:
		// an attach does not start it again.
		start = *pod.Status.StartTime
	}
	t := &podTrack{pod: pod.DeepCopy(), startTime: start, diedWhileDown: diedWhileDown(rs)}
	r.mu.Lock()
	r.track[id] = t
	r.mu.Unlock()

	r.linkContainerLogs(pod, rs)
	r.startProber(pod, rs.GetPodIp())
	r.log.Warn("re-attached a pod that survived a node-daemon restart", "namespace", pod.Namespace, "name", pod.Name)
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonPodReattached, msgPodReattached)
	r.dispatch(id, rs)
	return true
}

// reattachPodIP returns the address an attached pod keeps, re-reserving it on
// the pod network. false means the pod cannot be attached with its address
// intact and must be created again.
func (r *runtimedRuntime) reattachPodIP(ctx context.Context, pod *corev1.Pod) (string, bool) {
	if r.network == nil {
		return r.nodeIP, true
	}
	id := string(pod.UID)
	if pod.Spec.HostNetwork {
		r.network.MarkHostNetwork(id)
		return r.nodeIP, true
	}
	ip, err := netip.ParseAddr(pod.Status.PodIP)
	if err != nil {
		r.log.Info("startup re-attachment: the pod publishes no address to keep; it will be created again", "namespace", pod.Namespace, "name", pod.Name, "pod_ip", pod.Status.PodIP)
		return "", false
	}
	re, ok := r.network.(podNetReattacher)
	if !ok {
		r.log.Warn("startup re-attachment: the pod network cannot re-reserve an address; the pod will be created again", "namespace", pod.Namespace, "name", pod.Name)
		return "", false
	}
	if err := re.Reattach(ctx, id, ip.String()); err != nil {
		r.log.Warn("startup re-attachment: cannot re-reserve the pod's address; it will be created again", "namespace", pod.Namespace, "name", pod.Name, "pod_ip", ip.String(), "err", err)
		return "", false
	}
	return ip.String(), true
}

// diedWhileDown returns the names of the containers an attach reported
// Terminated: they died while the node daemon was down and have no process
// under this one. nil when every container is running.
func diedWhileDown(rs *runtimev1.PodStatus) map[string]bool {
	var out map[string]bool
	for _, list := range [][]*runtimev1.ContainerStatus{rs.GetContainerStatuses(), rs.GetInitContainerStatuses()} {
		for _, cs := range list {
			if cs.GetState().GetTerminated() == nil {
				continue
			}
			if out == nil {
				out = map[string]bool{}
			}
			out[cs.GetName()] = true
		}
	}
	return out
}
