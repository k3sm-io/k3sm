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
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
)

// The node's side of the container-log split: directory creation, the
// /var/log/containers symlinks, and the three consumer-side seams
// pkg/provider/podlogs defines (its HTTP Backend, its rotation Runtime, and its
// GC PodStateSource). Everything here reads runtimed's status or the filesystem;
// nothing here writes a log file.

// podLogDirMode is the mode of every directory in the pod log tree.
//
// 0700, not upstream's 0755. Upstream's tree is root-owned, so 0755 still means
// "root only can write, and only root-equivalent processes are around to read".
// On a Mac the node runs as _k3sm, whose primary group is `staff` — the default
// group of every ordinary account — so copying the numeric mode across would turn
// "root only" into "every local user can read every pod's output". The installer
// lays the roots down `_k3sm:wheel 0700` for the same reason; this keeps the
// subdirectories the node creates at rest consistent with them.
const podLogDirMode os.FileMode = 0o700

// ensurePodLogDirs creates the pod's log directory and one subdirectory per
// container — regular, init and ephemeral — and returns the pod's directory.
//
// It runs BEFORE the CreatePod RPC, because the box carries the directory and
// runtimed opens <dir>/<container>/<n>.log inside it without creating anything
// above the container directory. A failure here fails the create: a pod started
// with nowhere to write is a pod whose output is gone and whose kubectl logs
// answers "no log file", which is worse than a create that says why.
func (r *runtimedRuntime) ensurePodLogDirs(pod *corev1.Pod) (string, error) {
	podDir := podlogs.BuildPodLogsDirectory(r.podLogsDir, pod.Namespace, pod.Name, string(pod.UID))
	names := make([]string, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers)+len(pod.Spec.EphemeralContainers))
	for _, c := range pod.Spec.Containers {
		names = append(names, c.Name)
	}
	for _, c := range pod.Spec.InitContainers {
		names = append(names, c.Name)
	}
	for _, c := range pod.Spec.EphemeralContainers {
		names = append(names, c.Name)
	}
	for _, name := range names {
		dir := filepath.Join(podDir, name)
		if err := os.MkdirAll(dir, podLogDirMode); err != nil {
			return "", fmt.Errorf("failed to create container log directory %q: %w", dir, err)
		}
	}
	// A pod with no containers at all still gets its directory, so the tree is
	// uniform and the GC's orphan sweep has something to key on.
	if len(names) == 0 {
		if err := os.MkdirAll(podDir, podLogDirMode); err != nil {
			return "", fmt.Errorf("failed to create pod log directory %q: %w", podDir, err)
		}
	}
	return podDir, nil
}

// linkContainerLogs creates the flat /var/log/containers symlinks for a pod's
// started containers.
//
// Best effort, and deliberately so: the symlinks exist for log shippers, not for
// `kubectl logs`, which reads the pod tree directly. A link is created ONLY when
// its target already exists — a dangling symlink is what the GC sweeps, so
// creating one preemptively would make the node fight itself.
func (r *runtimedRuntime) linkContainerLogs(pod *corev1.Pod, rs *runtimev1.PodStatus) {
	if r.containerLogsDir == "" {
		return
	}
	link := func(cs *runtimev1.ContainerStatus) {
		target := cs.GetLogPath()
		if target == "" || cs.GetContainerId() == "" {
			return
		}
		if _, err := os.Stat(target); err != nil {
			return
		}
		path := podlogs.LogSymlink(r.containerLogsDir, pod.Name, pod.Namespace, cs.GetName(), cs.GetContainerId())
		if existing, err := os.Readlink(path); err == nil {
			if existing == target {
				return
			}
			_ = os.Remove(path)
		}
		if err := os.Symlink(target, path); err != nil && !os.IsExist(err) {
			r.log.Warn("failed to create a container log symlink",
				"namespace", pod.Namespace, "pod", pod.Name, "container", cs.GetName(),
				"path", path, "target", target, "err", err)
		}
	}
	for _, cs := range rs.GetContainerStatuses() {
		link(cs)
	}
	for _, cs := range rs.GetInitContainerStatuses() {
		link(cs)
	}
}

// removePodLogs removes a deleted pod's whole log tree. Called after the runtime
// has confirmed the delete, so no container is still writing into it.
func (r *runtimedRuntime) removePodLogs(pod *corev1.Pod) {
	if r.logGC == nil {
		return
	}
	if err := r.logGC.RemovePodLogs(pod.Namespace, pod.Name, string(pod.UID)); err != nil {
		r.log.Warn("failed to remove the pod log directory",
			"namespace", pod.Namespace, "pod", pod.Name, "err", err)
	}
}

// --- podlogs.Backend (the /containerLogs HTTP surface) ---

// GetPodByName returns a tracked pod, comma-ok. It is podlogs.Backend's 404.
func (r *runtimedRuntime) GetPodByName(_ context.Context, namespace, name string) (*corev1.Pod, bool) {
	_, _, pod, ok := r.lookup(namespace, name)
	if !ok {
		return nil, false
	}
	return pod.DeepCopy(), true
}

// --- podlogs.Runtime (the rotation manager) ---

// RunningContainerLogs returns one ref per RUNNING container across every
// tracked pod. The rotator only ever rotates a running container: an exited one
// writes nothing more, so rotating it would leave an empty current file and
// push its real output one slot closer to deletion.
func (r *runtimedRuntime) RunningContainerLogs(ctx context.Context) ([]podlogs.ContainerLogRef, error) {
	var refs []podlogs.ContainerLogRef
	for _, id := range r.trackedIDs() {
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
		if err != nil {
			// One unreadable pod must not stop the sweep over the others; the
			// next tick retries it.
			r.log.Debug("log rotation: could not read a pod status", "pod-id", id, "err", err)
			continue
		}
		st := resp.GetStatus()
		for _, cs := range append(append([]*runtimev1.ContainerStatus{}, st.GetContainerStatuses()...), st.GetInitContainerStatuses()...) {
			if cs.GetState().GetRunning() == nil || cs.GetLogPath() == "" || cs.GetContainerId() == "" {
				continue
			}
			refs = append(refs, podlogs.ContainerLogRef{ID: cs.GetContainerId(), Path: cs.GetLogPath()})
		}
	}
	return refs, nil
}

// ContainerLog re-reads one container's current log path at the moment of
// rotation, by runtime container id.
func (r *runtimedRuntime) ContainerLog(ctx context.Context, id string) (podlogs.ContainerLogRef, error) {
	cs, _, _, err := r.findContainerByID(ctx, id)
	if err != nil {
		return podlogs.ContainerLogRef{}, err
	}
	return podlogs.ContainerLogRef{ID: id, Path: cs.GetLogPath()}, nil
}

// ReopenContainerLog asks runtimed — the only component that holds the write
// descriptor — to close and reopen the container's log file at its configured
// path. It is the half of rotation the reader cannot perform.
func (r *runtimedRuntime) ReopenContainerLog(ctx context.Context, id string) error {
	_, podID, name, err := r.findContainerByID(ctx, id)
	if err != nil {
		return err
	}
	if _, err := r.rt.ReopenContainerLog(ctx, &runtimev1.ReopenContainerLogRequest{PodId: podID, Container: name}); err != nil {
		return fmt.Errorf("runtimed reopen container log %s/%s: %w", podID, name, err)
	}
	return nil
}

// findContainerByID locates a container's runtime status by its container id,
// returning the status, its pod id and its container name.
func (r *runtimedRuntime) findContainerByID(ctx context.Context, id string) (*runtimev1.ContainerStatus, string, string, error) {
	for _, podID := range r.trackedIDs() {
		resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: podID})
		if err != nil {
			continue
		}
		st := resp.GetStatus()
		for _, cs := range append(append([]*runtimev1.ContainerStatus{}, st.GetContainerStatuses()...), st.GetInitContainerStatuses()...) {
			if cs.GetContainerId() == id {
				return cs, podID, cs.GetName(), nil
			}
		}
	}
	return nil, "", "", fmt.Errorf("container %q not found", id)
}

// trackedIDs returns the pod ids the provider is tracking, under r.mu.
func (r *runtimedRuntime) trackedIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.track))
	for id := range r.track {
		ids = append(ids, id)
	}
	return ids
}

// --- podlogs.PodStateSource (the garbage collector) ---

// KnownPodUIDs returns the UIDs of every pod the provider tracks, and whether
// the provider has SYNCED — that is, whether Virtual Kubelet's pod informer has
// delivered the cluster's view of this node at least once.
//
// The sync bit is what stops the GC from deleting the log trees of every pod on
// the node during the seconds after a restart, when the track map is legitimately
// empty and "unknown pod" does not yet mean "deleted pod".
func (r *runtimedRuntime) KnownPodUIDs(_ context.Context) (map[string]struct{}, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.podsSynced {
		return nil, false
	}
	uids := make(map[string]struct{}, len(r.track))
	for id := range r.track {
		uids[id] = struct{}{}
	}
	return uids, true
}

// ContainerRunning reports whether a container id is currently running. The GC
// uses it to leave a running container's briefly-dangling symlink alone (the
// rename-then-reopen window of rotation).
func (r *runtimedRuntime) ContainerRunning(ctx context.Context, id string) (bool, error) {
	cs, _, _, err := r.findContainerByID(ctx, id)
	if err != nil {
		// Not found means no container claims this symlink, which is precisely
		// the state the sweep exists to clean up.
		return false, nil
	}
	return cs.GetState().GetRunning() != nil, nil
}

// MarkPodsSynced records that the node has seen the cluster's pod set for this
// node at least once, arming the log GC's deletions. It is idempotent.
func (r *runtimedRuntime) MarkPodsSynced() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.podsSynced = true
}
