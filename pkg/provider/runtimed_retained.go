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
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// Terminated pods across a node-daemon restart.
//
// The provider's track map is in-memory, and after a restart it is refilled by
// two paths only: the startup attach (Running native pods) and Virtual Kubelet's
// creates (pods it still syncs). Virtual Kubelet never syncs a pod in the
// Succeeded or Failed phase, so a pod that had TERMINATED before the restart
// re-enters neither: it was untracked, `kubectl logs` answered "pod does not
// exist" for a pod the apiserver still holds, and the log GC then removed its
// tree as an orphan. A finished Job pod on the vm RuntimeClass is the common
// case, because a vm pod never re-attaches; a terminated native pod had the same
// gap.
//
// The kubelet keeps a terminated pod's logs until the pod is deleted. This node
// does the same from durable state: the startup list already read every pod
// bound to this node from the apiserver, so each terminated one is RETAINED,
// and its logs are resolved straight from the CRI tree on disk, where runtimed
// wrote them (<podLogsDir>/<ns>_<pod>_<uid>/<container>/<n>.log, native and vm
// alike). Nothing about the file layout changes.

// retainTerminatedPods records every terminated pod of the startup list. It runs
// once, at startup, before Virtual Kubelet is started.
func (r *runtimedRuntime) retainTerminatedPods(listed []corev1.Pod) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range listed {
		p := &listed[i]
		if p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
			continue
		}
		if r.retained == nil {
			r.retained = map[string]*corev1.Pod{}
		}
		r.retained[string(p.UID)] = p.DeepCopy()
	}
}

// retainedPod returns a copy of the retained pod named namespace/name, comma-ok.
func (r *runtimedRuntime) retainedPod(namespace, name string) (*corev1.Pod, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.retained {
		if p.Namespace == namespace && p.Name == name {
			return p.DeepCopy(), true
		}
	}
	return nil, false
}

// forgetRetained drops a retained pod by UID; a pod that is not retained is a
// no-op.
func (r *runtimedRuntime) forgetRetained(uid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.retained, uid)
}

// pruneRetained drops every retained pod whose UID a successful node pod list
// no longer holds: the pod was deleted, so its logs are no longer owed.
func (r *runtimedRuntime) pruneRetained(present map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for uid := range r.retained {
		if !present[uid] {
			delete(r.retained, uid)
		}
	}
}

// retainedContainerLogs renders a retained pod's container logs. No container
// of a retained pod is running, so a follow read drains the file once and ends.
func (r *runtimedRuntime) retainedContainerLogs(ctx context.Context, pod *corev1.Pod, containerName string, opts *corev1.PodLogOptions, stdout, stderr io.Writer) error {
	path, err := r.retainedLogPath(pod, containerName, opts.Previous)
	if err != nil {
		return err
	}
	notRunning := func(context.Context) (bool, error) { return false, nil }
	return podlogs.ReadLogs(ctx, path, r.readOptions(opts), notRunning, r.log, stdout, stderr)
}

// retainedLogPath resolves a retained pod's container instance file from disk.
//
// The current instance is the highest-numbered <n>.log in the container's
// directory, and the previous one is the next lower: runtimed numbers each new
// instance one past the highest on disk, and the log GC keeps the current
// instance plus MaxPerPodContainer older ones, so the two highest files are
// exactly the instances `kubectl logs` and `kubectl logs --previous` name.
// Rotated (<n>.log.<stamp>) and compressed files are never the file a read
// starts from, so they are not candidates.
func (r *runtimedRuntime) retainedLogPath(pod *corev1.Pod, containerName string, previous bool) (string, error) {
	if !declaresContainer(pod, containerName) {
		return "", fmt.Errorf("container %q in pod %q is not available", containerName, pod.Name)
	}
	dir := podlogs.BuildContainerLogsDirectory(r.podLogsDir, pod.Namespace, pod.Name, string(pod.UID), containerName)
	nums, err := instanceLogNumbers(dir)
	if err != nil {
		return "", fmt.Errorf("read container log directory %q: %w", dir, err)
	}
	if previous {
		if len(nums) < 2 {
			return "", vkadapter.NotFoundf("previous terminated container %q in pod %q not found", containerName, pod.Name)
		}
		return podlogs.BuildContainerLogsPath(r.podLogsDir, pod.Namespace, pod.Name, string(pod.UID), containerName, nums[1]), nil
	}
	if len(nums) == 0 {
		return "", vkadapter.NotFoundf("container %q in pod %q has no log file", containerName, pod.Name)
	}
	return podlogs.BuildContainerLogsPath(r.podLogsDir, pod.Namespace, pod.Name, string(pod.UID), containerName, nums[0]), nil
}

// instanceLogNumbers returns the instance numbers of the plain <n>.log files in
// dir, highest first. A missing directory has none.
func instanceLogNumbers(dir string) ([]int32, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var nums []int32
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		stem, ok := strings.CutSuffix(e.Name(), ".log")
		if !ok || stem == "" || strings.TrimLeft(stem, "0123456789") != "" {
			continue
		}
		n, err := strconv.ParseInt(stem, 10, 32)
		if err != nil {
			continue
		}
		nums = append(nums, int32(n))
	}
	sort.Slice(nums, func(i, j int) bool { return nums[i] > nums[j] })
	return nums, nil
}

// declaresContainer reports whether pod declares a regular, init or ephemeral
// container named name.
func declaresContainer(pod *corev1.Pod, name string) bool {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return true
		}
	}
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return true
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == name {
			return true
		}
	}
	return false
}
