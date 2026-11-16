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
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/hostshare"
)

const (
	// reasonFailedHostShare is recorded when a native pod mounts a hostPath
	// volume the node's host-share allowlist does not admit, or mounts it in a
	// way a share cannot be used (another mount path, a subPath, a read-write
	// mount of a read-only share), so the pod is refused BEFORE the CreatePod
	// RPC. No upstream analogue: a kubelet mounts any hostPath.
	reasonFailedHostShare = "FailedHostShare"
	// reasonHostShareGranted is recorded once at create for each hostPath
	// volume the node admitted, naming the path and the mode: the cluster-side
	// audit record of what the pod was given.
	reasonHostShareGranted = "HostShareGranted"
)

// authorizeHostShares decides box's hostPath volumes against the node's
// allowlist. A refusal is a *volumeRefusal (reason FailedHostShare) wrapping
// both ErrVolumeSourceUnsupported and the hostshare sentinel, so CreatePod
// records it and refuses the pod before the RPC. runtimed makes the same
// decision from the same root-owned file when it compiles the pod's profile;
// this check exists so the refusal is an Event on the pod rather than a
// runtime create failure.
func (r *runtimedRuntime) authorizeHostShares(pod *corev1.Pod, box *runtimev1.PodBox) error {
	if !boxMountsHostPath(box) {
		return nil
	}
	var entries []hostshare.Entry
	if r.hostSharesFile != "" {
		var err error
		load := r.loadHostShares
		if load == nil {
			load = hostshare.Load
		}
		if entries, err = load(r.hostSharesFile); err != nil {
			r.log.Error("host share allowlist unreadable; sharing nothing", "file", r.hostSharesFile, "err", err)
			return hostShareRefusal(firstHostPathVolume(box), err)
		}
	}
	if _, err := hostshare.Authorize(entries, box); err != nil {
		return hostShareRefusal(refusedVolumeName(box, err), err)
	}
	return nil
}

func hostShareRefusal(volume string, err error) error {
	return &volumeRefusal{
		reason: reasonFailedHostShare,
		volume: volume,
		kind:   "hostPath",
		err:    fmt.Errorf("%w: %w", ErrVolumeSourceUnsupported, err),
	}
}

// recordHostShareGrants records one Normal Event per admitted hostPath volume
// of box. buildBox has already admitted every one of them.
func (r *runtimedRuntime) recordHostShareGrants(pod *corev1.Pod, box *runtimev1.PodBox) {
	if r.recorder == nil || !boxMountsHostPath(box) {
		return
	}
	for _, v := range box.GetVolumes() {
		hp := v.GetHostPath()
		if hp == nil {
			continue
		}
		r.recorder.Eventf(pod, corev1.EventTypeNormal, reasonHostShareGranted,
			"volume %q: host path %s is shared with this pod by the node's host-share allowlist", v.GetName(), hp.GetPath())
	}
}

// msgFailedHostShare is the FailedHostShare-event message. It carries the
// volume name and the reason, which names no path from the node's allowlist.
func msgFailedHostShare(volume string, err error) string {
	why := "the node's host-share list could not be read, so it shares nothing (see the node log)"
	if errors.Is(err, hostshare.ErrNotShared) {
		why = err.Error()
	}
	if i := strings.Index(why, ": volume "); i >= 0 {
		if j := strings.Index(why[i+len(": volume "):], ": "); j >= 0 {
			why = why[i+len(": volume ")+j+2:]
		}
	}
	return fmt.Sprintf("Error: hostPath volume %q is not shared with this pod: %s. A native pod can mount only "+
		"a host path the node admin listed (sudo k3sm share add), at that same path, with no subPath.", volume, why)
}

func boxMountsHostPath(box *runtimev1.PodBox) bool {
	hp := map[string]bool{}
	for _, v := range box.GetVolumes() {
		if v.GetHostPath() != nil {
			hp[v.GetName()] = true
		}
	}
	if len(hp) == 0 {
		return false
	}
	for _, cs := range [][]*runtimev1.Container{box.GetInitContainers(), box.GetContainers()} {
		for _, c := range cs {
			for _, m := range c.GetVolumeMounts() {
				if hp[m.GetName()] {
					return true
				}
			}
		}
	}
	return false
}

func firstHostPathVolume(box *runtimev1.PodBox) string {
	for _, v := range box.GetVolumes() {
		if v.GetHostPath() != nil {
			return v.GetName()
		}
	}
	return ""
}

// refusedVolumeName picks the volume an Authorize error names, by matching
// the box's hostPath volume names against the error text hostshare writes
// (`volume "<name>"`); the first hostPath volume otherwise.
func refusedVolumeName(box *runtimev1.PodBox, err error) string {
	for _, v := range box.GetVolumes() {
		if v.GetHostPath() != nil && strings.Contains(err.Error(), fmt.Sprintf("volume %q", v.GetName())) {
			return v.GetName()
		}
	}
	return firstHostPathVolume(box)
}

// toHostPathSource carries a hostPath volume's shape (path and type) to the
// runtime; whether the node shares it is authorizeHostShares' decision.
func toHostPathSource(hp *corev1.HostPathVolumeSource) *runtimev1.HostPathVolumeSource {
	out := &runtimev1.HostPathVolumeSource{Path: hp.Path}
	if hp.Type != nil {
		out.Type = string(*hp.Type)
	}
	return out
}
