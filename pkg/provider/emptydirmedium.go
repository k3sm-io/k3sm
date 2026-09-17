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

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// ErrEmptyDirMediumUnsupported is the sentinel for a pod refused because it asks
// for an emptyDir on a storage medium the NATIVE runtime cannot provide. It is
// errors.Is-able so a caller can distinguish "this node will never run that pod"
// from a transient create failure.
var ErrEmptyDirMediumUnsupported = errors.New("emptyDir medium is not supported on the native runtime")

// maxEmptyDirMediumValueLen bounds how much of an emptyDir medium value an error
// or Event echoes back. The value is user-supplied and reaches the node log and a
// namespace-readable Event; the apiserver validates it against a closed set
// today, so a well-formed value is never cut, and the bound plus %q rendering is
// what keeps that a property of this code rather than of upstream validation.
const maxEmptyDirMediumValueLen = 32

// preflightEmptyDirMedium refuses, BEFORE the CreatePod RPC, a NATIVE pod that
// declares an emptyDir with a non-empty medium.
//
// WHY A REFUSAL AND NOT A BEST EFFORT: native pods are ordinary Darwin processes
// with no mount namespace, so there is no tmpfs to give them — runtimed's native
// materialize has no Medium branch and hands back an ordinary directory on disk.
// A workload that asked for `medium: Memory` and silently got disk was told a
// lie it cannot detect: it keeps its RAM-speed assumption, its data survives in
// the pod data volume, and nothing anywhere reports the substitution. Refusing at
// create makes the gap legible on the pod itself, which is the only diagnostic
// surface a headless Mac has.
//
// THE MEDIUM CHECK IS A CLOSED SET, deliberately inverted: only the EMPTY medium
// is accepted. `Memory`, `HugePages` and `HugePages-<size>` are all refused, and
// so is any medium upstream adds later — a new value would otherwise inherit the
// silent disk-backing this check exists to remove.
//
// THE BACKEND COMES OFF THE BOX, never from pod.Spec.RuntimeClassName. toPodBox
// has already resolved the RuntimeClass through the apis handler table
// (podSandboxBackend), so reading the box is reading the decision that will
// actually be enforced; re-deriving it here would put a second answer to "is this
// pod native" next to the first one. A vm-backend pod returns nil untouched: the
// guest has a real Linux tmpfs and runtimed's vm share plan classifies
// `medium: Memory` as one, so that path owns its own verdict (including its own
// refusal of the media it does not implement).
func (r *runtimedRuntime) preflightEmptyDirMedium(pod *corev1.Pod, box *runtimev1.PodBox) error {
	if box.GetSandboxProfile().GetBackend() == runtimev1.SandboxBackend_SANDBOX_BACKEND_VM {
		return nil
	}
	for i := range pod.Spec.Volumes {
		v := &pod.Spec.Volumes[i]
		if v.EmptyDir == nil || v.EmptyDir.Medium == "" {
			continue
		}
		medium := boundEmptyDirMedium(string(v.EmptyDir.Medium))
		r.log.Error("CreatePod: emptyDir medium is not supported on the native runtime",
			"namespace", pod.Namespace, "name", pod.Name,
			"volume", v.Name, "medium", medium)
		r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedEmptyDirMedium,
			msgFailedEmptyDirMedium(v.Name, medium))
		return fmt.Errorf("create pod %s/%s: volume %q requests emptyDir medium %q: %w",
			pod.Namespace, pod.Name, v.Name, medium, ErrEmptyDirMediumUnsupported)
	}
	return nil
}

// boundEmptyDirMedium caps a medium value for an error or Event echo. The cut is
// on a byte boundary and every caller renders with %q, whose escaping leaves the
// result printable ASCII whatever byte the cut landed on.
func boundEmptyDirMedium(medium string) string {
	if len(medium) > maxEmptyDirMediumValueLen {
		return medium[:maxEmptyDirMediumValueLen]
	}
	return medium
}
