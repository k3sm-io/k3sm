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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

// Pod lifecycle Event reasons. They match the kubelet's UpperCamelCase reason
// vocabulary so `kubectl describe pod` reads identically to upstream and event
// consumers keying off the reason behave the same. Shared (unexported) here so a
// future runtimed-path emit reuses the identical reasons and messages.
//
// SCOPE: BackOff is emitted on the RUNTIMED path ONLY (B26 — the exit-driven
// re-exec + CrashLoopBackOff loop lives there). The M0 HostProcess provider has
// no live restart/backoff loop (reap never re-execs, UpdatePod is a no-op), so
// emitting it there would fabricate a control-loop state that does not exist.
const (
	reasonPulled  = "Pulled"  // image (M0: binary) resolved for the container
	reasonCreated = "Created" // container object created, before process start
	reasonStarted = "Started" // container process started successfully
	reasonKilling = "Killing" // container process is being stopped (DeletePod)
	reasonFailed  = "Failed"  // container process failed to start
	reasonBackOff = "BackOff" // container re-exec is throttled by CrashLoopBackOff
	// reasonFailedPostStartHook is recorded when a container's postStart hook
	// returns an error — upstream's `FailedPostStartHook`, the event that makes a
	// hook failure visible in `kubectl describe pod` before the container is
	// killed per its restart policy.
	reasonFailedPostStartHook = "FailedPostStartHook"
	// reasonFailedImagePlatform is recorded when a pod's k3sm.io/image-platform
	// annotation names a platform this node's capabilities cannot serve, so the
	// pod is refused BEFORE the CreatePod RPC (preflightImagePlatform).
	//
	// It is the ONE reason in this block with NO upstream analogue, deliberately:
	// upstream has no node-capability-scoped platform annotation, so there is no
	// kubelet reason to mirror and inventing a near-miss (`Failed`, `ErrImagePull`)
	// would tell a consumer the pod failed at a stage it never reached. The name
	// keeps the UpperCamelCase shape the rest of the vocabulary uses.
	reasonFailedImagePlatform = "FailedImagePlatform"
)

// msgBackOffRestarting is the BackOff-event message for a container whose re-exec
// is being throttled by the CrashLoopBackOff schedule. It reproduces the
// kubelet's phrasing (and its "name_namespace(uid)" pod rendering) verbatim, so
// `kubectl describe pod` on a crash-looping k3sm pod reads identically to
// upstream and event consumers keying off the text behave the same.
func msgBackOffRestarting(container string, pod *corev1.Pod) string {
	return fmt.Sprintf("Back-off restarting failed container %s in pod %s_%s(%s)",
		container, pod.Name, pod.Namespace, pod.UID)
}

// msgFailedPostStartHook is the FailedPostStartHook-event message. It carries NO
// handler output or error text: upstream withholds it deliberately ("do not record
// the message in the event so that secrets won't leak from the server") and Events
// flow to a namespace-readable sink here too — the concrete error stays in the node
// log. Upstream identifies the container through the Event's fieldPath; this
// provider's involved object is the Pod (see the reason block above), so the
// container name moves into the message.
func msgFailedPostStartHook(container string) string {
	return "PostStartHook failed for container " + container
}

// msgImageAlreadyPresent is the Pulled-event message. M0 treats the image
// reference as an already-present native binary path (there is no registry pull),
// so this uses the kubelet's "already present on machine" phrasing rather than a
// fabricated "Successfully pulled … in Xs".
func msgImageAlreadyPresent(image string) string {
	return fmt.Sprintf("Container image %q already present on machine", image)
}

// msgCreatedContainer is the Created-event message; the container name lives in
// the message because the Event's involved object is the Pod.
func msgCreatedContainer(name string) string { return "Created container " + name }

// msgStartedContainer is the Started-event message.
func msgStartedContainer(name string) string { return "Started container " + name }

// msgStoppingContainer is the Killing-event message.
func msgStoppingContainer(name string) string { return "Stopping container " + name }

// msgFailedStart is the Failed-event message for a container whose process could
// not be started. It deliberately does NOT interpolate the raw start error: Events
// flow to a namespace-readable sink (often gated looser than pod spec/status), and
// a future wider error source could fold env/args into the string. The concrete
// error is preserved where it belongs — the container's StartError waiting status
// (see startPod) and the node log — not this broadcast message.
func msgFailedStart(name string) string {
	return "Error: failed to start container " + name
}

// msgFailedImagePlatform is the FailedImagePlatform-event message. Unlike
// msgFailedStart it DOES carry its error: the error is
// imagePlatformUnservableError, authored entirely from the pod's own annotation
// and this node's advertised capability labels — no env, no args, no registry
// response — and naming the missing k3sm.io/* label is the entire point of
// emitting the Event. The platform tokens inside it are rendered through
// image.Platform.String(), the sanitising choke point.
func msgFailedImagePlatform(err error) string {
	return "Error: " + err.Error()
}

// nopRecorder is a no-op record.EventRecorder. NewHostProcess substitutes it when
// a caller passes a nil recorder so the hot pod path never nil-panics on an
// un-wired provider (e.g. an in-process test or a degraded bring-up).
type nopRecorder struct{}

func (nopRecorder) Event(runtime.Object, string, string, string)          {}
func (nopRecorder) Eventf(runtime.Object, string, string, string, ...any) {}
func (nopRecorder) AnnotatedEventf(runtime.Object, map[string]string, string, string, string, ...any) {
}

var _ record.EventRecorder = nopRecorder{}
