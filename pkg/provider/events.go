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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// Pod lifecycle Event reasons. They match the kubelet's UpperCamelCase reason
// vocabulary so `kubectl describe pod` reads identically to upstream and event
// consumers keying off the reason behave the same. Shared (unexported) here so a
// future runtimed-path emit reuses the identical reasons and messages.
//
// SCOPE: BackOff is emitted on the RUNTIMED path ONLY (the exit-driven
// re-exec + CrashLoopBackOff loop lives there). The HostProcess provider has
// no live restart/backoff loop (reap never re-execs, UpdatePod is a no-op), so
// emitting it there would fabricate a control-loop state that does not exist.
const (
	reasonPulling = "Pulling" // the image is being resolved for a start attempt
	reasonPulled  = "Pulled"  // image (or host binary) resolved for the container
	reasonCreated = "Created" // container object created, before process start
	reasonStarted = "Started" // container process started successfully
	reasonKilling = "Killing" // container process is being stopped (DeletePod)
	reasonFailed  = "Failed"  // container process failed to start
	reasonBackOff = "BackOff" // container re-exec is throttled by CrashLoopBackOff
	// reasonInspectFailed is recorded when a container's image reference cannot
	// be parsed at all — upstream's InspectFailed, the event that pairs with the
	// InvalidImageName waiting reason.
	reasonInspectFailed = "InspectFailed"
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
	// reasonXcodeToolchainUngranted is recorded when a pod carries the
	// k3sm.io/xcode-toolchain annotation but this node's developer-directory
	// selection yields no grant — the node has none, or the one it has is not a
	// directory the profile generator accepts.
	//
	// Like FailedImagePlatform it has no upstream analogue, and unlike it the pod
	// is NOT refused: the annotation is a request, and a node that cannot honour
	// it still runs the pod. The Event exists because that outcome is otherwise
	// invisible — the pod reports healthy and builds against whatever toolchain it
	// finds, while the only other trace is a node-daemon line written at startup,
	// possibly days before this pod was scheduled.
	reasonXcodeToolchainUngranted = "XcodeToolchainUngranted"
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

// msgFailedPullImage is the Failed-event message for an image that could not be
// pulled. Unlike msgFailedStart it DOES carry the error text, and the reason is
// the same one that lets msgFailedImagePlatform carry its own: this string is the
// kubelet's own pull message, and runtimed has already BOUNDED it (quoteBounded)
// before it reaches the waiting entry — the same text `kubectl describe pod`
// shows in status. Withholding it here would leave an operator with a Failed
// event that names no registry, no status code and no digest, while the same
// text sits one column away in the pod status.
func msgFailedPullImage(image, message string) string {
	return fmt.Sprintf("Failed to pull image %q: %s", image, message)
}

// msgBackOffPullingImage is the BackOff-event message (and the waiting message)
// for an image whose retry schedule is sleeping. Kubelet-verbatim, so
// `kubectl describe pod` reads identically to upstream.
func msgBackOffPullingImage(image string) string {
	return fmt.Sprintf("Back-off pulling image %q", image)
}

// msgImageNeverPull is the ErrImageNeverPull-event message for a container whose
// imagePullPolicy is Never and whose image is not in this node's store.
// Kubelet-verbatim.
func msgImageNeverPull(image string) string {
	return fmt.Sprintf("Container image %q is not present with pull policy of Never", image)
}

// msgInspectFailed is the InspectFailed-event message for a reference that does
// not parse. It carries runtimed's bounded parse error for the same reason
// msgFailedPullImage does: the text is the node's own, and the malformed
// reference is the entire actionable content.
//
// The phrasing is the kubelet's for THIS cause specifically: upstream reaches
// InspectFailed/InvalidImageName from applyDefaultImageTag, whose message is
// "Failed to apply default image tag %q: %v" (pkg/kubelet/images/image_manager.go).
// Its own "Failed to inspect image" text belongs to a different failure — an
// image the runtime holds but cannot describe — which is not a state k3sm can
// reach, so borrowing it would name the wrong stage for every pod that lands
// here.
func msgInspectFailed(image, message string) string {
	return fmt.Sprintf("Failed to apply default image tag %q: %s", image, message)
}

// msgContainerConfigError is the Failed-event message for a container whose run
// spec could not be built. Upstream's phrasing for this class is a bare
// "Error: <what went wrong>", which is what the CreateContainerConfigError
// waiting message carries too.
func msgContainerConfigError(message string) string {
	return "Error: " + message
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

// msgPullingImage is the Pulling-event message, recorded when the provider
// dispatches a start attempt for a container whose image must be resolved.
// Kubelet-verbatim.
//
// It is emitted per ATTEMPT, not per container-start: upstream records one
// Pulling per trip through its image manager, and a retry is another trip. A
// host-binary route (the native sentinel, an absolute path) gets none at all,
// because runtimed resolves it in place and never contacts a registry.
func msgPullingImage(image string) string {
	return fmt.Sprintf("Pulling image %q", image)
}

// msgPulledImage is the Pulled-event message for an image the runtime FETCHED,
// carrying the kubelet's two durations: the resolution step itself, and the
// wall time since the attempt was announced (upstream's "including waiting",
// which covers the queueing its serialized puller adds).
//
// Both are truncated to milliseconds, as upstream truncates, so the text is
// stable enough to read and to match. The image-size clause upstream appends is
// omitted rather than guessed: runtimed reports no size for a resolution, and a
// fabricated byte count on a diagnostic event is worse than a shorter sentence.
func msgPulledImage(image string, pull, total time.Duration) string {
	return fmt.Sprintf("Successfully pulled image %q in %v (%v including waiting)",
		image, pull.Truncate(time.Millisecond), total.Truncate(time.Millisecond))
}

// msgImageAlreadyPresent is the Pulled-event message for an image the runtime did
// NOT fetch. HostProcess treats the image reference as an already-present native
// binary path (there is no registry pull), and the runtimed path uses the same
// text when runtimed reports the image was already in the node's store — the
// kubelet's "already present on machine" phrasing rather than a fabricated
// "Successfully pulled … in Xs".
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

// msgXcodeToolchainUngranted is the XcodeToolchainUngranted-event message for a
// pod that asked for the node's developer toolchain and got nothing.
// developerDir is what the node's `xcode-select -p` printed at daemon start, or
// empty when it printed nothing.
//
// It DOES carry that path, and the reasoning is the same one that lets
// msgFailedImagePlatform carry its error: the value is authored by the node
// itself (a developer-directory selection), not by pod env, args, or a registry
// response, and naming it is the whole point — an operator cannot act on "the
// grant is empty" without knowing which directory the node is pointed at.
//
// The remediation line is stated once and identically in both branches, and it
// names the restart: the directory is read once, at daemon construction, so an
// `xcode-select --switch` alone changes nothing for a running node.
func msgXcodeToolchainUngranted(developerDir string) string {
	const remedy = "To grant the Xcode toolchain, run `sudo xcode-select -s " +
		"/Applications/Xcode.app/Contents/Developer` on this node and restart the k3sm node daemon — " +
		"the directory is read once, at daemon start."
	if developerDir == "" {
		return fmt.Sprintf("Pod requests %s, but this node has no developer directory selected, "+
			"so the annotation grants nothing here. %s",
			runtimev1.AnnotationXcodeToolchain, remedy)
	}
	return fmt.Sprintf("Pod requests %s, but this node's developer directory %s is not one the "+
		"toolchain grant accepts — it grants a full Xcode developer directory, and a Command Line "+
		"Tools root needs no grant because a pod already reads that tree. %s",
		runtimev1.AnnotationXcodeToolchain, developerDir, remedy)
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
