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
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/runtimeclass"
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
	// reasonFailedEmptyDirMedium is recorded when a pod on the NATIVE runtime
	// declares an emptyDir with a non-empty medium, so the pod is refused BEFORE
	// the CreatePod RPC (preflightEmptyDirMedium).
	//
	// Like FailedImagePlatform it has no upstream analogue: a kubelet with a
	// medium it cannot serve is not a state upstream models, so there is no reason
	// to mirror, and borrowing `Failed` would place the failure at container start,
	// a stage this pod never reaches.
	reasonFailedEmptyDirMedium = "FailedEmptyDirMedium"
	// reasonFailedGPUFit is recorded when a pod requesting the GPU extended
	// resource does not fit in this node's GPU memory beside the GPU pods already
	// admitted, so the pod is refused BEFORE the CreatePod RPC.
	//
	// Like FailedImagePlatform it has no upstream analogue: the GPU slot count is a
	// memory-derived co-tenancy budget, not a device count, so there is no kubelet
	// reason to mirror, and `OutOfmlx.k3sm.io/gpu` (the scheduler's own out-of-resource
	// reason) would be a lie — the slot was available, the memory beside it was not.
	reasonFailedGPUFit = "FailedGPUFit"
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
	// reasonRestrictedShellEntrypoint is recorded when a container that received
	// the cluster DNS shim env has an entrypoint dyld treats as a macOS SIP
	// platform binary — see restrictedPlatformEntrypoint. dyld strips every
	// DYLD_* variable before it loads a platform binary, so the DNS
	// getaddrinfo shim never loads and the container's cluster-name lookups
	// silently NXDOMAIN.
	//
	// Like XcodeToolchainUngranted it has no upstream analogue and the pod is
	// NOT refused: most /bin/sh entrypoints exec a compiled binary that
	// inherits the shim fine, so refusing every one would be a false positive
	// for most of them. The Event exists because the ones that do fail
	// otherwise show only an in-pod "no such host", with nothing pointing at
	// the cause.
	reasonRestrictedShellEntrypoint = "RestrictedShellEntrypoint"
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

// msgFailedEmptyDirMedium is the FailedEmptyDirMedium-event message for a native
// pod whose emptyDir asks for a storage medium this runtime cannot provide.
//
// It DOES carry the volume name and the medium, for the same reason
// msgFailedImagePlatform carries its error: both values are the pod's own spec,
// not env, args, or a registry response, and an operator cannot find the offending
// volume among several without being told which one it is. The medium is bounded
// by the caller and rendered with %q, so a value that ever stops being one of the
// closed set upstream validates still prints as printable ASCII.
//
// Both ways out are stated, because the refusal is only actionable with them: drop
// the field and take a disk-backed directory, or move the pod to the runtime that
// has a real tmpfs.
func msgFailedEmptyDirMedium(volume, medium string) string {
	return fmt.Sprintf("Error: volume %q sets spec.volumes[].emptyDir.medium to %q, which the "+
		"default runtime cannot provide: its pods are native processes with no tmpfs, so the "+
		"directory would be disk-backed with no notice. Remove the medium field to take an "+
		"ordinary disk-backed directory, or schedule the pod with runtimeClassName: %s, whose "+
		"Linux guest honours medium: Memory as a tmpfs.",
		volume, medium, runtimeclass.Name)
}

// msgFailedGPUFit is the FailedGPUFit-event message for a GPU pod refused for
// want of GPU memory beside the pods already admitted.
//
// It carries all THREE byte counts, in GiB, because no two of them are enough to
// act on: the ceiling alone does not say how much is spoken for, the admitted
// total alone does not say by how much this pod misses, and neither says which
// number the operator controls. And it states both ways out, for the same reason
// msgFailedEmptyDirMedium does: a refusal an operator cannot act on is barely
// better than the overcommit it replaces.
//
// The numbers are this node's own arithmetic over pod specs and runtimed's facts
// — no env, no args, no registry response — so there is nothing here to sanitise.
func msgFailedGPUFit(want, admitted, ceiling int64) string {
	return fmt.Sprintf("Error: this pod needs %s of GPU memory, but %s of the node's %s usable GPU memory "+
		"is already committed to admitted GPU pods, so it cannot be started without overcommitting the GPU. "+
		"Delete or shrink another pod requesting %s, or lower this pod's memory limit to fit in what is left.",
		gpuFitGiB(want), gpuFitGiB(admitted), gpuFitGiB(ceiling), mlxv1alpha1.ResourceGPU)
}

// msgFailedGPUUnbounded is the FailedGPUFit-event message for a GPU pod that
// declares no enforceable memory limit on a node that knows its GPU ceiling.
//
// It shares the reason with msgFailedGPUFit because it is the same refusal from
// the operator's side (this pod will not start on this node for want of a GPU
// memory budget), but the text is a different one: naming the three byte counts
// would be misleading here, since the missing number is the pod's own. The way
// out is stated as the field to set, because that is the whole fix, and every
// MLXModel-rendered pod already carries it.
func msgFailedGPUUnbounded(ceiling int64) string {
	return fmt.Sprintf("Error: this pod requests %s but declares no memory limit on every container, so the node "+
		"cannot fit it against its %s of usable GPU memory and would be overcommitting the GPU by an amount "+
		"nothing can measure. Set spec.containers[].resources.limits.memory on every container.",
		mlxv1alpha1.ResourceGPU, gpuFitGiB(ceiling))
}

// gpuFitGiB renders a byte count as the binary quantity a pod's memory limit is
// written in, so the message compares its three numbers in the notation the
// offending spec used rather than in raw bytes.
func gpuFitGiB(bytes int64) string {
	return resource.NewQuantity(bytes, resource.BinarySI).String()
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

// msgRestrictedShellEntrypoint is the RestrictedShellEntrypoint-event message for
// a container whose entrypoint dyld treats as a macOS platform binary.
//
// It carries the resolved path, rendered with %q for the same reason the other
// user-authored values in this file are: the value is the pod's own spec
// (Command[0] or the image reference), not env, args, or a registry response,
// and %q escapes any control byte before it reaches a namespace-readable Event.
// It names neither a fully-qualified path list nor a resolver file — k3sm ships
// no such thing — only the one remedy that actually restores the shim.
func msgRestrictedShellEntrypoint(path string) string {
	return fmt.Sprintf("This container's entrypoint %q is a macOS platform binary, which drops the DNS "+
		"shim this pod was given, so cluster names will not resolve from it. Use a compiled binary as the "+
		"entrypoint instead — a pod that execs its binary directly keeps the shim and resolves cluster names.",
		path)
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
