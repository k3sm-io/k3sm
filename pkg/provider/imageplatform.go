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
	"strings"

	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/runtimeclass"
	"k3sm.io/runtimed/pkg/image"
)

// maxImagePlatformValueLen bounds how much of a MALFORMED k3sm.io/image-platform
// value an error echoes back. The value is user-supplied and reaches the node log
// and a namespace-readable Event, so the echo is bounded here and rendered with
// %q (which escapes control bytes) at every site — a well-formed value never
// takes this path, because a parsed platform is rendered through
// image.Platform.String(), which sanitises.
const maxImagePlatformValueLen = 64

// podImagePlatform is the ONE parse point for the pod-level
// k3sm.io/image-platform annotation (apis runtimev1.AnnotationImagePlatform).
//
// It returns (nil, nil) for an un-annotated pod — "no override", which is what
// the absent Container.image_platform field means on the wire — and an error for
// a malformed value. Failing closed on malformed is deliberate: a pod that asked
// for a specific platform and got the node's default instead would run the wrong
// binaries with no signal anywhere, which is exactly the silent mis-selection
// the typed field exists to prevent.
//
// The result is a NORMALIZED runtimev1.Platform message, never the raw string.
// The annotation is pod-level and stamped onto every container (stampImagePlatform),
// so nothing downstream ever sees the user's string again — one parse, one place
// a malformed value is rejected, which is the contract AnnotationImagePlatform
// documents.
func podImagePlatform(pod *corev1.Pod) (*runtimev1.Platform, error) {
	raw, ok := pod.Annotations[runtimev1.AnnotationImagePlatform]
	if !ok {
		return nil, nil
	}
	plat, err := parseImagePlatform(raw)
	if err != nil {
		return nil, fmt.Errorf("annotation %s: %w", runtimev1.AnnotationImagePlatform, err)
	}
	return plat, nil
}

// parseImagePlatform parses one OCI platform string — os/arch or os/arch/variant
// — into the normalized apis Platform message.
//
// NORMALIZATION IS DELEGATED to image.Platform.Normalize, so the one OCI
// equivalence k3sm honours (architecture arm64 with an empty variant IS
// arm64/v8) is applied by the same code the pull-side matcher uses. A
// second normalizer here would be free to disagree with the selector, and the
// disagreement would surface as an unrunnable pod rather than a compile error.
//
// There is no os.version slot in the annotation form and none is synthesized:
// k3sm's candidate platforms all leave OSVersion empty, so a pinned one could
// only ever fail to match.
func parseImagePlatform(raw string) (*runtimev1.Platform, error) {
	parts := strings.Split(strings.TrimSpace(raw), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("%q is not an OCI platform string, want os/arch or os/arch/variant", boundImagePlatformValue(raw))
	}
	for i, p := range parts {
		t := strings.ToLower(strings.TrimSpace(p))
		if !validImagePlatformToken(t) {
			return nil, fmt.Errorf("%q is not an OCI platform string, want os/arch or os/arch/variant", boundImagePlatformValue(raw))
		}
		parts[i] = t
	}
	p := image.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	n := p.Normalize()
	return &runtimev1.Platform{Os: n.OS, Architecture: n.Architecture, Variant: n.Variant}, nil
}

// validImagePlatformToken reports whether one already-lowercased platform token
// is well formed: non-empty, and drawn from the OCI GOOS/GOARCH/variant charset.
//
// The charset check is about LEGIBILITY, not safety — an off-charset token can
// never equal a candidate, so it would be refused by the servability check
// anyway. The point is that it be refused as MALFORMED, naming the annotation,
// rather than as "this node cannot serve linux/amd64\n\n…".
func validImagePlatformToken(t string) bool {
	if t == "" || len(t) > maxImagePlatformValueLen {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// boundImagePlatformValue caps a malformed annotation value for an error echo.
// The cut is on a byte boundary and the caller renders with %q, whose escaping
// leaves the result printable ASCII whatever byte the cut landed on.
func boundImagePlatformValue(raw string) string {
	if len(raw) > maxImagePlatformValueLen {
		return raw[:maxImagePlatformValueLen]
	}
	return raw
}

// stampImagePlatform stamps plat onto EVERY container of the box, init containers
// included. A nil plat stamps nothing (the un-annotated pod).
//
// The annotation is pod-level by contract, so the stamp is pod-wide: there is no
// per-container annotation form, and mixed-platform containers in one pod is not
// a workload k3sm supports (they share one guest, hence one binfmt registration
// set) — see apis runtimev1.AnnotationImagePlatform.
//
// FORWARD-PROVISIONING, STATED PLAINLY: the field's consumer is still owed.
// runtimed's pullPolicy (runtimed/pkg/runtime/pod.go) builds an
// image.PlatformPolicy from the resolved backend alone and never populates
// PlatformPolicy.Override, so nothing reads image_platform off the wire today.
// This is NOT a field someone forgot to read: the wire half is stamped here so
// the annotation is already normalized and carried when that consumer lands, and
// the node-capability half is enforced BEFORE the RPC (preflightImagePlatform),
// which is what makes an unservable annotated pod fail legibly in the meantime.
func stampImagePlatform(box *runtimev1.PodBox, plat *runtimev1.Platform) {
	if plat == nil {
		return
	}
	for _, c := range box.GetInitContainers() {
		c.ImagePlatform = plat
	}
	for _, c := range box.GetContainers() {
		c.ImagePlatform = plat
	}
}

// boxImagePlatform reads the stamped override back off a translated box. It is
// how the pre-RPC check CONSUMES the single parse rather than re-parsing the
// annotation: re-reading the user's string would put a second parser on this
// side of the wire, and a divergence between the value checked and the value
// sent is precisely the bug the typed field exists to remove.
func boxImagePlatform(box *runtimev1.PodBox) *runtimev1.Platform {
	for _, c := range box.GetInitContainers() {
		if p := c.GetImagePlatform(); p != nil {
			return p
		}
	}
	for _, c := range box.GetContainers() {
		if p := c.GetImagePlatform(); p != nil {
			return p
		}
	}
	return nil
}

// imagePlatformPolicy builds the image-platform policy for a pod on THIS node
// from the pod's resolved sandbox backend and the node capabilities runtimed
// reported — the same facts the k3sm.io/rosetta{,-linux} node labels are derived
// from, read once, so the provider never restates platform-matching policy.
//
// GuestRosetta is the k3sm.io/rosetta-linux CONJUNCTION (VMBackend ∧
// RosettaGuest), composed HERE and only here on this path. Rosetta for Linux
// translates INSIDE a guest, so guest Rosetta on a node with no vm backend has
// nothing to translate in; collapsing the conjunction to the guest bool alone
// would admit linux/amd64 pods onto a node that cannot boot a guest. It is the
// same composition cmd/k3sm's applyRosettaLabels performs for the node label —
// see pkg/runtimeclass LabelRosettaLinux, which names that function as the
// label's composition point.
//
// A pod with no runtimeClassName carries SANDBOX_BACKEND_UNSPECIFIED, because
// the rung choice belongs to runtimed's host-OS-gated SelectBackend. The policy
// needs a backend, and image.Candidates fails closed on UNSPECIFIED, so a
// representative NATIVE rung is substituted: every native rung (SEATBELT_INPROC,
// SEATBELT_EXEC, UIDJAIL) has the IDENTICAL candidate set in
// image.backendPlatforms, so the substitution cannot change the verdict — while
// passing UNSPECIFIED through would refuse every annotated native pod, turning a
// fail-closed check into a fail-always one.
func imagePlatformPolicy(backend runtimev1.SandboxBackend, caps NodeCapabilities) image.PlatformPolicy {
	if backend == runtimev1.SandboxBackend_SANDBOX_BACKEND_UNSPECIFIED {
		backend = runtimev1.SandboxBackend_SANDBOX_BACKEND_SEATBELT_INPROC
	}
	return image.PlatformPolicy{
		Backend:      backend,
		HostRosetta:  caps.RosettaHost,
		GuestRosetta: caps.VMBackend && caps.RosettaGuest,
	}
}

// imagePlatformUnservableError is the typed refusal for an annotated pod this
// node cannot serve. It names the missing node capability LABEL when one exists,
// because that key is what an operator greps for and what a multi-node
// nodeSelector would have matched on.
type imagePlatformUnservableError struct {
	// want is the normalized platform the annotation asked for.
	want image.Platform
	// runnable is what the pod's OWN sandbox backend can execute on this node —
	// backend-scoped, not node-wide — for the operator who now has to decide
	// between changing the pod and changing the node. Empty when the backend
	// itself has no candidates.
	runnable []image.Platform
	// missingLabel is the node capability label whose presence would have made
	// want servable, or "" when no label can grant it (nothing about this node
	// will ever run that platform).
	missingLabel string
}

func (e *imagePlatformUnservableError) Error() string {
	cause := "no node capability label grants it"
	if e.missingLabel != "" {
		cause = "node capability label " + e.missingLabel + " is absent"
	}
	return fmt.Sprintf("pod annotation %s requests %s, which this node cannot serve: %s (runnable for this pod: %s)",
		runtimev1.AnnotationImagePlatform, e.want.String(), cause, renderImagePlatforms(e.runnable))
}

// renderImagePlatforms joins a runnable set for a message. Every element is
// rendered through image.Platform.String(), the sanitising choke point.
func renderImagePlatforms(ps []image.Platform) string {
	if len(ps) == 0 {
		return "nothing"
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return strings.Join(out, ", ")
}

// checkImagePlatformServable reports whether this node can serve the annotated
// platform for a pod on the given backend, failing CLOSED.
//
// THE DECISION IS DELEGATED to image.Candidates with the platform as its
// Override — the same fail-closed override check the pull path is specified
// against — so the provider adds a capability gate without owning a second
// answer to "can this node run that platform". Only the MESSAGE is authored
// here; image.PlatformMismatchError's own text describes an image's offered
// platforms, which is not what has failed at this point (no image has been
// fetched, and none will be).
func checkImagePlatformServable(want *runtimev1.Platform, backend runtimev1.SandboxBackend, caps NodeCapabilities) error {
	base := imagePlatformPolicy(backend, caps)
	target := image.Platform{
		OS:           want.GetOs(),
		Architecture: want.GetArchitecture(),
		Variant:      want.GetVariant(),
		OSVersion:    want.GetOsVersion(),
	}.Normalize()
	if servableUnder(base, target) {
		return nil
	}
	// Runnable set for the message; nil when the backend has no candidates at all.
	runnable, _ := image.Candidates(base)
	return &imagePlatformUnservableError{
		want:         target,
		runnable:     runnable,
		missingLabel: missingCapabilityLabel(base, target),
	}
}

// servableUnder reports whether policy admits exactly want, via image.Candidates'
// Override arm (which checks the override against the backend's runnable set and
// fails closed).
func servableUnder(policy image.PlatformPolicy, want image.Platform) bool {
	policy.Override = &want
	_, err := image.Candidates(policy)
	return err == nil
}

// missingCapabilityLabel names the node capability label whose presence would
// have made want servable, or "" when none would.
//
// It is derived by ASSERTING each label's capability input in turn and re-running
// the same servability decision — never by restating which platform each label
// grants. That derivation is what keeps the answer honest as the candidate table
// evolves: the label named is, by construction, the one that flips the verdict.
// The mapping label → policy input is one line each, and the rosetta-linux
// conjunction lives in imagePlatformPolicy, so it is not re-composed here.
func missingCapabilityLabel(base image.PlatformPolicy, want image.Platform) string {
	if !base.HostRosetta {
		p := base
		p.HostRosetta = true
		if servableUnder(p, want) {
			return runtimeclass.LabelRosetta
		}
	}
	if !base.GuestRosetta {
		p := base
		p.GuestRosetta = true
		if servableUnder(p, want) {
			return runtimeclass.LabelRosettaLinux
		}
	}
	return ""
}

// preflightImagePlatform refuses, BEFORE the CreatePod RPC, a pod whose
// k3sm.io/image-platform annotation names a platform this node's capabilities
// cannot serve.
//
// It runs pre-RPC on purpose. runtimed would refuse the pull too, but that
// refusal arrives as a CreatePod error the VK provider surfaces by failing the
// pod; refusing here keeps the diagnosis on the node's own advertised
// capabilities and puts it where a headless Mac's operator can see it — a
// Warning Event on the pod, so `kubectl describe pod` names the missing
// k3sm.io/* label instead of the failure reaching only server.log.
//
// SCOPE, stated so it is not mistaken for more: this covers the ANNOTATED case
// only. An un-annotated pod whose image simply offers no runnable platform is
// discovered inside runtimed at pull, and surfacing THAT as a waiting
// ErrImagePull/ImagePullBackOff (pod Pending, never terminal Failed) is the
// kubelet pull-failure taxonomy — a separate deliverable, deliberately not
// approximated here.
//
// The capability probe is one GetRuntimeInfo RPC, made ONLY for an annotated
// pod, so an un-annotated CreatePod costs nothing. Capabilities fails CLOSED on
// a probe error (it advertises nothing), which refuses the annotated pod rather
// than admitting it on an unanswered question.
func (r *runtimedRuntime) preflightImagePlatform(ctx context.Context, pod *corev1.Pod, box *runtimev1.PodBox) error {
	want := boxImagePlatform(box)
	if want == nil {
		return nil
	}
	caps := r.Capabilities(ctx)
	err := checkImagePlatformServable(want, box.GetSandboxProfile().GetBackend(), caps)
	if err == nil {
		return nil
	}
	r.log.Error("CreatePod: node cannot serve the annotated image platform",
		"namespace", pod.Namespace, "name", pod.Name,
		"vm_backend", caps.VMBackend, "rosetta_host", caps.RosettaHost, "rosetta_guest", caps.RosettaGuest,
		"err", err)
	r.recorder.Event(pod, corev1.EventTypeWarning, reasonFailedImagePlatform, msgFailedImagePlatform(err))
	return fmt.Errorf("create pod %s/%s: %w", pod.Namespace, pod.Name, err)
}
