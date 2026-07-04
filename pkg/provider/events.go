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

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
)

// Pod lifecycle Event reasons. They match the kubelet's UpperCamelCase reason
// vocabulary so `kubectl describe pod` reads identically to upstream and event
// consumers keying off the reason behave the same. Shared (unexported) here so a
// future runtimed-path emit reuses the identical reasons and messages.
//
// NOTE: BackOff is deliberately absent — the M0 HostProcess has no live
// restart/backoff loop (reap never re-execs, UpdatePod is a no-op), so a BackOff
// event would fabricate a control-loop state that does not exist. It arrives with
// container restart (B26/B39).
const (
	reasonPulled  = "Pulled"  // image (M0: binary) resolved for the container
	reasonCreated = "Created" // container object created, before process start
	reasonStarted = "Started" // container process started successfully
	reasonKilling = "Killing" // container process is being stopped (DeletePod)
	reasonFailed  = "Failed"  // container process failed to start
)

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

// nopRecorder is a no-op record.EventRecorder. NewHostProcess substitutes it when
// a caller passes a nil recorder so the hot pod path never nil-panics on an
// un-wired provider (e.g. an in-process test or a degraded bring-up).
type nopRecorder struct{}

func (nopRecorder) Event(runtime.Object, string, string, string)          {}
func (nopRecorder) Eventf(runtime.Object, string, string, string, ...any) {}
func (nopRecorder) AnnotatedEventf(runtime.Object, map[string]string, string, string, string, ...any) {
}

var _ record.EventRecorder = nopRecorder{}
