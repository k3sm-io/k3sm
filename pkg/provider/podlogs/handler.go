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

package podlogs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Ported from k8s.io/kubernetes@v1.36.2 pkg/kubelet/server/server.go
// (getContainerLogs) and pkg/kubelet/kubelet_pods.go (GetKubeletContainerLogs,
// validateContainerLogStatus), Apache-2.0.
//
// `kubectl logs` reaches a node by proxying GET
// /containerLogs/<ns>/<pod>/<container> through the apiserver, so this handler IS
// the kubelet contract as far as kubectl and every client library are concerned:
// the status codes, the exact body strings, and the chunked transfer are all part
// of it. They are reproduced literally, including the two bodies that are JSON
// while their neighbours are plain text.

// HandlerPath is the ServeMux pattern the handler registers under. The trailing
// slash makes it a SUBTREE pattern, and a subtree pattern is more specific than
// the "/" catch-all the Virtual Kubelet router installs, so net/http's
// longest-pattern-wins rule routes container-log requests here without depending
// on registration order.
const HandlerPath = "/containerLogs/"

// Backend is the consumer-side seam the handler needs from the provider: the pod
// and its status (to decide 404 and which instance to read) and the read itself.
type Backend interface {
	// GetPodByName returns the tracked pod, comma-ok. The bool is the 404.
	GetPodByName(ctx context.Context, namespace, name string) (*corev1.Pod, bool)
	// GetPodStatus returns the pod's current status. An error makes the handler
	// fall back to the pod object's own .status, which is what the kubelet does
	// when its status cache has no entry yet.
	GetPodStatus(ctx context.Context, namespace, name string) (*corev1.PodStatus, error)
	// ContainerLogs renders one container's logs onto stdout/stderr per opts.
	// It resolves the instance (current, or the previous one for opts.Previous)
	// to an on-disk file itself.
	ContainerLogs(ctx context.Context, namespace, podName, containerName string, opts *corev1.PodLogOptions, stdout, stderr io.Writer) error
}

// Handler serves the kubelet's /containerLogs surface.
type Handler struct {
	backend Backend
	log     *slog.Logger
}

// NewHandler returns the /containerLogs handler over backend.
func NewHandler(backend Backend, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{backend: backend, log: log}
}

// writeError reproduces go-restful's WriteError: the status code, then the
// message as the whole body, verbatim and with no trailing newline. Clients
// (kubectl included) surface that body to the user, so its exact text is part of
// the contract.
func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, msg)
}

// ServeHTTP answers GET /containerLogs/<podNamespace>/<podID>/<containerName>.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var podNamespace, podID, containerName string
	rest := strings.TrimPrefix(r.URL.Path, HandlerPath)
	parts := strings.Split(rest, "/")
	if len(parts) > 0 {
		podNamespace = parts[0]
	}
	if len(parts) > 1 {
		podID = parts[1]
	}
	if len(parts) > 2 {
		containerName = parts[2]
	}

	// The order of these three is upstream's, not alphabetical, and the two
	// JSON-shaped bodies are upstream's too.
	if podID == "" {
		writeError(w, http.StatusBadRequest, `{"message": "Missing podID."}`)
		return
	}
	if containerName == "" {
		writeError(w, http.StatusBadRequest, `{"message": "Missing container name."}`)
		return
	}
	if podNamespace == "" {
		writeError(w, http.StatusBadRequest, `{"message": "Missing podNamespace."}`)
		return
	}

	query := r.URL.Query()
	// Backwards compatibility for the pre-PodLogOptions `tail` parameter, which
	// old clients still send. "all" is spelled as the ABSENCE of a limit, so it
	// deletes the key rather than setting it to anything.
	if tail := query.Get("tail"); tail != "" {
		query["tailLines"] = []string{tail}
		if tail == "all" {
			delete(query, "tailLines")
		}
	}
	// The kubelet's container-log surface is locked to the v1 PodLogOptions
	// shape; the codec is the same one client-go encodes the request with, so
	// every option kubectl can send round-trips.
	logOptions := &corev1.PodLogOptions{}
	if err := DecodePodLogOptions(query, logOptions); err != nil {
		writeError(w, http.StatusBadRequest, `{"message": "Unable to decode query."}`)
		return
	}
	logOptions.TypeMeta = metav1.TypeMeta{}
	if err := ValidatePodLogOptions(logOptions); err != nil {
		h.log.Debug("rejected container log options", "err", err)
		writeError(w, http.StatusUnprocessableEntity, `{"message": "Invalid request."}`)
		return
	}

	pod, ok := h.backend.GetPodByName(ctx, podNamespace, podID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("pod %q does not exist", podID))
		return
	}
	if containerSpec(pod, containerName) == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("container %q not found in pod %q", containerName, podID))
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("unable to convert %T into http.Flusher, cannot show logs", w))
		return
	}
	fw := &flushWriter{w: w, f: flusher}
	// Gate-OFF stream handling, and the reason it is unconditional here: the
	// upstream stream-selection branch is guarded by the PodLogsQuerySplitStreams
	// feature gate, which is ALPHA and defaults to FALSE at v1.36.2 (k8s
	// pkg/features: {Version: 1.32, Default: false, PreRelease: Alpha}). k3sm
	// registers no feature gates at all, so the gate can never be on, and the
	// gate-off contract is that both streams go to one writer. A request naming
	// any `stream` has already been rejected 422 by ValidatePodLogOptions above,
	// which is exactly what a kubelet with the gate off does.
	var stdout io.Writer = fw
	var stderr io.Writer = fw

	w.Header().Set("Transfer-Encoding", "chunked")

	podStatus := pod.Status
	if st, err := h.backend.GetPodStatus(ctx, podNamespace, podID); err == nil && st != nil {
		podStatus = *st
	}
	if _, err := ValidateContainerLogStatus(pod.Name, &podStatus, containerName, logOptions.Previous); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// A zero-byte write before the copy starts. It commits the 200 and the
	// headers, so `kubectl logs -f` on a container that has not said anything yet
	// returns immediately with an open, empty stream instead of appearing to
	// hang. Everything that can still produce a non-200 has therefore already
	// run, by construction.
	if _, err := stdout.Write([]byte{}); err != nil {
		return
	}

	if err := h.backend.ContainerLogs(ctx, podNamespace, podID, containerName, logOptions, stdout, stderr); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
}

// flushWriter flushes after every write, which is what turns the chunked
// response into a live stream rather than a buffer the client sees at the end.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

// Write writes and flushes.
func (f *flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	f.f.Flush()
	return n, err
}

// containerSpec returns the named container's spec from any of the pod's three
// container lists, or nil. Init and ephemeral containers count: `kubectl logs -c`
// names them, and answering 404 for a container the pod plainly declares is the
// most confusing possible reply.
func containerSpec(pod *corev1.Pod, name string) *corev1.Container {
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == name {
			return &pod.Spec.Containers[i]
		}
	}
	for i := range pod.Spec.InitContainers {
		if pod.Spec.InitContainers[i].Name == name {
			return &pod.Spec.InitContainers[i]
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		if pod.Spec.EphemeralContainers[i].Name == name {
			c := corev1.Container(pod.Spec.EphemeralContainers[i].EphemeralContainerCommon)
			return &c
		}
	}
	return nil
}

// ValidatePodLogOptions is the hand port of k8s.io/kubernetes
// pkg/apis/core/validation.ValidatePodLogOptions with allowStreamSelection=FALSE
// — the only form reachable on this node, because stream selection is gated by
// PodLogsQuerySplitStreams (Alpha, default false at v1.36.2) and k3sm registers
// no feature gates. Under that form any `stream` at all is forbidden.
//
// The returned error is for the node's own log; the HTTP body is the fixed
// upstream string, which is why this returns one error rather than a field list.
func ValidatePodLogOptions(opts *corev1.PodLogOptions) error {
	var problems []string
	if opts.TailLines != nil && *opts.TailLines < 0 {
		problems = append(problems, "tailLines: must be greater than or equal to 0")
	}
	if opts.LimitBytes != nil && *opts.LimitBytes < 1 {
		problems = append(problems, "limitBytes: must be greater than 0")
	}
	switch {
	case opts.SinceSeconds != nil && opts.SinceTime != nil:
		problems = append(problems, "at most one of `sinceTime` or `sinceSeconds` may be specified")
	case opts.SinceSeconds != nil:
		if *opts.SinceSeconds < 1 {
			problems = append(problems, "sinceSeconds: must be greater than 0")
		}
	}
	if opts.Stream != nil {
		problems = append(problems, "stream: may not be specified")
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

// ValidateContainerLogStatus returns the container ID whose logs to read, from
// the pod's status, or the error the client is shown.
//
// The precedence is upstream's and each arm is load-bearing: --previous reads the
// LAST terminated instance and fails rather than silently showing the current
// one; a running container wins over an older termination; a terminated container
// whose own ContainerID is empty (the next instance never started) falls back to
// the last termination; and a waiting container explains WHY it is waiting
// instead of reporting an empty log.
func ValidateContainerLogStatus(podName string, podStatus *corev1.PodStatus, containerName string, previous bool) (string, error) {
	var cID string

	cStatus, found := findContainerStatus(podStatus.ContainerStatuses, containerName)
	if !found {
		cStatus, found = findContainerStatus(podStatus.InitContainerStatuses, containerName)
	}
	if !found {
		cStatus, found = findContainerStatus(podStatus.EphemeralContainerStatuses, containerName)
	}
	if !found {
		return "", fmt.Errorf("container %q in pod %q is not available", containerName, podName)
	}
	lastState := cStatus.LastTerminationState
	waiting, running, terminated := cStatus.State.Waiting, cStatus.State.Running, cStatus.State.Terminated

	switch {
	case previous:
		if lastState.Terminated == nil || lastState.Terminated.ContainerID == "" {
			return "", fmt.Errorf("previous terminated container %q in pod %q not found", containerName, podName)
		}
		cID = lastState.Terminated.ContainerID

	case running != nil:
		cID = cStatus.ContainerID

	case terminated != nil:
		if terminated.ContainerID == "" {
			if lastState.Terminated != nil && lastState.Terminated.ContainerID != "" {
				cID = lastState.Terminated.ContainerID
			} else {
				return "", fmt.Errorf("container %q in pod %q is terminated", containerName, podName)
			}
		} else {
			cID = terminated.ContainerID
		}

	case lastState.Terminated != nil:
		if lastState.Terminated.ContainerID == "" {
			return "", fmt.Errorf("container %q in pod %q is terminated", containerName, podName)
		}
		cID = lastState.Terminated.ContainerID

	case waiting != nil:
		switch reason := waiting.Reason; reason {
		case "ErrImagePull":
			return "", fmt.Errorf("container %q in pod %q is waiting to start: image can't be pulled", containerName, podName)
		case "ImagePullBackOff":
			return "", fmt.Errorf("container %q in pod %q is waiting to start: trying and failing to pull image", containerName, podName)
		default:
			return "", fmt.Errorf("container %q in pod %q is waiting to start: %v", containerName, podName, reason)
		}
	default:
		return "", fmt.Errorf("container %q in pod %q is waiting to start - no logs yet", containerName, podName)
	}
	return cID, nil
}

// findContainerStatus returns the named status from a list, comma-ok.
func findContainerStatus(statuses []corev1.ContainerStatus, name string) (corev1.ContainerStatus, bool) {
	for i := range statuses {
		if statuses[i].Name == name {
			return statuses[i], true
		}
	}
	return corev1.ContainerStatus{}, false
}
