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
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/podlogs"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// The node reads container logs OFF THE FILESYSTEM, exactly as the kubelet does.
//
// runtimed writes each container instance to
// <podLogsDir>/<ns>_<pod>_<uid>/<container>/<n>.log in the CRI line format and
// reports the path on ContainerStatus.log_path; nothing else about a log crosses
// the runtime boundary. The runtime's GetLogs RPC survives on the wire for the
// guest relay but answers Unimplemented for a native pod, and the provider no
// longer calls it: a streamed copy through gRPC could serve `kubectl logs` only
// for output the runtime still held in memory, which is why `--previous` was
// unimplementable and why a bounded in-memory buffer silently dropped the
// beginning of a chatty container's output.

// ContainerLogs renders one container's logs onto stdout and stderr per opts. It
// is the kubelet's GetKubeletContainerLogs half: resolve the INSTANCE to a file,
// then read the file.
//
// stderr may be the same writer as stdout (it is, on the `kubectl logs` path,
// because the kubelet's gate-off stream handling sends both to one response).
func (r *runtimedRuntime) ContainerLogs(ctx context.Context, namespace, podName, containerName string, opts *corev1.PodLogOptions, stdout, stderr io.Writer) error {
	if opts == nil {
		opts = &corev1.PodLogOptions{}
	}
	r.mu.Lock()
	id, t := r.lookupTrackLocked(namespace, podName)
	r.mu.Unlock()
	if t == nil {
		if pod, ok := r.retainedPod(ctx, namespace, podName); ok {
			return r.retainedContainerLogs(ctx, pod, containerName, opts, stdout, stderr)
		}
		return vkadapter.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	path, err := r.containerLogPath(ctx, id, namespace, podName, containerName, opts.Previous)
	if err != nil {
		return err
	}
	readOpts := r.readOptions(opts)
	var isRunning podlogs.RunningFunc
	if opts.Follow {
		isRunning = r.followRunning(id, t, namespace, podName, containerName)
	}
	return podlogs.ReadLogs(ctx, path, readOpts, isRunning, r.log, stdout, stderr)
}

// GetContainerLogs satisfies the Runtime seam by rendering ContainerLogs into a
// ReadCloser.
//
// Two delivery shapes, kept from the RPC-backed implementation this replaced and
// for the same reason: a NON-follow read is performed synchronously into a buffer
// so a resolution failure (unknown pod, no log file, an unreadable file) is
// returned by THIS call and can become a proper HTTP status, while a FOLLOW read
// returns a pipe fed by a goroutine so lines reach the client as they land.
// Closing the returned reader cancels the follow.
func (r *runtimedRuntime) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
	if opts == nil {
		opts = &corev1.PodLogOptions{}
	}
	if !opts.Follow {
		var buf bytes.Buffer
		if err := r.ContainerLogs(ctx, namespace, podName, containerName, opts, &buf, &buf); err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	go func() {
		defer cancel()
		err := r.ContainerLogs(ctx, namespace, podName, containerName, opts, pw, pw)
		// A nil error closes the pipe with io.EOF, the clean end of a followed
		// stream (the container exited and its final drain completed).
		_ = pw.CloseWithError(err)
	}()
	return &followReader{PipeReader: pr, cancel: cancel}, nil
}

// followReader is the follow path's ReadCloser: closing it stops the producing
// goroutine as well as the read side.
type followReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

// Close cancels the underlying read and closes the pipe.
func (f *followReader) Close() error {
	f.cancel()
	return f.PipeReader.Close()
}

// readOptions translates the kubelet's PodLogOptions into the reader's options.
//
// sinceSeconds and sinceTime are one absolute instant to the reader: the kubelet
// API accepts either (and rejects both together), and a relative sinceSeconds is
// resolved here, against the provider's clock, because that is the only clock
// that knows when the request was made. An absolute sinceTime wins if both
// somehow arrive.
func (r *runtimedRuntime) readOptions(opts *corev1.PodLogOptions) *podlogs.Options {
	out := &podlogs.Options{
		TailLines:  opts.TailLines,
		LimitBytes: opts.LimitBytes,
		Timestamps: opts.Timestamps,
		Follow:     opts.Follow,
	}
	switch {
	case opts.SinceTime != nil:
		out.Since = opts.SinceTime.Time
	case opts.SinceSeconds != nil:
		out.Since = r.clk.Now().Add(-time.Duration(*opts.SinceSeconds) * time.Second)
	}
	return out
}

// containerLogPath resolves which instance's file to read.
//
// previous names the LAST TERMINATED instance, whose path the runtime carries on
// last_termination_state.log_path; it is empty once this package's garbage
// collector has pruned that instance, and the refusal below is the honest answer
// rather than silently showing the current instance under the previous one's
// name. The current instance's path is ContainerStatus.log_path, falling back to
// the terminated state's own path for a container that has exited and has no
// successor.
func (r *runtimedRuntime) containerLogPath(ctx context.Context, id, namespace, podName, containerName string, previous bool) (string, error) {
	cs, _, err := r.containerStatus(ctx, id, namespace, podName, containerName)
	if err != nil {
		return "", err
	}
	if previous {
		path := cs.GetLastTerminationState().GetTerminated().GetLogPath()
		if path == "" {
			return "", fmt.Errorf("previous terminated container %q in pod %q not found", containerName, podName)
		}
		return path, nil
	}
	if path := cs.GetLogPath(); path != "" {
		return path, nil
	}
	if path := cs.GetState().GetTerminated().GetLogPath(); path != "" {
		return path, nil
	}
	return "", fmt.Errorf("container %q in pod %q has no log file", containerName, podName)
}

// containerStatus returns the runtime's status for one container of the tracked
// pod id, searching the regular, init and ephemeral container lists. All three are
// `kubectl logs -c` addressable, as on the kubelet; the ephemeral list matters
// most here, because interactive attach to a native process is unsupported, so
// `kubectl debug` output reaches the user only through these logs.
//
// forgotten reports that the runtime answered NotFound for the pod, which it
// usually does in the response body rather than as a call error. The error is
// still returned, so a caller that makes nothing of forgotten reports it as is.
func (r *runtimedRuntime) containerStatus(ctx context.Context, id, namespace, podName, containerName string) (cs *runtimev1.ContainerStatus, forgotten bool, err error) {
	// A pod refused at admission never started a container, so the kubelet's
	// answer is validateContainerLogStatus's for a container with no status
	// (pkg/kubelet/kubelet_pods.go, v1.36.2), and the runtime, which never heard
	// of the pod, is not asked.
	if t := r.trackByID(id); t != nil && t.rejected {
		return nil, false, fmt.Errorf("container %q in pod %q is not available", containerName, podName)
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return nil, status.Code(err) == codes.NotFound, fmt.Errorf("runtimed get pod status %s/%s: %w", namespace, podName, err)
	}
	st := resp.GetStatus()
	for _, list := range [][]*runtimev1.ContainerStatus{st.GetContainerStatuses(), st.GetInitContainerStatuses(), st.GetEphemeralContainerStatuses()} {
		for _, c := range list {
			if c.GetName() == containerName {
				return c, false, nil
			}
		}
	}
	forgotten = resp.GetError().GetCode() == int32(codes.NotFound)
	return nil, forgotten, fmt.Errorf("container %q in pod %q is not available", containerName, podName)
}

// followRunning returns the follow path's exit signal for the pod id whose file
// is being read. The reader performs ONE final drain after it goes false, so
// nothing written between the last read and the exit is lost.
//
// The runtime forgets a pod as its DeletePod BEGINS and goes on stopping it, so
// while this provider's delete is running a NotFound means "still stopping", and
// the follow ends once that delete has returned and the runtime has written all
// it will. removePodLogs then unlinks the file, which the reader still holds open
// and drains through its descriptor; neither side waits on the other. A NotFound
// for a pod that is not being deleted is an error, as is any other failed read.
//
// The signal is pinned to id, not to the pod's name: a same-name successor's
// running container says nothing about this file, which no one will write again.
// t is the track followed so far, replaced when an idempotent CreatePod installs a
// fresh one. The reader calls the signal from one goroutine, so t needs no guard.
func (r *runtimedRuntime) followRunning(id string, t *podTrack, namespace, podName, containerName string) podlogs.RunningFunc {
	return func(ctx context.Context) (bool, error) {
		// Asked first because a runtime that became unreachable is assumed to be
		// running (podlogs containerRunning), which must not hold this open.
		if t.runtimeStopSucceeded() {
			return false, nil
		}
		current := r.trackByID(id)
		if current == nil {
			if trackDeleting(t) {
				return false, nil
			}
			return false, vkadapter.NotFoundf("pod %q not found", namespace+"/"+podName)
		}
		t = current
		cs, forgotten, err := r.containerStatus(ctx, id, namespace, podName, containerName)
		if forgotten {
			switch deleting, stopReturned := t.deleteProgress(); {
			case !deleting:
				return false, err
			case stopReturned:
				return false, nil
			default:
				return true, nil
			}
		}
		if err != nil {
			return false, err
		}
		return cs.GetState().GetRunning() != nil, nil
	}
}

// runtimeStop is what a track knows of the runtime DeletePod calls made for it.
// Calls can overlap (the orphan reaper and a delete), and a call made while
// another is stopping the pod returns at once, because the runtime has already
// forgotten it; so the stop counts as over only when none is in flight.
type runtimeStop struct {
	inFlight  int
	returned  bool
	succeeded bool
}

// beginRuntimeStop records a runtime DeletePod about to be made. t may be nil: a
// delete can arrive for a pod this provider does not track.
func (t *podTrack) beginRuntimeStop() {
	if t == nil {
		return
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.stop.inFlight++
}

// endRuntimeStop records that a runtime DeletePod returned with err.
func (t *podTrack) endRuntimeStop(err error) {
	if t == nil {
		return
	}
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	t.stop.inFlight--
	t.stop.returned = true
	t.stop.succeeded = t.stop.succeeded || err == nil
}

// runtimeStopSucceeded reports that the runtime confirmed the stop and no call is
// still in flight: the pod's containers are gone, whatever the runtime says next.
func (t *podTrack) runtimeStopSucceeded() bool {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.stop.succeeded && t.stop.inFlight == 0
}

// deleteProgress reports whether the track is being deleted, and whether a
// runtime DeletePod has returned with none still in flight. A failed call counts
// as returned: a runtime that has forgotten the pod after it has nothing to say
// about it, and a retry that begins afterwards makes the answer false again.
func (t *podTrack) deleteProgress() (deleting, stopReturned bool) {
	t.restartMu.Lock()
	defer t.restartMu.Unlock()
	return t.deleting, t.stop.returned && t.stop.inFlight == 0
}
