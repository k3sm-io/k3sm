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
	path, err := r.containerLogPath(ctx, namespace, podName, containerName, opts.Previous)
	if err != nil {
		return err
	}
	readOpts := r.readOptions(opts)
	var isRunning podlogs.RunningFunc
	if opts.Follow {
		isRunning = func(ctx context.Context) (bool, error) {
			return r.containerRunning(ctx, namespace, podName, containerName)
		}
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
func (r *runtimedRuntime) containerLogPath(ctx context.Context, namespace, podName, containerName string, previous bool) (string, error) {
	cs, err := r.containerStatus(ctx, namespace, podName, containerName)
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

// containerStatus returns the runtime's status for one container of a tracked
// pod, searching the regular and init container lists (an init container's logs
// are `kubectl logs -c` addressable too).
func (r *runtimedRuntime) containerStatus(ctx context.Context, namespace, podName, containerName string) (*runtimev1.ContainerStatus, error) {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	resp, err := r.rt.GetPodStatus(ctx, &runtimev1.GetPodStatusRequest{PodId: id})
	if err != nil {
		return nil, fmt.Errorf("runtimed get pod status %s/%s: %w", namespace, podName, err)
	}
	st := resp.GetStatus()
	for _, cs := range st.GetContainerStatuses() {
		if cs.GetName() == containerName {
			return cs, nil
		}
	}
	for _, cs := range st.GetInitContainerStatuses() {
		if cs.GetName() == containerName {
			return cs, nil
		}
	}
	return nil, fmt.Errorf("container %q in pod %q is not available", containerName, podName)
}

// containerRunning reports whether the named container is running right now. It
// is the follow path's exit signal: the reader performs ONE final drain after
// this goes false, so nothing written between the last read and the exit is lost.
func (r *runtimedRuntime) containerRunning(ctx context.Context, namespace, podName, containerName string) (bool, error) {
	cs, err := r.containerStatus(ctx, namespace, podName, containerName)
	if err != nil {
		return false, err
	}
	return cs.GetState().GetRunning() != nil, nil
}
