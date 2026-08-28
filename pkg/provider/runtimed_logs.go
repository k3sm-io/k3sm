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
	"io"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// GetContainerLogs serves `kubectl logs` from the runtime's GetLogs RPC, honoring
// the full kubelet option set: tail, since, timestamps, limit-bytes, previous and
// follow. Every option is translated into the apis GetLogsRequest and applied by
// the RUNTIME (which owns the buffer and its per-line timestamps) — the provider
// never re-filters, so what the client asked for and what the runtime evaluated
// are the same predicate.
//
// Two delivery shapes, deliberately:
//   - non-follow reads the whole selection into a buffer and returns it, so a
//     runtime-side failure (unknown pod, an option the runtime refuses) surfaces
//     as an error from THIS call and becomes a proper HTTP status;
//   - follow returns a pipe fed by a goroutine, so lines reach the client as they
//     are written. Its errors can only arrive mid-stream, as a Read error.
//
// Closing the returned ReadCloser cancels the follow stream; the non-follow reader
// holds no resources.
func (r *runtimedRuntime) GetContainerLogs(ctx context.Context, namespace, podName, containerName string, opts vkadapter.ContainerLogOpts) (io.ReadCloser, error) {
	id, _, _, ok := r.lookup(namespace, podName)
	if !ok {
		return nil, vkadapter.NotFoundf("pod %q not found", namespace+"/"+podName)
	}
	req := r.logsRequest(id, containerName, opts)
	if opts.Follow {
		return r.followLogs(ctx, req, namespace, podName, containerName), nil
	}
	sink := newLogSink(ctx)
	if err := r.rt.GetLogs(req, sink); err != nil {
		return nil, fmt.Errorf("runtimed logs %s/%s/%s: %w", namespace, podName, containerName, err)
	}
	return io.NopCloser(strings.NewReader(sink.String())), nil
}

// logsRequest translates the kubelet's ContainerLogOpts into the wire request.
//
// sinceSeconds and sinceTime are one field on the wire: the kubelet API accepts
// either (and rejects both together), while GetLogsRequest carries only the
// ABSOLUTE since_time — the form the runtime can evaluate against a stored line
// timestamp without knowing when the request was made. A relative sinceSeconds is
// therefore resolved here, against the provider's clock, and an absolute sinceTime
// wins if both somehow arrive.
func (r *runtimedRuntime) logsRequest(podID, container string, opts vkadapter.ContainerLogOpts) *runtimev1.GetLogsRequest {
	req := &runtimev1.GetLogsRequest{
		PodId:      podID,
		Container:  container,
		Follow:     opts.Follow,
		TailLines:  int64(opts.Tail),
		Timestamps: opts.Timestamps,
		Previous:   opts.Previous,
		LimitBytes: int64(opts.LimitBytes),
	}
	switch {
	case !opts.SinceTime.IsZero():
		req.SinceTime = timestamppb.New(opts.SinceTime)
	case opts.SinceSeconds > 0:
		req.SinceTime = timestamppb.New(r.clk.Now().Add(-time.Duration(opts.SinceSeconds) * time.Second))
	}
	return req
}

// followLogs runs GetLogs in a goroutine that writes each entry into a pipe, and
// returns the read end. The goroutine's lifetime is bounded twice over: by ctx
// (the client's request context) and by Close on the returned reader, which both
// cancels that context and closes the pipe — so an in-flight Send unblocks with
// ErrClosedPipe even if the runtime is not watching its context.
func (r *runtimedRuntime) followLogs(ctx context.Context, req *runtimev1.GetLogsRequest, namespace, podName, containerName string) io.ReadCloser {
	ctx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	go func() {
		err := r.rt.GetLogs(req, &logPipe{ctx: ctx, w: pw})
		if err != nil {
			err = fmt.Errorf("runtimed logs %s/%s/%s: %w", namespace, podName, containerName, err)
		}
		// A nil error closes the pipe with io.EOF, which is the clean end of a
		// followed stream (the container exited).
		_ = pw.CloseWithError(err)
	}()
	return &followReader{PipeReader: pr, cancel: cancel}
}

// followReader is the follow path's ReadCloser: closing it stops the producing
// goroutine as well as the read side.
type followReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

// Close cancels the underlying GetLogs stream and closes the pipe.
func (f *followReader) Close() error {
	f.cancel()
	return f.PipeReader.Close()
}

// logSink is an in-process grpc.ServerStreamingServer[LogEntry] that collects the
// runtime's GetLogs output into a buffer the VK logs handler returns as a
// ReadCloser. Like watchStream, it lets the provider consume a streaming
// RuntimeServer method in-process without a gRPC socket; the M2 daemon split
// swaps it for a real client stream.
type logSink struct {
	grpc.ServerStream
	ctx context.Context
	buf strings.Builder
}

// newLogSink returns a logSink bound to ctx.
func newLogSink(ctx context.Context) *logSink {
	return &logSink{ctx: ctx}
}

// Context returns the stream context.
func (s *logSink) Context() context.Context { return s.ctx }

// Send appends a log entry's line to the buffer, adding a newline so the on-wire
// format matches the kubelet's line-delimited logs.
func (s *logSink) Send(e *runtimev1.LogEntry) error {
	s.buf.Write(logLineBytes(e))
	return nil
}

// String returns the accumulated log text.
func (s *logSink) String() string { return s.buf.String() }

// logPipe is the follow path's counterpart to logSink: instead of accumulating,
// it writes each entry straight through to w. A blocked write is the intended
// backpressure — it propagates the client's read rate to the runtime rather than
// growing an unbounded buffer in the provider.
type logPipe struct {
	grpc.ServerStream
	ctx context.Context
	w   io.Writer
}

// Context returns the stream context.
func (p *logPipe) Context() context.Context { return p.ctx }

// Send writes one log entry through to the reader.
func (p *logPipe) Send(e *runtimev1.LogEntry) error {
	_, err := p.w.Write(logLineBytes(e))
	return err
}

// logLineBytes renders one entry in the kubelet's line-delimited log format: the
// line as the runtime emitted it (already carrying the RFC3339 prefix when the
// request asked for timestamps), newline-terminated if it is not already.
func logLineBytes(e *runtimev1.LogEntry) []byte {
	line := e.GetLine()
	if n := len(line); n > 0 && line[n-1] == '\n' {
		return line
	}
	out := make([]byte, 0, len(line)+1)
	out = append(out, line...)
	return append(out, '\n')
}
