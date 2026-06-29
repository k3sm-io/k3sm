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
	"strings"

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

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
	s.buf.Write(e.GetLine())
	if n := len(e.GetLine()); n == 0 || e.GetLine()[n-1] != '\n' {
		s.buf.WriteByte('\n')
	}
	return nil
}

// String returns the accumulated log text.
func (s *logSink) String() string { return s.buf.String() }
