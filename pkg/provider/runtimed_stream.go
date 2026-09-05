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

	"google.golang.org/grpc"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// watchStream is an in-process grpc.ServerStreamingServer[PodStatusEvent]. The
// runtimed Runtime satisfies runtimev1.RuntimeServer (server-side), so to consume
// its WatchPodStatus in-process — without a gRPC socket — we hand it this stream:
// Send pushes each event onto a buffered channel the provider reads. It mirrors
// the fake stream runtimed's own tests use, making a future daemon split (a real
// gRPC stream) a swap of this type, not a redesign.
type watchStream struct {
	grpc.ServerStream
	ctx context.Context
	ch  chan *runtimev1.PodStatusEvent
}

// newWatchStream returns a watchStream bound to ctx with a buffered event
// channel. The buffer absorbs bursts so a busy reader never blocks the runtime's
// publish path.
func newWatchStream(ctx context.Context) *watchStream {
	return &watchStream{ctx: ctx, ch: make(chan *runtimev1.PodStatusEvent, 128)}
}

// Context returns the stream context (honored by WatchPodStatus for cancellation).
func (s *watchStream) Context() context.Context { return s.ctx }

// Send delivers ev to the reader, or returns the context error if cancelled.
func (s *watchStream) Send(ev *runtimev1.PodStatusEvent) error {
	select {
	case s.ch <- ev:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
