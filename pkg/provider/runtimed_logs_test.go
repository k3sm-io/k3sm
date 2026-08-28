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
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/provider/vkadapter"
)

// logCaptureRuntime is a runtimev1.RuntimeServer that records the GetLogsRequest
// the provider built and replays canned entries back over the stream. Recording
// the REQUEST (not a provider-internal struct) is what makes the assertions below
// wire-level: every kubectl log option has to survive the translation into the
// apis GetLogsRequest or the runtime never sees it.
type logCaptureRuntime struct {
	runtimev1.UnimplementedRuntimeServer

	mu      sync.Mutex
	got     *runtimev1.GetLogsRequest
	entries []*runtimev1.LogEntry
	// follow, when non-nil, is sent after the canned entries and before the
	// stream ends, so the follow path's incremental delivery is observable.
	follow chan *runtimev1.LogEntry
}

func (f *logCaptureRuntime) CreatePod(_ context.Context, req *runtimev1.CreatePodRequest) (*runtimev1.CreatePodResponse, error) {
	return &runtimev1.CreatePodResponse{Status: &runtimev1.PodStatus{PodId: req.GetPod().GetPodId(), Phase: runtimev1.PodPhase_POD_PHASE_RUNNING}}, nil
}

func (f *logCaptureRuntime) GetLogs(req *runtimev1.GetLogsRequest, stream grpc.ServerStreamingServer[runtimev1.LogEntry]) error {
	f.mu.Lock()
	f.got = req
	entries := f.entries
	f.mu.Unlock()

	for _, e := range entries {
		if err := stream.Send(e); err != nil {
			return err
		}
	}
	if !req.GetFollow() || f.follow == nil {
		return nil
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case e, ok := <-f.follow:
			if !ok {
				return nil
			}
			if err := stream.Send(e); err != nil {
				return err
			}
		}
	}
}

// request returns the recorded GetLogsRequest.
func (f *logCaptureRuntime) request(t *testing.T) *runtimev1.GetLogsRequest {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.got == nil {
		t.Fatal("runtime never received a GetLogs request")
	}
	return f.got
}

// TestContainerLogOptsForwarded is the B163 gate. `kubectl logs` options reach the
// provider as a vkadapter.ContainerLogOpts and only reach the runtime if
// GetContainerLogs translates them into the GetLogsRequest fields apis has always
// defined (follow, tail_lines, since_time, timestamps, previous, limit_bytes). M1
// deliberately wired tail_lines alone and scoped the gate to non-follow; every
// other option was therefore accepted from the client and silently dropped on the
// floor, which is worse than rejecting it — `--since`/`--limit-bytes` returned a
// full, unfiltered buffer that LOOKED like a correct answer.
//
// The assertions are on the REQUEST THE RUNTIME RECEIVED, not on any provider
// field, so a translation that copies an option into a struct it never sends
// still fails.
func TestContainerLogOptsForwarded(t *testing.T) {
	// A fixed "now" so the relative sinceSeconds option has an exact expected
	// absolute since_time (the proto carries only the absolute form).
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	sinceAbs := time.Date(2026, 8, 28, 11, 30, 0, 0, time.UTC)

	tests := []struct {
		name string
		opts vkadapter.ContainerLogOpts
		want *runtimev1.GetLogsRequest
	}{
		{
			name: "no options is a plain whole-buffer read",
			opts: vkadapter.ContainerLogOpts{},
			want: &runtimev1.GetLogsRequest{},
		},
		{
			name: "tail lines",
			opts: vkadapter.ContainerLogOpts{Tail: 12},
			want: &runtimev1.GetLogsRequest{TailLines: 12},
		},
		{
			name: "timestamps",
			opts: vkadapter.ContainerLogOpts{Timestamps: true},
			want: &runtimev1.GetLogsRequest{Timestamps: true},
		},
		{
			name: "limit bytes",
			opts: vkadapter.ContainerLogOpts{LimitBytes: 4096},
			want: &runtimev1.GetLogsRequest{LimitBytes: 4096},
		},
		{
			name: "absolute since time",
			opts: vkadapter.ContainerLogOpts{SinceTime: sinceAbs},
			want: &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(sinceAbs)},
		},
		{
			name: "relative since seconds resolves against the clock",
			opts: vkadapter.ContainerLogOpts{SinceSeconds: 1800},
			want: &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(now.Add(-1800 * time.Second))},
		},
		{
			name: "an absolute since time wins over sinceSeconds",
			opts: vkadapter.ContainerLogOpts{SinceTime: sinceAbs, SinceSeconds: 99},
			want: &runtimev1.GetLogsRequest{SinceTime: timestamppb.New(sinceAbs)},
		},
		{
			name: "every option at once",
			opts: vkadapter.ContainerLogOpts{Tail: 5, LimitBytes: 64, Timestamps: true, SinceTime: sinceAbs},
			want: &runtimev1.GetLogsRequest{TailLines: 5, LimitBytes: 64, Timestamps: true, SinceTime: timestamppb.New(sinceAbs)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &logCaptureRuntime{entries: []*runtimev1.LogEntry{{Line: []byte("hello")}}}
			r := newStreamProvider(t, f)
			r.clk = testclock.NewFakeClock(now)

			rc, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", tt.opts)
			if err != nil {
				t.Fatalf("GetContainerLogs: %v", err)
			}
			defer func() { _ = rc.Close() }()
			if _, err := io.ReadAll(rc); err != nil {
				t.Fatalf("read logs: %v", err)
			}

			got := f.request(t)
			if got.GetContainer() != "c0" {
				t.Errorf("container = %q, want %q", got.GetContainer(), "c0")
			}
			if got.GetTailLines() != tt.want.GetTailLines() {
				t.Errorf("tail_lines = %d, want %d", got.GetTailLines(), tt.want.GetTailLines())
			}
			if got.GetLimitBytes() != tt.want.GetLimitBytes() {
				t.Errorf("limit_bytes = %d, want %d", got.GetLimitBytes(), tt.want.GetLimitBytes())
			}
			if got.GetTimestamps() != tt.want.GetTimestamps() {
				t.Errorf("timestamps = %v, want %v", got.GetTimestamps(), tt.want.GetTimestamps())
			}
			if got.GetFollow() != tt.want.GetFollow() {
				t.Errorf("follow = %v, want %v", got.GetFollow(), tt.want.GetFollow())
			}
			if got.GetPrevious() != tt.want.GetPrevious() {
				t.Errorf("previous = %v, want %v", got.GetPrevious(), tt.want.GetPrevious())
			}
			switch want := tt.want.GetSinceTime(); {
			case want == nil && got.GetSinceTime() != nil:
				t.Errorf("since_time = %v, want unset", got.GetSinceTime().AsTime())
			case want != nil && got.GetSinceTime() == nil:
				t.Errorf("since_time unset, want %v", want.AsTime())
			case want != nil && !got.GetSinceTime().AsTime().Equal(want.AsTime()):
				t.Errorf("since_time = %v, want %v", got.GetSinceTime().AsTime(), want.AsTime())
			}
		})
	}

	// previous is a distinct axis: the provider must forward it even though the
	// runtime does not serve it yet, so the client gets the runtime's explicit
	// refusal rather than the CURRENT instance's logs mislabelled as the previous
	// one's. The fake serves it, so this asserts forwarding only.
	t.Run("previous is forwarded, not swallowed", func(t *testing.T) {
		f := &logCaptureRuntime{entries: []*runtimev1.LogEntry{{Line: []byte("old")}}}
		r := newStreamProvider(t, f)

		rc, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", vkadapter.ContainerLogOpts{Previous: true})
		if err != nil {
			t.Fatalf("GetContainerLogs: %v", err)
		}
		defer func() { _ = rc.Close() }()
		if _, err := io.ReadAll(rc); err != nil {
			t.Fatalf("read logs: %v", err)
		}
		if !f.request(t).GetPrevious() {
			t.Error("previous = false on the wire, want true")
		}
	})

	// follow sets the wire field AND changes the provider's delivery contract: the
	// reader must hand back lines as they arrive instead of buffering the whole
	// stream, or `kubectl logs -f` shows nothing until the container exits.
	t.Run("follow streams incrementally", func(t *testing.T) {
		f := &logCaptureRuntime{
			entries: []*runtimev1.LogEntry{{Line: []byte("first")}},
			follow:  make(chan *runtimev1.LogEntry, 1),
		}
		r := newStreamProvider(t, f)

		rc, err := r.GetContainerLogs(context.Background(), "default", "web", "c0", vkadapter.ContainerLogOpts{Follow: true})
		if err != nil {
			t.Fatalf("GetContainerLogs: %v", err)
		}
		defer func() { _ = rc.Close() }()

		buf := make([]byte, 64)
		n, err := rc.Read(buf)
		if err != nil {
			t.Fatalf("read before the stream ended: %v", err)
		}
		if got := string(buf[:n]); !strings.HasPrefix(got, "first") {
			t.Fatalf("first read = %q, want the buffered line while the stream is still open", got)
		}

		f.follow <- &runtimev1.LogEntry{Line: []byte("later")}
		n, err = rc.Read(buf)
		if err != nil {
			t.Fatalf("read of the followed line: %v", err)
		}
		if got := string(buf[:n]); !strings.HasPrefix(got, "later") {
			t.Fatalf("second read = %q, want the line written after the stream opened", got)
		}
		if !f.request(t).GetFollow() {
			t.Error("follow = false on the wire, want true")
		}
	})
}
