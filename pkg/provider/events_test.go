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
	"testing"
	"time"

	"k8s.io/client-go/tools/record"
)

// drainEvents reads exactly want events off the FakeRecorder channel, failing the
// test if they do not arrive within timeout. The FakeRecorder DROPS on a full
// buffer, so the caller sizes the buffer generously and reads promptly — the
// channel must never be the limiter.
func drainEvents(t *testing.T, ch <-chan string, want int, timeout time.Duration) []string {
	t.Helper()
	var got []string
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case e := <-ch:
			got = append(got, e)
		case <-deadline:
			t.Fatalf("timed out waiting for %d events, got %d: %v", want, len(got), got)
		}
	}
	return got
}

// TestProviderEmitsLifecycleEvents is the B75 gate: the HostProcess provider must
// emit Pulled/Created/Started on CreatePod and Killing on DeletePod, each carrying
// the exact reason/type and the container name in the message. A provider that
// accepts the recorder but emits nothing fails the drain (behavioral red), and it
// must NOT emit BackOff (no restart/backoff loop exists in M0).
func TestProviderEmitsLifecycleEvents(t *testing.T) {
	// Buffer strictly greater than the max events one drive produces
	// (Pulled+Created+Started+Killing = 4 for a single container) so the channel
	// never drops and never becomes the limiter.
	rec := record.NewFakeRecorder(32)
	p := NewHostProcess("test-node", t.TempDir(), "127.0.0.1", rec)

	// A LONG-LIVED process so the reap goroutine does not exit and race the Started
	// emit; DeletePod (cleanup) tears it down.
	pod := newPod("default", "evt", "/bin/sleep", "60")
	t.Cleanup(func() { _ = p.DeletePod(context.Background(), pod) })

	if err := p.CreatePod(context.Background(), pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}

	// The FakeRecorder renders each event as "<EventType> <Reason> <message>".
	// Assert the SET of create-events (order-insensitive: the reap goroutine and the
	// Started emit can interleave). newPod uses image "native", container "c0".
	createEvents := drainEvents(t, rec.Events, 3, 3*time.Second)
	wantCreate := map[string]bool{
		`Normal Pulled Container image "native" already present on machine`: false,
		`Normal Created Created container c0`:                               false,
		`Normal Started Started container c0`:                               false,
	}
	for _, e := range createEvents {
		if _, ok := wantCreate[e]; !ok {
			t.Fatalf("unexpected create-event %q (want one of %v)", e, keys(wantCreate))
		}
		wantCreate[e] = true
	}
	for want, seen := range wantCreate {
		if !seen {
			t.Fatalf("missing create-event %q; got %v", want, createEvents)
		}
	}

	// The Created/Started/Killing messages must name the container (the Event's
	// involved object is the Pod, so the name has to live in the message).
	for _, e := range createEvents {
		if strings.Contains(e, "Created ") || strings.Contains(e, "Started ") {
			if !strings.Contains(e, "c0") {
				t.Fatalf("create-event missing container name: %q", e)
			}
		}
	}

	// BackOff must NOT be emitted (no restart/backoff loop in M0).
	for _, e := range createEvents {
		if strings.Contains(e, "BackOff") {
			t.Fatalf("provider emitted a BackOff event it must not: %q", e)
		}
	}

	// DeletePod → exactly one Killing event, Normal, naming the container.
	if err := p.DeletePod(context.Background(), pod); err != nil {
		t.Fatalf("DeletePod: %v", err)
	}
	killEvents := drainEvents(t, rec.Events, 1, 3*time.Second)
	if got, want := killEvents[0], `Normal Killing Stopping container c0`; got != want {
		t.Fatalf("kill-event = %q, want %q", got, want)
	}
	if !strings.Contains(killEvents[0], "c0") {
		t.Fatalf("kill-event missing container name: %q", killEvents[0])
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
