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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	runtimev1 "k3sm.io/apis/runtime/v1"
	runtimed "k3sm.io/runtimed/pkg/runtime"
)

// TestShimInactiveConditionBecomesAnEvent pins the node half of B243's
// detection: runtimed publishes k3sm.io/shim-inactive on PodStatus.conditions
// and has no API client, so the provider must (1) forward the condition onto
// the published pod status, and (2) record exactly ONE Warning ShimInactive
// Event per pod per reason carrying the condition's message, however many
// status builds observe it; a second reason is its own Event.
func TestShimInactiveConditionBecomesAnEvent(t *testing.T) {
	t.Parallel()
	rec := record.NewFakeRecorder(16)
	f := newFakeRuntimeServer()
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10", Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder: rec, ResolverVIP: "10.43.0.10",
	}, nil, nil)
	ctx := context.Background()

	pod := restrictedShellPod("py", "", corev1.Container{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/usr/bin/python3"}})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	restricted := shimInactiveCondition(runtimed.ShimInactiveReason, "c0", "/usr/bin/python3\x1b[2J")
	f.setConditions(string(pod.UID), restricted)

	for i := range 3 {
		st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
		if err != nil {
			t.Fatalf("GetPodStatus #%d: %v", i, err)
		}
		var got []corev1.PodCondition
		for _, c := range st.Conditions {
			if c.Type == runtimed.ShimInactiveConditionType {
				got = append(got, c)
			}
		}
		if len(got) != 1 {
			t.Fatalf("status #%d carries %d %s conditions, want exactly 1 (forwarded, not duplicated): %+v",
				i, len(got), runtimed.ShimInactiveConditionType, st.Conditions)
		}
		if got[0].Status != corev1.ConditionTrue || got[0].Reason != runtimed.ShimInactiveReason || got[0].Message != stripControl(restricted.GetMessage()) {
			t.Fatalf("forwarded condition = %+v, want True/%s with the runtime's message, control characters stripped", got[0], runtimed.ShimInactiveReason)
		}
	}
	// The pod-list path is the same convergence and must not re-fire either.
	if _, err := r.GetPods(ctx); err != nil {
		t.Fatalf("GetPods: %v", err)
	}

	ev := nextLifecycleEvent(rec.Events, time.Second)
	wantMsg := stripControl(restricted.GetMessage())
	if want := corev1.EventTypeWarning + " " + reasonShimInactive + " " + wantMsg; ev != want {
		t.Fatalf("Event = %q, want %q", ev, want)
	}
	if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
		t.Fatalf("second Event %q for the same reason, want one per pod per reason", ev)
	}

	hardened := shimInactiveCondition(runtimed.ShimInactiveHardenedReason, "c1", "/app/server")
	f.setConditions(string(pod.UID), restricted, hardened)
	for range 2 {
		if _, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name); err != nil {
			t.Fatalf("GetPodStatus: %v", err)
		}
	}
	if want := corev1.EventTypeWarning + " " + reasonShimInactive + " " + hardened.GetMessage(); nextLifecycleEvent(rec.Events, time.Second) != want {
		t.Fatalf("no Event for the second reason, want %q", want)
	}
	if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
		t.Fatalf("unexpected extra Event %q", ev)
	}

	// A FALSE condition is published but is not a loss: no Event.
	other := restrictedShellPod("ok", "", corev1.Container{Name: "c0", Image: runtimed.NativeImage, Command: []string{"/bin/sh"}})
	if err := r.CreatePod(ctx, other); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	f.setConditions(string(other.UID), &runtimev1.PodCondition{
		Type: runtimed.ShimInactiveConditionType, Status: runtimev1.ConditionStatus_CONDITION_STATUS_FALSE,
	})
	if _, err := r.GetPodStatus(ctx, other.Namespace, other.Name); err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	if ev := nextLifecycleEvent(rec.Events, 100*time.Millisecond); ev != "" {
		t.Fatalf("Event %q for a FALSE condition, want none", ev)
	}
}
