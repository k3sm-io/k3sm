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
	"slices"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// conditions returns the LAST condition set the VK callback carried for podID.
func (n *leaseNode) conditions(podID string) []corev1.PodCondition {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.conds[podID])
}

// awaitCondition blocks until the VK callback has reported podID carrying a
// condition of type ct with the given status, and returns it. Waiting for the
// published condition (rather than reading a computed value) is what keeps these
// assertions on the real path: the value asserted is the one a Service
// controller would see.
func (n *leaseNode) awaitCondition(t *testing.T, podID string, ct corev1.PodConditionType, want corev1.ConditionStatus) corev1.PodCondition {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if c := findPodCondition(n.conditions(podID), ct); c != nil && c.Status == want {
			return *c
		}
		select {
		case <-n.notify:
		case <-time.After(5 * time.Millisecond):
		case <-deadline:
			got := "<absent>"
			if c := findPodCondition(n.conditions(podID), ct); c != nil {
				got = string(c.Status) + "/" + c.Reason
			}
			t.Fatalf("published %s for %s = %s, want %s", ct, podID, got, want)
		}
	}
}

// condStatusOf is the status of the named condition in conds, or "<absent>".
func condStatusOf(conds []corev1.PodCondition, ct corev1.PodConditionType) string {
	if c := findPodCondition(conds, ct); c != nil {
		return string(c.Status)
	}
	return "<absent>"
}

// TestVMPodReadyWaitsForTransportOverride is the B314 named gate: a vm pod's
// POD-LEVEL PodReady is withheld until the Service proxy holds the published->live
// transport override that makes the pod dialable at the address its EndpointSlice
// carries — and is withheld again if that override is lost.
//
// WHY IT IS NOT VACUOUS. Every verdict is read off the status the provider
// PUBLISHED to VK, built by the real buildStatus path from a status the fake
// runtimed pushed down the real watch stream, with the pod's published /32 drawn
// from the node's own allocator. The container in every pushed status is Running
// and Ready, so a PodReady=False here can only come from the transport gate; the
// native leg then proves the gate is vm-scoped rather than a blanket delay, and
// the ContainersReady/container-Ready assertions prove the gate is confined to the
// pod-level condition instead of being smuggled in by clearing a container's Ready.
func TestVMPodReadyWaitsForTransportOverride(t *testing.T) {
	t.Parallel()

	t.Run("a vm pod with ready containers and no lease is not PodReady", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "waiting")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		// The node DID provision a guest for this pod — so the withheld readiness
		// below is the missing lease, not a pod that never reached the vm path.
		if _, ok := n.adapt.GuestNetwork(id); !ok {
			t.Fatalf("no guest network recorded for %s; the pod never took the vm path", id)
		}

		n.rt.push(t, id, "") // the guest holds no lease yet
		ready := n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionFalse)
		if ready.Reason != reasonGuestTransportNotReady {
			t.Errorf("PodReady reason = %q, want %q", ready.Reason, reasonGuestTransportNotReady)
		}
		if ready.Message == "" {
			t.Error("PodReady carries no message; an operator has nothing to act on")
		}
		// The SAME message serves the lease-loss case below, so it must not read as
		// start-up-only: a pod that was Ready for hours and lost its lease carries
		// this string too, and "still starting" would misdirect the reader.
		if !strings.Contains(ready.Message, "lost") {
			t.Errorf("PodReady message %q does not cover the lease-loss state", ready.Message)
		}

		// The containers ARE ready: the gate is a statement about the node's path
		// to the pod, and must not be laundered through the container-level facts.
		conds := n.conditions(id)
		if got := condStatusOf(conds, corev1.ContainersReady); got != string(corev1.ConditionTrue) {
			t.Errorf("ContainersReady = %s, want True (the containers are running and ready)", got)
		}
		if sets, live := n.sink.snapshot(); sets != 0 {
			t.Fatalf("the sink was called %d times (last=%v) for a pod with no lease", sets, renderOverrides(live))
		}
	})

	t.Run("the lease arrives and PodReady flips, with a stable transition time", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "leased")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		pub := n.published(t, id)

		n.rt.push(t, id, "")
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionFalse)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		flip := n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)
		if flip.Reason != "" || flip.Message != "" {
			t.Errorf("a True PodReady carries reason=%q message=%q, want both empty", flip.Reason, flip.Message)
		}
		if flip.LastTransitionTime.IsZero() {
			t.Fatal("the PodReady flip carries a zero LastTransitionTime")
		}

		// An identical re-observation must not restamp the transition: a PodReady
		// whose LastTransitionTime moves on every status resets minReadySeconds and
		// stalls a rolling update (see buildStatus).
		before := n.seenCount(id)
		n.rt.push(t, id, leaseFirst)
		n.awaitStatus(t, id, before+1)
		again := n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)
		if !again.LastTransitionTime.Equal(&flip.LastTransitionTime) {
			t.Errorf("LastTransitionTime moved on an identical observation: %v -> %v",
				flip.LastTransitionTime, again.LastTransitionTime)
		}
	})

	t.Run("a lost lease withholds PodReady again", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := vmPod("team-a", "lost")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)
		pub := n.published(t, id)

		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)

		// The guest rebooted and has not leased again. Its published address is
		// undialable, so the backend must leave the EndpointSlice.
		n.rt.push(t, id, "")
		n.awaitOverrides(t, map[string]string{})
		lost := n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionFalse)
		if lost.Reason != reasonGuestTransportNotReady {
			t.Errorf("PodReady reason after the lease loss = %q, want %q", lost.Reason, reasonGuestTransportNotReady)
		}
		if lost.Message == "" {
			t.Error("the lease-loss PodReady carries no message")
		}
	})

	t.Run("a native pod with the same container state is Ready immediately", func(t *testing.T) {
		t.Parallel()
		n := newLeaseNode(t)
		pod := hostPod("team-a", "native")
		id := string(pod.UID)
		if err := n.r.CreatePod(context.Background(), pod); err != nil {
			t.Fatalf("CreatePod: %v", err)
		}
		n.watch(t)

		// The IDENTICAL status the vm leg was withheld on: same container, Running
		// and Ready, no transport address.
		n.rt.push(t, id, "")
		n.awaitCondition(t, id, corev1.PodReady, corev1.ConditionTrue)

		// The full provider-owned condition set, unchanged by the gate's existence.
		want := []struct {
			t corev1.PodConditionType
			s corev1.ConditionStatus
		}{
			{corev1.PodInitialized, corev1.ConditionTrue},
			{corev1.PodReady, corev1.ConditionTrue},
			{corev1.ContainersReady, corev1.ConditionTrue},
			{corev1.PodScheduled, corev1.ConditionTrue},
		}
		conds := n.conditions(id)
		if len(conds) != len(want) {
			t.Fatalf("native pod conditions = %v, want exactly %d", conds, len(want))
		}
		for i, w := range want {
			got := conds[i]
			if got.Type != w.t || got.Status != w.s || got.Reason != "" || got.Message != "" {
				t.Errorf("condition[%d] = %+v, want {Type:%s Status:%s} with no reason/message", i, got, w.t, w.s)
			}
		}
	})
}

// seenCount is the number of status callbacks delivered for podID so far.
func (n *leaseNode) seenCount(podID string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.seen[podID]
}

// TestComputeReadinessTransportGate is the pure table over the gate's own rules:
// what each combination of the container precondition, the transport gate and a
// readinessGate reduces PodReady to.
func TestComputeReadinessTransportGate(t *testing.T) {
	t.Parallel()

	gated := gatedPod([]string{"example.com/g"},
		corev1.PodCondition{Type: corev1.PodConditionType("example.com/g"), Status: corev1.ConditionFalse})

	cases := []struct {
		name            string
		pod             *corev1.Pod
		containersReady bool
		transport       transportGate
		want            corev1.ConditionStatus
		wantReason      string
	}{
		{
			name:            "a satisfied gate is ignored (every native pod)",
			containersReady: true, transport: transportReady,
			want: corev1.ConditionTrue,
		},
		{
			name:            "a pending gate withholds PodReady",
			containersReady: true, transport: transportPending,
			want: corev1.ConditionFalse, wantReason: reasonGuestTransportNotReady,
		},
		{
			name:            "containers not ready wins over a pending gate",
			containersReady: false, transport: transportPending,
			want: corev1.ConditionFalse, wantReason: "ContainersNotReady",
		},
		{
			name:            "a pending gate wins over an unsatisfied readinessGate",
			pod:             gated,
			containersReady: true, transport: transportPending,
			want: corev1.ConditionFalse, wantReason: reasonGuestTransportNotReady,
		},
		{
			name:            "a satisfied gate still lets a readinessGate block",
			pod:             gated,
			containersReady: true, transport: transportReady,
			want: corev1.ConditionFalse, wantReason: "ReadinessGatesNotReady",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := computeReadiness(tc.pod, tc.containersReady, tc.transport)
			if got.Status != tc.want || got.Reason != tc.wantReason {
				t.Errorf("computeReadiness = %s/%q, want %s/%q", got.Status, got.Reason, tc.want, tc.wantReason)
			}
		})
	}
}

// TestPostStartRefreshKeepsTransportGate pins the composition of the two gates at
// the seam the postStart overlay re-derives readiness through: a refresh must not
// hand a vm pod PodReady=True just because its containers came up.
func TestPostStartRefreshKeepsTransportGate(t *testing.T) {
	t.Parallel()

	build := func(transport transportGate) *corev1.PodStatus {
		return toPodStatus(nil, runningRS("uid-r", time.Unix(2000, 0)), "192.168.1.10",
			metav1.NewTime(time.Unix(1000, 0)), nil, transport)
	}

	t.Run("a refresh carrying the pending gate keeps PodReady withheld", func(t *testing.T) {
		t.Parallel()
		st := build(transportPending)
		refreshReadinessConditions(nil, st, transportPending)
		c := findPodCondition(st.Conditions, corev1.PodReady)
		if c == nil || c.Status != corev1.ConditionFalse || c.Reason != reasonGuestTransportNotReady {
			t.Fatalf("PodReady after the refresh = %+v, want False/%s", c, reasonGuestTransportNotReady)
		}
		if got := condStatusOf(st.Conditions, corev1.ContainersReady); got != string(corev1.ConditionTrue) {
			t.Errorf("ContainersReady after the refresh = %s, want True", got)
		}
	})

	t.Run("a container held NotReady by postStart wins the reason", func(t *testing.T) {
		t.Parallel()
		st := build(transportPending)
		for i := range st.ContainerStatuses {
			st.ContainerStatuses[i].Ready = false
		}
		refreshReadinessConditions(nil, st, transportPending)
		c := findPodCondition(st.Conditions, corev1.PodReady)
		if c == nil || c.Status != corev1.ConditionFalse || c.Reason != "ContainersNotReady" {
			t.Fatalf("PodReady after the refresh = %+v, want False/ContainersNotReady", c)
		}
	})
}
