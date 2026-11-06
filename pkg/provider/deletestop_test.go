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
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// stopBound bounds a wait on something the provider must already have done.
const stopBound = 5 * time.Second

// roundTripFunc is an http.RoundTripper over a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// heldStop is one DeletePod RPC the runtime is holding open, the stand-in for a
// guest working through its termination grace.
type heldStop struct {
	entered chan struct{}
	release chan struct{}
}

// holdNextStop makes the runtime hold the next DeletePod until release closes.
// Later ones answer at once, so the fixture's cleanup delete does not block.
func (n *leaseNode) holdNextStop() *heldStop {
	h := &heldStop{entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	n.rt.mu.Lock()
	n.rt.onDelete = func(string) error {
		once.Do(func() {
			close(h.entered)
			<-h.release
		})
		return nil
	}
	n.rt.mu.Unlock()
	return h
}

// answerStops makes the runtime answer every DeletePod with err.
func (n *leaseNode) answerStops(err error) {
	n.rt.mu.Lock()
	n.rt.onDelete = func(string) error { return err }
	n.rt.mu.Unlock()
}

// await blocks until ch closes, or fails the test naming what did not happen.
func await(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	if !closesWithin(ch, stopBound) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func closesWithin(ch <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	}
}

// probeLoopsEnded closes once every probe loop of pp has returned. A prober nobody
// stopped never gets there, which is how the caller's bound turns into a failure.
func probeLoopsEnded(pp *podProber) <-chan struct{} {
	ended := make(chan struct{})
	go func() {
		pp.wg.Wait()
		close(ended)
	}()
	return ended
}

// proberOf returns the pod's running prober itself, for a test that needs it
// after the runtime has been asked to stop the pod.
func (n *leaseNode) proberOf(t *testing.T, podID string) *podProber {
	t.Helper()
	n.r.mu.Lock()
	defer n.r.mu.Unlock()
	pp := n.r.probers[podID]
	if pp == nil {
		t.Fatalf("no prober for %s", podID)
	}
	return pp
}

// readStatus takes the direct status path, synchronously: when it returns, the
// provider has observed the runtime's report.
func (n *leaseNode) readStatus(t *testing.T, pod *corev1.Pod) *corev1.PodStatus {
	t.Helper()
	st, err := n.r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
	if err != nil {
		t.Fatalf("GetPodStatus: %v", err)
	}
	return st
}

// pushDeleted delivers the runtime's DELETED event carrying lease, which is what
// a real runtimed publishes as its stop ends: the guest is gone, its lease is not
// yet blanked.
func (s *leaseRuntimeServer) pushDeleted(t *testing.T, podID, lease string) {
	t.Helper()
	timer := time.NewTimer(stopBound)
	defer timer.Stop()
	st := leaseStatus(podID, s.reportedPodIP(podID), lease)
	st.Phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	select {
	case s.events <- &runtimev1.PodStatusEvent{Type: runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED, Status: st}:
	case <-timer.C:
		t.Fatalf("push DELETED for %s: the provider is not consuming the stream", podID)
	}
}

// releaseMarks is how many pods the transport feed still refuses observations for.
func (n *leaseNode) releaseMarks() int {
	n.r.transport.mu.Lock()
	defer n.r.transport.mu.Unlock()
	return len(n.r.transport.releasing)
}

// TestDeletingVMPodStopsProbesAndKeepsItsOverrideDown pins what a vm pod's stop does
// to the two things that act on its lease. Its probes end before the runtime is
// asked to stop it, so no check runs against a guest that is shutting down. Its
// override goes down at the same point, after preStop, and stays down through every
// status the runtime reports during the stop, the DELETED that still carries the
// lease above all: the override is what keeps the relay up, and a reinstall opens a
// relay onto a lease macOS may have handed to the next guest.
//
// WHY IT IS NOT VACUOUS. The probes are real loops that are first seen dialing the
// lease and the override is first seen installed, each observation is delivered down
// the provider's own status paths with the lease in it, and the sink's generation
// count catches an override that came back and left again between two reads.
func TestDeletingVMPodStopsProbesAndKeepsItsOverrideDown(t *testing.T) {
	t.Parallel()

	// servingVMPod runs a probed vm pod to the point where its probes are passing
	// against its lease through an installed override.
	servingVMPod := func(t *testing.T, pod *corev1.Pod) (*probeNode, string, string) {
		t.Helper()
		n := newProbeNode(t)
		id := n.start(t, withGateProbes(pod))
		pub := n.published(t, id)
		n.tgt.serve(leaseFirst)
		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		waitCond(t, "the probes to pass against the lease", func() bool { return n.probeReady(id) })
		return n, id, pub
	}

	for _, tc := range []struct {
		name string
		stop func(n *probeNode, pod *corev1.Pod) error
	}{
		{"DeletePod", func(n *probeNode, pod *corev1.Pod) error {
			return n.r.DeletePod(context.Background(), pod)
		}},
		{"the orphan reaper", func(n *probeNode, pod *corev1.Pod) error {
			n.r.reapOrphan(context.Background(), pod, n.r.trackByID(string(pod.UID)))
			return nil
		}},
	} {
		t.Run("through "+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := portedVMPod("team-a", "stopping")
			n, id, _ := servingVMPod(t, pod)
			pp := n.proberOf(t, id)
			held := n.holdNextStop()
			done := make(chan error, 1)
			go func() { done <- tc.stop(n, pod) }()
			await(t, "the runtime to be asked to stop the pod", held.entered)

			if !closesWithin(probeLoopsEnded(pp), 2*time.Second) {
				t.Error("the pod's probes are still running while the runtime stops it")
			}
			dials := n.tgt.count()
			sets, live := n.sink.snapshot()
			if len(live) != 0 {
				t.Errorf("overrides during the stop = %v, want none", renderOverrides(live))
			}

			// Every path a status arrives by, each carrying the lease.
			n.readStatus(t, pod)
			seen := n.seenCount(id)
			n.rt.push(t, id, leaseFirst)
			n.awaitStatus(t, id, seen+1)
			n.rt.pushDeleted(t, id, leaseFirst)
			n.awaitStatus(t, id, seen+2)
			if got, live := n.sink.snapshot(); got != sets || len(live) != 0 {
				t.Errorf("after the stop's statuses: %d generations (want %d), overrides %v (want none)",
					got, sets, renderOverrides(live))
			}

			close(held.release)
			if err := <-done; err != nil {
				t.Fatalf("stop: %v", err)
			}
			if got := n.tgt.count(); got != dials {
				t.Errorf("probe dials went from %d to %d during the stop", dials, got)
			}
			if got, live := n.sink.snapshot(); got != sets || len(live) != 0 {
				t.Errorf("after the stop: %d generations (want %d), overrides %v (want none)",
					got, sets, renderOverrides(live))
			}
			if n.r.proberFor(id) != nil {
				t.Error("the pod's prober outlived its teardown")
			}
			if got := n.releaseMarks(); got != 0 {
				t.Errorf("%d release marks left after the teardown, want none", got)
			}
		})
	}

	t.Run("a container that was not ready stays not ready during the stop", func(t *testing.T) {
		t.Parallel()
		// The probed port is never served, so the readiness verdict commits false.
		// Forgetting the prober at the stop would hand the status back to the
		// runtime's own flag, which reads true for a running container.
		n := newProbeNode(t)
		pod := vmPod("team-a", "unready")
		pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{
			ProbeHandler:     corev1.ProbeHandler{TCPSocket: &corev1.TCPSocketAction{Port: intstr.FromInt32(probeTCPPort)}},
			PeriodSeconds:    1,
			TimeoutSeconds:   3,
			SuccessThreshold: 1,
			FailureThreshold: 2,
		}
		id := n.start(t, pod)
		n.rt.push(t, id, leaseFirst)
		waitCond(t, "the readiness verdict to commit false", func() bool {
			v, ok := n.verdictOf(id)
			return ok && !v.ready && n.tgt.count() >= 2
		})
		held := n.holdNextStop()
		done := make(chan error, 1)
		go func() { done <- n.r.DeletePod(context.Background(), pod) }()
		await(t, "the runtime to be asked to stop the pod", held.entered)

		st := n.readStatus(t, pod)
		if len(st.ContainerStatuses) != 1 || st.ContainerStatuses[0].Ready {
			t.Errorf("container statuses during the stop = %+v, want c0 not ready", st.ContainerStatuses)
		}
		close(held.release)
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
	})

	t.Run("preStop still reaches the pod through its relay, with the probes already ended", func(t *testing.T) {
		t.Parallel()
		// A preStop httpGet dials the pod's published address, and for a vm pod only
		// the relay answers there, so the override must outlast the hook.
		pod := portedVMPod("team-a", "prestop")
		pod.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/drain", Port: intstr.FromInt32(probeHTTPPort)},
		}}
		n, id, pub := servingVMPod(t, pod)
		pod.Status.PodIP = pub
		pp := n.proberOf(t, id)
		var overrides map[string]string
		var ended bool
		hookRan := make(chan struct{})
		var once sync.Once
		n.r.probeTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			once.Do(func() {
				_, live := n.sink.snapshot()
				overrides = renderOverrides(live)
				ended = closesWithin(probeLoopsEnded(pp), time.Second)
				close(hookRan)
			})
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		await(t, "the preStop hook to run", hookRan)
		if overrides[pub] != leaseFirst {
			t.Errorf("overrides while preStop ran = %v, want %s -> %s", overrides, pub, leaseFirst)
		}
		if !ended {
			t.Error("the pod's probes were still running while its preStop hook ran")
		}
		n.awaitOverrides(t, map[string]string{})
	})

	for _, tc := range []struct {
		name     string
		code     codes.Code
		wantBack bool
	}{
		// The runtime refused, so the guest is still serving at its lease and the
		// next status restores the way to it.
		{"a refused stop gives the override back", codes.FailedPrecondition, true},
		// The stop may have happened, and a lease with no guest behind it is one
		// macOS can hand on, so the override stays down until a retry settles it.
		{"a stop that may have happened keeps the override down", codes.Unavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pod := portedVMPod("team-a", "refused")
			n, id, pub := servingVMPod(t, pod)
			n.answerStops(status.Error(tc.code, "stop failed"))
			if err := n.r.DeletePod(context.Background(), pod); err == nil {
				t.Fatal("DeletePod returned nil for a stop the runtime failed")
			}
			n.readStatus(t, pod)
			want := map[string]string{}
			if tc.wantBack {
				want[pub] = leaseFirst
			}
			n.awaitOverrides(t, want)

			n.answerStops(nil)
			if err := n.r.DeletePod(context.Background(), pod); err != nil {
				t.Fatalf("retried DeletePod: %v", err)
			}
			n.awaitOverrides(t, map[string]string{})
			if got := n.releaseMarks(); got != 0 {
				t.Errorf("%d release marks left after the retried teardown, want none", got)
			}
			if _, recorded := n.adapt.GuestNetwork(id); recorded {
				t.Error("the guest record outlived the retried teardown")
			}
		})
	}

	t.Run("a native pod's probes keep running through its stop", func(t *testing.T) {
		t.Parallel()
		n := newProbeNode(t)
		pod := withGateProbes(hostPod("team-a", "native-stop"))
		id := n.start(t, pod)
		n.tgt.serve(n.rt.boxPodIP(id))
		held := n.holdNextStop()
		done := make(chan error, 1)
		go func() { done <- n.r.DeletePod(context.Background(), pod) }()
		await(t, "the runtime to be asked to stop the pod", held.entered)
		dials := n.tgt.count()
		waitCond(t, "a probe to dial during the stop", func() bool { return n.tgt.count() > dials })
		close(held.release)
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
	})
}
