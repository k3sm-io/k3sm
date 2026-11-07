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
	"maps"
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

// deletedStatus is what a real runtimed publishes as its stop ends: the DELETED
// status of a guest that is gone, its lease not yet blanked.
func (s *leaseRuntimeServer) deletedStatus(podID, lease string) *runtimev1.PodStatus {
	st := leaseStatus(podID, s.reportedPodIP(podID), lease)
	st.Phase = runtimev1.PodPhase_POD_PHASE_SUCCEEDED
	return st
}

// pushDeleted delivers the runtime's DELETED event carrying lease down the stream.
func (s *leaseRuntimeServer) pushDeleted(t *testing.T, podID, lease string) {
	t.Helper()
	timer := time.NewTimer(stopBound)
	defer timer.Stop()
	select {
	case s.events <- &runtimev1.PodStatusEvent{Type: runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED, Status: s.deletedStatus(podID, lease)}:
	case <-timer.C:
		t.Fatalf("push DELETED for %s: the provider is not consuming the stream", podID)
	}
}

// releaseMarks is how many stop freezes and release marks the transport feed holds.
func (n *leaseNode) releaseMarks() int {
	n.r.transport.mu.Lock()
	defer n.r.transport.mu.Unlock()
	return len(n.r.transport.stopping) + len(n.r.transport.releasing)
}

// checkOverrides fails unless the sink holds want and has taken exactly sets
// generations, which catches an override that left and came back between two reads.
func (n *leaseNode) checkOverrides(t *testing.T, when string, sets int, want map[string]string) {
	t.Helper()
	got, live := n.sink.snapshot()
	if rendered := renderOverrides(live); got != sets || !maps.Equal(rendered, want) {
		t.Errorf("%s: %d generations (want %d), overrides %v (want %v)", when, got, sets, rendered, want)
	}
}

// pushAndWait delivers one status down the stream and waits for its publish.
func (n *leaseNode) pushAndWait(t *testing.T, podID, lease string) {
	t.Helper()
	seen := n.seenCount(podID)
	n.rt.push(t, podID, lease)
	n.awaitStatus(t, podID, seen+1)
}

// releaseNetwork runs onRelease at the first Teardown, while the pod's release mark
// is set and its guest record still exists: only the mark can refuse an observation
// there, which is the reinstall guard the case wants to see alone.
type releaseNetwork struct {
	*PodNetAdapter
	once      sync.Once
	onRelease func()
}

func (w *releaseNetwork) Teardown(podID string) error {
	w.once.Do(w.onRelease)
	return w.PodNetAdapter.Teardown(podID)
}

// TestDeletingVMPodStopsProbesAndKeepsItsRelayUntilTheGuestStops pins what a vm pod's
// stop does to the two things that act on its lease. Its probes end before preStop,
// so no check runs against a guest that is shutting down. Its override, which is what
// keeps the relay up, stays through preStop and the runtime's stop whatever the
// runtime reports meanwhile, as a terminating pod keeps serving until its process
// exits. It drops once when the stop succeeds, and the DELETED status that still
// carries the lease cannot put it back: the address can go to another guest.
//
// WHY IT IS NOT VACUOUS. The probes are real loops that are first seen dialing the
// lease and the override is first seen installed, each observation goes down the
// provider's own status paths, the NotFound takes the synthesized status a real
// runtimed's early forget leads to, and the sink's generation count catches an
// override that left and came back between two reads.
func TestDeletingVMPodStopsProbesAndKeepsItsRelayUntilTheGuestStops(t *testing.T) {
	t.Parallel()

	// servingVMPod runs a probed vm pod to the point where its probes are passing
	// against its lease through an installed override. onRelease, if any, runs at the
	// pod's network release.
	servingVMPod := func(t *testing.T, pod *corev1.Pod, onRelease func(n *probeNode)) (*probeNode, string, string) {
		t.Helper()
		n := newProbeNode(t)
		if onRelease != nil {
			n.r.network = &releaseNetwork{PodNetAdapter: n.adapt, onRelease: func() { onRelease(n) }}
		}
		id := n.start(t, withGateProbes(pod))
		pub := n.published(t, id)
		n.tgt.serve(leaseFirst)
		n.rt.push(t, id, leaseFirst)
		n.awaitOverrides(t, map[string]string{pub: leaseFirst})
		waitCond(t, "the probes to pass against the lease", func() bool { return n.probeReady(id) })
		return n, id, pub
	}

	stopPaths := []struct {
		name string
		// surfaces is whether the path returns a failed stop to its caller.
		surfaces bool
		stop     func(n *probeNode, pod *corev1.Pod) error
	}{
		{"DeletePod", true, func(n *probeNode, pod *corev1.Pod) error {
			return n.r.DeletePod(context.Background(), pod)
		}},
		{"the orphan reaper", false, func(n *probeNode, pod *corev1.Pod) error {
			n.r.reapOrphan(context.Background(), pod, n.r.trackByID(string(pod.UID)))
			return nil
		}},
	}

	for _, tc := range stopPaths {
		t.Run("through "+tc.name, func(t *testing.T) {
			t.Parallel()
			pod := portedVMPod("team-a", "stopping")
			id := string(pod.UID)
			var inRelease struct {
				sets     int
				live     map[string]string
				recorded bool
			}
			n, _, pub := servingVMPod(t, pod, func(n *probeNode) {
				_, inRelease.recorded = n.adapt.GuestNetwork(id)
				n.r.emit(n.rt.deletedStatus(id, leaseFirst))
				sets, live := n.sink.snapshot()
				inRelease.sets, inRelease.live = sets, renderOverrides(live)
			})
			pp := n.proberOf(t, id)
			held := n.holdNextStop()
			done := make(chan error, 1)
			go func() { done <- tc.stop(n, pod) }()
			await(t, "the runtime to be asked to stop the pod", held.entered)

			if !closesWithin(probeLoopsEnded(pp), 2*time.Second) {
				// Fatal: every dial count below is only meaningful once the loops have
				// ended, so a run that goes on would report a second, misleading failure.
				t.Fatal("the pod's probes are still running while the runtime stops it")
			}
			// The baseline is taken once no dial is in flight: one begun before the
			// stop is counted in it, and one arriving after is refused uncounted.
			dials := n.tgt.settled(t)
			frozen := map[string]string{pub: leaseFirst}
			sets, _ := n.sink.snapshot()
			n.checkOverrides(t, "as the stop begins", sets, frozen)

			// Every path a status arrives by, none of which may move the override.
			n.readStatus(t, pod)
			n.checkOverrides(t, "after a direct status with the lease", sets, frozen)
			n.pushAndWait(t, id, "")
			n.checkOverrides(t, "after a stream status with no lease", sets, frozen)
			n.readStatus(t, pod)
			n.checkOverrides(t, "after a direct status with no lease", sets, frozen)
			n.pushAndWait(t, id, leaseSecond)
			n.checkOverrides(t, "after a stream status with another lease", sets, frozen)
			n.rt.forget(id)
			n.readStatus(t, pod)
			n.checkOverrides(t, "after a direct NotFound", sets, frozen)
			if _, err := n.r.GetPods(context.Background()); err != nil {
				t.Fatalf("GetPods: %v", err)
			}
			n.checkOverrides(t, "after a backstop NotFound", sets, frozen)
			seen := n.seenCount(id)
			n.rt.pushDeleted(t, id, leaseFirst)
			n.awaitStatus(t, id, seen+1)
			n.checkOverrides(t, "after a DELETED ahead of the stop's answer", sets, frozen)

			close(held.release)
			if err := <-done; err != nil {
				t.Fatalf("stop: %v", err)
			}
			n.checkOverrides(t, "after the stop", sets+1, map[string]string{})
			if !inRelease.recorded {
				t.Error("the guest record was gone during the release, so the mark was not what refused")
			}
			if inRelease.sets != sets+1 || len(inRelease.live) != 0 {
				t.Errorf("a DELETED with the old lease during the release: %d generations (want %d), overrides %v (want none)",
					inRelease.sets, sets+1, inRelease.live)
			}
			n.r.observeTransport(pod, n.rt.deletedStatus(id, leaseFirst))
			n.checkOverrides(t, "after a DELETED past the release", sets+1, map[string]string{})

			if got := n.tgt.count(); got != dials {
				t.Errorf("probe dials went from %d to %d during the stop", dials, got)
			}
			if n.r.proberFor(id) != nil {
				t.Error("the pod's prober outlived its teardown")
			}
			if got := n.releaseMarks(); got != 0 {
				t.Errorf("%d release marks left after the teardown, want none", got)
			}
		})

		t.Run("through "+tc.name+", a refused stop leaves the override and normal observation", func(t *testing.T) {
			t.Parallel()
			pod := portedVMPod("team-a", "refused")
			n, id, pub := servingVMPod(t, pod, nil)
			sets, _ := n.sink.snapshot()
			n.answerStops(status.Error(codes.FailedPrecondition, "stop refused"))
			if err := tc.stop(n, pod); tc.surfaces && err == nil {
				t.Fatal("the stop returned nil for one the runtime refused")
			}
			n.checkOverrides(t, "after the refusal", sets, map[string]string{pub: leaseFirst})
			if got := n.releaseMarks(); got != 0 {
				t.Errorf("%d release marks left after the refusal, want none", got)
			}

			// The guest is still serving, so its reports count again, both ways.
			n.rt.push(t, id, leaseSecond)
			n.awaitOverrides(t, map[string]string{pub: leaseSecond})
			n.rt.push(t, id, "")
			n.awaitOverrides(t, map[string]string{})
			n.rt.push(t, id, leaseFirst)
			n.awaitOverrides(t, map[string]string{pub: leaseFirst})

			n.answerStops(nil)
			if err := tc.stop(n, pod); err != nil {
				t.Fatalf("retried stop: %v", err)
			}
			n.awaitOverrides(t, map[string]string{})
			if _, recorded := n.adapt.GuestNetwork(id); recorded {
				t.Error("the guest record outlived the retried teardown")
			}
		})

		t.Run("through "+tc.name+", a stop that may have happened keeps the override until a report or a retry", func(t *testing.T) {
			t.Parallel()
			pod := portedVMPod("team-a", "uncertain")
			n, id, pub := servingVMPod(t, pod, nil)
			sets, _ := n.sink.snapshot()
			n.answerStops(status.Error(codes.Unavailable, "stop lost"))
			if err := tc.stop(n, pod); tc.surfaces && err == nil {
				t.Fatal("the stop returned nil for one that failed")
			}
			held := map[string]string{pub: leaseFirst}
			n.checkOverrides(t, "after the failure alone", sets, held)
			n.pushAndWait(t, id, leaseSecond)
			n.checkOverrides(t, "after a status with another lease", sets, held)

			// The stop's call has answered, so nothing freezes the override now, and a
			// runtime that no longer knows the pod is what takes it down.
			n.rt.forget(id)
			n.readStatus(t, pod)
			n.checkOverrides(t, "after a NotFound", sets+1, map[string]string{})
			n.pushAndWait(t, id, leaseFirst)
			n.checkOverrides(t, "after a status with the lease", sets+1, map[string]string{})

			n.answerStops(nil)
			if err := tc.stop(n, pod); err != nil {
				t.Fatalf("retried stop: %v", err)
			}
			n.checkOverrides(t, "after the retried stop", sets+1, map[string]string{})
			if got := n.releaseMarks(); got != 0 {
				t.Errorf("%d release marks left after the retried teardown, want none", got)
			}
			if _, recorded := n.adapt.GuestNetwork(id); recorded {
				t.Error("the guest record outlived the retried teardown")
			}
		})
	}

	t.Run("a NotFound on the backstop path alone leaves the override", func(t *testing.T) {
		t.Parallel()
		// The path that closed the relay mid-grace: the next resync tick after the
		// runtime forgets the pod reads NotFound, which becomes a synthesized status
		// with no lease, while the guest is still working through its grace.
		pod := portedVMPod("team-a", "backstop")
		n, id, pub := servingVMPod(t, pod, nil)
		sets, _ := n.sink.snapshot()
		held := n.holdNextStop()
		done := make(chan error, 1)
		go func() { done <- n.r.DeletePod(context.Background(), pod) }()
		await(t, "the runtime to be asked to stop the pod", held.entered)
		n.rt.forget(id)
		if _, err := n.r.GetPods(context.Background()); err != nil {
			t.Fatalf("GetPods: %v", err)
		}
		n.checkOverrides(t, "after the backstop's NotFound", sets, map[string]string{pub: leaseFirst})
		close(held.release)
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		n.checkOverrides(t, "after the stop", sets+1, map[string]string{})
	})

	t.Run("a retry that succeeds drops an override the failed stop left", func(t *testing.T) {
		t.Parallel()
		pod := portedVMPod("team-a", "retried")
		n, _, pub := servingVMPod(t, pod, nil)
		sets, _ := n.sink.snapshot()
		n.answerStops(status.Error(codes.DeadlineExceeded, "stop lost"))
		if err := n.r.DeletePod(context.Background(), pod); err == nil {
			t.Fatal("DeletePod returned nil for a stop that failed")
		}
		n.checkOverrides(t, "after the failure", sets, map[string]string{pub: leaseFirst})
		n.answerStops(nil)
		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("retried DeletePod: %v", err)
		}
		n.checkOverrides(t, "after the retried stop", sets+1, map[string]string{})
	})

	t.Run("the guard holds until a release a call in flight owes", func(t *testing.T) {
		t.Parallel()
		pod := portedVMPod("team-a", "owed")
		n, id, _ := servingVMPod(t, pod, nil)
		sets, _ := n.sink.snapshot()
		n.r.beginUpdate(id)
		if err := n.r.DeletePod(context.Background(), pod); err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		n.checkOverrides(t, "after the stop", sets+1, map[string]string{})
		if _, recorded := n.adapt.GuestNetwork(id); !recorded {
			t.Fatal("the guest record went before the call in flight ended, so the mark is not what refuses")
		}
		n.r.emit(n.rt.deletedStatus(id, leaseFirst))
		n.checkOverrides(t, "after a DELETED with the old lease", sets+1, map[string]string{})
		n.r.updateDone(pod)
		n.checkOverrides(t, "after the owed release", sets+1, map[string]string{})
		if got := n.releaseMarks(); got != 0 {
			t.Errorf("%d release marks left after the owed release, want none", got)
		}
	})

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
		// the relay answers there, so the override must outlast the hook and whatever
		// the runtime reports while the hook runs.
		pod := portedVMPod("team-a", "prestop")
		pod.Spec.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
			HTTPGet: &corev1.HTTPGetAction{Path: "/drain", Port: intstr.FromInt32(probeHTTPPort)},
		}}
		n, id, pub := servingVMPod(t, pod, nil)
		pod.Status.PodIP = pub
		pp := n.proberOf(t, id)
		sets, _ := n.sink.snapshot()
		var setsInHook int
		var overrides map[string]string
		var ended bool
		var statusErrs []error
		hookRan := make(chan struct{})
		var once sync.Once
		n.r.probeTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			once.Do(func() {
				ended = closesWithin(probeLoopsEnded(pp), time.Second)
				n.rt.setLease(id, "")
				_, noLeaseErr := n.r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
				n.rt.forget(id)
				_, notFoundErr := n.r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
				statusErrs = []error{noLeaseErr, notFoundErr}
				got, live := n.sink.snapshot()
				setsInHook, overrides = got, renderOverrides(live)
				close(hookRan)
			})
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		held := n.holdNextStop()
		done := make(chan error, 1)
		go func() { done <- n.r.DeletePod(context.Background(), pod) }()
		await(t, "the preStop hook to run", hookRan)
		await(t, "the runtime to be asked to stop the pod", held.entered)
		for _, err := range statusErrs {
			if err != nil {
				t.Errorf("status during preStop: %v", err)
			}
		}
		if setsInHook != sets || overrides[pub] != leaseFirst {
			t.Errorf("while preStop ran: %d generations (want %d), overrides %v (want %s -> %s)",
				setsInHook, sets, overrides, pub, leaseFirst)
		}
		if !ended {
			t.Error("the pod's probes were still running while its preStop hook ran")
		}
		n.checkOverrides(t, "as the stop begins after preStop", sets, map[string]string{pub: leaseFirst})
		close(held.release)
		if err := <-done; err != nil {
			t.Fatalf("DeletePod: %v", err)
		}
		n.checkOverrides(t, "after the stop", sets+1, map[string]string{})
	})

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
