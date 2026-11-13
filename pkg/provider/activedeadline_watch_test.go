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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// deletedEventRuntime is the base fake whose status stream the test drives and
// whose DeletePod of holdID behaves as runtimed's does: it forgets the pod, then,
// before it answers, publishes the pod's DELETED event with phase SUCCEEDED on
// the watch stream (runtimed's DeletePod replaces the stopped pod's phase with
// SUCCEEDED for that event), followed by a Running event for sentinelID, which
// the provider's single consume loop can only publish after the DELETED one.
// It then holds until hold is closed.
type deletedEventRuntime struct {
	*fakeRuntimeServer
	events     chan *runtimev1.PodStatusEvent
	holdID     string
	sentinelID string
	entered    chan struct{}
	hold       chan struct{}
}

func (d *deletedEventRuntime) DeletePod(ctx context.Context, req *runtimev1.DeletePodRequest) (*runtimev1.DeletePodResponse, error) {
	resp, err := d.fakeRuntimeServer.DeletePod(ctx, req)
	if req.GetPodId() != d.holdID || err != nil {
		return resp, err
	}
	now := timestamppb.Now()
	d.events <- &runtimev1.PodStatusEvent{
		Type: runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_DELETED,
		Status: &runtimev1.PodStatus{
			PodId: d.holdID,
			Phase: runtimev1.PodPhase_POD_PHASE_SUCCEEDED,
			PodIp: "10.0.0.5",
			ContainerStatuses: []*runtimev1.ContainerStatus{{
				Name:  "c0",
				Image: "web",
				State: &runtimev1.ContainerState{Terminated: &runtimev1.ContainerStateTerminated{
					ExitCode: 143, Reason: "Error", StartedAt: now, FinishedAt: now,
				}},
			}},
		},
	}
	d.events <- &runtimev1.PodStatusEvent{
		Type: runtimev1.PodStatusEventType_POD_STATUS_EVENT_TYPE_MODIFIED,
		Status: &runtimev1.PodStatus{
			PodId: d.sentinelID,
			Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp: "10.0.0.6",
			ContainerStatuses: []*runtimev1.ContainerStatus{{
				Name: "c0", Image: sentinelImage, Ready: true,
				State: &runtimev1.ContainerState{Running: &runtimev1.ContainerStateRunning{StartedAt: now}},
			}},
		},
	}
	close(d.entered)
	<-d.hold
	return resp, nil
}

// sentinelImage marks the sentinel event's container, so the test tells its
// publication apart from the sentinel pod's create-time one.
const sentinelImage = "sentinel-after-deleted"

// WatchPodStatus forwards the events DeletePod publishes until the stream ends.
func (d *deletedEventRuntime) WatchPodStatus(_ *runtimev1.WatchPodStatusRequest, stream grpc.ServerStreamingServer[runtimev1.PodStatusEvent]) error {
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case ev := <-d.events:
			if err := stream.Send(ev); err != nil {
				return err
			}
		}
	}
}

// TestDeadlineStopNeverPublishesSucceededBeforeFailed pins what the watch path
// publishes while a deadline stop is in flight. runtimed's DeletePod publishes
// the stopped pod's DELETED event with phase SUCCEEDED before it answers; the
// provider consumes it while its stop is still in flight. No status surface
// (the NotifyPods callback, GetPodStatus, GetPods) may report the pod anything
// but Running before the stop succeeds, and the last publication must be
// Failed/DeadlineExceeded: a Succeeded and then Failed would be a terminal
// phase regression. Run for each restart policy, because the phase derived
// from that event depends on it.
func TestDeadlineStopNeverPublishesSucceededBeforeFailed(t *testing.T) {
	for _, policy := range []corev1.RestartPolicy{corev1.RestartPolicyAlways, corev1.RestartPolicyNever} {
		t.Run("restartPolicy "+string(policy), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			f := newFakeRuntimeServer()
			d := &deletedEventRuntime{
				fakeRuntimeServer: f,
				events:            make(chan *runtimev1.PodStatusEvent, 8),
				entered:           make(chan struct{}),
				hold:              make(chan struct{}),
			}
			var released atomic.Bool
			release := func() {
				if released.CompareAndSwap(false, true) {
					close(d.hold)
				}
			}
			deadline := int64(60)
			pod := pullPod("deadline-watch")
			pod.Spec.RestartPolicy = policy
			pod.Spec.ActiveDeadlineSeconds = &deadline
			sentinel := pullPod("deadline-watch-sentinel")
			d.holdID, d.sentinelID = string(pod.UID), string(sentinel.UID)

			r := newRuntimedWith(d, RuntimedConfig{
				NodeName: "n",
				NodeIP:   testNodeIP,
				Root:     t.TempDir(), PodLogsDir: t.TempDir(),
				Recorder: record.NewFakeRecorder(64),
				Network:  NewPodNetAdapter(newFakeIPAM(t, "100.64.0.0/24"), testNodeIP, nil),
			}, nil, nil)
			clk := testclock.NewFakeClock(time.Now())
			r.clk = clk

			var (
				mu         sync.Mutex
				recording  bool
				published  []string // "<surface> <phase>/<reason>", in order
				phases     []corev1.PodStatus
				sentinelOK = make(chan struct{}, 64)
			)
			add := func(surface string, st corev1.PodStatus) {
				mu.Lock()
				defer mu.Unlock()
				if !recording {
					return
				}
				published = append(published, fmt.Sprintf("%s %s/%s", surface, st.Phase, st.Reason))
				phases = append(phases, st)
			}
			r.mu.Lock()
			r.notify = func(p *corev1.Pod) {
				switch p.Name {
				case pod.Name:
					add("notify", *p.Status.DeepCopy())
				case sentinel.Name:
					if len(p.Status.ContainerStatuses) == 0 || p.Status.ContainerStatuses[0].Image != sentinelImage {
						return
					}
					select {
					case sentinelOK <- struct{}{}:
					default:
					}
				}
			}
			r.mu.Unlock()
			for _, p := range []*corev1.Pod{pod, sentinel} {
				if err := r.CreatePod(ctx, p); err != nil {
					t.Fatalf("CreatePod %s: %v", p.Name, err)
				}
			}
			watchDone := make(chan struct{})
			go func() {
				defer close(watchDone)
				r.runWatch(ctx)
			}()
			t.Cleanup(func() {
				release()
				cancel()
				<-watchDone
				r.shutdown()
			})

			read := func(when string) {
				st, err := r.GetPodStatus(ctx, pod.Namespace, pod.Name)
				if err != nil {
					t.Fatalf("GetPodStatus %s: %v", when, err)
				}
				add("GetPodStatus", *st)
				pods, err := r.GetPods(ctx)
				if err != nil {
					t.Fatalf("GetPods %s: %v", when, err)
				}
				for _, p := range pods {
					if p.Name == pod.Name {
						add("GetPods", p.Status)
					}
				}
			}

			mu.Lock()
			recording = true
			mu.Unlock()

			clk.Step(20 * time.Minute)
			r.resync(ctx)
			select {
			case <-d.entered:
			case <-time.After(30 * time.Second):
				t.Fatal("the deadline stop never reached the runtime")
			}
			// The sentinel follows the DELETED event on the one stream, so once it
			// is published the DELETED event has been consumed and emitted.
			waitSentinel := time.After(30 * time.Second)
			for done := false; !done; {
				select {
				case <-sentinelOK:
					done = true
				case <-waitSentinel:
					t.Fatal("the watch never consumed the events DeletePod published")
				}
			}
			read("while the stop is in flight")

			release()
			waitDeadlineStops(r)
			clk.Step(10 * time.Second)
			r.resync(ctx)
			read("after the stop")

			mu.Lock()
			defer mu.Unlock()
			t.Logf("published: %v", published)
			// The post-stop tick and reads all report the final status, so the
			// sequence must be Running..., then Failed/DeadlineExceeded to the end.
			final := len(phases)
			for i, st := range phases {
				if st.Phase == corev1.PodFailed && st.Reason == reasonDeadlineExceeded {
					final = i
					break
				}
			}
			if final == 0 || final == len(phases) {
				t.Fatalf("publications = %v, want Running while the stop is in flight, then Failed/%s", published, reasonDeadlineExceeded)
			}
			for i, st := range phases[:final] {
				if st.Phase != corev1.PodRunning {
					t.Errorf("publication %d = %q, want Running before the final Failed; sequence %v", i, published[i], published)
				}
			}
			for i, st := range phases[final:] {
				if st.Phase != corev1.PodFailed || st.Reason != reasonDeadlineExceeded {
					t.Errorf("publication %d = %q after Failed, want Failed/%s; sequence %v", final+i, published[final+i], reasonDeadlineExceeded, published)
				}
			}
		})
	}
}
