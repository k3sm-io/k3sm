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
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
)

// TestLivenessNotCountedDuringRestart pins the kubelet's prober semantics around
// a liveness restart. A committed liveness failure restarts the container
// asynchronously, so for a while the probe keeps hitting the old instance and
// then a replacement that is not listening yet. The kubelet puts the liveness
// worker on hold until it sees a new container id, starts the count over for
// that container, and skips the probe until initialDelaySeconds have passed since
// the new container started. Counting those refusals restarts a healthy
// container a second time for the one failure that was already acted on.
//
// It drives the real prober the runtime starts at CreatePod, with a dial that
// always refuses, and feeds runtime statuses through buildStatus, the path every
// status observation takes.
func TestLivenessNotCountedDuringRestart(t *testing.T) {
	r, _ := newRuntimedFake(t)
	clk := testclock.NewFakeClock(time.Unix(100000, 0))
	r.clk = clk
	r.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	ctx := context.Background()

	pod := probePod("live-restart", corev1.Container{
		Name:    "c0",
		Command: []string{"/web"},
		LivenessProbe: &corev1.Probe{
			ProbeHandler: tcpHandler(8080),
			// Parks the probe loop on its initial wait so the test drives every
			// tick itself; it is also the delay a replacement instance gets.
			InitialDelaySeconds: 3600,
			FailureThreshold:    3,
		},
	})
	if err := r.CreatePod(ctx, pod); err != nil {
		t.Fatalf("CreatePod: %v", err)
	}
	t.Cleanup(func() { _ = r.DeletePod(ctx, pod) })

	id := string(pod.UID)
	pp, ok := r.proberFor(id).(*podProber)
	if !ok {
		t.Fatal("a probed pod must have a prober after CreatePod")
	}
	m := pp.monitors["c0"]
	track := r.trackByID(id)
	if track == nil {
		t.Fatal("CreatePod must track the pod")
	}

	// observe renders one runtime status for c0 through buildStatus.
	observe := func(containerID string, startedAt time.Time) {
		t.Helper()
		rs := &runtimev1.PodStatus{
			PodId: id,
			Phase: runtimev1.PodPhase_POD_PHASE_RUNNING,
			PodIp: "10.0.0.5",
			ContainerStatuses: []*runtimev1.ContainerStatus{{
				Name:        "c0",
				Image:       "web",
				ContainerId: containerID,
				State: &runtimev1.ContainerState{
					Running: &runtimev1.ContainerStateRunning{StartedAt: timestamppb.New(startedAt)},
				},
			}},
		}
		r.buildStatus(pod.DeepCopy(), track, rs, pp)
	}
	ticks := func(n int) {
		for i := 0; i < n; i++ {
			pp.tick(ctx, m, probeLiveness, m.liveness)
		}
	}
	wantRestarts := func(phase string, want int32) {
		t.Helper()
		if got := vd(m).restarts; got != want {
			t.Fatalf("%s: liveness restarts = %d, want %d", phase, got, want)
		}
	}

	// The first instance has been up for an hour and stops answering:
	// failureThreshold refusals restart it once.
	longAgo := clk.Now().Add(-2 * time.Hour)
	observe("instance-1", longAgo)
	ticks(3)
	wantRestarts("first instance fails", 1)

	// The restart is in flight: the runtime still reports the old instance.
	// Refusals now are the same failure, already acted on.
	observe("instance-1", longAgo)
	ticks(3)
	wantRestarts("restart in flight (old instance still reported)", 1)

	// The replacement is running but has just started and is not listening yet:
	// its initialDelaySeconds run from its own start.
	observe("instance-2", clk.Now())
	ticks(3)
	wantRestarts("replacement inside its initialDelaySeconds", 1)

	// Another replacement (an exit-driven restart, say) whose delay has passed:
	// liveness resumes, counting from zero, so two refusals are not enough and
	// the third restarts it.
	observe("instance-3", longAgo)
	ticks(2)
	wantRestarts("two failures on a fresh instance", 1)
	ticks(1)
	wantRestarts("failureThreshold failures on a fresh instance", 2)
}
