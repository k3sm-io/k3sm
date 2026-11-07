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

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	testclock "k8s.io/utils/clock/testing"

	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/runtimed/pkg/image"
)

// artifactRef is the image volume reference the refusal tests mount: on the
// cluster registry, so the provider's own pre-RPC check admits it and the
// refusal under test is the runtime's.
const artifactRef = testClusterRegistry + "/models/qwen3:v1"

// newArtifactPullProvider is newPullProvider with the cluster registry mapped,
// so a pod mounting artifactRef reaches the runtime's CreatePod.
func newArtifactPullProvider(t *testing.T) (*runtimedRuntime, *fakeRuntimeServer, *testclock.FakeClock, *record.FakeRecorder) {
	t.Helper()
	f := newFakeRuntimeServer()
	rec := record.NewFakeRecorder(64)
	r := newRuntimedWith(f, RuntimedConfig{
		NodeName: "n", NodeIP: "192.168.1.10",
		Root: t.TempDir(), PodLogsDir: t.TempDir(),
		Recorder:     rec,
		FlatRegistry: image.FlatRegistry{Host: testClusterRegistry},
	}, nil, nil)
	clk := testclock.NewFakeClock(time.Unix(10000, 0))
	r.clk = clk
	return r, f, clk, rec
}

// artifactRefusal is runtimed's CreatePod refusal of an image volume's pull:
// its message begins with the stable ArtifactPullRefused prefix and names the
// pod and the volume, and its typed reason says which kind of refusal it is.
func artifactRefusal(pod *corev1.Pod, fr runtimev1.FailureReason, cause string) *runtimev1.CreatePodResponse {
	return createRefusal(fr, "ArtifactPullRefused: pod "+string(pod.UID)+" image volume model: "+cause)
}

// parkSchedule reports the parked pod's single schedule: whether one is filed,
// its class, and whether a worker holds it. The worker claim is taken
// synchronously under restartMu before any goroutine starts, so attempt=false
// is positive proof that no worker was launched.
func parkSchedule(tr *podTrack) (filed bool, cls pullRetryClass, attempt bool) {
	tr.restartMu.Lock()
	defer tr.restartMu.Unlock()
	if tr.parked == nil {
		return false, pullClassNone, false
	}
	pr := tr.pulls[tr.parked.image]
	if pr == nil {
		return false, pullClassNone, false
	}
	return true, pr.class, pr.attempt
}

// eventLog accumulates a FakeRecorder's events across reads.
type eventLog struct {
	ch  <-chan string
	all []string
}

func (l *eventLog) drain() []string {
	l.all = append(l.all, recordedEvents(l.ch)...)
	return l.all
}

// count is the number of Warning events with reason whose text contains substr.
func (l *eventLog) count(reason, substr string) int {
	n := 0
	for _, ev := range l.drain() {
		if strings.HasPrefix(ev, corev1.EventTypeWarning+" "+reason+" ") && strings.Contains(ev, substr) {
			n++
		}
	}
	return n
}

// TestImageVolumeRefusalReasons pins what the provider does with each typed
// reason runtimed gives an image volume whose pull it refused: which causes are
// retried on the image path's back-off and which park the pod, the waiting
// reason each one renders, and the Warning Event each one records.
//
//   - IMAGE_PULL (a transfer or registry failure) and RESOURCE_EXHAUSTED (the
//     store would drop below its free-space floor) may heal on their own, so
//     the pod is kept and the create retried on the 10s→300s schedule, with a
//     Warning Event per failed attempt. IMAGE_PULL reads ErrImagePull and
//     ImagePullBackOff, as an image's pull does; RESOURCE_EXHAUSTED reads
//     ArtifactPullBackOff throughout.
//   - INVALID_POD_BOX (a registry other than the cluster's) cannot heal: the
//     pod is parked with ArtifactPullRefused and one Event, and never retried.
//   - IMAGE_PULL_CREDENTIAL (the imagePullSecret will not resolve) is parked
//     with ErrImagePull and one Event, and re-checked quietly once per resync,
//     so fixing the Secret heals the pod without an Event or a back-off storm.
//
// Non-vacuity: before this change RESOURCE_EXHAUSTED and INVALID_POD_BOX failed
// the create (the pod went ProviderFailed and a controller churned replacements),
// IMAGE_PULL_CREDENTIAL was retried on the exponential schedule with an Event per
// attempt, and every Event named the pod's first container image instead of the
// artifact that failed.
func TestImageVolumeRefusalReasons(t *testing.T) {
	cases := []struct {
		name   string
		reason runtimev1.FailureReason
		cause  string
		// retry is true for a cause the back-off worker retries; false parks.
		retry bool
		// waiting is the reason the attempt (or the park) renders; backOff the
		// one rendered while the retry schedule sleeps.
		waiting, backOff string
		// eventReason/eventText identify the one Warning Event per failure.
		eventReason, eventText string
		// recovers is true for a parked cause re-checked on the resync, so a
		// fix outside the pod (the Secret) heals it.
		recovers bool
	}{
		{
			name:        "IMAGE_PULL is retried as an image pull",
			reason:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL,
			cause:       "fetch blob: stalled",
			retry:       true,
			waiting:     "ErrImagePull",
			backOff:     "ImagePullBackOff",
			eventReason: "Failed",
			eventText:   `Failed to pull image "` + artifactRef + `"`,
		},
		{
			name:        "RESOURCE_EXHAUSTED is retried with ArtifactPullBackOff",
			reason:      runtimev1.FailureReason_FAILURE_REASON_RESOURCE_EXHAUSTED,
			cause:       "store below its free-space floor",
			retry:       true,
			waiting:     "ArtifactPullBackOff",
			backOff:     "ArtifactPullBackOff",
			eventReason: "Failed",
			eventText:   `Failed to pull image "` + artifactRef + `"`,
		},
		{
			name:        "INVALID_POD_BOX is parked with ArtifactPullRefused",
			reason:      runtimev1.FailureReason_FAILURE_REASON_INVALID_POD_BOX,
			cause:       "reference does not name the cluster registry",
			waiting:     "ArtifactPullRefused",
			eventReason: "ArtifactPullRefused",
			eventText:   `image volume "model"`,
		},
		{
			name:        "IMAGE_PULL_CREDENTIAL is parked with ErrImagePull",
			reason:      runtimev1.FailureReason_FAILURE_REASON_IMAGE_PULL_CREDENTIAL,
			cause:       "resolve pull credential: secret default/regcred not found",
			waiting:     "ErrImagePull",
			eventReason: "Failed",
			eventText:   `Failed to pull image "` + artifactRef + `"`,
			recovers:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := volumePod("artifact", imageVolume("model", artifactRef, corev1.PullIfNotPresent), true)
			r, f, clk, rec := newArtifactPullProvider(t)
			events := &eventLog{ch: rec.Events}
			f.pushCreate(artifactRefusal(pod, tc.reason, tc.cause))

			if err := r.CreatePod(context.Background(), pod); err != nil {
				t.Fatalf("CreatePod = %v, want the pod kept and parked, not failed", err)
			}
			tr := r.trackByID(string(pod.UID))
			if tr == nil {
				t.Fatal("the refused pod is not tracked")
			}
			status := func() *corev1.PodStatus {
				t.Helper()
				st, err := r.GetPodStatus(context.Background(), pod.Namespace, pod.Name)
				if err != nil {
					t.Fatalf("GetPodStatus: %v", err)
				}
				return st
			}
			wantWaiting := func(when, want string) {
				t.Helper()
				st := status()
				if st.Phase != corev1.PodPending {
					t.Errorf("%s: phase = %s, want Pending", when, st.Phase)
				}
				if w := waitingOf(st, "c0"); w == nil || w.Reason != want {
					t.Fatalf("%s: waiting = %+v, want reason %s", when, w, want)
				}
			}
			wantWaiting("after the refusal", tc.waiting)
			if n := events.count(tc.eventReason, tc.eventText); n != 1 {
				t.Fatalf("Warning %s events naming %q = %d, want 1; events: %q", tc.eventReason, tc.eventText, n, events.all)
			}

			filed, cls, attempt := parkSchedule(tr)
			if !filed {
				t.Fatal("no schedule is filed for the parked pod")
			}

			if tc.retry {
				if cls != pullClassBackoff || !attempt {
					t.Fatalf("schedule class=%v attempt=%v, want the back-off worker armed", cls, attempt)
				}
				waitRestart(t, "the pull back-off timer to arm", clk.HasWaiters)
				wantWaiting("during the back-off", tc.backOff)

				// The retry fails again: a second Warning Event, and the pod stays.
				f.pushCreate(artifactRefusal(pod, tc.reason, tc.cause))
				clk.Step(11 * time.Second)
				waitRestart(t, "the first CreatePod retry", func() bool { return f.createCount() == 2 })
				waitRestart(t, "the second Warning Event", func() bool { return events.count(tc.eventReason, tc.eventText) == 2 })
				waitRestart(t, "the grown back-off to arm", clk.HasWaiters)
				wantWaiting("during the grown back-off", tc.backOff)

				// The cause heals; the next retry creates the pod.
				clk.Step(21 * time.Second)
				waitRestart(t, "the park to clear", func() bool { return tr.parkedFailure() == nil })
				if st := status(); st.Phase != corev1.PodRunning {
					t.Errorf("phase = %s, want Running once the retry created the pod", st.Phase)
				}
				return
			}

			if cls == pullClassBackoff || attempt {
				t.Fatalf("schedule class=%v attempt=%v, want the pod parked with no back-off worker", cls, attempt)
			}
			if !tc.recovers {
				// Nothing the node can do heals it: no retry however long the pod waits.
				for range 3 {
					clk.Step(301 * time.Second)
					wantWaiting("long after the refusal", tc.waiting)
				}
				if _, _, attempt := parkSchedule(tr); attempt {
					t.Fatal("a re-attempt was started for a cause no retry can fix")
				}
				if n := f.createCount(); n != 1 {
					t.Errorf("CreatePod RPCs = %d, want 1", n)
				}
			} else {
				// The resync re-checks it quietly while the Secret is still broken.
				f.pushCreate(artifactRefusal(pod, tc.reason, tc.cause))
				clk.Step(resyncInterval)
				wantWaiting("at the resync", tc.waiting)
				waitRestart(t, "the quiet re-check", func() bool { return f.createCount() == 2 })
				waitRestart(t, "the re-check to finish", func() bool { _, _, a := parkSchedule(tr); return !a })
				wantWaiting("after the failed re-check", tc.waiting)

				// The Secret is fixed: the next resync creates the pod.
				clk.Step(resyncInterval)
				status()
				waitRestart(t, "the park to clear", func() bool { return tr.parkedFailure() == nil })
				if st := status(); st.Phase != corev1.PodRunning {
					t.Errorf("phase = %s, want Running once the Secret was fixed", st.Phase)
				}
			}
			if n := events.count(tc.eventReason, tc.eventText); n != 1 {
				t.Errorf("Warning %s events = %d, want exactly the one recorded at the park; events: %q", tc.eventReason, n, events.all)
			}
			for _, ev := range events.drain() {
				if strings.Contains(ev, " "+reasonBackOff+" ") {
					t.Errorf("a parked cause recorded a back-off Event: %q", ev)
				}
			}
		})
	}
}
