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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	testclock "k8s.io/utils/clock/testing"
)

// TestReadinessStartsFalseUntilFirstSuccess pins the kubelet's seeding of a
// probed container on every status build, including one made before the pod's
// prober is registered. The runtime reports a running container as Ready (it
// runs no probes), and its status stream or the resync backstop can deliver a
// status between the container starting and CreatePod registering the prober.
// Passing the runtime's Ready through there published a pod Ready before its
// readiness probe had ever succeeded, which then flapped back to NotReady on the
// next build that had the prober.
func TestReadinessStartsFalseUntilFirstSuccess(t *testing.T) {
	readiness := &corev1.Probe{ProbeHandler: tcpHandler(8000), PeriodSeconds: 10, TimeoutSeconds: 5, FailureThreshold: 3, SuccessThreshold: 1}
	startup := &corev1.Probe{ProbeHandler: tcpHandler(8000)}
	liveness := &corev1.Probe{ProbeHandler: tcpHandler(8000)}

	cases := []struct {
		name string
		c    corev1.Container
		// registered builds the status with the pod's prober; otherwise with none.
		registered bool
		// feed is the readiness outcomes the prober records before the build.
		feed        []probeOutcome
		wantReady   bool
		wantStarted bool
	}{
		{name: "readiness probe, prober not yet registered", c: corev1.Container{Name: "c0", ReadinessProbe: readiness}, wantReady: false, wantStarted: true},
		{name: "startup probe, prober not yet registered", c: corev1.Container{Name: "c0", StartupProbe: startup}, wantReady: false, wantStarted: false},
		{name: "liveness probe only, prober not yet registered", c: corev1.Container{Name: "c0", LivenessProbe: liveness}, wantReady: true, wantStarted: true},
		{name: "no probes", c: corev1.Container{Name: "c0"}, wantReady: true, wantStarted: true},
		{name: "readiness probe, registered, no probe answered", c: corev1.Container{Name: "c0", ReadinessProbe: readiness}, registered: true, wantReady: false, wantStarted: true},
		{name: "readiness probe, registered, first probe refused", c: corev1.Container{Name: "c0", ReadinessProbe: readiness}, registered: true, feed: []probeOutcome{outcomeFailure}, wantReady: false, wantStarted: true},
		{name: "readiness probe, registered, first success", c: corev1.Container{Name: "c0", ReadinessProbe: readiness}, registered: true, feed: []probeOutcome{outcomeFailure, outcomeSuccess}, wantReady: true, wantStarted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := probePod("seed", tc.c)
			var ps probeState
			if tc.registered {
				pp := newPodProber(pod, testclock.NewFakeClock(metav1.Now().Time), noopCheckFactory, nil)
				if pp == nil {
					t.Fatal("newPodProber returned nil for a probed pod")
				}
				for _, o := range tc.feed {
					feed(pp.monitors["c0"], probeReadiness, o)
				}
				ps = pp
			}

			st := toPodStatus(pod, runningProto("uid-seed", "c0"), "192.168.1.10", metav1.Now(), ps, transportReady)

			cs := st.ContainerStatuses[0]
			if cs.Ready != tc.wantReady {
				t.Errorf("container Ready = %v, want %v", cs.Ready, tc.wantReady)
			}
			if cs.Started == nil || *cs.Started != tc.wantStarted {
				t.Errorf("container Started = %v, want %v", cs.Started, tc.wantStarted)
			}
			want := corev1.ConditionFalse
			if tc.wantReady {
				want = corev1.ConditionTrue
			}
			for _, ct := range []corev1.PodConditionType{corev1.ContainersReady, corev1.PodReady} {
				if got := condStatus(st, ct); got != want {
					t.Errorf("%s = %s, want %s", ct, got, want)
				}
			}
		})
	}
}
