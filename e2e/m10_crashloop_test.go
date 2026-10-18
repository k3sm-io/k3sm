//go:build e2e

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

package e2e

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The upstream kubelet CrashLoopBackOff schedule (pkg/kubelet/util/flowcontrol):
// 10s base, doubling, capped at 300s, and reset to the base once a container
// stayed up for 2x the cap since its previous crash.
const (
	crashBase         = 10 * time.Second
	crashStableWindow = 10 * time.Minute
)

// crashScript counts its runs in the pod's emptyDir (which survives an
// in-place re-exec, so the count is the number of executions the node really
// performed), prints run=<n>, and exits 3 after a second, except on run
// longRun (0 = never), which stays up for longFor seconds first, and on any
// run after it, which stays up.
func crashScript(longRun int, longFor int) string {
	return fmt.Sprintf(`n=$(cat /data/runs 2>/dev/null || echo 0); n=$((n+1)); echo $n > /data/runs
echo "run=$n"
if [ %d -gt 0 ] && [ $n -gt %d ]; then while :; do sleep 3600; done; fi
if [ $n -eq %d ]; then sleep %d; else sleep 1; fi
exit 3`, longRun, longRun, longRun, longFor)
}

// crashSample is one observation of the crashing container.
type crashSample struct {
	uid          string
	phase        corev1.PodPhase
	restartCount int32
	waiting      string // waiting reason
	message      string // waiting message
	lastExit     int32  // lastState.terminated.exitCode, -1 when absent
	lastFinished string // lastState.terminated.finishedAt + containerID: one per termination
	running      bool
}

var backoffMsg = regexp.MustCompile(`^back-off (\S+) restarting failed container=(\S+) pod=(\S+)$`)

// TestM10_CrashLoopBackOff is the M10.2/B26 live-restart criterion: the provider is
// the SINGLE exit-driven restart authority on the runtimed path (runtimed performs no
// exit-driven restarts), re-execing a crashed container in place under the effective
// restart policy with the upstream CrashLoopBackOff schedule. The unit-level contract
// is pinned by pkg/provider TestNativeSidecarStaysRunning / TestRestartTriggerIdempotent.
//
// Two legs, run in parallel because the second needs the 10-minute
// stabilization window to elapse:
//
//   - crash loop: a restartPolicy:Always pod whose container exits 3 after a
//     second is re-exec'd IN PLACE (same pod UID, the emptyDir run count keeps
//     climbing); between attempts the container waits with
//     reason=CrashLoopBackOff and the message "back-off <d> restarting failed
//     container=c pod=<name>_<ns>(<uid>)", the delays running 10s, 20s, 40s;
//     lastState.terminated carries exit code 3; restartCount rises by exactly
//     one per termination (never double-counted); the pod phase is Running
//     for the whole loop.
//   - stabilization reset: after two quick crashes (back-offs 10s, 20s) the
//     third run stays up past the stabilization window and then crashes, and
//     the back-off that follows is the 10s base again, not 40s.
func TestM10_CrashLoopBackOff(t *testing.T) {
	c := Up(t)
	node := m10Node(t, c)
	ns := m10Namespace(t, c)

	t.Run("crash loop", func(t *testing.T) {
		t.Parallel()
		pod := crashPod(ns, "crashloop", node, crashScript(0, 0))
		created := m10Create(t, c, pod)
		samples := sampleCrashLoop(t, c, ns, pod.Name, 4*time.Minute, func(s []crashSample) bool {
			return len(delaySequence(s)) >= 3
		})
		assertCrashSurface(t, created, samples)
		delays := delaySequence(samples)
		want := []string{"10s", "20s", "40s"}
		if len(delays) < len(want) || strings.Join(delays[:len(want)], ",") != strings.Join(want, ",") {
			t.Errorf("back-off delays observed %v, want the upstream schedule to start %v", delays, want)
		}
		runs := waitRunCount(t, c, ns, pod.Name)
		last := samples[len(samples)-1]
		if runs < int(last.restartCount)+1 {
			t.Errorf("restartCount %d but the container ran only %d time(s): restarts counted that never executed", last.restartCount, runs)
		}
		t.Logf("delays %v; last restartCount %d; in-pod run count %d", delays, last.restartCount, runs)
	})

	t.Run("stabilization resets the back-off", func(t *testing.T) {
		t.Parallel()
		// Run 3 stays up for the whole window. The window is measured from the
		// previous crash, which also covers the 20s back-off before run 3, so
		// staying up for the full window has margin.
		longFor := int(crashStableWindow / time.Second)
		pod := crashPod(ns, "stabilize", node, crashScript(3, longFor))
		created := m10Create(t, c, pod)
		samples := sampleCrashLoop(t, c, ns, pod.Name, crashStableWindow+5*time.Minute, func(s []crashSample) bool {
			return len(delaySequence(s)) >= 3
		})
		assertCrashSurface(t, created, samples)
		delays := delaySequence(samples)
		t.Logf("back-off sequence %v", delays)
		want := []string{"10s", "20s", "10s"}
		if len(delays) < len(want) || strings.Join(delays[:len(want)], ",") != strings.Join(want, ",") {
			t.Fatalf("back-off sequence %v, want %v: a container that stayed up past the %s stabilization window must restart its back-off at the %s base",
				delays, want, crashStableWindow, crashBase)
		}
	})
}

// crashPod is a restartPolicy:Always pinned pod with an emptyDir at /data.
func crashPod(ns, name, node, script string) *corev1.Pod {
	pod := m10PinnedPod(ns, name, node, corev1.RestartPolicyAlways, script)
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	return pod
}

// sampleCrashLoop polls the pod's container "c" every 250ms until done reports
// true over the samples so far or timeout elapses (a failure).
func sampleCrashLoop(t *testing.T, c *Cluster, ns, name string, timeout time.Duration, done func([]crashSample) bool) []crashSample {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var out []crashSample
	for {
		pod, err := c.Client.CoreV1().Pods(ns).Get(context.Background(), name, metav1.GetOptions{})
		if err == nil {
			if st := m10Status(pod, "c"); st != nil {
				s := crashSample{uid: string(pod.UID), phase: pod.Status.Phase, restartCount: st.RestartCount, lastExit: -1, running: st.State.Running != nil}
				if w := st.State.Waiting; w != nil {
					s.waiting, s.message = w.Reason, w.Message
				}
				if lt := st.LastTerminationState.Terminated; lt != nil {
					s.lastExit = lt.ExitCode
					s.lastFinished = lt.FinishedAt.UTC().Format(time.RFC3339Nano) + "|" + lt.ContainerID
				}
				out = append(out, s)
				if done(out) {
					return out
				}
			}
		}
		if time.Now().After(deadline) {
			last := "<none>"
			if len(out) > 0 {
				last = fmt.Sprintf("%+v", out[len(out)-1])
			}
			t.Fatalf("pod %s/%s: crash loop did not reach the asserted state within %s; delays %v; last sample %s",
				ns, name, timeout, delaySequence(out), last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// assertCrashSurface checks the invariants every sample must hold: once
// Running the phase never leaves Running; a CrashLoopBackOff waiting state
// carries the kubelet's message for this container and pod and a lastState
// exit of 3; restartCount never decreases, never jumps by more than one, and
// never exceeds the number of terminations observed.
func assertCrashSurface(t *testing.T, pod *corev1.Pod, samples []crashSample) {
	t.Helper()
	sawRunning := false
	sawCLB := false
	var prev int32
	terms := map[string]bool{}
	podRef := fmt.Sprintf("%s_%s(%s)", pod.Name, pod.Namespace, pod.UID)
	for i, s := range samples {
		if s.uid != string(pod.UID) {
			t.Fatalf("sample %d: pod UID %s, want %s: the pod was replaced, not restarted in place", i, s.uid, pod.UID)
		}
		if s.phase == corev1.PodRunning {
			sawRunning = true
		} else if sawRunning {
			t.Errorf("sample %d: pod phase %s during the crash loop, want Running throughout", i, s.phase)
		}
		if s.lastFinished != "" {
			terms[s.lastFinished] = true
		}
		if s.waiting == "CrashLoopBackOff" {
			sawCLB = true
			m := backoffMsg.FindStringSubmatch(s.message)
			if m == nil || m[2] != "c" || m[3] != podRef {
				t.Errorf("sample %d: CrashLoopBackOff message %q, want \"back-off <d> restarting failed container=c pod=%s\"", i, s.message, podRef)
			}
			if s.lastExit != 3 {
				t.Errorf("sample %d: CrashLoopBackOff with lastState.terminated exit %d, want 3 (the prior run's exit)", i, s.lastExit)
			}
		}
		if s.restartCount < prev {
			t.Errorf("sample %d: restartCount fell %d -> %d", i, prev, s.restartCount)
		}
		if s.restartCount > prev+1 {
			t.Errorf("sample %d: restartCount jumped %d -> %d (double-counted re-exec)", i, prev, s.restartCount)
		}
		if int(s.restartCount) > len(terms) {
			t.Errorf("sample %d: restartCount %d exceeds the %d termination(s) observed", i, s.restartCount, len(terms))
		}
		prev = s.restartCount
	}
	if !sawCLB {
		t.Errorf("never observed waiting.reason=CrashLoopBackOff between attempts")
	}
	if prev == 0 {
		t.Errorf("restartCount never rose: the container was not re-exec'd")
	}
}

// delaySequence returns the back-off delays in the order they were shown, one
// entry per throttled attempt (a new entry each time the terminated instance
// behind the CrashLoopBackOff changes).
func delaySequence(samples []crashSample) []string {
	var out []string
	lastTerm := ""
	for _, s := range samples {
		if s.waiting != "CrashLoopBackOff" || s.lastFinished == lastTerm {
			continue
		}
		if m := backoffMsg.FindStringSubmatch(s.message); m != nil {
			out = append(out, m[1])
			lastTerm = s.lastFinished
		}
	}
	return out
}

// waitRunCount reads the in-pod run count the script last printed.
func waitRunCount(t *testing.T, c *Cluster, ns, name string) int {
	t.Helper()
	n := 0
	pollUntil(30*time.Second, func() bool {
		_, err := fmt.Sscanf(m10Line(m10ContainerLogs(c, ns, name, "c"), "run"), "%d", &n)
		return err == nil && n > 0
	})
	return n
}
