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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestM10_NativeSidecar is the native-sidecar criterion (Res.8): an initContainer
// with restartPolicy:Always (the k8s 1.33 stable sidecar) STAYS RUNNING alongside the
// regular containers and tears down in reverse order — over the new apis PodBox/
// Container proto restart_policy field (never a k3sm.io/* annotation). That the
// field rides the proto, not an annotation, is pinned at the unit tier (pkg/provider
// TestNativeSidecarStaysRunning); this criterion asserts the live behavior.
//
// One restartPolicy:Never pod with an emptyDir at /data, sidecars s1 then s2
// (initContainers with restartPolicy:Always) and one main container c that
// runs for 20s and exits 0. Asserted:
//
//   - s1 and s2 are Running and started before c starts (their running
//     startedAt is not after c's), and while c runs all three are Running,
//     the sidecars never restarted and the pod is Running;
//   - when c exits 0 the pod goes Succeeded, with s1 and s2 terminated;
//   - teardown order: each container records a marker in /data as it stops,
//     and each sidecar's SIGTERM handler logs which markers already exist.
//     s2 must see c's marker (the mains stop first) and s1 must see both c's
//     and s2's (sidecars stop in reverse start order).
func TestM10_NativeSidecar(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := m10Node(t, c)
	ns := m10Namespace(t, c)

	sidecar := func(me, later string) corev1.Container {
		always := corev1.ContainerRestartPolicyAlways
		script := `on_term() {
	main=no; [ -e /data/c-done ] && main=yes
	later=none; [ -n "` + later + `" ] && { later=no; [ -e "/data/` + later + `-term" ] && later=yes; }
	echo "term name=` + me + ` main_done=$main later_done=$later"
	touch /data/` + me + `-term
	exit 0
}
trap on_term TERM
echo "up name=` + me + `"
while :; do sleep 1; done`
		return corev1.Container{
			Name:          me,
			Image:         "native",
			RestartPolicy: &always,
			Command:       []string{"/bin/sh", "-c", script},
			VolumeMounts:  []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
		}
	}

	pod := m10PinnedPod(ns, "sidecars", node, corev1.RestartPolicyNever, `echo main-up; sleep 20; touch /data/c-done; echo main-done; exit 0`)
	grace := int64(15)
	pod.Spec.TerminationGracePeriodSeconds = &grace
	pod.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	pod.Spec.InitContainers = []corev1.Container{sidecar("s1", "s2"), sidecar("s2", "")}
	m10Create(t, c, pod)

	// While the main runs: every container Running, sidecars never restarted.
	var during *corev1.Pod
	if !pollUntil(2*time.Minute, func() bool {
		p, err := c.Client.CoreV1().Pods(ns).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		for _, name := range []string{"s1", "s2", "c"} {
			st := m10Status(p, name)
			if st == nil || st.State.Running == nil {
				return false
			}
		}
		during = p
		return true
	}) {
		p, _ := c.Client.CoreV1().Pods(ns).Get(ctx, pod.Name, metav1.GetOptions{})
		t.Fatalf("pod %s/%s never had s1, s2 and c Running together: %s; init %+v", ns, pod.Name, podFailureDetail(p), initStates(p))
	}
	if during.Status.Phase != corev1.PodRunning {
		t.Errorf("pod phase %s while its main runs, want Running", during.Status.Phase)
	}
	mainStart := m10Status(during, "c").State.Running.StartedAt
	for _, name := range []string{"s1", "s2"} {
		st := m10Status(during, name)
		if st.RestartCount != 0 {
			t.Errorf("sidecar %s restartCount %d while the main runs, want 0 (it must stay running)", name, st.RestartCount)
		}
		if st.Started == nil || !*st.Started {
			t.Errorf("sidecar %s is Running but not started=true", name)
		}
		if st.State.Running.StartedAt.After(mainStart.Time) {
			t.Errorf("sidecar %s started at %s, after the main (%s): sidecars must be up before the mains start",
				name, st.State.Running.StartedAt.Time, mainStart.Time)
		}
	}

	done := c.WaitPodPhase(t, ns, pod.Name, corev1.PodSucceeded, 2*time.Minute)
	if st := m10Status(done, "c"); st == nil || st.State.Terminated == nil || st.State.Terminated.ExitCode != 0 {
		t.Errorf("main c must be terminated with exit 0: %s", podFailureDetail(done))
	}
	// A terminal phase is final: upstream reports it only once every container
	// of the pod has stopped, sidecars included.
	for _, name := range []string{"s1", "s2"} {
		if st := m10Status(done, name); st == nil || st.State.Terminated == nil {
			t.Errorf("pod reported Succeeded while sidecar %s was not terminated (%v): a terminal phase must wait for every container to stop", name, initStates(done))
		}
	}
	// However long the phase ran ahead, the teardown itself must complete
	// within the grace period, and in order.
	var final *corev1.Pod
	if !pollUntil(time.Duration(grace+15)*time.Second, func() bool {
		p, err := c.Client.CoreV1().Pods(ns).Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false
		}
		final = p
		for _, name := range []string{"s1", "s2"} {
			if st := m10Status(p, name); st == nil || st.State.Terminated == nil {
				return false
			}
		}
		return true
	}) {
		t.Errorf("sidecars not all terminated %ds after the main exited: %v", grace+15, initStates(final))
	}
	for _, name := range []string{"s1", "s2"} {
		if st := m10Status(final, name); st != nil && st.RestartCount != 0 {
			t.Errorf("sidecar %s restartCount %d at the end, want 0", name, st.RestartCount)
		}
	}

	s2 := m10ContainerLogs(c, ns, pod.Name, "s2")
	s1 := m10ContainerLogs(c, ns, pod.Name, "s1")
	t.Logf("s2 log:\n%s\ns1 log:\n%s", s2, s1)
	if !strings.Contains(s2, "term name=s2 main_done=yes") {
		t.Errorf("s2 was not stopped after the main (its SIGTERM handler did not see the main's marker): %q", s2)
	}
	if !strings.Contains(s1, "term name=s1 main_done=yes later_done=yes") {
		t.Errorf("s1 was not stopped after s2 (reverse order: the later sidecar stops first): %q", s1)
	}
}

// initStates summarizes the init-container states of p for a failure message.
func initStates(p *corev1.Pod) []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, st := range p.Status.InitContainerStatuses {
		s := st.Name + "="
		switch {
		case st.State.Running != nil:
			s += "running"
		case st.State.Terminated != nil:
			s += "terminated(" + st.State.Terminated.Reason + ")"
		case st.State.Waiting != nil:
			s += "waiting(" + st.State.Waiting.Reason + ")"
		}
		out = append(out, s)
	}
	return out
}
