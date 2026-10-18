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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
)

// TestM10_ProviderEvents is the M10.2 node-lifecycle-Events criterion: the provider's
// EventRecorder emits Pulled/Created/Started/Killing/BackOff so `kubectl describe pod`
// shows the container lifecycle.
//
// One restartPolicy:Always pod with two containers: "steady" runs, "crasher"
// exits 1 after a second, so it is re-exec'd under the CrashLoopBackOff
// schedule. Selected by the pod's UID (involvedObject.uid), the Events must
// carry, in the kubelet's vocabulary and naming the container they concern:
//
//   - Pulled for each container (the image resolved for the start);
//   - Created and Started for each container;
//   - a Warning BackOff naming crasher ("Back-off restarting failed container crasher");
//   - Killing naming steady once the pod is deleted.
//
// A missing reason is reported per reason and container, so a failure lists
// every gap at once.
func TestM10_ProviderEvents(t *testing.T) {
	c := Up(t)
	ctx := context.Background()
	node := m10Node(t, c)
	ns := m10Namespace(t, c)

	pod := m10PinnedPod(ns, "events", node, corev1.RestartPolicyAlways, "")
	grace := int64(10)
	pod.Spec.TerminationGracePeriodSeconds = &grace
	pod.Spec.Containers = []corev1.Container{
		{Name: "steady", Image: "native", Command: []string{"/bin/sh", "-c", "trap 'exit 0' TERM; while :; do sleep 1; done"}},
		{Name: "crasher", Image: "native", Command: []string{"/bin/sh", "-c", "sleep 1; exit 1"}},
	}
	created := m10Create(t, c, pod)
	uid := string(created.UID)

	list := func() []corev1.Event {
		evs, err := c.Client.CoreV1().Events(ns).List(ctx, metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("involvedObject.uid", uid).String(),
		})
		if err != nil {
			t.Logf("list events: %v", err)
			return nil
		}
		return evs.Items
	}
	// has reports whether an Event with reason names container, by the
	// kubelet's fieldPath (spec.containers{name}) or by the message.
	has := func(evs []corev1.Event, reason, container string) bool {
		for _, e := range evs {
			if e.Reason != reason {
				continue
			}
			if container == "" || strings.Contains(e.InvolvedObject.FieldPath, "{"+container+"}") ||
				strings.Contains(e.Message, container) {
				return true
			}
		}
		return false
	}

	// Wait for the crash loop to be throttled (the BackOff Event), bounded by
	// a few back-off periods; the remaining reasons have been due since start.
	var evs []corev1.Event
	pollUntil(90*time.Second, func() bool {
		evs = list()
		return has(evs, "BackOff", "crasher")
	})

	type want struct{ reason, container string }
	pre := []want{
		{"Pulled", "steady"}, {"Pulled", "crasher"},
		{"Created", "steady"}, {"Created", "crasher"},
		{"Started", "steady"}, {"Started", "crasher"},
		{"BackOff", "crasher"},
	}
	// pulledWithoutFieldPath counts Pulled Events that name no container. A
	// Pulled message names the image, not the container, so two containers on
	// one image are told apart only by fieldPath; without it the recorder
	// aggregates them into one Event whose count is the number of pulls.
	pulledWithoutFieldPath := func(evs []corev1.Event) int32 {
		var n int32
		for _, e := range evs {
			if e.Reason == "Pulled" && e.InvolvedObject.FieldPath == "" {
				n += max(e.Count, 1)
			}
		}
		return n
	}
	for _, w := range pre {
		if w.reason == "Pulled" && pulledWithoutFieldPath(evs) >= int32(len(pod.Spec.Containers)) {
			continue
		}
		if !has(evs, w.reason, w.container) {
			t.Errorf("no %s Event for container %s", w.reason, w.container)
		}
	}
	for _, e := range evs {
		if e.Reason == "BackOff" && e.Type != corev1.EventTypeWarning {
			t.Errorf("BackOff Event is type %s, want Warning (kubelet parity)", e.Type)
		}
	}

	if err := c.Client.CoreV1().Pods(ns).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete pod: %v", err)
	}
	pollUntil(45*time.Second, func() bool {
		evs = list()
		return has(evs, "Killing", "steady")
	})
	if !has(evs, "Killing", "steady") {
		t.Errorf("no Killing Event for container steady after the pod was deleted")
	}

	var b strings.Builder
	for _, e := range evs {
		fmt.Fprintf(&b, "  %s %s %s: %s\n", e.Type, e.Reason, e.InvolvedObject.FieldPath, e.Message)
	}
	t.Logf("%d Event(s) for pod %s/%s (uid %s):\n%s", len(evs), ns, pod.Name, uid, b.String())
}
