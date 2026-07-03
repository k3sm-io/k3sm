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
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// gatedPod builds a pod declaring the named readinessGates and carrying the given
// (external) status conditions — the shape a Deployment rolling update produces
// when a readinessGate names a condition a controller patches onto status.
func gatedPod(gates []string, conds ...corev1.PodCondition) *corev1.Pod {
	rg := make([]corev1.PodReadinessGate, 0, len(gates))
	for _, g := range gates {
		rg = append(rg, corev1.PodReadinessGate{ConditionType: corev1.PodConditionType(g)})
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "p", UID: types.UID("uid-p")},
		Spec: corev1.PodSpec{
			ReadinessGates: rg,
			Containers:     []corev1.Container{{Name: "c0", Image: "native"}},
		},
		Status: corev1.PodStatus{Conditions: conds},
	}
}

func readyStatusOf(conds []corev1.PodCondition) (corev1.PodCondition, bool) {
	for _, c := range conds {
		if c.Type == corev1.PodReady {
			return c, true
		}
	}
	return corev1.PodCondition{}, false
}

// TestRollingUpdateSurfacesReadyGates is the B79 gate: PodReady must honor
// spec.readinessGates so a Deployment rolling update does not advance before the
// gates are satisfied — while NEVER stalling on a gate condition the k3sm VK
// provider cannot observe (the absent-gate anti-stall ceiling).
func TestRollingUpdateSurfacesReadyGates(t *testing.T) {
	trueCond := func(g string) corev1.PodCondition {
		return corev1.PodCondition{Type: corev1.PodConditionType(g), Status: corev1.ConditionTrue}
	}
	falseCond := func(g string) corev1.PodCondition {
		return corev1.PodCondition{Type: corev1.PodConditionType(g), Status: corev1.ConditionFalse}
	}

	// (a) gate PRESENT+True & containersReady=true → PodReady True.
	t.Run("present-true gate is ready", func(t *testing.T) {
		got := computeReadiness(gatedPod([]string{"example.com/g"}, trueCond("example.com/g")), true)
		if got.Status != corev1.ConditionTrue {
			t.Fatalf("PodReady = %s/%s, want True", got.Status, got.Reason)
		}
	})

	// (b) gate PRESENT+False → PodReady False, Reason "ReadinessGatesNotReady".
	t.Run("present-false gate blocks", func(t *testing.T) {
		got := computeReadiness(gatedPod([]string{"example.com/g"}, falseCond("example.com/g")), true)
		if got.Status != corev1.ConditionFalse {
			t.Fatalf("PodReady = %s, want False", got.Status)
		}
		if got.Reason != "ReadinessGatesNotReady" {
			t.Fatalf("Reason = %q, want ReadinessGatesNotReady", got.Reason)
		}
		if got.Message == "" {
			t.Error("blocked PodReady should name the gate in its Message")
		}
	})

	// (c) NO readinessGates → PodReady == containersReady (both the true and false
	// legs — the common-path regression guard).
	t.Run("no gates tracks containersReady", func(t *testing.T) {
		pod := newPod("default", "p")
		if got := computeReadiness(pod, true); got.Status != corev1.ConditionTrue {
			t.Errorf("containersReady=true → PodReady = %s, want True", got.Status)
		}
		got := computeReadiness(pod, false)
		if got.Status != corev1.ConditionFalse {
			t.Errorf("containersReady=false → PodReady = %s, want False", got.Status)
		}
		if got.Reason != "ContainersNotReady" {
			t.Errorf("Reason = %q, want ContainersNotReady", got.Reason)
		}
	})

	// (d) two gates both present-True → True; one present-False → False.
	t.Run("multiple gates AND", func(t *testing.T) {
		bothTrue := gatedPod([]string{"a/x", "b/y"}, trueCond("a/x"), trueCond("b/y"))
		if got := computeReadiness(bothTrue, true); got.Status != corev1.ConditionTrue {
			t.Errorf("both gates True → PodReady = %s, want True", got.Status)
		}
		oneFalse := gatedPod([]string{"a/x", "b/y"}, trueCond("a/x"), falseCond("b/y"))
		if got := computeReadiness(oneFalse, true); got.Status != corev1.ConditionFalse {
			t.Errorf("one gate False → PodReady = %s, want False", got.Status)
		}
	})

	// (e) containersReady=false short-circuits gates: PodReady False regardless of
	// a satisfied gate.
	t.Run("containers not ready short-circuits gates", func(t *testing.T) {
		got := computeReadiness(gatedPod([]string{"example.com/g"}, trueCond("example.com/g")), false)
		if got.Status != corev1.ConditionFalse {
			t.Fatalf("PodReady = %s, want False (ContainersReady short-circuit)", got.Status)
		}
		if got.Reason != "ContainersNotReady" {
			t.Fatalf("Reason = %q, want ContainersNotReady", got.Reason)
		}
	})

	// (f) an EXTERNAL/non-owned condition SURVIVES a toPodStatus status rebuild
	// (merge-not-replace). toPodStatus otherwise emits only the four owned
	// conditions; without the carry-forward the gate condition would be clobbered.
	t.Run("external condition survives toPodStatus rebuild", func(t *testing.T) {
		pod := gatedPod([]string{"example.com/g"}, trueCond("example.com/g"))
		out := toPodStatus(pod, runningRS("uid-p", time.Unix(2000, 0)), "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
		ext := findPodCondition(out.Conditions, corev1.PodConditionType("example.com/g"))
		if ext == nil {
			t.Fatal("external readinessGate condition was clobbered by the status rebuild")
		}
		if ext.Status != corev1.ConditionTrue {
			t.Errorf("carried-forward external condition = %s, want True (verbatim)", ext.Status)
		}
		// and the present-True gate makes the running pod Ready.
		if r, ok := readyStatusOf(out.Conditions); !ok || r.Status != corev1.ConditionTrue {
			t.Errorf("PodReady = %+v, want True with the satisfied gate", r)
		}
	})

	// LastTransitionTime flips ONLY on a real status change (flip-only), not every
	// call — the invariant the runtimed buildStatus seam relies on (it threads the
	// track's last PodReady as the prior). Without it PodReady.LTT would churn to
	// Now() every resync tick, resetting minReadySeconds windows and stalling rollouts.
	t.Run("LastTransitionTime flips only on status change", func(t *testing.T) {
		past := metav1.NewTime(time.Unix(1000, 0))
		pod := newPod("default", "p")
		pod.Status.Conditions = []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: past},
		}
		// unchanged status → LTT preserved (no per-tick churn).
		same := computeReadiness(pod, true)
		if same.Status != corev1.ConditionTrue {
			t.Fatalf("status = %s, want True", same.Status)
		}
		if !same.LastTransitionTime.Equal(&past) {
			t.Errorf("unchanged status churned LTT: %v, want preserved %v", same.LastTransitionTime, past)
		}
		// real flip → LTT advances off the prior value.
		flip := computeReadiness(pod, false)
		if flip.Status != corev1.ConditionFalse {
			t.Fatalf("status = %s, want False", flip.Status)
		}
		if flip.LastTransitionTime.Equal(&past) {
			t.Error("status flip should advance LastTransitionTime off the prior value")
		}
	})

	// (g) THE CEILING: a readinessGate whose condition is ABSENT does NOT stall the
	// pod — PodReady stays True when the containers are ready (the anti-permanent-
	// stall safety rule; the provider cannot observe external gate patches).
	t.Run("absent gate does not stall", func(t *testing.T) {
		pod := gatedPod([]string{"example.com/never-observed"}) // gate declared, no condition
		if got := computeReadiness(pod, true); got.Status != corev1.ConditionTrue {
			t.Fatalf("absent gate → PodReady = %s/%s, want True (no permanent stall)", got.Status, got.Reason)
		}
		// Same through toPodStatus (the live path): a running pod with an
		// unobservable gate is Ready, not stuck NotReady forever.
		out := toPodStatus(pod, runningRS("uid-p", time.Unix(2000, 0)), "192.168.1.10", metav1.NewTime(time.Unix(1000, 0)), nil)
		if r, ok := readyStatusOf(out.Conditions); !ok || r.Status != corev1.ConditionTrue {
			t.Fatalf("toPodStatus PodReady = %+v, want True (absent gate must not stall)", r)
		}
	})
}
