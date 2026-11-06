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

package updatectl

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	updatesv1alpha1 "k3sm.io/apis/updates/v1alpha1"
	"k3sm.io/k3sm/pkg/update"
)

// deleteUpdate removes an Update, the way `kubectl delete update` does.
func (r *rig) deleteUpdate(name string) {
	r.t.Helper()
	if err := r.dyn.Resource(updateResource).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		r.t.Fatal(err)
	}
}

// pass is one reconcile that must not fail.
func (r *rig) pass(c *Controller) {
	r.t.Helper()
	if _, err := c.reconcile(context.Background()); err != nil {
		r.t.Fatalf("reconcile: %v", err)
	}
}

// updateKeys is the k3sm.io/update-* annotations on a node, sorted.
func (r *rig) updateKeys(name string) []string {
	r.t.Helper()
	var keys []string
	for k := range r.node(name).Annotations {
		if strings.HasPrefix(k, "k3sm.io/update-") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

// failedRoll drives a roll until w1 fails, so w1 is left cordoned with the
// annotations of its handover.
func failedRoll(t *testing.T, nodes ...*corev1.Node) (*rig, *Controller) {
	t.Helper()
	r := newRig(t, nodes...)
	r.failNodes["w1"] = "disk full"
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	r.drive(c, nil)
	if got := r.update(updatesv1alpha1.UpdateName).Status.Phase; got != updatesv1alpha1.UpdatePhaseFailed {
		t.Fatalf("phase %q, want Failed", got)
	}
	return r, c
}

func wantReleased(t *testing.T, r *rig, name string, unschedulable bool) {
	t.Helper()
	if got := r.updateKeys(name); len(got) != 0 {
		t.Errorf("%s still carries %v", name, got)
	}
	if got := r.node(name).Spec.Unschedulable; got != unschedulable {
		t.Errorf("%s unschedulable = %v, want %v", name, got, unschedulable)
	}
}

func TestDeletedUpdateReleasesTheNode(t *testing.T) {
	t.Run("the running controller", func(t *testing.T) {
		r, c := failedRoll(t, threeNodes()...)
		n := r.node("w1")
		n.Annotations["k3sm.io/release-latest"] = target // a server's release check, not a roll's
		if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
			t.Fatal(err)
		}

		r.deleteUpdate(updatesv1alpha1.UpdateName)
		r.pass(c)

		wantReleased(t, r, "w1", false)
		if got := r.node("w1").Annotations["k3sm.io/release-latest"]; got != target {
			t.Errorf("the release check's annotation went with the roll's: %q", got)
		}
		if log := r.log(); log[len(log)-1] != "uncordon w1" {
			t.Errorf("node actions %v, want the last to lift w1's cordon", log)
		}
		before := len(r.log())
		r.pass(c)
		if got := len(r.log()); got != before {
			t.Errorf("a released node was patched again: %v", r.log())
		}
	})

	t.Run("a controller that restarts into the orphan", func(t *testing.T) {
		r, _ := failedRoll(t, threeNodes()...)
		r.deleteUpdate(updatesv1alpha1.UpdateName)

		r.pass(r.controller())

		wantReleased(t, r, "w1", false)
	})

	t.Run("an operator's cordon stays", func(t *testing.T) {
		nodes := threeNodes()
		nodes[2].Spec.Unschedulable = true // w1
		r, c := failedRoll(t, nodes...)
		r.deleteUpdate(updatesv1alpha1.UpdateName)

		r.pass(c)

		wantReleased(t, r, "w1", true)
		if slices.Contains(r.log(), "uncordon w1") {
			t.Errorf("an operator's cordon was lifted: %v", r.log())
		}
	})

	t.Run("a phase written after the release goes too", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		n := r.node("w1")
		n.Annotations = map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Failed: refused"}
		if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
			t.Fatal(err)
		}

		r.pass(r.controller())

		wantReleased(t, r, "w1", false)
	})

	t.Run("a successful roll's record goes with its Update", func(t *testing.T) {
		r := newRig(t, threeNodes()...)
		r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
		c := r.controller()
		r.drive(c, nil)
		r.pass(c)
		// The Update is still there, so the record is: an admin token rotation
		// reported late is still read from it.
		want := []string{updatesv1alpha1.AnnotationUpdatePayload, updatesv1alpha1.AnnotationUpdatePhase, updatesv1alpha1.AnnotationUpdateVersion}
		slices.Sort(want)
		for _, name := range []string{"w1", "w2", serverName} {
			if got := r.updateKeys(name); !slices.Equal(got, want) {
				t.Errorf("%s after Succeeded carries %v, want %v", name, got, want)
			}
		}

		r.deleteUpdate(updatesv1alpha1.UpdateName)
		r.pass(c)

		for _, name := range []string{"w1", "w2", serverName} {
			wantReleased(t, r, name, false)
		}
	})

	t.Run("an Update under another name holds nothing", func(t *testing.T) {
		r, c := failedRoll(t, threeNodes()...)
		r.createUpdate("other", updatesv1alpha1.UpdateSpec{Version: target})
		r.deleteUpdate(updatesv1alpha1.UpdateName)

		r.pass(c)

		wantReleased(t, r, "w1", false)
	})
}

// drainEvents is the Events the recorder holds, emptied.
func (r *rig) drainEvents() []string {
	var out []string
	for {
		select {
		case e := <-r.recorder.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

// Clearing the leftovers of a finished Update from a node with no cordon to lift
// is bookkeeping: no Event. Lifting a cordon is worth one, naming the node.
func TestReplacingAFinishedUpdateRaisesNoOrphanEvent(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	r.drive(c, nil)
	r.pass(c)
	r.drainEvents()

	r.deleteUpdate(updatesv1alpha1.UpdateName)
	r.pass(c)

	for _, name := range []string{"w1", "w2", serverName} {
		wantReleased(t, r, name, false)
	}
	for _, e := range r.drainEvents() {
		if strings.Contains(e, ReasonOrphanReleased) {
			t.Errorf("an uncordoned node raised %q", e)
		}
	}

	f, fc := failedRoll(t, threeNodes()...)
	f.drainEvents()
	f.deleteUpdate(updatesv1alpha1.UpdateName)
	f.pass(fc)
	var got []string
	for _, e := range f.drainEvents() {
		if strings.Contains(e, ReasonOrphanReleased) {
			got = append(got, e)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "Normal") || !strings.Contains(got[0], "w1") || !strings.Contains(got[0], "cordon was lifted") {
		t.Errorf("lifting w1's cordon raised %q, want one Normal Event naming w1", got)
	}
}

// A roll that has started owns its nodes, whatever its entries read: the entry
// of a node handed over just before a restart can still read Pending.
func TestLiveUpdateKeepsItsHandover(t *testing.T) {
	r := newRig(t, threeNodes()...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	r.drive(r.controller(), func() bool {
		return r.node("w1").Annotations[updatesv1alpha1.AnnotationUpdatePhase] == string(updatesv1alpha1.UpdateNodePhaseInstalling)
	})
	keys := r.updateKeys("w1")

	r.pass(r.controller())

	if got := r.updateKeys("w1"); !slices.Equal(got, keys) {
		t.Errorf("w1 mid-handover carries %v, had %v", got, keys)
	}
	if !r.node("w1").Spec.Unschedulable || slices.Contains(r.log(), "uncordon w1") {
		t.Errorf("w1 was uncordoned mid-handover: %v", r.log())
	}
}

// A failed step leaves its node for the operator while its Update stands, and
// `k3sm update abort` is what lets go of it.
func TestFailedNodeIsHeldUntilAbortOrDelete(t *testing.T) {
	r, c := failedRoll(t, threeNodes()...)
	r.pass(c)
	if !r.node("w1").Spec.Unschedulable || len(r.updateKeys("w1")) == 0 {
		t.Fatalf("the failed node was released under its Update: %+v", r.node("w1").ObjectMeta.Annotations)
	}

	// An abort ends the Update Cancelled; one that lost a node's patch leaves
	// that node to the controller.
	u := r.update(updatesv1alpha1.UpdateName)
	c.setCondition(u, ConditionProgressing, metav1.ConditionFalse, ReasonCancelled, "k3sm update abort ended the roll")
	u.Status.Phase = updatesv1alpha1.UpdatePhaseCancelled
	if err := c.writeStatus(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	r.pass(c)
	wantReleased(t, r, "w1", false)
}

// A node a finished Update never moved keeps nothing an earlier roll left.
func TestFinishedUpdateReleasesWhatItNeverHeld(t *testing.T) {
	nodes := threeNodes()
	nodes[1].Spec.Unschedulable = true                   // w2
	nodes[1].Status.NodeInfo.KubeletVersion = newKubelet // Skipped
	nodes[1].Annotations = map[string]string{
		CordonedAnnotation:                      "true",
		updatesv1alpha1.AnnotationUpdateVersion: "v0.1.9",
		updatesv1alpha1.AnnotationUpdatePhase:   string(updatesv1alpha1.UpdateNodePhaseFailed),
		update.AnnotationUpdatePayload:          "{}",
	}
	r := newRig(t, nodes...)
	r.createUpdate(updatesv1alpha1.UpdateName, updatesv1alpha1.UpdateSpec{Version: target})
	c := r.controller()
	r.drive(c, nil)
	if got := phases(r.update(updatesv1alpha1.UpdateName))["w2"]; got != updatesv1alpha1.UpdateNodePhaseSkipped {
		t.Fatalf("w2 phase %q, want Skipped", got)
	}
	r.pass(c)
	wantReleased(t, r, "w2", false)
}

// No answer about the Update is not an answer that it is gone.
func TestUnreadableUpdateReleasesNothing(t *testing.T) {
	t.Run("the list fails", func(t *testing.T) {
		r, c := failedRoll(t, threeNodes()...)
		r.deleteUpdate(updatesv1alpha1.UpdateName)
		r.dyn.PrependReactor("list", "updates", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("the apiserver went away")
		})
		if _, err := c.reconcile(context.Background()); err == nil {
			t.Fatal("reconcile did not report the failed list")
		}
		if !r.node("w1").Spec.Unschedulable || len(r.updateKeys("w1")) == 0 {
			t.Errorf("w1 was released on a failed list")
		}
	})

	t.Run("the singleton does not decode", func(t *testing.T) {
		r, c := failedRoll(t, threeNodes()...)
		r.deleteUpdate(updatesv1alpha1.UpdateName)
		bad := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": updatesv1alpha1.SchemeGroupVersion.String(), "kind": "Update",
			"metadata": map[string]any{"name": updatesv1alpha1.UpdateName},
			"spec":     "not an object",
		}}
		if _, err := r.dyn.Resource(updateResource).Create(context.Background(), bad, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		r.pass(c)
		if !r.node("w1").Spec.Unschedulable || len(r.updateKeys("w1")) == 0 {
			t.Errorf("w1 was released behind an Update the controller could not read")
		}
	})
}

// A patch the apiserver loses is tried again on the next pass, and costs no
// other node its release.
func TestReleaseRetriesAFailedPatch(t *testing.T) {
	r, c := failedRoll(t, threeNodes()...)
	n := r.node("w2")
	n.Annotations = map[string]string{updatesv1alpha1.AnnotationUpdatePhase: "Failed: refused"}
	if err := r.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), n, ""); err != nil {
		t.Fatal(err)
	}
	r.deleteUpdate(updatesv1alpha1.UpdateName)
	lost := true
	r.cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.PatchAction).GetName() == "w1" && lost {
			lost = false
			return true, nil, errors.New("the apiserver went away")
		}
		return false, nil, nil
	})

	if _, err := c.reconcile(context.Background()); err == nil {
		t.Fatal("reconcile did not report the lost patch")
	}
	if len(r.updateKeys("w1")) == 0 {
		t.Fatal("w1 was released through a failed patch")
	}
	wantReleased(t, r, "w2", false)

	r.pass(c)
	wantReleased(t, r, "w1", false)
}
