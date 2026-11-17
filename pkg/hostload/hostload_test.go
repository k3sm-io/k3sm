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

package hostload

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

var (
	provider = corev1.Taint{Key: "k3sm.io/provider", Effect: corev1.TaintEffectNoSchedule}
	operator = corev1.Taint{Key: "example.com/estate-off", Effect: corev1.TaintEffectNoSchedule}
	ours     = corev1.Taint{Key: TaintKey, Effect: corev1.TaintEffectPreferNoSchedule}
	// foreign carries our key with another effect: written by someone else.
	foreign = corev1.Taint{Key: TaintKey, Effect: corev1.TaintEffectNoSchedule}
	// valued carries our key and effect with a value: also someone else's.
	valued = corev1.Taint{Key: TaintKey, Value: "x", Effect: corev1.TaintEffectPreferNoSchedule}
)

func node(name string, cond *corev1.ConditionStatus, taints ...corev1.Taint) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, ResourceVersion: "7"}}
	n.Spec.Taints = taints
	n.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}
	if cond != nil {
		n.Status.Conditions = append(n.Status.Conditions, corev1.NodeCondition{Type: ConditionHostCPUBusy, Status: *cond})
	}
	return n
}

func status(s corev1.ConditionStatus) *corev1.ConditionStatus { return &s }

func TestBusy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cond *corev1.ConditionStatus
		want bool
	}{
		{"true", status(corev1.ConditionTrue), true},
		{"false", status(corev1.ConditionFalse), false},
		{"unknown", status(corev1.ConditionUnknown), false},
		{"absent (an older node)", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Busy(node("n", tc.cond)); got != tc.want {
				t.Fatalf("Busy = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDesiredTaints(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          []corev1.Taint
		want        bool
		out         []corev1.Taint
		wantChanged bool
	}{
		{"add after the others", []corev1.Taint{provider, operator}, true, []corev1.Taint{provider, operator, ours}, true},
		{"add to none", nil, true, []corev1.Taint{ours}, true},
		{"already present", []corev1.Taint{provider, ours}, true, []corev1.Taint{provider, ours}, false},
		{"remove keeps order", []corev1.Taint{provider, ours, operator}, false, []corev1.Taint{provider, operator}, true},
		{"already absent", []corev1.Taint{provider}, false, []corev1.Taint{provider}, false},
		{"duplicate of ours collapses", []corev1.Taint{ours, provider, ours}, true, []corev1.Taint{ours, provider}, true},
		{"our key with another effect is never touched", []corev1.Taint{foreign}, false, []corev1.Taint{foreign}, false},
		{"our key with another effect stays beside ours", []corev1.Taint{foreign}, true, []corev1.Taint{foreign, ours}, true},
		{"our key and effect with a value is someone else's", []corev1.Taint{valued}, false, []corev1.Taint{valued}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := node("n", nil, tc.in...)
			out, changed := DesiredTaints(n, tc.want)
			if changed != tc.wantChanged {
				t.Fatalf("changed = %v, want %v", changed, tc.wantChanged)
			}
			if !reflect.DeepEqual(out, tc.out) {
				t.Fatalf("taints = %v, want %v", out, tc.out)
			}
			if !reflect.DeepEqual(n.Spec.Taints, tc.in) {
				t.Fatalf("DesiredTaints modified the node's taints: %v", n.Spec.Taints)
			}
		})
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func taintsOf(t *testing.T, cs *fake.Clientset, name string) []corev1.Taint {
	t.Helper()
	n, err := cs.CoreV1().Nodes().Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", name, err)
	}
	return n.Spec.Taints
}

func countPatches(cs *fake.Clientset) int {
	n := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "patch" {
			n++
		}
	}
	return n
}

// fakeClock is the Reconciler's injected clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestReconciler(t *testing.T, cs *fake.Clientset) (*Reconciler, *fakeClock) {
	t.Helper()
	r, err := New(Config{Client: cs, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeClock{t: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}
	r.now = c.now
	return r, c
}

// TestReconcileTaintsExactlyTheBusyNodes is the B1855 unit gate: a busy node
// gains the PreferNoSchedule taint, a calm one loses it, every other taint
// survives, and a second pass writes nothing.
func TestReconcileTaintsExactlyTheBusyNodes(t *testing.T) {
	cs := fake.NewClientset(
		node("busy", status(corev1.ConditionTrue), provider, operator),
		node("calm", status(corev1.ConditionFalse), provider, ours),
		node("settled", status(corev1.ConditionTrue), provider, ours),
		node("old", nil, provider),
	)
	r, _ := newTestReconciler(t, cs)
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := map[string][]corev1.Taint{
		"busy":    {provider, operator, ours},
		"calm":    {provider},
		"settled": {provider, ours},
		"old":     {provider},
	}
	for name, w := range want {
		if got := taintsOf(t, cs, name); !reflect.DeepEqual(got, w) {
			t.Errorf("%s taints = %v, want %v", name, got, w)
		}
	}
	if got := countPatches(cs); got != 2 {
		t.Errorf("first pass patched %d nodes, want 2 (settled and old are already right)", got)
	}
	cs.ClearActions()
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if got := countPatches(cs); got != 0 {
		t.Errorf("second pass patched %d nodes, want 0", got)
	}
}

// TestReconcileKeepsTheTaintThroughAShortSilence: a tainted node that stops
// publishing the condition (its daemon restarted) keeps the taint for
// AbsentGrace, and loses it after; a condition that comes back resets the wait.
func TestReconcileKeepsTheTaintThroughAShortSilence(t *testing.T) {
	cs := fake.NewClientset(node("silent", nil, provider, ours))
	r, clock := newTestReconciler(t, cs)
	pass := func() {
		t.Helper()
		if err := r.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	pass()
	clock.t = clock.t.Add(AbsentGrace - time.Second)
	pass()
	if got := taintsOf(t, cs, "silent"); !reflect.DeepEqual(got, []corev1.Taint{provider, ours}) {
		t.Fatalf("inside the grace taints = %v, want ours kept", got)
	}
	clock.t = clock.t.Add(2 * time.Second)
	pass()
	if got := taintsOf(t, cs, "silent"); !reflect.DeepEqual(got, []corev1.Taint{provider}) {
		t.Fatalf("after the grace taints = %v, want ours removed", got)
	}
	if len(r.absentSince) != 0 {
		t.Fatalf("absentSince kept %v after the taint left", r.absentSince)
	}
}

// TestReconcileWriteIsGuardedByResourceVersion: a Node changed between the list
// and the patch (another writer's taint) fails the patch's resourceVersion test,
// so the other writer's taint is never overwritten.
func TestReconcileWriteIsGuardedByResourceVersion(t *testing.T) {
	cs := fake.NewClientset(node("busy", status(corev1.ConditionTrue), provider))
	// The list returns the node at resourceVersion 7; before the patch lands an
	// operator taints the node, moving it to 8.
	cs.PrependReactor("list", "nodes", func(k8stesting.Action) (bool, runtime.Object, error) {
		cs.ReactionChain = cs.ReactionChain[1:] // answer one list only
		stale := node("busy", status(corev1.ConditionTrue), provider)
		live := node("busy", status(corev1.ConditionTrue), provider, operator)
		live.ResourceVersion = "8"
		if err := cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("nodes"), live, ""); err != nil {
			return true, nil, err
		}
		return true, &corev1.NodeList{Items: []corev1.Node{*stale}}, nil
	})
	r, err := New(Config{Client: cs, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile succeeded against a node that changed after the list")
	}
	if got, want := taintsOf(t, cs, "busy"), []corev1.Taint{provider, operator}; !reflect.DeepEqual(got, want) {
		t.Fatalf("taints = %v, want %v (the operator's write kept, ours not applied)", got, want)
	}
}

// TestReconcileWritesEveryNodeItCan: one Node's failed write does not stop the
// pass; the error names it.
func TestReconcileWritesEveryNodeItCan(t *testing.T) {
	cs := fake.NewClientset(
		node("a", status(corev1.ConditionTrue)),
		node("b", status(corev1.ConditionTrue)),
	)
	boom := errors.New("boom")
	cs.PrependReactor("patch", "nodes", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.PatchAction).GetName() == "a" {
			return true, nil, boom
		}
		return false, nil, nil
	})
	r, err := New(Config{Client: cs, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	err = r.Reconcile(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("Reconcile error = %v, want it to wrap the failed write", err)
	}
	if got := taintsOf(t, cs, "b"); !reflect.DeepEqual(got, []corev1.Taint{ours}) {
		t.Fatalf("b taints = %v, want ours", got)
	}
}

func TestNewRequiresClient(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New with no client succeeded")
	}
}
