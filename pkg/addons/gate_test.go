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

package addons

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

// servingPosture is a server where metrics-server can serve: the kubelet
// serving certs chain to the cluster CA.
// The add-on is a native pod, so no node capability is part of it.
var servingPosture = Posture{ClusterCAKubeletServing: true}

// TestMetricsServerAddonGate is the gate on WHERE the metrics-server add-on is
// applied. Applied where it cannot serve, its APIService stays unavailable,
// which breaks aggregated discovery and wedges namespace deletion, so it is
// applied only on the cluster-CA kubelet serving posture, and never
// over an operator's own metrics.k8s.io APIService. Elsewhere
// it is skipped with one Info line naming the reason, and objects k3sm applied
// earlier are withdrawn, the APIService first.
func TestMetricsServerAddonGate(t *testing.T) {
	convergeFS := func(t *testing.T, fsys fs.FS, p Posture, seed ...*unstructured.Unstructured) ([]k8stesting.Action, string) {
		t.Helper()
		dc := newFakeDynamic(t, seed...)
		var logs bytes.Buffer
		r := New(fsys, dc, metricsServerMapper()).WithPosture(p)
		r.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := r.Converge(context.Background()); err != nil {
			t.Fatalf("converge: %v", err)
		}
		return dc.Actions(), logs.String()
	}
	converge := func(t *testing.T, p Posture, seed ...*unstructured.Unstructured) ([]k8stesting.Action, string) {
		t.Helper()
		return convergeFS(t, FS(), p, seed...)
	}
	verbs := func(actions []k8stesting.Action) map[string]int {
		n := map[string]int{}
		for _, a := range actions {
			n[a.GetVerb()]++
		}
		return n
	}

	t.Run("applied on the cluster-CA kubelet serving posture", func(t *testing.T) {
		actions, logs := converge(t, servingPosture)
		if applies := verifyTrafficShape(t, afterGuardRead(t, actions)); len(applies) != len(wantMetricsServerObjects) {
			t.Errorf("%d applies, want %d", len(applies), len(wantMetricsServerObjects))
		}
		if logs != "" {
			t.Errorf("logged on the serving path: %s", logs)
		}
	})

	for _, tc := range []struct {
		name    string
		posture Posture
		reason  string
	}{
		{"skipped when the kubelet serving certs do not chain to the in-cluster CA", Posture{}, "do not chain to the in-cluster CA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actions, logs := converge(t, tc.posture)
			got := verbs(actions)
			if got["patch"] != 0 || got["delete"] != 0 || got["list"] != 0 {
				t.Errorf("verbs %v on an empty cluster: want no apply, delete or list", got)
			}
			if n := strings.Count(logs, "embedded add-on not applied"); n != 1 {
				t.Errorf("%d skip lines, want exactly 1:\n%s", n, logs)
			}
			if !strings.Contains(logs, "level=INFO") || !strings.Contains(logs, tc.reason) || !strings.Contains(logs, "file=metrics-server.yaml") {
				t.Errorf("skip line does not carry Info level, the file and the reason %q:\n%s", tc.reason, logs)
			}
		})
	}

	t.Run("a transition to skipped withdraws k3sm's objects, APIService first", func(t *testing.T) {
		objs, errs := (&Reconciler{fsys: FS()}).load()
		if len(errs) != 0 {
			t.Fatalf("load: %v", errs)
		}
		// The cluster as an earlier serving boot left it, except that the
		// Service was applied by someone else: an object of the same name
		// k3sm never applied must survive.
		var seed []*unstructured.Unstructured
		for _, o := range objs {
			live := o.DeepCopy()
			live.SetUID(types.UID("uid-" + live.GetName()))
			manager := FieldManager
			if live.GetKind() == "Service" {
				manager = "kubectl-client-side-apply"
			}
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: manager, Operation: metav1.ManagedFieldsOperationApply, APIVersion: live.GetAPIVersion()}})
			seed = append(seed, live)
		}
		actions, logs := converge(t, Posture{}, seed...)

		var deletes []k8stesting.DeleteActionImpl
		for _, a := range actions {
			switch a.GetVerb() {
			case "get":
			case "delete":
				deletes = append(deletes, a.(k8stesting.DeleteActionImpl))
			default:
				t.Errorf("verb %q while withdrawing; want only get-by-name and delete", a.GetVerb())
			}
		}
		if len(deletes) != len(objs)-1 {
			t.Fatalf("%d deletes, want %d (every object but the foreign Service)", len(deletes), len(objs)-1)
		}
		if first := deletes[0]; first.GetResource().Resource != "apiservices" || first.GetName() != "v1beta1.metrics.k8s.io" {
			t.Errorf("first delete = %s %s, want the APIService v1beta1.metrics.k8s.io", first.GetResource().Resource, first.GetName())
		}
		for _, d := range deletes {
			if d.GetResource().Resource == "services" {
				t.Error("deleted the Service k3sm did not apply")
			}
			pc := d.DeleteOptions.Preconditions
			if pc == nil || pc.UID == nil || *pc.UID != types.UID("uid-"+d.GetName()) {
				t.Errorf("delete %s carries no UID precondition for the object it read", d.GetName())
			}
		}
		if !strings.Contains(logs, "withdrawn=8") || !strings.Contains(logs, "leftNotAppliedByK3sm=1") {
			t.Errorf("skip line does not count the withdrawal:\n%s", logs)
		}
	})

	t.Run("a foreign metrics.k8s.io APIService is never adopted nor deleted", func(t *testing.T) {
		objs, errs := (&Reconciler{fsys: FS()}).load()
		if len(errs) != 0 {
			t.Fatalf("load: %v", errs)
		}
		// The operator runs metrics-server: its APIService carries only its own
		// manager. The other objects are seeded as k3sm-applied, the worst case
		// for a withdrawal that must still not happen.
		var seed []*unstructured.Unstructured
		for _, o := range objs {
			live := o.DeepCopy()
			manager := FieldManager
			if live.GetKind() == apiServiceKind {
				manager = "kubectl-client-side-apply"
			}
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: manager, Operation: metav1.ManagedFieldsOperationApply}})
			seed = append(seed, live)
		}
		for _, p := range []Posture{servingPosture, {}} {
			actions, logs := converge(t, p, seed...)
			got := verbs(actions)
			if got["patch"] != 0 || got["delete"] != 0 || got["list"] != 0 {
				t.Errorf("posture %+v: verbs %v, want only the guard read", p, got)
			}
			if got["get"] != 1 {
				t.Errorf("posture %+v: %d gets, want exactly the one guard read", p, got["get"])
			}
			if !strings.Contains(logs, foreignMetricsReason) {
				t.Errorf("posture %+v: skip line does not name the foreign APIService:\n%s", p, logs)
			}
		}
	})

	t.Run("an undecided posture neither applies nor withdraws", func(t *testing.T) {
		objs, _ := (&Reconciler{fsys: FS()}).load()
		var seed []*unstructured.Unstructured
		for _, o := range objs {
			live := o.DeepCopy()
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: FieldManager, Operation: metav1.ManagedFieldsOperationApply}})
			seed = append(seed, live)
		}
		actions, logs := converge(t, Posture{ClusterCAKubeletServing: true, Undecided: "list nodes: connection refused"}, seed...)
		if got := verbs(actions); got["patch"] != 0 || got["delete"] != 0 {
			t.Errorf("verbs %v, want no apply and no delete", got)
		}
		if !strings.Contains(logs, "connection refused") {
			t.Errorf("skip line does not carry the undecided reason:\n%s", logs)
		}
	})

	t.Run("the APIService goes first wherever the manifest places it", func(t *testing.T) {
		// The shipped file lists the APIService last, so reverse order alone would
		// put it first. This fixture lists it FIRST, so only the explicit rule does.
		objs, errs := (&Reconciler{fsys: FS()}).load()
		if len(errs) != 0 {
			t.Fatalf("load: %v", errs)
		}
		var reordered []*unstructured.Unstructured
		for _, o := range objs {
			if o.GetKind() == apiServiceKind {
				reordered = append([]*unstructured.Unstructured{o}, reordered...)
			} else {
				reordered = append(reordered, o)
			}
		}
		var doc strings.Builder
		var seed []*unstructured.Unstructured
		for _, o := range reordered {
			raw, err := o.MarshalJSON()
			if err != nil {
				t.Fatalf("marshal %s: %v", o.GetName(), err)
			}
			doc.WriteString("---\n")
			doc.Write(raw)
			doc.WriteString("\n")
			live := o.DeepCopy()
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: FieldManager, Operation: metav1.ManagedFieldsOperationApply}})
			seed = append(seed, live)
		}
		fsys := fstest.MapFS{"metrics-server.yaml": &fstest.MapFile{Data: []byte(doc.String())}}
		actions, _ := convergeFS(t, fsys, Posture{}, seed...)
		for _, a := range actions {
			if a.GetVerb() != "delete" {
				continue
			}
			if d := a.(k8stesting.DeleteActionImpl); d.GetResource().Resource != "apiservices" {
				t.Errorf("first delete = %s %s, want the APIService", d.GetResource().Resource, d.GetName())
			}
			return
		}
		t.Fatal("no delete issued")
	})
}

// afterGuardRead asserts that a gated metrics-server converge opened with exactly
// one read, the Get of the ownership guard APIService by name, and returns the
// actions after it.
func afterGuardRead(t *testing.T, actions []k8stesting.Action) []k8stesting.Action {
	t.Helper()
	if len(actions) == 0 {
		t.Fatal("no API traffic; want the ownership guard read first")
	}
	g, ok := actions[0].(k8stesting.GetActionImpl)
	if !ok || g.GetResource().Resource != "apiservices" || g.GetName() != "v1beta1.metrics.k8s.io" {
		t.Fatalf("first action = %v, want a Get of apiservices/v1beta1.metrics.k8s.io", actions[0])
	}
	return actions[1:]
}

// TestMetricsServerAddonRegate is the gate on the post-start re-evaluation. The
// ticks channel is the fake clock: it is pre-filled and closed, so Regate
// returns after the last tick and every assertion reads a finished run. The
// posture is a script, one entry per tick, standing in for the server's node
// reads.
func TestMetricsServerAddonRegate(t *testing.T) {
	var (
		undecided = Posture{ClusterCAKubeletServing: true, Undecided: "no Node is registered yet"}
		failing   = Posture{} // positive: Nodes exist, and the requirement fails
		serving   = servingPosture
	)
	ownedSeed := func(t *testing.T) []*unstructured.Unstructured {
		t.Helper()
		objs, errs := (&Reconciler{fsys: FS()}).load()
		if len(errs) != 0 {
			t.Fatalf("load: %v", errs)
		}
		var seed []*unstructured.Unstructured
		for _, o := range objs {
			live := o.DeepCopy()
			live.SetManagedFields([]metav1.ManagedFieldsEntry{{Manager: FieldManager, Operation: metav1.ManagedFieldsOperationApply}})
			seed = append(seed, live)
		}
		return seed
	}
	// run converges at start under startPosture, then regates over len(ticks)
	// ticks with the scripted postures, and returns the regate's actions, how
	// many times it read the posture, and its log.
	run := func(t *testing.T, startPosture Posture, script []Posture, ticks int, seed ...*unstructured.Unstructured) ([]k8stesting.Action, int, string) {
		t.Helper()
		dc := newFakeDynamic(t, seed...)
		var logs bytes.Buffer
		r := New(FS(), dc, metricsServerMapper()).WithPosture(startPosture)
		r.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
		if err := r.Converge(context.Background()); err != nil {
			t.Fatalf("converge: %v", err)
		}
		dc.ClearActions()
		reads := 0
		posture := func(context.Context) Posture {
			p := script[min(reads, len(script)-1)]
			reads++
			return p
		}
		ch := make(chan time.Time, ticks)
		for i := 0; i < ticks; i++ {
			ch <- time.Unix(int64(i)*int64(RegateInterval/time.Second), 0)
		}
		close(ch)
		r.Regate(context.Background(), posture, ch)
		return dc.Actions(), reads, logs.String()
	}
	count := func(actions []k8stesting.Action, verb string) int {
		n := 0
		for _, a := range actions {
			if a.GetVerb() == verb {
				n++
			}
		}
		return n
	}

	t.Run("a requirement that holds after start is applied on the next tick", func(t *testing.T) {
		actions, reads, logs := run(t, undecided, []Posture{failing, serving}, 3)
		if got := count(actions, "patch"); got != len(wantMetricsServerObjects) {
			t.Errorf("%d applies, want %d on the tick that saw the requirement hold", got, len(wantMetricsServerObjects))
		}
		if got := count(actions, "delete"); got != 0 {
			t.Errorf("%d deletes; one positive read must not withdraw", got)
		}
		if reads != 2 {
			t.Errorf("posture read %d times, want 2: the loop is done once the file is applied", reads)
		}
		if !strings.Contains(logs, "embedded add-on applied after re-evaluation") {
			t.Errorf("no applied line:\n%s", logs)
		}
	})

	t.Run("a file applied at start leaves the loop a no-op", func(t *testing.T) {
		actions, reads, _ := run(t, serving, []Posture{failing}, 3)
		if len(actions) != 0 || reads != 0 {
			t.Errorf("regate issued %d actions and %d posture reads after a full start-up apply, want none", len(actions), reads)
		}
	})

	t.Run("a single stale read between undecided ones never withdraws", func(t *testing.T) {
		actions, _, _ := run(t, undecided, []Posture{failing, undecided, failing, undecided}, 4, ownedSeed(t)...)
		if got := count(actions, "delete"); got != 0 {
			t.Errorf("%d deletes; non-consecutive positive reads must not withdraw", got)
		}
	})

	t.Run("two consecutive positive reads withdraw, once per process", func(t *testing.T) {
		actions, _, logs := run(t, undecided, []Posture{failing}, 5, ownedSeed(t)...)
		if got := count(actions, "delete"); got != len(wantMetricsServerObjects) {
			t.Fatalf("%d deletes, want %d (one withdrawal)", got, len(wantMetricsServerObjects))
		}
		if first := actions[0]; first.GetVerb() != "get" {
			t.Errorf("first regate action %v, want the guard read", first)
		}
		// Tick 1: guard read only (one positive read). Tick 2: guard read plus a
		// Get per object to withdraw. Ticks 3 to 5: guard read only, because the
		// withdrawal is spent for this process.
		if got, want := count(actions, "get"), 1+(1+len(wantMetricsServerObjects))+3; got != want {
			t.Errorf("%d gets, want %d: a second withdrawal was attempted", got, want)
		}
		if n := strings.Count(logs, "withdrawn=9"); n != 1 {
			t.Errorf("%d withdrawal lines, want 1:\n%s", n, logs)
		}
	})

	t.Run("it honours ctx", func(t *testing.T) {
		r := New(FS(), newFakeDynamic(t), metricsServerMapper()).WithPosture(undecided)
		r.logger = slog.New(slog.DiscardHandler)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() {
			defer close(done)
			r.Regate(ctx, func(context.Context) Posture { return serving }, make(chan time.Time))
		}()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Regate did not return on a cancelled ctx")
		}
	})
}
