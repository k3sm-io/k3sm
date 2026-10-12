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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
)

// servingPosture is a server where metrics-server can serve: mesh serving certs
// and a usable vm runtime.
var servingPosture = Posture{ClusterCAKubeletServing: true, VMUsable: true}

// TestMetricsServerAddonGate is the gate on WHERE the metrics-server add-on is
// applied. Applied where it cannot serve, its APIService stays unavailable,
// which breaks aggregated discovery and wedges namespace deletion, so it is
// applied only on the mesh serving posture with a usable vm runtime. Elsewhere
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

	t.Run("applied when both conditions hold", func(t *testing.T) {
		actions, logs := converge(t, servingPosture)
		if applies := verifyTrafficShape(t, actions); len(applies) != len(wantMetricsServerObjects) {
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
		{"skipped on the single-node posture", Posture{VMUsable: true}, "single-node posture"},
		{"skipped without a usable vm runtime", Posture{ClusterCAKubeletServing: true}, "vm runtime is not usable"},
		{"skipped when neither holds", Posture{}, "single-node posture"},
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
		actions, logs := converge(t, Posture{VMUsable: true}, seed...)

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
		actions, _ := convergeFS(t, fsys, Posture{ClusterCAKubeletServing: true}, seed...)
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
