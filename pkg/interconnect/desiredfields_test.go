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

package interconnect

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"

	netv1alpha1 "k3sm.io/apis/net/v1alpha1"
)

// TestResolverDesiredCarriesNamespacesAndModels covers the two desired
// fields the node's pod attach reads instead of the Interconnect and MLXModel:
// both are filled, a change in either rewrites the value, and a
// failed MLXModel read writes nothing new and clears nothing.
func TestResolverDesiredCarriesNamespacesAndModels(t *testing.T) {
	ctx := context.Background()
	desiredOf := func(t *testing.T, h *harness, node string) netv1alpha1.InterconnectDesired {
		t.Helper()
		v, ok := h.annotation(t, node)
		if !ok {
			t.Fatalf("%s carries no desired annotation", node)
		}
		d, err := netv1alpha1.ParseInterconnectDesired(v)
		if err != nil {
			t.Fatalf("parse %s desired %q: %v", node, v, err)
		}
		return d
	}
	armed := func(namespaces ...string) *netv1alpha1.Interconnect {
		ic := interconnect(true)
		ic.Spec.AllowedNamespaces = namespaces
		return ic
	}
	// refresh copies the live Nodes into the resolver's cache, as the informer
	// would after the resolver's own patches.
	refresh := func(t *testing.T, h *harness) {
		t.Helper()
		for _, n := range []string{"a", "b"} {
			live, err := h.cs.CoreV1().Nodes().Get(ctx, n, metavOpts)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.nodes.Update(live); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run("both fields are filled, models sorted and deduplicated", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), armed("ml", "serving"))
		r := h.resolver()
		r.cfg.MLXModels = func(context.Context) ([]netv1alpha1.InterconnectModelRef, error) {
			return []netv1alpha1.InterconnectModelRef{ref("ml", "b", "uid-b"), ref("ml", "a", "uid-a"), ref("ml", "b", "uid-b"), ref("ml", "c", "")}, nil
		}
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		for _, n := range []string{"a", "b"} {
			d := desiredOf(t, h, n)
			if !reflect.DeepEqual(d.AllowedNamespaces, []string{"ml", "serving"}) {
				t.Errorf("%s allowedNamespaces = %v", n, d.AllowedNamespaces)
			}
			if want := []netv1alpha1.InterconnectModelRef{ref("ml", "a", "uid-a"), ref("ml", "b", "uid-b")}; !reflect.DeepEqual(d.MLXModels, want) {
				t.Errorf("%s mlxModels = %v, want %v", n, d.MLXModels, want)
			}
		}
	})

	t.Run("a change in either list rewrites desired; no change writes nothing", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), armed())
		models := []netv1alpha1.InterconnectModelRef{ref("ml", "a", "uid-a")}
		r := h.resolver()
		r.cfg.MLXModels = func(context.Context) ([]netv1alpha1.InterconnectModelRef, error) { return slices.Clone(models), nil }
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		refresh(t, h)
		before := h.nodePatches()
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if got := h.nodePatches(); got != before {
			t.Fatalf("an unchanged resolution patched %d nodes", got-before)
		}

		models = append(models, ref("ml", "c", "uid-c"))
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if d := desiredOf(t, h, "a"); !reflect.DeepEqual(d.MLXModels, models) {
			t.Errorf("after a new model: mlxModels = %v, want %v", d.MLXModels, models)
		}
		refresh(t, h)

		ic := h.object(t)
		ic.Spec.AllowedNamespaces = []string{"ml"}
		u, err := toUnstructured(ic)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.dyn.Resource(GVR).Update(ctx, u, updateOpts); err != nil {
			t.Fatal(err)
		}
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if d := desiredOf(t, h, "b"); !reflect.DeepEqual(d.AllowedNamespaces, []string{"ml"}) {
			t.Errorf("after an allowedNamespaces edit: %v, want [ml]", d.AllowedNamespaces)
		}
	})

	t.Run("a failed MLXModel read writes nothing new and clears nothing", func(t *testing.T) {
		nodes := cabledPair(t)
		stale := `{"schema":1,"interconnect":"thunderbolt","fallback":"network","mlxModels":[{"namespace":"ml","name":"a","uid":"uid-a"}]}`
		nodes[0].Annotations[netv1alpha1.AnnotationInterconnectDesired] = stale
		h := newHarness(t, nodes, armed("ml"))
		r := h.resolver()
		r.cfg.MLXModels = func(context.Context) ([]netv1alpha1.InterconnectModelRef, error) {
			return nil, errors.New("apiserver unavailable")
		}
		if err := r.Reconcile(ctx); err == nil {
			t.Error("a failed MLXModel read must be reported")
		}
		if h.nodePatches() != 0 {
			t.Fatalf("a failed MLXModel read patched %d nodes", h.nodePatches())
		}
		if v, _ := h.annotation(t, "a"); v != stale {
			t.Errorf("a desired = %q, want it left as %q", v, stale)
		}

		// A disarm still removes the annotation: removal needs no UID.
		off := newHarness(t, nodes, interconnect(false))
		ro := off.resolver()
		ro.cfg.MLXModels = r.cfg.MLXModels
		_ = ro.Reconcile(ctx)
		if v, ok := off.annotation(t, "a"); ok {
			t.Errorf("a disarmed node keeps desired %q on a failed MLXModel read", v)
		}
	})

	t.Run("models beyond the bounds are left out, namespaces never", func(t *testing.T) {
		h := newHarness(t, cabledPair(t), armed("ml"))
		var many []netv1alpha1.InterconnectModelRef
		for i := range netv1alpha1.MaxInterconnectListItems + 10 {
			many = append(many, ref("ml", fmt.Sprintf("model-%03d", i), fmt.Sprintf("%036d", i)))
		}
		r := h.resolver()
		r.cfg.MLXModels = func(context.Context) ([]netv1alpha1.InterconnectModelRef, error) { return many, nil }
		if err := r.Reconcile(ctx); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		d := desiredOf(t, h, "a")
		if n := len(d.MLXModels); n == 0 || n > netv1alpha1.MaxInterconnectListItems {
			t.Errorf("mlxModels carries %d, want 1..%d", n, netv1alpha1.MaxInterconnectListItems)
		}
		if !reflect.DeepEqual(d.AllowedNamespaces, []string{"ml"}) {
			t.Errorf("allowedNamespaces = %v, want [ml]", d.AllowedNamespaces)
		}
	})
}

// TestMLXModelLister asserts which MLXModels name a slot-1 owner: sharded
// ones over any path but "network", by namespace, name and UID, and that an
// unserved CRD reads as none.
func TestMLXModelLister(t *testing.T) {
	model := func(name, uid string, distributed map[string]any) *unstructured.Unstructured {
		spec := map[string]any{"model": "m"}
		if distributed != nil {
			spec["distributed"] = distributed
		}
		u := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "mlx.k3sm.io/v1alpha1",
			"kind":       "MLXModel",
			"metadata":   map[string]any{"name": name, "namespace": "ml", "uid": uid},
			"spec":       spec,
		}}
		return u
	}
	listKinds := map[schema.GroupVersionResource]string{mlxModelGVR: "MLXModelList"}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds,
		model("auto", "u-auto", map[string]any{"ranks": int64(2)}),
		model("tb", "u-tb", map[string]any{"ranks": int64(2), "interconnect": "thunderbolt"}),
		model("net", "u-net", map[string]any{"ranks": int64(2), "interconnect": "network"}),
		model("single", "u-single", nil),
	)
	got, err := MLXModelLister(dyn)(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	set := map[netv1alpha1.InterconnectModelRef]bool{}
	for _, m := range got {
		set[m] = true
	}
	if want := map[netv1alpha1.InterconnectModelRef]bool{ref("ml", "auto", "u-auto"): true, ref("ml", "tb", "u-tb"): true}; !reflect.DeepEqual(set, want) {
		t.Errorf("models = %v, want the auto and tb models", got)
	}

	missing := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	missing.PrependReactor("list", "mlxmodels", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, notFound()
	})
	if got, err := MLXModelLister(missing)(context.Background()); err != nil || len(got) != 0 {
		t.Errorf("unserved CRD = %v, %v; want none, nil", got, err)
	}
	failing := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	failing.PrependReactor("list", "mlxmodels", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unavailable")
	})
	if _, err := MLXModelLister(failing)(context.Background()); err == nil {
		t.Error("a failed list must be reported")
	}
}

var (
	metavOpts  = metav1.GetOptions{}
	updateOpts = metav1.UpdateOptions{}
)

func ref(ns, name, uid string) netv1alpha1.InterconnectModelRef {
	return netv1alpha1.InterconnectModelRef{Namespace: ns, Name: name, UID: uid}
}

func notFound() error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "mlx.k3sm.io", Resource: "mlxmodels"}, "")
}
