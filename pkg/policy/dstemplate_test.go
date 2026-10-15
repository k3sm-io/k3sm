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

package policy

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/mutating/patch"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/cel/environment"
	"k8s.io/client-go/kubernetes/fake"
)

// TestDaemonSetTemplateTolerationPolicy is the B566 gate. The DaemonSet controller
// chooses nodes from the pod TEMPLATE, so the provider toleration must be in the
// stored template, not only in the pods: without it desiredNumberScheduled stays 0
// on a cluster where every node carries the provider taint, and no pod is ever
// created for the pod-level injector to mutate. It pins the rendered policy and
// binding, evaluates the shared ToleratesTaint CEL at both roots, and runs the
// template patch through the apiserver's own MutatingAdmissionPolicy JSONPatch
// compiler and patcher (the code a live apiserver runs), so the
// Object.spec.template.spec.tolerations constructor and both has() branches are
// proven to compile and apply.
func TestDaemonSetTemplateTolerationPolicy(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
		t.Fatalf("EnsureDaemonSetTolerationMutation: %v", err)
	}

	pol, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx,
		"k3sm-inject-daemonset-template-provider-toleration", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get template policy: %v", err)
	}
	if pol.Labels[managedLabel] != "true" {
		t.Errorf("template policy labels = %v, want %s=true", pol.Labels, managedLabel)
	}
	rules := pol.Spec.MatchConstraints.ResourceRules
	if len(rules) != 1 {
		t.Fatalf("want exactly one resource rule, got %d", len(rules))
	}
	r := rules[0]
	if len(r.APIGroups) != 1 || r.APIGroups[0] != "apps" {
		t.Errorf("apiGroups = %v, want [apps]", r.APIGroups)
	}
	if len(r.APIVersions) != 1 || r.APIVersions[0] != "v1" {
		t.Errorf("apiVersions = %v, want [v1]", r.APIVersions)
	}
	if len(r.Resources) != 1 || r.Resources[0] != "daemonsets" {
		t.Errorf("resources = %v, want exactly [daemonsets] (never daemonsets/status)", r.Resources)
	}
	if !sameOps(r.Operations, []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}) {
		t.Errorf("operations = %v, want [CREATE UPDATE]", r.Operations)
	}
	if pol.Spec.FailurePolicy == nil || *pol.Spec.FailurePolicy != admissionregistrationv1.Ignore {
		t.Errorf("failurePolicy = %v, want Ignore", pol.Spec.FailurePolicy)
	}
	if pol.Spec.ReinvocationPolicy != admissionregistrationv1.IfNeededReinvocationPolicy {
		t.Errorf("reinvocationPolicy = %q, want IfNeeded", pol.Spec.ReinvocationPolicy)
	}

	const templateRoot = "object.spec.template.spec"
	wantCond := "!(" + providerTolerationExprAt(templateRoot) + ")"
	if len(pol.Spec.MatchConditions) != 1 || pol.Spec.MatchConditions[0].Name != "not-already-tolerating" ||
		pol.Spec.MatchConditions[0].Expression != wantCond {
		t.Errorf("matchConditions = %+v, want one not-already-tolerating = %q", pol.Spec.MatchConditions, wantCond)
	}
	// The pod-root instance must be the expression the Warn and pod-level policies
	// have always carried: parameterising it changed no pod semantics.
	if providerTolerationExpr != providerTolerationExprAt("object.spec") {
		t.Errorf("pod-root expression drifted from the parameterised form")
	}

	if len(pol.Spec.Mutations) != 1 || pol.Spec.Mutations[0].PatchType != admissionregistrationv1.PatchTypeJSONPatch ||
		pol.Spec.Mutations[0].JSONPatch == nil {
		t.Fatalf("want exactly one JSONPatch mutation, got %+v", pol.Spec.Mutations)
	}
	patchExpr := pol.Spec.Mutations[0].JSONPatch.Expression
	for _, want := range []string{
		"has(object.spec.template.spec.tolerations)",
		`"/spec/template/spec/tolerations/-"`,
		`"/spec/template/spec/tolerations"`,
		"Object.spec.template.spec.tolerations{",
		ProviderTaintKey, "Exists", "NoSchedule",
	} {
		if !strings.Contains(patchExpr, want) {
			t.Errorf("template patch missing %q: %s", want, patchExpr)
		}
	}
	// Res.7: the toleration only, never a nodeSelector.
	blob := patchExpr + " " + wantCond
	for _, banned := range []string{"nodeSelector", "darwin"} {
		if strings.Contains(blob, banned) {
			t.Errorf("template policy must not reference %q: %s", banned, blob)
		}
	}

	bind, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicyBindings().Get(ctx,
		"k3sm-inject-daemonset-template-provider-toleration-binding", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get template binding: %v", err)
	}
	if bind.Spec.PolicyName != pol.Name || bind.Labels[managedLabel] != "true" {
		t.Errorf("binding = %+v, want policyName %s and the managed label", bind, pol.Name)
	}

	// The pod-level policy is still provisioned beside it.
	if _, err := cs.AdmissionregistrationV1().MutatingAdmissionPolicies().Get(ctx, dsTolerationPolicyName, metav1.GetOptions{}); err != nil {
		t.Errorf("pod-level policy must still be provisioned: %v", err)
	}

	t.Run("ToleratesTaint at both roots", func(t *testing.T) {
		tests := []struct {
			name        string
			tolerations []any // nil: the list is absent
			want        bool
		}{
			{"Exists, no effect", []any{map[string]any{"key": ProviderTaintKey, "operator": "Exists"}}, true},
			{"Exists, NoSchedule", []any{map[string]any{"key": ProviderTaintKey, "operator": "Exists", "effect": "NoSchedule"}}, true},
			{"Equal with empty value", []any{map[string]any{"key": ProviderTaintKey, "operator": "Equal", "value": "", "effect": "NoSchedule"}}, true},
			{"Equal with a value", []any{map[string]any{"key": ProviderTaintKey, "operator": "Equal", "value": "x", "effect": "NoSchedule"}}, false},
			{"NoExecute only", []any{map[string]any{"key": ProviderTaintKey, "operator": "Exists", "effect": "NoExecute"}}, false},
			{"different key", []any{map[string]any{"key": "example.com/other", "operator": "Exists"}}, false},
			{"empty list", []any{}, false},
			{"absent list", nil, false},
		}
		for _, root := range []string{"object.spec", templateRoot} {
			prg := celProgram(t, providerTolerationExprAt(root))
			for _, tt := range tests {
				t.Run(root+"/"+tt.name, func(t *testing.T) {
					podSpec := map[string]any{}
					if tt.tolerations != nil {
						podSpec["tolerations"] = tt.tolerations
					}
					obj := map[string]any{"spec": podSpec}
					if root == templateRoot {
						obj = map[string]any{"spec": map[string]any{"template": map[string]any{"spec": podSpec}}}
					}
					out, _, err := prg.Eval(map[string]any{"object": obj})
					if err != nil {
						t.Fatalf("eval: %v", err)
					}
					if got, _ := out.Value().(bool); got != tt.want {
						t.Errorf("tolerates = %v, want %v", got, tt.want)
					}
				})
			}
		}
	})

	t.Run("negated matchCondition", func(t *testing.T) {
		// The exact string the policy carries: false (no mutation, so an UPDATE of a
		// tolerating template is a no-op) when the template tolerates the taint.
		prg := celProgram(t, wantCond)
		tests := []struct {
			name        string
			tolerations []any
			wantMatch   bool
		}{
			{"Exists tolerates: not matched", []any{map[string]any{"key": ProviderTaintKey, "operator": "Exists"}}, false},
			{"Equal empty tolerates: not matched", []any{map[string]any{"key": ProviderTaintKey, "operator": "Equal", "value": "", "effect": "NoSchedule"}}, false},
			{"different key: matched", []any{map[string]any{"key": "example.com/other", "operator": "Exists"}}, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				obj := map[string]any{"spec": map[string]any{"template": map[string]any{"spec": map[string]any{"tolerations": tt.tolerations}}}}
				out, _, err := prg.Eval(map[string]any{"object": obj})
				if err != nil {
					t.Fatalf("eval: %v", err)
				}
				if got, _ := out.Value().(bool); got != tt.wantMatch {
					t.Errorf("matchCondition = %v, want %v", got, tt.wantMatch)
				}
			})
		}
	})

	t.Run("apiserver JSONPatch on a present empty list", func(t *testing.T) {
		// A typed DaemonSet drops an empty Tolerations (omitempty), so this case is
		// built unstructured to keep `tolerations: []` present and take the has()
		// branch that appends with /-.
		ds := &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apps/v1",
			"kind":       "DaemonSet",
			"metadata":   map[string]any{"name": "ds", "namespace": "default"},
			"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
				"tolerations": []any{},
				"containers":  []any{map[string]any{"name": "c", "image": "x"}},
			}}},
		}}
		hasPrg := celProgram(t, "has(object.spec.template.spec.tolerations)")
		if out, _, err := hasPrg.Eval(map[string]any{"object": ds.Object}); err != nil || out.Value() != true {
			t.Fatalf("has() on the present empty list = %v (err %v), want true: the case must take the /- branch", out, err)
		}
		got := applyJSONPatch(t, patchExpr, ds, schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"})
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(got)
		if err != nil {
			t.Fatalf("to unstructured: %v", err)
		}
		tols, found, err := unstructured.NestedSlice(u, "spec", "template", "spec", "tolerations")
		if err != nil || !found {
			t.Fatalf("tolerations after patch: found=%v err=%v", found, err)
		}
		if len(tols) != 1 {
			t.Fatalf("tolerations = %v, want exactly one", tols)
		}
		tol, _ := tols[0].(map[string]any)
		if tol["key"] != ProviderTaintKey || tol["operator"] != "Exists" || tol["effect"] != "NoSchedule" {
			t.Errorf("toleration = %v, want the provider toleration", tol)
		}
	})

	t.Run("apiserver JSONPatch", func(t *testing.T) {
		provider := corev1.Toleration{Key: ProviderTaintKey, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}
		other := corev1.Toleration{Key: "example.com/other", Operator: corev1.TolerationOpExists}
		tests := []struct {
			name string
			in   []corev1.Toleration
			want []corev1.Toleration
		}{
			{"absent list gets a one-element list", nil, []corev1.Toleration{provider}},
			{"empty list gets the toleration appended", []corev1.Toleration{}, []corev1.Toleration{provider}},
			{"a different-key list keeps its entry", []corev1.Toleration{other}, []corev1.Toleration{other, provider}},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ds := &appsv1.DaemonSet{
					ObjectMeta: metav1.ObjectMeta{Name: "ds", Namespace: "default"},
					Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
						Tolerations: tt.in,
						Containers:  []corev1.Container{{Name: "c", Image: "x"}},
					}}},
				}
				got := applyJSONPatch(t, patchExpr, ds, schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"})
				gotDS, ok := got.(*appsv1.DaemonSet)
				if !ok {
					t.Fatalf("patched object is %T, want *appsv1.DaemonSet", got)
				}
				gotTols := gotDS.Spec.Template.Spec.Tolerations
				if len(gotTols) != len(tt.want) {
					t.Fatalf("tolerations = %+v, want %+v", gotTols, tt.want)
				}
				for i := range tt.want {
					if gotTols[i] != tt.want[i] {
						t.Errorf("tolerations[%d] = %+v, want %+v", i, gotTols[i], tt.want[i])
					}
				}
				if gotDS.Spec.Template.Spec.NodeSelector != nil {
					t.Errorf("nodeSelector injected: %v", gotDS.Spec.Template.Spec.NodeSelector)
				}
			})
		}
	})
}

// applyJSONPatch compiles expr with the apiserver's MutatingAdmissionPolicy compiler
// (with the JSONPatch and Object.<path> types declared, as for a live policy) and
// applies it to obj as a CREATE.
func applyJSONPatch(t *testing.T, expr string, obj runtime.Object, gvr schema.GroupVersionResource) runtime.Object {
	t.Helper()
	compiler, err := plugincel.NewCompositedCompiler(environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion()))
	if err != nil {
		t.Fatalf("compiler: %v", err)
	}
	eval := compiler.CompileMutatingEvaluator(&patch.JSONPatchCondition{Expression: expr},
		plugincel.OptionalVariableDeclarations{HasPatchTypes: true}, environment.StoredExpressions)
	scheme := runtime.NewScheme()
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	gvks, _, err := scheme.ObjectKinds(obj)
	if err != nil || len(gvks) != 1 {
		t.Fatalf("object kinds for %T: %v %v", obj, gvks, err)
	}
	acc, err := meta.Accessor(obj)
	if err != nil {
		t.Fatal(err)
	}
	attrs := admission.NewAttributesRecord(obj, nil, gvks[0], acc.GetNamespace(), acc.GetName(), gvr,
		"", admission.Create, &metav1.CreateOptions{}, false, nil)
	req := patch.Request{
		MatchedResource: gvr,
		VersionedAttributes: &admission.VersionedAttributes{
			Attributes:      attrs,
			VersionedKind:   gvks[0],
			VersionedObject: admission.NewLazyObject(obj),
		},
		ObjectInterfaces:  admission.NewObjectInterfacesFromScheme(scheme),
		OptionalVariables: plugincel.OptionalVariableBindings{},
	}
	got, err := patch.NewJSONPatcher(eval).Patch(context.Background(), req, celconfig.RuntimeCELCostBudget)
	if err != nil {
		t.Fatalf("apply JSONPatch: %v\nexpression:\n%s", err, expr)
	}
	return got
}
