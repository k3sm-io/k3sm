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

package crdensure

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	structuralschema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuralcel "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"sigs.k8s.io/yaml"

	"k3sm.io/apis/config/crd"
)

// The CEL contract test lives HERE, beside the ensure that applies the manifest,
// and deliberately not in k3sm.io/apis. A faithful test of a CRD's CEL rule needs
// the apiextensions structural-schema and CEL-validation machinery, and apis
// depends on nothing in the org precisely so that every repo can import it; the
// dependency set this test needs is already in this package, so the rule's
// BEHAVIOUR is proven where the machinery lives. apis proves only that the rule
// is present in the bytes it ships.

// celValidator compiles the shipped MLXModel schema's x-kubernetes-validations
// the same way the API server does: v1 schema -> internal schema -> structural
// schema -> compiled validator.
//
// Every step is the API server's own code path. A test that instead matched the
// rule's TEXT would pass for a rule that does not compile, and a test that
// hand-evaluated the expression would prove something about the test's CEL
// environment rather than about the one admission uses.
func celValidator(t *testing.T) *structuralcel.Validator {
	t.Helper()

	var v1CRD apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(crd.MLXModelCRD(), &v1CRD); err != nil {
		t.Fatalf("decode the shipped MLXModel manifest: %v", err)
	}
	if len(v1CRD.Spec.Versions) != 1 {
		t.Fatalf("manifest declares %d versions, want 1", len(v1CRD.Spec.Versions))
	}
	if v1CRD.Spec.Versions[0].Schema == nil || v1CRD.Spec.Versions[0].Schema.OpenAPIV3Schema == nil {
		t.Fatal("manifest declares no openAPIV3Schema")
	}

	var internal apiextensions.JSONSchemaProps
	if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		v1CRD.Spec.Versions[0].Schema.OpenAPIV3Schema, &internal, nil); err != nil {
		t.Fatalf("convert the shipped schema to its internal form: %v", err)
	}
	structural, err := structuralschema.NewStructural(&internal)
	if err != nil {
		t.Fatalf("build the structural schema: %v", err)
	}

	validator := structuralcel.NewValidator(structural, true, celconfig.PerCallLimit)
	if validator == nil {
		t.Fatal("the shipped schema compiled to NO cel validator; the x-kubernetes-validations rule is missing")
	}
	return validator
}

// validateCEL runs the compiled validator over one candidate object, exactly as
// admission would on a CREATE (no oldObj).
func validateCEL(t *testing.T, obj map[string]any) field.ErrorList {
	t.Helper()
	errs, _ := celValidator(t).Validate(context.Background(), field.NewPath(""), nil, obj, nil, celconfig.RuntimeCELCostBudget)
	return errs
}

// modelObject builds a minimally-valid MLXModel as the unstructured object CEL
// sees, applying each mutation in turn. Building it from the Go type would not
// help: CEL evaluates the wire object, and the whole point of spec.distributed is
// that the Go type CAN represent it.
func modelObject(mutate ...func(spec map[string]any)) map[string]any {
	spec := map[string]any{
		"model":  "mlx-community/Qwen3-0.6B-4bit",
		"memory": "8Gi",
	}
	for _, m := range mutate {
		m(spec)
	}
	return map[string]any{
		"apiVersion": "mlx.k3sm.io/v1alpha1",
		"kind":       "MLXModel",
		"metadata":   map[string]any{"name": "demo", "namespace": "default"},
		"spec":       spec,
	}
}

// TestCELRejectsReservedDistributed is the M8.5-a1 CEL slice: a spec that sets
// the reserved spec.distributed field is REJECTED by the rule the shipped CRD
// carries.
//
// The field is representable on purpose, so that a sharding request can be
// refused with a legible reason instead of ignored — and "ignored" is precisely
// what it degrades to if this rule stops working: no controller reads
// spec.distributed, so the model would serve single-node and report success.
// Nothing but admission stands between a user asking for sharding and getting a
// green status that means the opposite.
func TestCELRejectsReservedDistributed(t *testing.T) {
	cases := []struct {
		name       string
		spec       func(map[string]any)
		wantReject bool
	}{
		{
			name:       "a spec that does not mention distributed is accepted",
			spec:       func(map[string]any) {},
			wantReject: false,
		},
		{
			name:       "distributed with nodes set is rejected",
			spec:       func(s map[string]any) { s["distributed"] = map[string]any{"nodes": int64(4)} },
			wantReject: true,
		},
		{
			name: "an EMPTY distributed object is still rejected",
			// has() is true for a present-but-empty object, and it must be: an
			// empty {} is still a user asking for sharding, and accepting it
			// would serve the model single-node under a spec that says otherwise.
			spec:       func(s map[string]any) { s["distributed"] = map[string]any{} },
			wantReject: true,
		},
		{
			name:       "distributed alongside every other field is still rejected",
			spec:       func(s map[string]any) { s["replicas"] = int64(2); s["distributed"] = map[string]any{"nodes": int64(2)} },
			wantReject: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateCEL(t, modelObject(tc.spec))
			if tc.wantReject {
				if len(errs) == 0 {
					t.Fatal("the CEL rule accepted a spec that sets the reserved distributed field")
				}
				joined := errs.ToAggregate().Error()
				if !strings.Contains(joined, "spec.distributed") {
					t.Errorf("rejection message %q does not name spec.distributed; the reason is the whole reason the field is representable", joined)
				}
				return
			}
			if len(errs) != 0 {
				t.Fatalf("the CEL rule rejected a valid spec: %v", errs.ToAggregate())
			}
		})
	}
}

// TestCELRuleIsScopedToSpec pins that the reserved-field rule is attached to the
// spec sub-schema and not to the object root.
//
// A rule hung off the root would evaluate has(self.distributed) against the whole
// custom resource, where the field never exists — so it would accept every spec
// while looking, in the manifest, exactly like a rule that works. That is the
// silent failure this assertion exists to catch, and it is not visible from the
// rejection test above.
func TestCELRuleIsScopedToSpec(t *testing.T) {
	var v1CRD apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(crd.MLXModelCRD(), &v1CRD); err != nil {
		t.Fatalf("decode the shipped MLXModel manifest: %v", err)
	}
	root := v1CRD.Spec.Versions[0].Schema.OpenAPIV3Schema
	if len(root.XValidations) != 0 {
		t.Errorf("the schema root carries %d validation rules; a reserved-field rule there would never fire", len(root.XValidations))
	}
	spec, ok := root.Properties["spec"]
	if !ok {
		t.Fatal("the schema has no spec property")
	}
	if len(spec.XValidations) == 0 {
		t.Fatal("spec carries no x-kubernetes-validations")
	}
	if _, ok := spec.Properties["distributed"]; !ok {
		t.Error("spec.distributed is not declared; an undeclared field is pruned before CEL ever sees it, so the rule could never fire")
	}
}

// TestCELRejectionIsAboutTheRuleNotTheSchema guards the rejection test against
// passing for the wrong reason.
//
// If the object built by modelObject were invalid for some OTHER reason — a
// missing required field, a pruned property — the rejection assertions above
// would be satisfied by structural validation rather than by the CEL rule. This
// asserts the baseline object is JSON-clean and CEL-clean, so the only thing
// distributed changes is the rule's verdict.
func TestCELRejectionIsAboutTheRuleNotTheSchema(t *testing.T) {
	obj := modelObject()
	if _, err := json.Marshal(obj); err != nil {
		t.Fatalf("the baseline object is not serializable: %v", err)
	}
	if errs := validateCEL(t, obj); len(errs) != 0 {
		t.Fatalf("the baseline object is already rejected (%v); every rejection asserted elsewhere would be vacuous", errs.ToAggregate())
	}
}
