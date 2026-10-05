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
	apiservervalidation "k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
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

// validateSchema runs the API server's OpenAPI schema validation (the enums and
// types) over one candidate object. CEL rules do not cover enums, so the enum
// half of the distributed shape is proven through this path.
func validateSchema(t *testing.T, obj map[string]any) field.ErrorList {
	t.Helper()

	var v1CRD apiextensionsv1.CustomResourceDefinition
	if err := yaml.Unmarshal(crd.MLXModelCRD(), &v1CRD); err != nil {
		t.Fatalf("decode the shipped MLXModel manifest: %v", err)
	}
	var internal apiextensions.JSONSchemaProps
	if err := apiextensionsv1.Convert_v1_JSONSchemaProps_To_apiextensions_JSONSchemaProps(
		v1CRD.Spec.Versions[0].Schema.OpenAPIV3Schema, &internal, nil); err != nil {
		t.Fatalf("convert the shipped schema to its internal form: %v", err)
	}
	validator, _, err := apiservervalidation.NewSchemaValidator(&internal)
	if err != nil {
		t.Fatalf("build the schema validator: %v", err)
	}
	return apiservervalidation.ValidateCustomResource(field.NewPath(""), obj, validator)
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

// TestCELAcceptsDistributedShape is the M17.4-d5 CEL slice: spec.distributed is
// no longer reserved. The MLXModel rule validates its shape (ranks set and at
// least 2, one rank per node) and the enums on backend and parallelism reject
// anything else, so a well-formed sharding request is admitted for the operator
// to place and a malformed one is refused with a legible reason.
//
// The rule and the operator that honours the field ship in one binary, so
// admitting ranks: 2 can never serve single-node and report success.
func TestCELAcceptsDistributedShape(t *testing.T) {
	dist := func(d map[string]any) func(map[string]any) {
		return func(s map[string]any) { s["distributed"] = d }
	}
	cases := []struct {
		name       string
		spec       func(map[string]any)
		wantReject bool
		wantText   string
	}{
		{
			name:       "a spec that does not mention distributed is accepted",
			spec:       func(map[string]any) {},
			wantReject: false,
		},
		{
			name:       "ranks 2, ring, tensor is accepted",
			spec:       dist(map[string]any{"ranks": int64(2), "backend": "ring", "parallelism": "tensor"}),
			wantReject: false,
		},
		{
			name:       "ranks alone is accepted",
			spec:       dist(map[string]any{"ranks": int64(3)}),
			wantReject: false,
		},
		{
			name:       "ranks 1 is rejected by the rule",
			spec:       dist(map[string]any{"ranks": int64(1)}),
			wantReject: true,
			wantText:   "spec.distributed.ranks must be set and at least 2",
		},
		{
			name:       "an EMPTY distributed object is rejected for the missing ranks",
			spec:       dist(map[string]any{}),
			wantReject: true,
			wantText:   "spec.distributed.ranks must be set and at least 2",
		},
		{
			name:       "backend nccl is rejected by the enum",
			spec:       dist(map[string]any{"ranks": int64(2), "backend": "nccl"}),
			wantReject: true,
			wantText:   "backend",
		},
		{
			name:       "parallelism expert is rejected by the enum",
			spec:       dist(map[string]any{"ranks": int64(2), "parallelism": "expert"}),
			wantReject: true,
			wantText:   "parallelism",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := modelObject(tc.spec)
			errs := append(validateCEL(t, obj), validateSchema(t, obj)...)
			if tc.wantReject {
				if len(errs) == 0 {
					t.Fatal("the validation accepted a malformed spec.distributed block")
				}
				if joined := errs.ToAggregate().Error(); !strings.Contains(joined, tc.wantText) {
					t.Errorf("rejection message %q does not contain %q", joined, tc.wantText)
				}
				return
			}
			if len(errs) != 0 {
				t.Fatalf("the validation rejected a valid spec: %v", errs.ToAggregate())
			}
		})
	}
}

// TestCELRuleIsScopedToSpec pins that the shape rule is attached to the
// spec.distributed sub-schema and not to the object root.
//
// A rule hung off the root would evaluate has(self.ranks) against the whole
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
		t.Errorf("the schema root carries %d validation rules; a shape rule there would never fire", len(root.XValidations))
	}
	spec, ok := root.Properties["spec"]
	if !ok {
		t.Fatal("the schema has no spec property")
	}
	distributed, ok := spec.Properties["distributed"]
	if !ok {
		t.Fatal("spec.distributed is not declared; an undeclared field is pruned before CEL ever sees it, so the rule could never fire")
	}
	if len(distributed.XValidations) == 0 {
		t.Fatal("spec.distributed carries no x-kubernetes-validations")
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
