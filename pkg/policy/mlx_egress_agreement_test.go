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

// Package policy_test is an EXTERNAL test package (deliberately not `package
// policy`): it imports both k3sm.io/k3sm/pkg/policy and k3sm.io/k3sm/pkg/mlx to
// prove the two packages AGREE on the operator-managed discriminator, without
// pkg/policy itself ever importing pkg/mlx (which would close the import cycle
// pkg/mlx -> pkg/policy documented at operatorManagedByLabelKey's declaration).
package policy_test

import (
	"context"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	mlxv1alpha1 "k3sm.io/apis/mlx/v1alpha1"
	runtimev1 "k3sm.io/apis/runtime/v1"
	"k3sm.io/k3sm/pkg/mlx"
	"k3sm.io/k3sm/pkg/policy"
)

// TestEgressWarnVAPAgreesWithMLXRenderedPodLabels is the cross-package agreement
// gate a same-package test cannot provide: TestEgressAnnotationWarnVAP in
// pkg/policy builds BOTH its CEL and its test fixtures from pkg/policy's own
// unexported operatorManagedByLabelKey/Value constants, so the two drift
// together — a mutation to either constant is invisible to that test (it stays
// green because both sides of the comparison moved).
//
// Here the pod-template label pkg/mlx.Render ACTUALLY STAMPS is the source of
// truth, taken from a real Render() call — independent of anything pkg/policy
// declares. The egress Warn policy's CEL, provisioned through
// policy.EnsureEgressAnnotationWarn's exported path, must contain BOTH that
// exact key and that exact value: an unexported-constant drift on either side
// (the key, e.g. a typo'd "...managed-by-x", or the value, e.g. "k3sm-x") makes
// the rendered label no longer appear in the CEL, and this test reds — closing
// the vacuity a single-package test has no way to catch.
func TestEgressWarnVAPAgreesWithMLXRenderedPodLabels(t *testing.T) {
	m := &mlxv1alpha1.MLXModel{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agreement-probe",
			Namespace: "models",
			UID:       types.UID("11111111-2222-3333-4444-555555555555"),
		},
		Spec: mlxv1alpha1.MLXModelSpec{
			Model:  "mlx-community/Qwen3-0.6B-4bit",
			Memory: resource.MustParse("8Gi"),
			Runtime: mlxv1alpha1.MLXRuntime{
				Image: "ghcr.io/k3sm-io/mlx-serve@sha256:1111111111111111111111111111111111111111111111111111111111111111",
			},
			Port:     8080,
			Replicas: ptr.To(int32(1)),
		},
	}
	objs, err := mlx.Render(m, mlx.Options{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if objs.StatefulSet == nil {
		t.Fatal("render produced no StatefulSet")
	}

	podLabels := objs.StatefulSet.Spec.Template.ObjectMeta.Labels
	if len(podLabels) == 0 {
		t.Fatal("rendered StatefulSet pod template carries no labels — nothing to agree on")
	}
	// managedByKey/Value are read OUT of the rendered pod-template labels, not
	// hand-typed and not read from pkg/policy — this is the independent source
	// of truth the agreement check is FOR.
	const managedByKey = "app.kubernetes.io/managed-by"
	managedByValue, ok := podLabels[managedByKey]
	if !ok {
		t.Fatalf("rendered pod template has no %q label; got %v", managedByKey, podLabels)
	}

	cs := fake.NewClientset()
	if err := policy.EnsureEgressAnnotationWarn(context.Background(), cs); err != nil {
		t.Fatalf("EnsureEgressAnnotationWarn: %v", err)
	}
	list, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	var expr string
	found := false
	for _, p := range list.Items {
		if len(p.Spec.Validations) == 0 {
			continue
		}
		e := p.Spec.Validations[0].Expression
		if strings.Contains(e, runtimev1.AnnotationInternetEgress) {
			expr = e
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no provisioned ValidatingAdmissionPolicy references %s", runtimev1.AnnotationInternetEgress)
	}

	// The load-bearing assertions: the CEL must contain the EXACT key AND the
	// EXACT value pkg/mlx.Render actually stamped — not pkg/policy's own
	// unexported constants restated. A key-only or value-only drift between the
	// two packages must red here even though pkg/policy's own internal test
	// (built from the same constants on both sides) cannot see it.
	//
	// Matched as the CEL single-quoted STRING LITERAL ('key'/'value'), not a
	// bare substring: a bare Contains(expr, managedByKey) would be silently
	// satisfied by a SUFFIX mutation (e.g. the key becoming
	// "app.kubernetes.io/managed-by-x" is still a superstring of the correct
	// key), which is exactly the kind of near-miss this agreement test exists
	// to catch. Quoting the literal pins the boundary the mutation would cross.
	quotedKey := "'" + managedByKey + "'"
	quotedValue := "'" + managedByValue + "'"
	if !strings.Contains(expr, quotedKey) {
		t.Errorf("egress Warn CEL does not contain the label KEY literal %s pkg/mlx.Render stamps: %s", quotedKey, expr)
	}
	if !strings.Contains(expr, quotedValue) {
		t.Errorf("egress Warn CEL does not contain the label VALUE literal %s pkg/mlx.Render stamps: %s", quotedValue, expr)
	}

	// Sanity: the policy this expression came from must still be Warn-only,
	// Ignore-failing, and pods/CREATE-scoped — the agreement check would be
	// worthless if it happened to match some unrelated Deny policy.
	for _, p := range list.Items {
		if len(p.Spec.Validations) == 0 || p.Spec.Validations[0].Expression != expr {
			continue
		}
		if p.Spec.FailurePolicy == nil || *p.Spec.FailurePolicy != admissionregistrationv1.Ignore {
			t.Errorf("egress Warn policy FailurePolicy = %v, want Ignore", p.Spec.FailurePolicy)
		}
		if len(p.Spec.MatchConstraints.ResourceRules) == 0 ||
			!containsResource(p.Spec.MatchConstraints.ResourceRules[0].Resources, "pods") {
			t.Errorf("egress Warn policy does not match pods: %+v", p.Spec.MatchConstraints)
		}
	}
}

func containsResource(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
