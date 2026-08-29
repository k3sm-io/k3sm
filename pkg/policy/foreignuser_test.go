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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// allowedTestUID is the uid the foreign-user expression under test is
// parameterised with — a plausible macOS hidden-service uid, deliberately not 0
// and not any uid a developer's shell runs as.
const allowedTestUID int64 = 271

// sc builds a securityContext map from the given uid/gid fields; a nil value is
// OMITTED, which is the shape that must be ADMITTED.
func sc(fields map[string]any) map[string]any { return fields }

// foreignUserPod builds the unstructured Pod an admission plugin would evaluate.
// podSC is the pod-level securityContext (nil => the key is absent entirely);
// containers/initContainers/ephemeralContainers are lists of per-container
// securityContexts, with a nil entry meaning "container with no securityContext".
// initContainers/ephemeralContainers are omitted entirely when empty, because the
// CEL's has() guards for those optional lists are part of what is under test.
func foreignUserPod(podSC map[string]any, containers, initContainers, ephemeral []map[string]any) map[string]any {
	build := func(list []map[string]any) []any {
		out := make([]any, 0, len(list))
		for _, c := range list {
			entry := map[string]any{"name": "c", "image": "native"}
			if c != nil {
				entry["securityContext"] = c
			}
			out = append(out, entry)
		}
		return out
	}
	spec := map[string]any{"containers": build(containers)}
	if podSC != nil {
		spec["securityContext"] = podSC
	}
	if len(initContainers) > 0 {
		spec["initContainers"] = build(initContainers)
	}
	if len(ephemeral) > 0 {
		spec["ephemeralContainers"] = build(ephemeral)
	}
	return map[string]any{"spec": spec}
}

// TestForeignUserExprEvaluates EVALUATES the foreign-user CEL with real cel-go —
// it does not grep the expression string. That distinction is the whole point of
// this gate: the pre-existing shape assertion (TestEnsureNoForeignUserAdmission)
// only checks that the rendered text CONTAINS "fsGroup" and the uid, so it has
// never once observed an admit or a reject, and it would pass unchanged against an
// expression that admits everything.
//
// Both directions are covered, because a guard that only ever denies is as broken
// as one that only ever admits: a pod omitting the fields, or carrying an empty
// securityContext, or naming exactly the allowed id, MUST be admitted.
func TestForeignUserExprEvaluates(t *testing.T) {
	prg := celProgram(t, foreignUserExpr(allowedTestUID))

	const foreign int64 = 2000
	allowed := allowedTestUID

	tests := []struct {
		name      string
		object    map[string]any
		wantAdmit bool
	}{
		// ---- REJECT: pod-level securityContext ----------------------------------
		// fsGroup 2000 is the exact shape e2e TestM2_FsGroup submits (B153).
		{"pod fsGroup foreign is REJECTED", foreignUserPod(sc(map[string]any{"fsGroup": foreign}), []map[string]any{nil}, nil, nil), false},
		{"pod runAsUser foreign is REJECTED", foreignUserPod(sc(map[string]any{"runAsUser": foreign}), []map[string]any{nil}, nil, nil), false},
		{"pod runAsGroup foreign is REJECTED", foreignUserPod(sc(map[string]any{"runAsGroup": foreign}), []map[string]any{nil}, nil, nil), false},
		{"pod supplementalGroups with one foreign entry is REJECTED",
			foreignUserPod(sc(map[string]any{"supplementalGroups": []any{allowed, foreign}}), []map[string]any{nil}, nil, nil), false},
		{"pod runAsUser 0 (root) is REJECTED", foreignUserPod(sc(map[string]any{"runAsUser": int64(0)}), []map[string]any{nil}, nil, nil), false},

		// ---- REJECT: per-container, across all three lists ----------------------
		{"container runAsUser foreign is REJECTED", foreignUserPod(nil, []map[string]any{{"runAsUser": foreign}}, nil, nil), false},
		{"container runAsGroup foreign is REJECTED", foreignUserPod(nil, []map[string]any{{"runAsGroup": foreign}}, nil, nil), false},
		{"the SECOND container's foreign runAsUser is REJECTED",
			foreignUserPod(nil, []map[string]any{nil, {"runAsUser": foreign}}, nil, nil), false},
		{"initContainer runAsUser foreign is REJECTED", foreignUserPod(nil, []map[string]any{nil}, []map[string]any{{"runAsUser": foreign}}, nil), false},
		{"initContainer runAsGroup foreign is REJECTED", foreignUserPod(nil, []map[string]any{nil}, []map[string]any{{"runAsGroup": foreign}}, nil), false},
		{"ephemeralContainer runAsUser foreign is REJECTED", foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{{"runAsUser": foreign}}), false},
		{"ephemeralContainer runAsGroup foreign is REJECTED", foreignUserPod(nil, []map[string]any{nil}, nil, []map[string]any{{"runAsGroup": foreign}}), false},

		// ---- ADMIT: the shapes a guard must never reject ------------------------
		{"a pod with no securityContext anywhere is ADMITTED", foreignUserPod(nil, []map[string]any{nil}, nil, nil), true},
		{"an EMPTY pod securityContext is ADMITTED", foreignUserPod(sc(map[string]any{}), []map[string]any{nil}, nil, nil), true},
		{"an EMPTY container securityContext is ADMITTED", foreignUserPod(nil, []map[string]any{{}}, nil, nil), true},
		{"pod fsGroup == the allowed id is ADMITTED", foreignUserPod(sc(map[string]any{"fsGroup": allowed}), []map[string]any{nil}, nil, nil), true},
		{"every uid/gid field set to the allowed id is ADMITTED",
			foreignUserPod(sc(map[string]any{
				"runAsUser": allowed, "runAsGroup": allowed, "fsGroup": allowed,
				"supplementalGroups": []any{allowed},
			}), []map[string]any{{"runAsUser": allowed, "runAsGroup": allowed}},
				[]map[string]any{{"runAsUser": allowed}}, []map[string]any{{"runAsGroup": allowed}}), true},
		{"an EMPTY supplementalGroups list is ADMITTED",
			foreignUserPod(sc(map[string]any{"supplementalGroups": []any{}}), []map[string]any{nil}, nil, nil), true},
		{"a pod with init and ephemeral containers that set nothing is ADMITTED",
			foreignUserPod(nil, []map[string]any{nil}, []map[string]any{nil}, []map[string]any{nil}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]any{"object": tt.object})
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			admit, ok := out.Value().(bool)
			if !ok {
				t.Fatalf("CEL returned %T (%v), want bool", out.Value(), out.Value())
			}
			if admit != tt.wantAdmit {
				t.Errorf("admit = %v, want %v\nexpression:\n%s", admit, tt.wantAdmit, foreignUserExpr(allowedTestUID))
			}
		})
	}
}

// TestForeignUserExprIsParameterised proves the allowed uid is a PARAMETER, not a
// constant baked into the expression: the same shape flips verdict when the
// expression is built for a different id. Without this, the evaluation table above
// would pass against an expression that hard-wired 271.
//
// It is the CEL-side half of the B153 sub-decision that the allowed uid comes from
// the pod-execution posture; the other half (which uid that is) is pinned in
// pkg/provider's TestPodExecutionUID, and the wiring between them in
// cmd/k3sm's TestBringupForeignUserPolicyPinsThePodExecutionUID.
func TestForeignUserExprIsParameterised(t *testing.T) {
	const other int64 = 4242
	pod := foreignUserPod(sc(map[string]any{"fsGroup": other}), []map[string]any{nil}, nil, nil)

	for _, tc := range []struct {
		allowed   int64
		wantAdmit bool
	}{
		{allowedTestUID, false}, // fsGroup 4242 against an allowed 271 -> reject
		{other, true},           // the SAME pod against an allowed 4242 -> admit
	} {
		out, _, err := celProgram(t, foreignUserExpr(tc.allowed)).Eval(map[string]any{"object": pod})
		if err != nil {
			t.Fatalf("eval (allowed=%d): %v", tc.allowed, err)
		}
		if got := out.Value().(bool); got != tc.wantAdmit {
			t.Errorf("allowed=%d: admit = %v, want %v", tc.allowed, got, tc.wantAdmit)
		}
	}
}

// TestEnsureNoForeignUserAdmissionProvisionsTheEvaluatedExpression closes the loop
// between the two halves above: the expression this package PROVISIONS must be the
// one the evaluation table proved, for the uid it was called with. A test that
// evaluates foreignUserExpr while the Ensure path shipped something else would be
// green and worthless.
func TestEnsureNoForeignUserAdmissionProvisionsTheEvaluatedExpression(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := EnsureNoForeignUserAdmission(ctx, cs, allowedTestUID); err != nil {
		t.Fatalf("EnsureNoForeignUserAdmission: %v", err)
	}
	pol, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if len(pol.Spec.Validations) != 1 {
		t.Fatalf("validations = %d, want 1", len(pol.Spec.Validations))
	}
	if got, want := pol.Spec.Validations[0].Expression, foreignUserExpr(allowedTestUID); got != want {
		t.Errorf("provisioned expression is not the evaluated one:\ngot:  %s\nwant: %s", got, want)
	}
	// The message must name the identity, or a rejected operator learns nothing.
	if msg := pol.Spec.Validations[0].Message; !strings.Contains(msg, "fsGroup") {
		t.Errorf("rejection message does not mention fsGroup: %q", msg)
	}
}
