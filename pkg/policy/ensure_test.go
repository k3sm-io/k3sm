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
	"errors"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestEnsureReconcilesAStalePolicyInPlace is the create-or-update gate (B153). It
// pins the property the old create-if-absent path did NOT have: a cluster whose
// datastore already holds an out-of-date object is REPAIRED on the next server
// start, not left frozen at whatever shape it was first created with.
//
// This is the merge-precondition of the B153 fix itself. Changing the foreign-user
// expression's allowed uid is INERT on every existing cluster without it — the fix
// would be green in CI and absent in production.
//
// "In place" is asserted through the object's UID: a delete-and-recreate would
// satisfy a naive spec comparison while opening a window in which the guard does
// not exist at all.
func TestEnsureReconcilesAStalePolicyInPlace(t *testing.T) {
	ctx := context.Background()

	t.Run("the foreign-user policy follows a changed allowed uid", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := EnsureNoForeignUserAdmission(ctx, cs, 271); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		first, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get after first provision: %v", err)
		}

		// The server restarts with a different pod-execution uid (an install, a
		// posture change) — the stored policy must follow.
		if err := EnsureNoForeignUserAdmission(ctx, cs, 4242); err != nil {
			t.Fatalf("second provision: %v", err)
		}
		got, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get after second provision: %v", err)
		}
		if want := foreignUserExpr(4242); got.Spec.Validations[0].Expression != want {
			t.Errorf("stale expression survived the reprovision:\ngot:  %s\nwant: %s", got.Spec.Validations[0].Expression, want)
		}
		if strings.Contains(got.Spec.Validations[0].Expression, "271") {
			t.Error("the superseded uid 271 is still in the stored expression")
		}
		if got.UID != first.UID {
			t.Errorf("policy UID changed (%q -> %q): it was delete-and-recreated, which leaves a window with NO guard", first.UID, got.UID)
		}
	})

	t.Run("a hand-edited os=darwin policy is repaired", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := EnsureDarwinAdmission(ctx, cs); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		stored, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, darwinPolicyName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		stored.Spec.Validations[0].Expression = "true" // an admit-everything drift
		if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Update(ctx, stored, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("seed the drift: %v", err)
		}

		if err := EnsureDarwinAdmission(ctx, cs); err != nil {
			t.Fatalf("reprovision: %v", err)
		}
		got, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, darwinPolicyName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get after reprovision: %v", err)
		}
		if got.Spec.Validations[0].Expression != darwinSelectorExpr {
			t.Errorf("drifted expression survived: %q", got.Spec.Validations[0].Expression)
		}
	})

	t.Run("a downgraded binding action is restored to Deny", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := EnsureNoForeignUserAdmission(ctx, cs, 271); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		b, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, foreignUserBindingName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get binding: %v", err)
		}
		b.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Warn}
		if _, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Update(ctx, b, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("seed the drift: %v", err)
		}

		if err := EnsureNoForeignUserAdmission(ctx, cs, 271); err != nil {
			t.Fatalf("reprovision: %v", err)
		}
		got, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, foreignUserBindingName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get binding after reprovision: %v", err)
		}
		if len(got.Spec.ValidationActions) != 1 || got.Spec.ValidationActions[0] != admissionregistrationv1.Deny {
			t.Errorf("binding actions = %v, want [Deny] — a guard downgraded to Warn stays downgraded", got.Spec.ValidationActions)
		}
	})

	t.Run("a stale default LimitRange follows the shipped defaults", func(t *testing.T) {
		cs := fake.NewClientset()
		if err := EnsureDefaultLimitRange(ctx, cs); err != nil {
			t.Fatalf("first provision: %v", err)
		}
		lr, err := cs.CoreV1().LimitRanges(defaultLimitRangeNamespace).Get(ctx, defaultLimitRangeName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get limitrange: %v", err)
		}
		lr.Spec.Limits[0].Default = corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Mi")}
		if _, err := cs.CoreV1().LimitRanges(defaultLimitRangeNamespace).Update(ctx, lr, metav1.UpdateOptions{}); err != nil {
			t.Fatalf("seed the drift: %v", err)
		}

		if err := EnsureDefaultLimitRange(ctx, cs); err != nil {
			t.Fatalf("reprovision: %v", err)
		}
		got, err := cs.CoreV1().LimitRanges(defaultLimitRangeNamespace).Get(ctx, defaultLimitRangeName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get limitrange after reprovision: %v", err)
		}
		want := resource.MustParse(defaultMemoryLimit)
		if cur := got.Spec.Limits[0].Default[corev1.ResourceMemory]; cur.Cmp(want) != 0 {
			t.Errorf("default memory = %s, want %s", cur.String(), want.String())
		}
	})
}

// TestEnsureIsNotAWriteWhenAlreadyCurrent pins the other half of the contract: an
// object whose spec already matches is left COMPLETELY alone. Without this, every
// server start (and every HA peer's start) would rewrite every policy, churning
// resourceVersions and waking every watcher for nothing.
//
// It counts the fake clientset's `update` actions rather than comparing
// resourceVersions, because a no-op Update is still a write at the apiserver even
// when the resulting object is byte-identical.
func TestEnsureIsNotAWriteWhenAlreadyCurrent(t *testing.T) {
	ctx := context.Background()
	provisionAll := func(cs *fake.Clientset) error {
		if err := EnsureDarwinAdmission(ctx, cs); err != nil {
			return err
		}
		if err := EnsureNoForeignUserAdmission(ctx, cs, 271); err != nil {
			return err
		}
		if err := EnsureRejectReservedLoadBalancerPort(ctx, cs); err != nil {
			return err
		}
		if err := EnsureExternalTrafficPolicyLocalWarn(ctx, cs); err != nil {
			return err
		}
		if err := EnsureUDPServiceWarn(ctx, cs); err != nil {
			return err
		}
		if err := EnsureProviderTolerationWarn(ctx, cs); err != nil {
			return err
		}
		if err := EnsureDaemonSetTolerationMutation(ctx, cs); err != nil {
			return err
		}
		return EnsureDefaultLimitRange(ctx, cs)
	}

	cs := fake.NewClientset()
	if err := provisionAll(cs); err != nil {
		t.Fatalf("first provision: %v", err)
	}
	cs.ClearActions()
	// The second start of the same server against the same datastore.
	if err := provisionAll(cs); err != nil {
		t.Fatalf("second provision: %v", err)
	}
	var updates []string
	for _, a := range cs.Actions() {
		if a.GetVerb() == "update" {
			updates = append(updates, a.GetResource().Resource)
		}
	}
	if len(updates) != 0 {
		t.Errorf("a restart against an already-current cluster issued %d update(s) %v, want none", len(updates), updates)
	}
}

// errSeededConflict is the cause the HA-race test's synthetic Conflict carries.
var errSeededConflict = errors.New("seeded conflict: another server provisioned this object first")

// TestEnsureRetriesAConflictingUpdate pins the HA case: two servers provision the
// same cluster-scoped objects on their own restarts, so the reconciling Update can
// lose a race. A Conflict must be retried, not surfaced as a provisioning failure
// that leaves the object stale until the next restart.
func TestEnsureRetriesAConflictingUpdate(t *testing.T) {
	ctx := context.Background()
	cs := fake.NewClientset()
	if err := EnsureNoForeignUserAdmission(ctx, cs, 271); err != nil {
		t.Fatalf("first provision: %v", err)
	}

	// Fail the first update with a Conflict, then let the retry through.
	conflicts := 0
	cs.PrependReactor("update", "validatingadmissionpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if conflicts == 0 {
			conflicts++
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "admissionregistration.k8s.io", Resource: "validatingadmissionpolicies"},
				foreignUserPolicyName, errSeededConflict)
		}
		return false, nil, nil
	})

	if err := EnsureNoForeignUserAdmission(ctx, cs, 4242); err != nil {
		t.Fatalf("reprovision through a Conflict: %v", err)
	}
	if conflicts != 1 {
		t.Fatalf("the seeded Conflict never fired (conflicts=%d) — the test proves nothing", conflicts)
	}
	got, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, foreignUserPolicyName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if want := foreignUserExpr(4242); got.Spec.Validations[0].Expression != want {
		t.Error("the retried Update did not land: the policy is still stale after a Conflict")
	}
}
