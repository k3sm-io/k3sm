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

package rbac

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// The in-pod push grants, spelled as literals so a renamed constant cannot
// move what an operator's kubectl reads back or what a namespace binds.
const (
	wantRegistryGateRole   = "k3sm:registry-gate"
	wantRegistryGateGroup  = "k3sm:registry-gates"
	wantRegistryPusherRole = "k3sm:registry-pusher"
)

// TestRegistryPushRBAC pins the two in-pod push roles: the gate's role grants
// exactly create on tokenreviews and subjectaccessreviews and get on
// namespaces, bound to the gate's group alone; the pusher role grants exactly
// push on registry.k3sm.io repositories; and both are repaired when drifted.
func TestRegistryPushRBAC(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	assertGate := func(t *testing.T) {
		t.Helper()
		role, err := cs.RbacV1().ClusterRoles().Get(ctx, wantRegistryGateRole, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get %s: %v", wantRegistryGateRole, err)
		}
		got := flattenGrants(t, role.Rules)
		want := map[string]string{
			"authentication.k8s.io/tokenreviews":        "create",
			"authorization.k8s.io/subjectaccessreviews": "create",
			"/namespaces": "get",
		}
		if len(got) != len(want) {
			t.Errorf("%s grants %v, want exactly %v", wantRegistryGateRole, got, want)
		}
		for gr, verbs := range want {
			if got[gr] != verbs {
				t.Errorf("%s: %s verbs = %q, want %q", wantRegistryGateRole, gr, got[gr], verbs)
			}
		}
		if role.Labels["k3sm.io/managed"] != "true" || role.AggregationRule != nil {
			t.Errorf("%s labels %v aggregation %v, want managed and no aggregation", wantRegistryGateRole, role.Labels, role.AggregationRule)
		}
		b, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, wantRegistryGateRole, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get binding %s: %v", wantRegistryGateRole, err)
		}
		if b.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: wantRegistryGateRole}) {
			t.Errorf("binding roleRef = %+v", b.RoleRef)
		}
		wantSubj := rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: wantRegistryGateGroup}
		if len(b.Subjects) != 1 || b.Subjects[0] != wantSubj {
			t.Errorf("binding subjects = %+v, want exactly the %s group", b.Subjects, wantRegistryGateGroup)
		}
		pusher, err := cs.RbacV1().ClusterRoles().Get(ctx, wantRegistryPusherRole, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get %s: %v", wantRegistryPusherRole, err)
		}
		if got := flattenGrants(t, pusher.Rules); len(got) != 1 || got["registry.k3sm.io/repositories"] != "push" {
			t.Errorf("%s grants %v, want exactly push on registry.k3sm.io/repositories", wantRegistryPusherRole, got)
		}
		if pusher.Labels["k3sm.io/managed"] != "true" {
			t.Errorf("%s labels = %v, want managed", wantRegistryPusherRole, pusher.Labels)
		}
	}
	assertGate(t)

	t.Run("a drifted copy is repaired on the next start", func(t *testing.T) {
		role, _ := cs.RbacV1().ClusterRoles().Get(ctx, wantRegistryGateRole, metav1.GetOptions{})
		role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"list"}})
		role.Labels = nil
		if _, err := cs.RbacV1().ClusterRoles().Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		pusher, _ := cs.RbacV1().ClusterRoles().Get(ctx, wantRegistryPusherRole, metav1.GetOptions{})
		pusher.Rules[0].Verbs = []string{"*"}
		if _, err := cs.RbacV1().ClusterRoles().Update(ctx, pusher, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		b, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, wantRegistryGateRole, metav1.GetOptions{})
		b.Subjects = append(b.Subjects, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "system:authenticated"})
		if _, err := cs.RbacV1().ClusterRoleBindings().Update(ctx, b, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		assertGate(t)
	})
}

// TestRegistryPusherRoleIsUnbound pins that k3sm's ONLY binding to the pusher
// role is the builder's ClusterRoleBinding, to exactly the builder
// ServiceAccount: every other pusher is a namespace's own RoleBinding, never a
// grant k3sm makes for it.
func TestRegistryPusherRoleIsUnbound(t *testing.T) {
	cs := fake.NewClientset()
	if err := Provision(context.Background(), cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, o := range createdObjects(t, cs.Actions()) {
		if o.RoleRef == nil || o.RoleRef.Name != wantRegistryPusherRole {
			continue
		}
		builder := rbacv1.Subject{Kind: "ServiceAccount", Name: wantBuilderSA, Namespace: wantBuilderNamespace}
		if o.Kind != "ClusterRoleBinding" || o.Name != wantBuilderBinding || len(o.Subjects) != 1 || o.Subjects[0] != builder {
			t.Errorf("%s %s/%s binds %s to %+v; k3sm binds it to the builder ServiceAccount alone", o.Kind, o.Namespace, o.Name, wantRegistryPusherRole, o.Subjects)
		}
	}
}

// The builder identity, spelled as literals for the same reason as above.
const (
	wantBuilderNamespace = "k3sm-registry"
	wantBuilderSA        = "builder"
	wantBuilderBinding   = "k3sm:registry-builder"
	wantBuilderTokenRole = "k3sm:registry-builder-token"
)

// TestEnsureGraphCreatesRegistryBuilder pins the builder identity a new
// cluster has from its first start: the k3sm-registry/builder ServiceAccount
// and a ClusterRoleBinding of k3sm:registry-pusher to exactly it, both
// repaired when drifted.
func TestEnsureGraphCreatesRegistryBuilder(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := ensureGraph(ctx, cs); err != nil {
		t.Fatalf("ensureGraph: %v", err)
	}
	assertBuilder := func(t *testing.T) {
		t.Helper()
		sa, err := cs.CoreV1().ServiceAccounts(wantBuilderNamespace).Get(ctx, wantBuilderSA, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get service account %s/%s: %v", wantBuilderNamespace, wantBuilderSA, err)
		}
		if sa.Labels["k3sm.io/managed"] != "true" {
			t.Errorf("service account labels = %v, want managed", sa.Labels)
		}
		b, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, wantBuilderBinding, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get binding %s: %v", wantBuilderBinding, err)
		}
		if b.RoleRef != (rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: wantRegistryPusherRole}) {
			t.Errorf("binding roleRef = %+v, want the %s ClusterRole", b.RoleRef, wantRegistryPusherRole)
		}
		want := rbacv1.Subject{Kind: "ServiceAccount", Name: wantBuilderSA, Namespace: wantBuilderNamespace}
		if len(b.Subjects) != 1 || b.Subjects[0] != want {
			t.Errorf("binding subjects = %+v, want exactly %+v", b.Subjects, want)
		}
		if b.Labels["k3sm.io/managed"] != "true" {
			t.Errorf("binding labels = %v, want managed", b.Labels)
		}
	}
	assertBuilder(t)

	t.Run("a widened binding is repaired on the next start", func(t *testing.T) {
		b, _ := cs.RbacV1().ClusterRoleBindings().Get(ctx, wantBuilderBinding, metav1.GetOptions{})
		b.Subjects = append(b.Subjects, rbacv1.Subject{APIGroup: rbacv1.GroupName, Kind: "Group", Name: "system:authenticated"})
		if _, err := cs.RbacV1().ClusterRoleBindings().Update(ctx, b, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := ensureGraph(ctx, cs); err != nil {
			t.Fatalf("ensureGraph: %v", err)
		}
		assertBuilder(t)
	})
	t.Run("a second start is a no-op", func(t *testing.T) {
		if err := ensureGraph(ctx, cs); err != nil {
			t.Fatalf("ensureGraph: %v", err)
		}
		assertBuilder(t)
	})
}

// TestRegistryBuilderTokenRoleShipsUnbound pins the token role: exactly create
// on serviceaccounts/token for the one name builder, and no binding to it
// anywhere in the graph k3sm provisions.
func TestRegistryBuilderTokenRoleShipsUnbound(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()
	if err := Provision(ctx, cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := cs.RbacV1().ClusterRoles().Get(ctx, wantBuilderTokenRole, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("%s exists as a ClusterRole (%v); it must be a Role in %s only", wantBuilderTokenRole, err, wantBuilderNamespace)
	}
	role, err := cs.RbacV1().Roles(wantBuilderNamespace).Get(ctx, wantBuilderTokenRole, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get %s: %v", wantBuilderTokenRole, err)
	}
	want := []rbacv1.PolicyRule{{
		APIGroups:     []string{""},
		Resources:     []string{"serviceaccounts/token"},
		ResourceNames: []string{wantBuilderSA},
		Verbs:         []string{"create"},
	}}
	if len(role.Rules) != 1 || !equalRule(role.Rules[0], want[0]) {
		t.Errorf("%s rules = %+v, want exactly %+v", wantBuilderTokenRole, role.Rules, want)
	}
	if role.Labels["k3sm.io/managed"] != "true" {
		t.Errorf("%s labels %v, want managed", wantBuilderTokenRole, role.Labels)
	}
	for _, o := range createdObjects(t, cs.Actions()) {
		if o.RoleRef != nil && o.RoleRef.Name == wantBuilderTokenRole {
			t.Errorf("%s %s/%s binds %s; k3sm must ship it unbound", o.Kind, o.Namespace, o.Name, wantBuilderTokenRole)
		}
	}

	t.Run("a widened copy is repaired on the next start", func(t *testing.T) {
		r, _ := cs.RbacV1().Roles(wantBuilderNamespace).Get(ctx, wantBuilderTokenRole, metav1.GetOptions{})
		r.Rules[0].ResourceNames = nil
		r.Rules[0].Verbs = []string{"create", "get"}
		if _, err := cs.RbacV1().Roles(wantBuilderNamespace).Update(ctx, r, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if err := Provision(ctx, cs); err != nil {
			t.Fatalf("Provision: %v", err)
		}
		r, _ = cs.RbacV1().Roles(wantBuilderNamespace).Get(ctx, wantBuilderTokenRole, metav1.GetOptions{})
		if len(r.Rules) != 1 || !equalRule(r.Rules[0], want[0]) {
			t.Errorf("after repair %s rules = %+v, want %+v", wantBuilderTokenRole, r.Rules, want)
		}
	})
}

// equalRule compares two policy rules field by field.
func equalRule(a, b rbacv1.PolicyRule) bool {
	eq := func(x, y []string) bool {
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	}
	return eq(a.APIGroups, b.APIGroups) && eq(a.Resources, b.Resources) && eq(a.ResourceNames, b.ResourceNames) &&
		eq(a.Verbs, b.Verbs) && eq(a.NonResourceURLs, b.NonResourceURLs)
}
