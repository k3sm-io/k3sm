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

// TestRegistryPusherRoleIsUnbound pins that k3sm ships the pusher role and NO
// binding to it: who may push is each namespace's own RoleBinding, never a
// grant k3sm makes for it.
func TestRegistryPusherRoleIsUnbound(t *testing.T) {
	cs := fake.NewClientset()
	if err := Provision(context.Background(), cs); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, o := range createdObjects(t, cs.Actions()) {
		if o.RoleRef != nil && o.RoleRef.Name == wantRegistryPusherRole {
			t.Errorf("%s %s/%s binds %s; k3sm must provision no binding to it", o.Kind, o.Namespace, o.Name, wantRegistryPusherRole)
		}
	}
}
